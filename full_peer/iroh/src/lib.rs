//! Iroh connection lifecycle for a full peer.
//!
//! This crate deliberately has no HTTP, grant, workspace, object-key, bucket,
//! repository, or authorization types.  One local TCP byte stream maps to one
//! Iroh bidirectional stream.  At the accepting peer that stream maps back to
//! the core peer-data HTTP listener, where the normal parser, limits, grant
//! gate, and storage calls execute unchanged.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use iroh::endpoint::{Incoming, PortmapperConfig, presets};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, Watcher};
use tokio::io::{copy_bidirectional, join};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Selects this byte-stream protocol; it does not grant repository authority.
pub const ALPN: &[u8] = b"poc16/http-byte-stream/1";

/// Tickets are local connection configuration, not repository capabilities.
pub const MAX_TICKET_BYTES: usize = 4 * 1024;

/// Wait this long for a usable local or relay address.
const ADDRESS_TIMEOUT: Duration = Duration::from_secs(30);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Establish one endpoint.
///
/// Loopback mode binds no all-interface socket, relay, discovery service, or
/// port mapper.  It exists so normal tests exercise real Iroh/QUIC without
/// reaching the public network.
///
/// # Errors
///
/// Returns an error when socket configuration or endpoint binding fails.
pub async fn bind_endpoint(
    loopback: bool,
    accepts_connections: bool,
    secret: Option<SecretKey>,
) -> Result<Endpoint> {
    let builder = if loopback {
        Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .portmapper_config(PortmapperConfig::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .context("configure loopback Iroh socket")?
    } else {
        Endpoint::builder(presets::N0)
    };
    let builder = if accepts_connections {
        builder.alpns(vec![ALPN.to_vec()])
    } else {
        builder
    };
    let builder = match secret {
        Some(secret) => builder.secret_key(secret),
        None => builder,
    };
    builder.bind().await.context("bind Iroh endpoint")
}

/// Return a complete address after Iroh has surfaced one reachable path.
///
/// # Errors
///
/// Returns an error when no address becomes available before the deadline.
pub async fn reachable_addr(endpoint: &Endpoint, loopback: bool) -> Result<EndpointAddr> {
    if !loopback {
        timeout(ADDRESS_TIMEOUT, endpoint.online())
            .await
            .context("Iroh endpoint did not become online")?;
        return Ok(endpoint.addr());
    }

    timeout(ADDRESS_TIMEOUT, async {
        let mut watched = endpoint.watch_addr();
        loop {
            let address = watched.get();
            if address.ip_addrs().next().is_some() {
                return address;
            }
            if watched.updated().await.is_err() {
                return endpoint.addr();
            }
        }
    })
    .await
    .context("Iroh loopback address did not become available")
}

/// Encode bounded Iroh reachability for copying out of band.
///
/// # Errors
///
/// Returns an error when serialization fails or the address exceeds the
/// ticket bound.
pub fn encode_ticket(address: &EndpointAddr) -> Result<String> {
    let raw = postcard::to_allocvec(address).context("encode Iroh address")?;
    if raw.len() > MAX_TICKET_BYTES {
        bail!("Iroh address ticket exceeds {MAX_TICKET_BYTES} bytes");
    }
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

/// Decode bounded Iroh reachability copied from the accepting peer.
///
/// # Errors
///
/// Returns an error for malformed, empty, or oversized tickets.
pub fn decode_ticket(encoded: &str) -> Result<EndpointAddr> {
    // Four base64 characters encode at most three bytes.  Reject before
    // allocation as well as after decoding.
    let encoded_limit = MAX_TICKET_BYTES.div_ceil(3) * 4;
    if encoded.is_empty() || encoded.len() > encoded_limit {
        bail!("invalid Iroh address ticket length");
    }
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode Iroh address ticket")?;
    if raw.len() > MAX_TICKET_BYTES {
        bail!("Iroh address ticket exceeds {MAX_TICKET_BYTES} bytes");
    }
    postcard::from_bytes(&raw).context("parse Iroh address ticket")
}

/// Load an endpoint key, atomically creating a mode-0600 raw key if absent.
///
/// Endpoint identity provides stable reachability and encryption only.  The
/// key is intentionally not exposed to any repository grant or gate call.
///
/// # Errors
///
/// Returns an error for filesystem failures or a key file that is not exactly
/// 32 bytes.
pub fn load_or_create_secret(path: &Path) -> Result<SecretKey> {
    match fs::read(path) {
        Ok(raw) => return decode_secret(&raw),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("read Iroh endpoint key"),
    }

    let parent = parent_dir(path);
    fs::create_dir_all(parent).context("create Iroh key directory")?;
    let generated = SecretKey::generate();
    let (temporary, mut file) = create_secret_temp(path)?;
    let result = (|| {
        file.write_all(&generated.to_bytes())
            .context("write Iroh endpoint key temporary")?;
        file.sync_all()
            .context("sync Iroh endpoint key temporary")?;
        drop(file);

        if publish_secret(&temporary, path)? {
            Ok(generated)
        } else {
            decode_secret(&fs::read(path).context("read raced Iroh endpoint key")?)
        }
    })();
    let cleanup = fs::remove_file(&temporary);
    if let Err(error) = cleanup
        && error.kind() != ErrorKind::NotFound
        && result.is_ok()
    {
        return Err(error).context("remove Iroh endpoint key temporary");
    }
    sync_directory(parent)?;
    result
}

fn create_secret_temp(path: &Path) -> Result<(PathBuf, fs::File)> {
    let parent = parent_dir(path);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("Iroh endpoint key needs a file name")?;

    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), sequence));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).context("create Iroh endpoint key temporary");
            }
        }
    }
    bail!("could not allocate Iroh endpoint key temporary");
}

fn publish_secret(temporary: &Path, path: &Path) -> Result<bool> {
    match fs::hard_link(temporary, path) {
        Ok(()) => {
            sync_directory(parent_dir(path))?;
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error).context("publish Iroh endpoint key"),
    }
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .context("sync Iroh key directory")
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn decode_secret(raw: &[u8]) -> Result<SecretKey> {
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("Iroh endpoint key must contain exactly 32 bytes"))?;
    Ok(SecretKey::from_bytes(&bytes))
}

/// Accept Iroh connections and unwrap each first bidirectional stream into
/// the same local core HTTP listener.
///
/// # Errors
///
/// Returns an error when the endpoint closes unexpectedly or the connection
/// limiter cannot continue.  Per-connection failures are isolated.
pub async fn serve(
    endpoint: Endpoint,
    upstream: SocketAddr,
    max_connections: usize,
    setup_timeout: Duration,
    session_timeout: Duration,
) -> Result<()> {
    if max_connections == 0 {
        bail!("max connections must be positive");
    }
    let permits = Arc::new(Semaphore::new(max_connections));
    while let Some(incoming) = endpoint.accept().await {
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .context("Iroh connection limiter closed")?;
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = accept_one(incoming, upstream, setup_timeout, session_timeout).await
            {
                eprintln!("poc16-iroh: dropped inbound byte stream: {error:#}");
            }
        });
    }
    Ok(())
}

async fn accept_one(
    incoming: Incoming,
    upstream: SocketAddr,
    setup_timeout: Duration,
    session_timeout: Duration,
) -> Result<()> {
    let connection = timeout(setup_timeout, incoming)
        .await
        .context("Iroh handshake timed out")?
        .context("Iroh handshake failed")?;
    let (send, recv) = timeout(setup_timeout, connection.accept_bi())
        .await
        .context("Iroh stream open timed out")?
        .context("accept Iroh byte stream")?;
    let local = timeout(setup_timeout, TcpStream::connect(upstream))
        .await
        .context("core HTTP connect timed out")?
        .context("connect core HTTP listener")?;
    copy_with_limit(local, recv, send, session_timeout).await?;
    Ok(())
}

/// Accept local TCP connections and wrap each one in a fresh Iroh
/// bidirectional stream to the peer.
///
/// # Errors
///
/// Returns an error when the local listener or connection limiter cannot
/// continue.  Per-connection failures are isolated.
pub async fn forward(
    endpoint: Endpoint,
    listener: TcpListener,
    remote: EndpointAddr,
    max_connections: usize,
    setup_timeout: Duration,
    session_timeout: Duration,
) -> Result<()> {
    if max_connections == 0 {
        bail!("max connections must be positive");
    }
    let permits = Arc::new(Semaphore::new(max_connections));
    loop {
        let (local, _) = listener.accept().await.context("accept local TCP")?;
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .context("local connection limiter closed")?;
        let endpoint = endpoint.clone();
        let remote = remote.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                forward_one(endpoint, local, remote, setup_timeout, session_timeout).await
            {
                eprintln!("poc16-iroh: dropped outbound byte stream: {error:#}");
            }
        });
    }
}

async fn forward_one(
    endpoint: Endpoint,
    local: TcpStream,
    remote: EndpointAddr,
    setup_timeout: Duration,
    session_timeout: Duration,
) -> Result<()> {
    let connection = timeout(setup_timeout, endpoint.connect(remote, ALPN))
        .await
        .context("Iroh dial timed out")?
        .context("dial Iroh peer")?;
    let (send, recv) = timeout(setup_timeout, connection.open_bi())
        .await
        .context("Iroh stream open timed out")?
        .context("open Iroh byte stream")?;
    copy_with_limit(local, recv, send, session_timeout).await?;
    Ok(())
}

async fn copy_with_limit(
    mut tcp: TcpStream,
    recv: iroh::endpoint::RecvStream,
    send: iroh::endpoint::SendStream,
    session_timeout: Duration,
) -> Result<()> {
    timeout(session_timeout, async {
        let mut iroh = join(recv, send);
        copy_bidirectional(&mut tcp, &mut iroh)
            .await
            .context("copy byte stream")?;
        let (_, send) = iroh.into_inner();
        if let Some(code) = send
            .stopped()
            .await
            .context("Iroh stream acknowledgement failed")?
        {
            bail!("Iroh peer stopped byte stream with code {code}");
        }
        Ok(())
    })
    .await
    .context("byte stream exceeded session deadline")?
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_TIMEOUT: Duration = Duration::from_secs(20);

    #[test]
    fn ticket_round_trip_and_bounds() {
        let address = EndpointAddr::from(SecretKey::generate().public())
            .with_ip_addr("127.0.0.1:12345".parse().unwrap());
        let encoded = encode_ticket(&address).unwrap();
        assert_eq!(decode_ticket(&encoded).unwrap(), address);
        assert!(decode_ticket("").is_err());
        assert!(decode_ticket(&"A".repeat(MAX_TICKET_BYTES * 2)).is_err());
        assert!(decode_ticket("not-valid-base64!").is_err());
    }

    #[test]
    fn endpoint_key_file_is_stable_and_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys").join("iroh.key");
        let first = load_or_create_secret(&path).unwrap();
        let second = load_or_create_secret(&path).unwrap();

        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(fs::read(&path).unwrap(), first.to_bytes());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::write(&path, b"short").unwrap();
        assert!(load_or_create_secret(&path).is_err());
    }

    #[test]
    fn prepared_key_publication_is_atomic_and_no_clobber() {
        let directory = tempfile::tempdir().unwrap();
        let final_path = directory.path().join("endpoint.key");
        let keys = [SecretKey::generate(), SecretKey::generate()];
        let temporary = [
            directory.path().join("first.tmp"),
            directory.path().join("second.tmp"),
        ];
        for (path, key) in temporary.iter().zip(&keys) {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
            file.write_all(&key.to_bytes()).unwrap();
            file.sync_all().unwrap();
        }

        let barrier = Arc::new(Barrier::new(3));
        let joins = temporary.map(|path| {
            let barrier = Arc::clone(&barrier);
            let final_path = final_path.clone();
            thread::spawn(move || {
                barrier.wait();
                publish_secret(&path, &final_path).unwrap()
            })
        });
        barrier.wait();
        let published = joins.map(|join| join.join().unwrap());

        assert_eq!(published.into_iter().filter(|value| *value).count(), 1);
        let raw = fs::read(final_path).unwrap();
        assert_eq!(raw.len(), 32);
        assert!(keys.iter().any(|key| raw == key.to_bytes()));
    }

    #[test]
    fn concurrent_creators_share_one_complete_key_and_clean_their_temps() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("endpoint.key");
        let barrier = Arc::new(Barrier::new(17));
        let joins: Vec<_> = (0..16)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                thread::spawn(move || {
                    barrier.wait();
                    load_or_create_secret(&path).unwrap().to_bytes()
                })
            })
            .collect();
        barrier.wait();
        let keys: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();

        assert!(keys.iter().all(|key| key == &keys[0]));
        assert_eq!(fs::read(&path).unwrap(), keys[0]);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn abandoned_partial_temps_cannot_brick_key_creation_or_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("endpoint.key");
        let residues = [
            directory.path().join(".endpoint.key.crash.empty.tmp"),
            directory.path().join(".endpoint.key.crash.partial.tmp"),
        ];
        fs::write(&residues[0], b"").unwrap();
        fs::write(&residues[1], b"partial").unwrap();

        let first = load_or_create_secret(&path).unwrap();
        let second = load_or_create_secret(&path).unwrap();

        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(fs::read(path).unwrap(), first.to_bytes());
        assert!(residues.iter().all(|residue| residue.exists()));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_iroh_loopback_wraps_one_tcp_byte_stream() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"ordinary HTTP-shaped bytes");
            stream.write_all(b"same bytes back").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let accepting = bind_endpoint(true, true, None).await.unwrap();
        assert!(
            accepting
                .bound_sockets()
                .iter()
                .all(|address| address.ip().is_loopback())
        );
        let remote = reachable_addr(&accepting, true).await.unwrap();
        let accepting_for_task = accepting.clone();
        let accept = tokio::spawn(async move {
            let incoming = accepting_for_task.accept().await.unwrap();
            accept_one(incoming, upstream_addr, TEST_TIMEOUT, TEST_TIMEOUT)
                .await
                .unwrap();
        });

        let dialing = bind_endpoint(true, false, None).await.unwrap();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local.local_addr().unwrap();
        let dialing_for_task = dialing.clone();
        let forward = tokio::spawn(async move {
            let (stream, _) = local.accept().await.unwrap();
            forward_one(dialing_for_task, stream, remote, TEST_TIMEOUT, TEST_TIMEOUT)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(local_addr).await.unwrap();
        client
            .write_all(b"ordinary HTTP-shaped bytes")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"same bytes back");

        timeout(TEST_TIMEOUT, async {
            echo.await.unwrap();
            accept.await.unwrap();
            forward.await.unwrap();
        })
        .await
        .unwrap();
        dialing.close().await;
        accepting.close().await;
    }
}
