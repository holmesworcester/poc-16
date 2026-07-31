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
use iroh::endpoint::{Incoming, PortmapperConfig, QuicTransportConfig, VarInt, presets};
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
    let incoming_bidi_streams = u32::from(accepts_connections);
    let transport = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(incoming_bidi_streams))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .datagram_receive_buffer_size(None)
        .build();
    let builder = if loopback {
        Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .portmapper_config(PortmapperConfig::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .context("configure loopback Iroh socket")?
    } else {
        Endpoint::builder(presets::N0)
    }
    .transport_config(transport);
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
/// Returns an error for an invalid connection bound. The loop ends normally
/// when the endpoint closes; per-connection failures are isolated.
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
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
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
    let (local, recv, send) = timeout(setup_timeout, async {
        let connection = incoming.await.context("Iroh handshake failed")?;
        let (send, recv) = connection
            .accept_bi()
            .await
            .context("accept Iroh byte stream")?;
        let local = TcpStream::connect(upstream)
            .await
            .context("connect core HTTP listener")?;
        Ok::<_, anyhow::Error>((local, recv, send))
    })
    .await
    .context("Iroh byte stream setup timed out")??;
    copy_with_limit(local, recv, send, session_timeout).await
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
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .context("local connection limiter closed")?;
        let (local, _) = listener.accept().await.context("accept local TCP")?;
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
    let (recv, send) = timeout(setup_timeout, async {
        let connection = endpoint
            .connect(remote, ALPN)
            .await
            .context("dial Iroh peer")?;
        let (send, recv) = connection
            .open_bi()
            .await
            .context("open Iroh byte stream")?;
        Ok::<_, anyhow::Error>((recv, send))
    })
    .await
    .context("Iroh byte stream setup timed out")??;
    copy_with_limit(local, recv, send, session_timeout).await
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
    use tokio::sync::{mpsc, oneshot};
    use tokio::task::JoinHandle;
    use tokio::time::{Instant, sleep};

    const TEST_TIMEOUT: Duration = Duration::from_secs(20);
    const ADVERSARIAL_SETUP_TIMEOUT: Duration = Duration::from_secs(1);
    const ADVERSARIAL_SESSION_TIMEOUT: Duration = Duration::from_secs(2);
    const OVERFLOW_ATTEMPTS: u8 = 16;

    async fn seeded_endpoint(seed: u8, accepts_connections: bool) -> Endpoint {
        bind_endpoint(
            true,
            accepts_connections,
            Some(SecretKey::from_bytes(&[seed; 32])),
        )
        .await
        .unwrap()
    }

    async fn loopback_server(seed: u8) -> (Endpoint, EndpointAddr) {
        let endpoint = seeded_endpoint(seed, true).await;
        let address = reachable_addr(&endpoint, true).await.unwrap();
        (endpoint, address)
    }

    async fn ordinary_round_trip(endpoint: &Endpoint, remote: &EndpointAddr) -> Result<Vec<u8>> {
        let connection = endpoint
            .connect(remote.clone(), ALPN)
            .await
            .context("connect ordinary test client")?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .context("open ordinary test stream")?;
        send.write_all(b"L")
            .await
            .context("write ordinary test request")?;
        send.shutdown()
            .await
            .context("finish ordinary test request")?;
        recv.read_to_end(1024)
            .await
            .context("read ordinary test response")
    }

    async fn assert_no_extra_peer_channels(
        connection: &iroh::endpoint::Connection,
        endpoint_kind: &str,
    ) {
        let blocked_stream_wait = Duration::from_millis(200);
        assert!(
            timeout(blocked_stream_wait, connection.open_bi())
                .await
                .is_err(),
            "{endpoint_kind} endpoint admitted an extra bidirectional stream"
        );
        assert!(
            timeout(blocked_stream_wait, connection.open_uni())
                .await
                .is_err(),
            "{endpoint_kind} endpoint admitted a unidirectional stream"
        );
        assert!(
            connection.send_datagram(vec![b'D'].into()).is_err(),
            "{endpoint_kind} endpoint admitted a datagram"
        );
    }

    fn spawn_upstream(listener: TcpListener) -> (mpsc::UnboundedReceiver<u8>, JoinHandle<()>) {
        let (seen, received) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut marker = [0];
                    if stream.read_exact(&mut marker).await.is_err() {
                        return;
                    }
                    let _ = seen.send(marker[0]);
                    match marker[0] {
                        b'L' => {
                            let _ = stream.write_all(b"ordinary response").await;
                            let _ = stream.shutdown().await;
                        }
                        b'H' => loop {
                            sleep(Duration::from_millis(20)).await;
                            if stream.write_all(b".").await.is_err() {
                                break;
                            }
                        },
                        _ => {
                            let mut discarded = Vec::new();
                            let _ = stream.read_to_end(&mut discarded).await;
                        }
                    }
                });
            }
        });
        (received, task)
    }

    async fn stop_server(endpoint: &Endpoint, task: JoinHandle<Result<()>>) {
        endpoint.close().await;
        timeout(TEST_TIMEOUT, task)
            .await
            .expect("server task did not stop")
            .expect("server task panicked")
            .expect("server returned an error");
    }

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_iroh_connection_allows_only_its_one_protocol_stream() {
        let (accepting, remote) = loopback_server(10).await;
        let accepting_for_task = accepting.clone();
        let (accepted, accepted_rx) = oneshot::channel();
        let (server_checked, server_checked_rx) = oneshot::channel();
        let (release_server, release_server_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let incoming = accepting_for_task.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let (server_send, mut server_recv) = connection.accept_bi().await.unwrap();
            let mut marker = [0];
            server_recv.read_exact(&mut marker).await.unwrap();
            accepted.send(()).unwrap();

            assert_no_extra_peer_channels(&connection, "dialing-only").await;
            server_checked.send(()).unwrap();
            release_server_rx.await.unwrap();
            drop((server_send, server_recv));
        });

        let dialing = seeded_endpoint(9, false).await;
        let connection = dialing.connect(remote, ALPN).await.unwrap();
        let (mut protocol_send, protocol_recv) = connection.open_bi().await.unwrap();
        protocol_send.write_all(b"P").await.unwrap();
        timeout(TEST_TIMEOUT, accepted_rx).await.unwrap().unwrap();

        assert_no_extra_peer_channels(&connection, "accepting").await;
        timeout(TEST_TIMEOUT, server_checked_rx)
            .await
            .unwrap()
            .unwrap();
        release_server.send(()).unwrap();

        drop((protocol_send, protocol_recv, connection));
        timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
        dialing.close().await;
        accepting.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn saturated_stalled_and_half_closed_streams_are_bounded_and_recover() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (mut received, upstream_task) = spawn_upstream(upstream);
        let (accepting, remote) = loopback_server(11).await;
        let accepting_for_task = accepting.clone();
        let server = tokio::spawn(serve(
            accepting_for_task,
            upstream_addr,
            2,
            ADVERSARIAL_SETUP_TIMEOUT,
            ADVERSARIAL_SESSION_TIMEOUT,
        ));
        let mut overflow_endpoints = Vec::new();
        for seed in 14..14 + OVERFLOW_ATTEMPTS {
            overflow_endpoints.push(seeded_endpoint(seed, false).await);
        }

        let stalled_endpoint = seeded_endpoint(12, false).await;
        let stalled_connection = stalled_endpoint
            .connect(remote.clone(), ALPN)
            .await
            .unwrap();
        let (mut stalled_send, mut stalled_recv) = stalled_connection.open_bi().await.unwrap();
        stalled_send.write_all(b"S").await.unwrap();
        assert_eq!(
            timeout(TEST_TIMEOUT, received.recv()).await.unwrap(),
            Some(b'S')
        );

        let half_endpoint = seeded_endpoint(13, false).await;
        let half_connection = half_endpoint.connect(remote.clone(), ALPN).await.unwrap();
        let (mut half_send, mut half_recv) = half_connection.open_bi().await.unwrap();
        half_send.write_all(b"H").await.unwrap();
        half_send.shutdown().await.unwrap();
        assert_eq!(
            timeout(TEST_TIMEOUT, received.recv()).await.unwrap(),
            Some(b'H')
        );

        let overflow_started = Instant::now();
        let mut overflow = tokio::task::JoinSet::new();
        for endpoint in &overflow_endpoints {
            let endpoint = endpoint.clone();
            let remote = remote.clone();
            overflow.spawn(async move { endpoint.connect(remote, ALPN).await });
        }
        let rejected = timeout(ADVERSARIAL_SETUP_TIMEOUT, async {
            let mut rejected = 0;
            while let Some(result) = overflow.join_next().await {
                assert!(result.unwrap().is_err());
                rejected += 1;
            }
            rejected
        })
        .await
        .expect("overflow handshakes were retained instead of refused");
        assert_eq!(rejected, usize::from(OVERFLOW_ATTEMPTS));
        assert!(overflow_started.elapsed() < ADVERSARIAL_SESSION_TIMEOUT);
        assert_eq!(
            received.try_recv(),
            Err(mpsc::error::TryRecvError::Empty),
            "overflow connection reached the upstream listener"
        );

        timeout(TEST_TIMEOUT, async {
            let (stalled_result, half_result) =
                tokio::join!(stalled_recv.read_to_end(1024), half_recv.read_to_end(1024),);
            let _ = stalled_result;
            let _ = half_result;
        })
        .await
        .expect("admitted hostile streams survived their session deadline");
        drop((stalled_send, half_send));

        let legitimate_endpoint = seeded_endpoint(15, false).await;
        assert_eq!(
            ordinary_round_trip(&legitimate_endpoint, &remote)
                .await
                .unwrap(),
            b"ordinary response"
        );
        assert_eq!(
            timeout(TEST_TIMEOUT, received.recv()).await.unwrap(),
            Some(b'L')
        );
        assert_eq!(
            received.try_recv(),
            Err(mpsc::error::TryRecvError::Empty),
            "more upstream sessions were created than admitted permits"
        );

        drop((stalled_connection, half_connection));
        stop_server(&accepting, server).await;
        upstream_task.abort();
        for endpoint in [stalled_endpoint, half_endpoint, legitimate_endpoint] {
            endpoint.close().await;
        }
        for endpoint in overflow_endpoints {
            endpoint.close().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn handshake_without_stream_expires_and_the_next_attempt_succeeds() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (mut received, upstream_task) = spawn_upstream(upstream);
        let (accepting, remote) = loopback_server(21).await;
        let accepting_for_task = accepting.clone();
        let server = tokio::spawn(serve(
            accepting_for_task,
            upstream_addr,
            1,
            ADVERSARIAL_SETUP_TIMEOUT,
            Duration::from_secs(5),
        ));

        let hostile_endpoint = seeded_endpoint(22, false).await;
        let hostile = hostile_endpoint
            .connect(remote.clone(), ALPN)
            .await
            .unwrap();
        let refused_endpoint = seeded_endpoint(23, false).await;
        let refused = timeout(
            ADVERSARIAL_SETUP_TIMEOUT,
            ordinary_round_trip(&refused_endpoint, &remote),
        )
        .await
        .expect("saturated handshake was retained instead of refused");
        assert!(refused.is_err());
        assert_eq!(
            received.try_recv(),
            Err(mpsc::error::TryRecvError::Empty),
            "a handshake without a stream reached upstream"
        );

        timeout(TEST_TIMEOUT, hostile.closed())
            .await
            .expect("handshake without stream survived its setup deadline");
        let legitimate_endpoint = seeded_endpoint(24, false).await;
        assert_eq!(
            ordinary_round_trip(&legitimate_endpoint, &remote)
                .await
                .unwrap(),
            b"ordinary response"
        );
        assert_eq!(
            timeout(TEST_TIMEOUT, received.recv()).await.unwrap(),
            Some(b'L')
        );

        stop_server(&accepting, server).await;
        upstream_task.abort();
        for endpoint in [hostile_endpoint, refused_endpoint, legitimate_endpoint] {
            endpoint.close().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn alpn_mismatch_and_stream_reset_release_the_only_permit() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (mut received, upstream_task) = spawn_upstream(upstream);
        let (accepting, remote) = loopback_server(31).await;
        let accepting_for_task = accepting.clone();
        let server = tokio::spawn(serve(
            accepting_for_task,
            upstream_addr,
            1,
            ADVERSARIAL_SETUP_TIMEOUT,
            Duration::from_secs(5),
        ));

        let mismatch_endpoint = seeded_endpoint(32, false).await;
        let mismatch = timeout(
            TEST_TIMEOUT,
            mismatch_endpoint.connect(remote.clone(), b"wrong/alpn"),
        )
        .await
        .unwrap();
        assert!(mismatch.is_err());
        assert_eq!(
            received.try_recv(),
            Err(mpsc::error::TryRecvError::Empty),
            "ALPN mismatch reached upstream"
        );

        let reset_endpoint = seeded_endpoint(33, false).await;
        let reset_connection = reset_endpoint.connect(remote.clone(), ALPN).await.unwrap();
        let (mut reset_send, reset_recv) = reset_connection.open_bi().await.unwrap();
        reset_send.write_all(b"R").await.unwrap();
        assert_eq!(
            timeout(TEST_TIMEOUT, received.recv()).await.unwrap(),
            Some(b'R')
        );
        reset_send.reset(VarInt::from_u32(7)).unwrap();
        drop((reset_send, reset_recv, reset_connection));

        let legitimate_endpoint = seeded_endpoint(34, false).await;
        let response = timeout(Duration::from_millis(500), async {
            loop {
                if let Ok(response) = ordinary_round_trip(&legitimate_endpoint, &remote).await {
                    break response;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stream reset retained its permit until the session deadline");
        assert_eq!(response, b"ordinary response");
        assert_eq!(
            timeout(TEST_TIMEOUT, received.recv()).await.unwrap(),
            Some(b'L')
        );

        stop_server(&accepting, server).await;
        upstream_task.abort();
        for endpoint in [mismatch_endpoint, reset_endpoint, legitimate_endpoint] {
            endpoint.close().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unavailable_upstream_does_not_wedge_the_next_stream() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = reservation.local_addr().unwrap();
        drop(reservation);
        let (accepting, remote) = loopback_server(41).await;
        let accepting_for_task = accepting.clone();
        let server = tokio::spawn(serve(
            accepting_for_task,
            upstream_addr,
            1,
            ADVERSARIAL_SETUP_TIMEOUT,
            Duration::from_secs(5),
        ));

        let unavailable_endpoint = seeded_endpoint(42, false).await;
        let unavailable_connection = unavailable_endpoint
            .connect(remote.clone(), ALPN)
            .await
            .unwrap();
        let (mut unavailable_send, mut unavailable_recv) =
            unavailable_connection.open_bi().await.unwrap();
        unavailable_send.write_all(b"U").await.unwrap();
        unavailable_send.shutdown().await.unwrap();
        let _ = timeout(
            Duration::from_millis(500),
            unavailable_recv.read_to_end(1024),
        )
        .await
        .expect("unavailable upstream retained its permit");
        drop((unavailable_send, unavailable_connection));

        let upstream = TcpListener::bind(upstream_addr).await.unwrap();
        let (mut received, upstream_task) = spawn_upstream(upstream);
        let legitimate_endpoint = seeded_endpoint(43, false).await;
        assert_eq!(
            ordinary_round_trip(&legitimate_endpoint, &remote)
                .await
                .unwrap(),
            b"ordinary response"
        );
        assert_eq!(
            timeout(TEST_TIMEOUT, received.recv()).await.unwrap(),
            Some(b'L')
        );

        stop_server(&accepting, server).await;
        upstream_task.abort();
        for endpoint in [unavailable_endpoint, legitimate_endpoint] {
            endpoint.close().await;
        }
    }
}
