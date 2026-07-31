use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use poc16_full_peer_iroh::{
    bind_endpoint, decode_ticket, encode_ticket, forward, load_or_create_secret, reachable_addr,
    serve,
};
use tokio::net::TcpListener;

const DEFAULT_MAX_CONNECTIONS: usize = 128;
const DEFAULT_SETUP_SECONDS: u64 = 30;
const DEFAULT_SESSION_SECONDS: u64 = 300;

#[derive(Debug, Parser)]
#[command(
    name = "poc16-iroh",
    about = "Wrap core HTTP byte connections in Iroh; repository authority stays in core"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Accept Iroh streams and unwrap them into a loopback core HTTP listener.
    Serve {
        /// Peer-data-only core HTTP listener. Never point this at local control.
        #[arg(long)]
        upstream: SocketAddr,
        /// Stable raw 32-byte Iroh endpoint key; created mode 0600 if absent.
        #[arg(long)]
        secret_key_file: Option<PathBuf>,
        /// Disable relay/discovery and bind only 127.0.0.1 (tests/local demos).
        #[arg(long)]
        loopback: bool,
        #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS)]
        max_connections: usize,
        #[arg(long, default_value_t = DEFAULT_SETUP_SECONDS)]
        setup_seconds: u64,
        #[arg(long, default_value_t = DEFAULT_SESSION_SECONDS)]
        session_seconds: u64,
    },
    /// Expose a local TCP listener whose byte connections dial an Iroh peer.
    Forward {
        /// Bounded ticket printed by the accepting peer.
        #[arg(long)]
        peer: String,
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
        /// Stable raw 32-byte Iroh endpoint key; ephemeral when omitted.
        #[arg(long)]
        secret_key_file: Option<PathBuf>,
        /// Disable relay/discovery and bind only 127.0.0.1 (tests/local demos).
        #[arg(long)]
        loopback: bool,
        #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS)]
        max_connections: usize,
        #[arg(long, default_value_t = DEFAULT_SETUP_SECONDS)]
        setup_seconds: u64,
        #[arg(long, default_value_t = DEFAULT_SESSION_SECONDS)]
        session_seconds: u64,
    },
}

fn duration(seconds: u64, label: &str) -> Result<Duration> {
    if seconds == 0 {
        bail!("{label} must be positive");
    }
    Ok(Duration::from_secs(seconds))
}

fn connections(value: usize) -> Result<usize> {
    if value == 0 || value > 4096 {
        bail!("max-connections must be in 1..=4096");
    }
    Ok(value)
}

fn loopback_address(value: SocketAddr, label: &str) -> Result<SocketAddr> {
    if !value.ip().is_loopback() {
        bail!("{label} must be a loopback address");
    }
    Ok(value)
}

fn secret(path: Option<PathBuf>) -> Result<Option<iroh::SecretKey>> {
    path.map(|path| load_or_create_secret(&path)).transpose()
}

fn ready(line: &str) -> Result<()> {
    println!("{line}");
    io::stdout().flush().context("flush readiness line")
}

#[tokio::main]
async fn main() -> Result<()> {
    match Arguments::parse().command {
        Command::Serve {
            upstream,
            secret_key_file,
            loopback,
            max_connections,
            setup_seconds,
            session_seconds,
        } => {
            let upstream = loopback_address(upstream, "upstream")?;
            let endpoint = bind_endpoint(loopback, true, secret(secret_key_file)?).await?;
            let address = reachable_addr(&endpoint, loopback).await?;
            ready(&format!(
                "READY endpoint_id={} peer={}",
                endpoint.id(),
                encode_ticket(&address)?
            ))?;
            let running = serve(
                endpoint.clone(),
                upstream,
                connections(max_connections)?,
                duration(setup_seconds, "setup-seconds")?,
                duration(session_seconds, "session-seconds")?,
            );
            tokio::select! {
                result = running => result?,
                signal = tokio::signal::ctrl_c() => {
                    signal.context("install Ctrl-C handler")?;
                }
            }
            endpoint.close().await;
        }
        Command::Forward {
            peer,
            listen,
            secret_key_file,
            loopback,
            max_connections,
            setup_seconds,
            session_seconds,
        } => {
            let listen = loopback_address(listen, "listen")?;
            let remote = decode_ticket(&peer)?;
            let endpoint = bind_endpoint(loopback, false, secret(secret_key_file)?).await?;
            let listener = TcpListener::bind(listen)
                .await
                .context("bind local TCP forwarder")?;
            ready(&format!(
                "READY endpoint_id={} listen={}",
                endpoint.id(),
                listener.local_addr().context("read local TCP address")?
            ))?;
            let running = forward(
                endpoint.clone(),
                listener,
                remote,
                connections(max_connections)?,
                duration(setup_seconds, "setup-seconds")?,
                duration(session_seconds, "session-seconds")?,
            );
            tokio::select! {
                result = running => result?,
                signal = tokio::signal::ctrl_c() => {
                    signal.context("install Ctrl-C handler")?;
                }
            }
            endpoint.close().await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_seams_reject_non_loopback_addresses() {
        assert!(loopback_address("127.0.0.1:1".parse().unwrap(), "value").is_ok());
        assert!(loopback_address("[::1]:1".parse().unwrap(), "value").is_ok());
        assert!(loopback_address("0.0.0.0:1".parse().unwrap(), "value").is_err());
        assert!(loopback_address("192.0.2.1:1".parse().unwrap(), "value").is_err());
    }
}
