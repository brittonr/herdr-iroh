//! iroh listener. Allowlisted peers get a bi-stream per herdr socket call.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Context;
use iroh::endpoint::{Accepting, Connection, RelayMode, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use iroh_tickets::Ticket;
use iroh_tickets::endpoint::EndpointTicket;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::RwLock;

use crate::policy::{Allowlist, Decision};
use crate::protocol::{self, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, error_line, request_meta};
use crate::stream::{Flushing, read_line_limited};

const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STREAMS_PER_CONNECTION: usize = 64;

pub struct ServeOptions {
    pub secret_key: SecretKey,
    pub socket_path: PathBuf,
    pub allow: Arc<RwLock<Allowlist>>,
    pub relays: bool,
    pub bind_addr: Option<SocketAddr>,
    pub relay_timeout: Duration,
}

pub struct RunningServer {
    router: Router,
    pub endpoint_id: EndpointId,
    pub ticket: String,
    pub socket_path: PathBuf,
}

impl RunningServer {
    #[must_use]
    pub fn addr(&self) -> EndpointAddr {
        self.router.endpoint().addr()
    }

    pub async fn shutdown(self) -> anyhow::Result<()> {
        self.router
            .shutdown()
            .await
            .map_err(|err| anyhow::anyhow!("iroh router shutdown: {err}"))
    }
}

/// Bind an endpoint and accept [`protocol::ALPN`].
///
/// # Errors
///
/// Returns an error when the endpoint cannot bind.
pub async fn serve(opts: ServeOptions) -> anyhow::Result<RunningServer> {
    let mut builder = Endpoint::builder(presets::N0).secret_key(opts.secret_key);
    if !opts.relays {
        builder = builder.relay_mode(RelayMode::Disabled);
    }
    if let Some(addr) = opts.bind_addr {
        builder = builder
            .bind_addr(addr)
            .map_err(|err| anyhow::anyhow!("iroh bind address {addr}: {err}"))?;
    } else if !opts.relays {
        builder = builder
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .map_err(|err| anyhow::anyhow!("iroh loopback bind: {err}"))?;
    }
    let endpoint = builder
        .bind()
        .await
        .map_err(|err| anyhow::anyhow!("bind iroh endpoint: {err}"))?;

    let socket_path = opts.socket_path.clone();
    let protocol = HerdrProtocol {
        socket_path: opts.socket_path,
        allow: opts.allow,
        relay_timeout: opts.relay_timeout,
    };
    let router = Router::builder(endpoint)
        .accept(protocol::ALPN, protocol)
        .spawn();

    let _ = wait_for_ip(router.endpoint(), Duration::from_secs(2)).await;
    if opts.relays {
        match tokio::time::timeout(Duration::from_secs(15), router.endpoint().online()).await {
            Ok(()) => tracing::info!("iroh relay connected"),
            Err(_) => tracing::warn!(
                "iroh relay not reached within 15s; direct peers need a ticket until it connects"
            ),
        }
    }

    let addr = router.endpoint().addr();
    let endpoint_id = router.endpoint().id();
    let ticket = EndpointTicket::new(addr).encode_string();
    tracing::info!(%endpoint_id, "herdr-iroh listener ready");

    Ok(RunningServer {
        router,
        endpoint_id,
        ticket,
        socket_path,
    })
}

async fn wait_for_ip(endpoint: &Endpoint, budget: Duration) -> EndpointAddr {
    let start = std::time::Instant::now();
    loop {
        let addr = endpoint.addr();
        if addr.addrs.iter().any(iroh::TransportAddr::is_ip) || start.elapsed() >= budget {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[derive(Clone)]
struct HerdrProtocol {
    socket_path: PathBuf,
    allow: Arc<RwLock<Allowlist>>,
    relay_timeout: Duration,
}

impl std::fmt::Debug for HerdrProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HerdrProtocol")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl HerdrProtocol {
    async fn peer_allowed(&self, remote: EndpointId) -> bool {
        self.allow.read().await.allows_peer(&remote)
    }

    async fn handle_stream(
        &self,
        remote: EndpointId,
        send: iroh::endpoint::SendStream,
        recv: iroh::endpoint::RecvStream,
    ) -> anyhow::Result<()> {
        let mut send = Flushing::new(send);
        let mut reader = BufReader::new(recv);
        let line = match tokio::time::timeout(
            REQUEST_READ_TIMEOUT,
            read_line_limited(&mut reader, MAX_REQUEST_BYTES),
        )
        .await
        {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(err)) => {
                tracing::info!(endpoint_id = %remote, "rejected oversize or unreadable request");
                write_text(
                    &mut send,
                    &error_line("", "invalid_request", &err.to_string()),
                )
                .await?;
                return Ok(());
            }
            Err(_) => {
                tracing::info!(endpoint_id = %remote, "request line timed out");
                write_text(
                    &mut send,
                    &error_line("", "timeout", "timed out waiting for a request line"),
                )
                .await?;
                return Ok(());
            }
        };

        let text = match std::str::from_utf8(&line) {
            Ok(text) => text,
            Err(_) => {
                tracing::info!(endpoint_id = %remote, "rejected non-utf8 request");
                write_text(
                    &mut send,
                    &error_line("", "invalid_request", "request must be utf-8"),
                )
                .await?;
                return Ok(());
            }
        };

        let meta = match request_meta(text) {
            Ok(meta) => meta,
            Err(err) => {
                tracing::info!(endpoint_id = %remote, "rejected malformed request");
                write_text(&mut send, &error_line(err.id(), err.code(), err.message())).await?;
                return Ok(());
            }
        };

        let decision = self.allow.read().await.decide(&remote, &meta.method);
        if decision != Decision::Allow {
            tracing::info!(
                endpoint_id = %remote,
                method = %meta.method,
                request_id = %meta.id,
                reason = decision.message(&meta.method),
                "denied"
            );
            write_text(
                &mut send,
                &error_line(
                    &meta.id,
                    decision.error_code(),
                    &decision.message(&meta.method),
                ),
            )
            .await?;
            return Ok(());
        }

        // Method and size only. Params can contain pane text and prompts.
        tracing::info!(
            endpoint_id = %remote,
            method = %meta.method,
            request_id = %meta.id,
            bytes = line.len(),
            "relay"
        );

        let relay = self.copy_herdr(&meta.id, &line, &mut send);
        if self.relay_timeout.is_zero() {
            relay.await?;
        } else if let Err(err) = tokio::time::timeout(self.relay_timeout, relay).await {
            let _ = err;
            tracing::info!(
                endpoint_id = %remote,
                method = %meta.method,
                request_id = %meta.id,
                "relay timed out"
            );
            let _ = write_text(
                &mut send,
                &error_line(&meta.id, "timeout", "herdr-iroh relay timed out"),
            )
            .await;
        }
        Ok(())
    }

    async fn copy_herdr(
        &self,
        request_id: &str,
        request_line: &[u8],
        send: &mut Flushing<iroh::endpoint::SendStream>,
    ) -> anyhow::Result<()> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "cannot connect to herdr socket {}",
                    self.socket_path.display()
                )
            });
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                write_text(
                    send,
                    &error_line(request_id, "herdr_unavailable", &err.to_string()),
                )
                .await?;
                return Ok(());
            }
        };
        stream.write_all(request_line).await?;
        if !request_line.ends_with(b"\n") {
            stream.write_all(b"\n").await?;
        }
        stream.flush().await?;

        let mut herdr = BufReader::new(stream);
        loop {
            let line = match read_line_limited(&mut herdr, MAX_RESPONSE_BYTES).await {
                Ok(line) => line,
                Err(err) => {
                    write_text(
                        send,
                        &error_line(request_id, "bad_response", &err.to_string()),
                    )
                    .await?;
                    break;
                }
            };
            let Some(line) = line else {
                break;
            };
            send.write_all(&line).await?;
            if !line.ends_with(b"\n") {
                send.write_all(b"\n").await?;
            }
        }
        let _ = send.shutdown().await;
        Ok(())
    }
}

async fn write_text(
    send: &mut Flushing<iroh::endpoint::SendStream>,
    text: &str,
) -> anyhow::Result<()> {
    send.write_all(text.as_bytes()).await?;
    send.flush().await?;
    Ok(())
}

impl ProtocolHandler for HerdrProtocol {
    async fn on_accepting(&self, accepting: Accepting) -> Result<Connection, AcceptError> {
        let connection = accepting.await?;
        let remote = connection.remote_id();
        if !self.peer_allowed(remote).await {
            tracing::warn!(endpoint_id = %remote, "rejected iroh peer not on the allowlist");
            connection.close(1u32.into(), b"endpoint not allowed");
            return Err(AcceptError::from_err(PeerRejected));
        }
        Ok(connection)
    }

    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        if !self.peer_allowed(remote).await {
            tracing::warn!(endpoint_id = %remote, "rejected iroh peer not on the allowlist");
            connection.close(1u32.into(), b"endpoint not allowed");
            return Err(AcceptError::from_err(PeerRejected));
        }
        tracing::info!(endpoint_id = %remote, "accepted iroh peer");
        let inflight = Arc::new(AtomicUsize::new(0));
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(err) => {
                    tracing::debug!(endpoint_id = %remote, error = %err, "peer connection closed");
                    break;
                }
            };
            let current = inflight.fetch_add(1, Ordering::Relaxed);
            if current >= MAX_STREAMS_PER_CONNECTION {
                inflight.fetch_sub(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut send = Flushing::new(send);
                    let _ = write_text(
                        &mut send,
                        &error_line("", "busy", "too many streams on this connection"),
                    )
                    .await;
                });
                continue;
            }
            let protocol = self.clone();
            let inflight = inflight.clone();
            tokio::spawn(async move {
                if let Err(err) = protocol.handle_stream(remote, send, recv).await {
                    tracing::debug!(endpoint_id = %remote, error = %err, "stream ended");
                }
                inflight.fetch_sub(1, Ordering::Relaxed);
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PeerRejected;

impl std::fmt::Display for PeerRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("endpoint not allowed")
    }
}

impl std::error::Error for PeerRejected {}
