//! iroh listener. Allowlisted peers get a bi-stream per herdr socket call.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

use crate::gateway::{self, MachineBackend};
use crate::policy::{Allowlist, Decision};
use crate::protocol::{
    self, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, encode_request, error_line, request_meta,
};
use crate::stream::{Flushing, read_line_limited};

const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STREAMS_PER_CONNECTION: usize = 64;

pub struct ServeOptions {
    pub secret_key: SecretKey,
    pub socket_path: PathBuf,
    pub allow: Arc<RwLock<Allowlist>>,
    /// `server.toml` `gateway`. SIGHUP stores a new value here.
    pub gateway: Arc<AtomicBool>,
    pub machines: Arc<dyn MachineBackend>,
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
        gateway: opts.gateway,
        machines: opts.machines,
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
    gateway: Arc<AtomicBool>,
    machines: Arc<dyn MachineBackend>,
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

        if meta.method == "gateway.machines" || meta.method == "gateway.forward" {
            return self.handle_gateway(remote, &meta, text, &mut send).await;
        }

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

    async fn handle_gateway(
        &self,
        remote: EndpointId,
        meta: &crate::protocol::RequestMeta,
        text: &str,
        send: &mut Flushing<iroh::endpoint::SendStream>,
    ) -> anyhow::Result<()> {
        if !self.allow.read().await.allows_peer(&remote) {
            self.write_decision(
                send,
                &meta.id,
                &meta.method,
                Decision::Denied(crate::policy::DenyReason::NotOnAllowlist),
            )
            .await?;
            return Ok(());
        }
        if meta.method == "gateway.machines" {
            self.gateway_machines(remote, &meta.id, send).await?;
            return Ok(());
        }
        let request = match gateway::parse_forward(text) {
            Ok(request) => request,
            Err(err) => {
                write_text(send, &error_line(&meta.id, err.code, &err.message)).await?;
                return Ok(());
            }
        };
        if let Err(block) =
            gateway::screen_forward(&*self.allow.read().await, &remote, &request.method)
        {
            tracing::info!(
                endpoint_id = %remote,
                method = %request.method,
                machine = %request.machine,
                request_id = %meta.id,
                "denied gateway forward"
            );
            write_text(
                send,
                &error_line(&meta.id, block.code(), &block.message(&request.method)),
            )
            .await?;
            return Ok(());
        }
        if !self.gateway.load(Ordering::Acquire) {
            write_text(
                send,
                &error_line(&meta.id, "gateway_disabled", "saved-machine gateway is off"),
            )
            .await?;
            return Ok(());
        }
        let machines = {
            let backend = Arc::clone(&self.machines);
            match tokio::task::spawn_blocking(move || backend.list()).await {
                Ok(Ok(machines)) => machines,
                Ok(Err(err)) => {
                    write_text(send, &error_line(&meta.id, err.code, &err.message)).await?;
                    return Ok(());
                }
                Err(_) => {
                    write_text(
                        send,
                        &error_line(
                            &meta.id,
                            "gateway_unavailable",
                            "saved-machine gateway failed",
                        ),
                    )
                    .await?;
                    return Ok(());
                }
            }
        };
        if let Err(err) = gateway::select_saved(&machines, &request.machine) {
            write_text(send, &error_line(&meta.id, err.code, &err.message)).await?;
            return Ok(());
        }
        let inner = serde_json::json!({
            "id": meta.id,
            "method": request.method,
            "params": request.params,
        });
        let line = match encode_request(&inner) {
            Ok(line) => line,
            Err(err) => {
                write_text(
                    send,
                    &error_line(&meta.id, "invalid_request", &err.to_string()),
                )
                .await?;
                return Ok(());
            }
        };
        tracing::info!(
            endpoint_id = %remote,
            method = %request.method,
            machine = %request.machine,
            request_id = %meta.id,
            bytes = line.len(),
            "gateway"
        );
        let relay = self.forward_saved(meta.id.clone(), request.machine, line, send);
        if self.relay_timeout.is_zero() {
            relay.await?;
        } else if tokio::time::timeout(self.relay_timeout, relay)
            .await
            .is_err()
        {
            tracing::info!(
                endpoint_id = %remote,
                method = %request.method,
                request_id = %meta.id,
                "gateway forward timed out"
            );
            let _ = write_text(
                send,
                &error_line(&meta.id, "timeout", "herdr-iroh relay timed out"),
            )
            .await;
        }
        Ok(())
    }

    async fn gateway_machines(
        &self,
        remote: EndpointId,
        request_id: &str,
        send: &mut Flushing<iroh::endpoint::SendStream>,
    ) -> anyhow::Result<()> {
        if !self.gateway.load(Ordering::Acquire) {
            let body = serde_json::json!({
                "id": request_id,
                "result": {"type": "machines", "enabled": false, "machines": []},
            });
            write_text(send, &format!("{body}\n")).await?;
            return Ok(());
        }
        let backend = Arc::clone(&self.machines);
        let listed = tokio::task::spawn_blocking(move || backend.list()).await;
        let machines = match listed {
            Ok(Ok(machines)) => machines,
            Ok(Err(err)) => {
                write_text(send, &error_line(request_id, err.code, &err.message)).await?;
                return Ok(());
            }
            Err(_) => {
                write_text(
                    send,
                    &error_line(
                        request_id,
                        "gateway_unavailable",
                        "saved-machine gateway failed",
                    ),
                )
                .await?;
                return Ok(());
            }
        };
        tracing::info!(
            endpoint_id = %remote,
            machines = machines.len(),
            request_id,
            "gateway machines"
        );
        let body = serde_json::json!({
            "id": request_id,
            "result": {
                "type": "machines",
                "enabled": true,
                "machines": machines,
            },
        });
        write_text(send, &format!("{body}\n")).await?;
        Ok(())
    }

    async fn forward_saved(
        &self,
        request_id: String,
        machine: String,
        line: String,
        send: &mut Flushing<iroh::endpoint::SendStream>,
    ) -> anyhow::Result<()> {
        let cancel = Arc::new(AtomicBool::new(false));
        let guard = CancelOnDrop(Arc::clone(&cancel));
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let backend = Arc::clone(&self.machines);
        let cancel_thread = Arc::clone(&cancel);
        let runner = tokio::task::spawn_blocking(move || {
            backend.forward(&machine, line.as_bytes(), &cancel_thread, &mut |chunk| {
                tx.blocking_send(chunk.to_vec()).is_ok()
            })
        });
        let mut wrote = false;
        while let Some(chunk) = rx.recv().await {
            wrote = true;
            send.write_all(&chunk).await?;
            if !chunk.ends_with(b"\n") {
                send.write_all(b"\n").await?;
            }
        }
        let joined = runner
            .await
            .map_err(|_| anyhow::anyhow!("saved-machine gateway failed"))?;
        if let Err(err) = joined {
            if !wrote {
                write_text(send, &error_line(&request_id, err.code, &err.message)).await?;
            }
            return Ok(());
        }
        if !wrote {
            write_text(
                send,
                &error_line(
                    &request_id,
                    "bad_response",
                    "saved machine closed the API bridge without a response",
                ),
            )
            .await?;
            return Ok(());
        }
        let _ = send.shutdown().await;
        drop(guard);
        Ok(())
    }

    async fn write_decision(
        &self,
        send: &mut Flushing<iroh::endpoint::SendStream>,
        id: &str,
        method: &str,
        decision: Decision,
    ) -> anyhow::Result<()> {
        write_text(
            send,
            &error_line(id, decision.error_code(), &decision.message(method)),
        )
        .await
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

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
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
