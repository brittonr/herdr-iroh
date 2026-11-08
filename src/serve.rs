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
use crate::notify::NotifyConfig;
use crate::policy::{Allowlist, Decision};
use crate::protocol::{
    self, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, encode_request, error_line, request_meta,
};
use crate::receipt::ReceiptStore;
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
    pub notify: NotifyConfig,
    pub dedupe_ttl: Duration,
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
        receipts: Arc::new(ReceiptStore::new(opts.dedupe_ttl)),
        notify: opts.notify,
        relay_timeout: opts.relay_timeout,
    };
    if protocol.notify.enabled() {
        let watcher = protocol.clone();
        tokio::spawn(async move {
            watcher.watch_statuses().await;
        });
    }
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
    receipts: Arc<ReceiptStore>,
    notify: NotifyConfig,
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

        if is_relay_method(&meta.method) {
            let params = object_params(text).unwrap_or_else(|| serde_json::json!({}));
            return self
                .dispatch_relay(remote, &meta.id, &meta.method, params, None, &mut send)
                .await;
        }
        if matches!(meta.method.as_str(), "agent.prompt" | "pane.send_text")
            && let Some(message_id) = top_message_id(text)
        {
            let params = object_params(text).unwrap_or_else(|| serde_json::json!({}));
            return self
                .idempotent_prompt(
                    remote,
                    &meta.id,
                    &meta.method,
                    params,
                    message_id,
                    None,
                    &mut send,
                )
                .await;
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
        if is_relay_method(&request.method) {
            return self
                .dispatch_relay(
                    remote,
                    &meta.id,
                    &request.method,
                    request.params,
                    Some(request.machine),
                    send,
                )
                .await;
        }
        if let Some(message_id) = request.message_id.clone()
            && matches!(request.method.as_str(), "agent.prompt" | "pane.send_text")
        {
            return self
                .idempotent_prompt(
                    remote,
                    &meta.id,
                    &request.method,
                    request.params,
                    message_id,
                    Some(request.machine),
                    send,
                )
                .await;
        }
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

    async fn dispatch_relay(
        &self,
        remote: EndpointId,
        request_id: &str,
        method: &str,
        params: serde_json::Value,
        machine: Option<String>,
        send: &mut Flushing<iroh::endpoint::SendStream>,
    ) -> anyhow::Result<()> {
        let value = match method {
            "relay.agent_session" => {
                self.agent_session(request_id, &params, machine.as_deref())
                    .await
            }
            "relay.answer" => {
                self.answer_ask(request_id, &params, machine.as_deref())
                    .await
            }
            _ => serde_json::json!({
                "id": request_id,
                "error": {"code": "invalid_request", "message": "unknown relay method"}
            }),
        };
        tracing::info!(
            endpoint_id = %remote,
            method,
            machine = machine.as_deref().unwrap_or("local"),
            request_id,
            "relay method"
        );
        write_text(send, &format!("{value}\n")).await?;
        let _ = send.shutdown().await;
        Ok(())
    }

    async fn agent_session(
        &self,
        request_id: &str,
        params: &serde_json::Value,
        machine: Option<&str>,
    ) -> serde_json::Value {
        let target = params
            .get("target")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if target.is_empty() || target.len() > 256 {
            return error_value(request_id, "invalid_request", "target is required");
        }
        let messages = params
            .get("messages")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(crate::omp::default_message_count() as u64)
            .clamp(1, 20) as usize;
        let agent = match self
            .exchange(machine, "agent.get", serde_json::json!({"target": target}))
            .await
        {
            Ok(value) => value,
            Err(message) => return error_value(request_id, "herdr_unavailable", &message),
        };
        if agent.get("error").is_some() {
            return agent;
        }
        let session = &agent_info(&agent)["agent_session"];
        let kind = session["agent"].as_str().unwrap_or("");
        let path_kind = session["kind"].as_str().unwrap_or("");
        let path = session["value"].as_str().unwrap_or("");
        if let Err(reason) = crate::omp::session_path_allowed(kind, path_kind, path) {
            let view = crate::omp::unsupported(Some(kind).filter(|name| !name.is_empty()), reason);
            return serde_json::json!({"id": request_id, "result": crate::omp::view_json(&view)});
        }
        let bytes = if let Some(machine) = machine {
            let backend = Arc::clone(&self.machines);
            let machine = machine.to_string();
            let path = path.to_string();
            match tokio::task::spawn_blocking(move || {
                backend.read_file(&machine, &path, crate::omp::MAX_SESSION_BYTES)
            })
            .await
            {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(err)) => return error_value(request_id, err.code, &err.message),
                Err(_) => {
                    return error_value(request_id, "gateway_unavailable", "session read failed");
                }
            }
        } else {
            match read_local_session(std::path::Path::new(path)) {
                Ok(bytes) => bytes,
                Err(message) => return error_value(request_id, "forbidden", &message),
            }
        };
        let view = crate::omp::parse_session(&bytes, messages);
        serde_json::json!({"id": request_id, "result": crate::omp::view_json(&view)})
    }

    async fn answer_ask(
        &self,
        request_id: &str,
        params: &serde_json::Value,
        machine: Option<&str>,
    ) -> serde_json::Value {
        let target = params
            .get("target")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let question_id = params
            .get("question_id")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if target.is_empty() || question_id.is_empty() {
            return error_value(
                request_id,
                "invalid_request",
                "target and question_id are required",
            );
        }
        let choice = match ask_choice(params) {
            Ok(choice) => choice,
            Err(message) => return error_value(request_id, "invalid_request", message),
        };
        let Some(first) = self.load_ask(target, machine).await else {
            return error_value(request_id, "not_found", "no omp session ask is pending");
        };
        if let Err(message) = first {
            return error_value(request_id, "herdr_unavailable", &message);
        }
        let first = first.unwrap();
        if first.question_id != question_id {
            return error_value(
                request_id,
                "conflict",
                "the pending ask is not the question that was requested",
            );
        }
        if first.question_count > 1 {
            return error_value(
                request_id,
                "conflict",
                "only the first question of an ask is on screen",
            );
        }
        let keys = match crate::omp::answer_keys(&first, &choice) {
            Ok(keys) => keys,
            Err(message) => return error_value(request_id, "invalid_request", message),
        };
        let fingerprint = crate::omp::ask_fingerprint(&first);
        let second = self.load_ask(target, machine).await;
        let Some(second) = second else {
            return error_value(
                request_id,
                "conflict",
                "the ask changed before it could be answered",
            );
        };
        let Ok(second) = second else {
            return error_value(
                request_id,
                "conflict",
                "the ask changed before it could be answered",
            );
        };
        if crate::omp::ask_fingerprint(&second) != fingerprint {
            return error_value(
                request_id,
                "conflict",
                "the ask changed before it could be answered",
            );
        }
        match self
            .exchange(
                machine,
                "agent.send_keys",
                serde_json::json!({"target": target, "keys": keys}),
            )
            .await
        {
            Ok(value) if value.get("error").is_none() => serde_json::json!({
                "id": request_id,
                "result": {
                    "type": "ask_answer",
                    "question_id": question_id,
                    "sent": true,
                    "keys": keys,
                    "herdr": value,
                }
            }),
            Ok(value) => value,
            Err(message) => error_value(request_id, "herdr_unavailable", &message),
        }
    }

    async fn load_ask(
        &self,
        target: &str,
        machine: Option<&str>,
    ) -> Option<Result<crate::omp::PendingAsk, String>> {
        let agent = self
            .exchange(machine, "agent.get", serde_json::json!({"target": target}))
            .await
            .ok()?;
        if agent.get("error").is_some() {
            return Some(Err("agent.get failed".to_string()));
        }
        let session = &agent_info(&agent)["agent_session"];
        let kind = session["agent"].as_str().unwrap_or("");
        let path_kind = session["kind"].as_str().unwrap_or("");
        let path = session["value"].as_str().unwrap_or("");
        if crate::omp::session_path_allowed(kind, path_kind, path).is_err() {
            return None;
        }
        let bytes = if let Some(machine) = machine {
            let backend = Arc::clone(&self.machines);
            let machine = machine.to_string();
            let path = path.to_string();
            tokio::task::spawn_blocking(move || {
                backend.read_file(&machine, &path, crate::omp::MAX_SESSION_BYTES)
            })
            .await
            .ok()?
            .ok()?
        } else {
            read_local_session(std::path::Path::new(path)).ok()?
        };
        crate::omp::parse_session(&bytes, 1).ask.map(Ok)
    }

    #[allow(clippy::too_many_arguments)]
    async fn idempotent_prompt(
        &self,
        remote: EndpointId,
        request_id: &str,
        method: &str,
        params: serde_json::Value,
        message_id: String,
        machine: Option<String>,
        send: &mut Flushing<iroh::endpoint::SendStream>,
    ) -> anyhow::Result<()> {
        if !crate::receipt::message_id_ok(&message_id) {
            write_text(
                send,
                &error_line(
                    request_id,
                    "invalid_request",
                    "message_id must be 1 to 80 letters, digits, '.', '_', ':' or '-'",
                ),
            )
            .await?;
            return Ok(());
        }
        let text = params
            .get("text")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let hash = crate::receipt::payload_hash(text);
        let key = format!(
            "{remote}|{}|{method}|{message_id}",
            machine.as_deref().unwrap_or("local")
        );
        let store = Arc::clone(&self.receipts);
        let begin_key = key.clone();
        let begin_hash = hash.clone();
        let begun = tokio::task::spawn_blocking(move || store.begin(&begin_key, &begin_hash))
            .await
            .map_err(|_| anyhow::anyhow!("delivery receipt failed"))?
            .map_err(|message| anyhow::anyhow!(message))?;
        if let Some(receipt) = begun {
            let payload_match = receipt.payload_hash == hash;
            let body =
                crate::receipt::receipt_json(request_id, &message_id, &receipt, payload_match);
            write_text(send, &format!("{body}\n")).await?;
            let _ = send.shutdown().await;
            return Ok(());
        }
        let response = match self
            .exchange(machine.as_deref(), method, params.clone())
            .await
        {
            Ok(value) => value,
            Err(message) => {
                let receipt = crate::receipt::Receipt {
                    delivery: "rejected",
                    agent_status: None,
                    herdr: serde_json::json!({"error": {"code": "herdr_unavailable", "message": message}}),
                    payload_hash: hash,
                };
                self.receipts.finish(&key, receipt.clone());
                let body = crate::receipt::receipt_json(request_id, &message_id, &receipt, true);
                write_text(send, &format!("{body}\n")).await?;
                return Ok(());
            }
        };
        let delivery = if response.get("error").is_some() {
            "rejected"
        } else {
            "delivered"
        };
        let mut agent_status = status_in(&response);
        if agent_status.is_none()
            && delivery == "delivered"
            && let Some(target) = params.get("target").and_then(serde_json::Value::as_str)
            && let Ok(agent) = self
                .exchange(
                    machine.as_deref(),
                    "agent.get",
                    serde_json::json!({"target": target}),
                )
                .await
        {
            agent_status = status_in(&agent);
        }
        let receipt = crate::receipt::Receipt {
            delivery,
            agent_status,
            herdr: response,
            payload_hash: hash.clone(),
        };
        self.receipts.finish(&key, receipt.clone());
        tracing::info!(
            endpoint_id = %remote,
            method,
            message_id,
            delivery,
            machine = machine.as_deref().unwrap_or("local"),
            "delivery receipt"
        );
        let body = crate::receipt::receipt_json(request_id, &message_id, &receipt, true);
        write_text(send, &format!("{body}\n")).await?;
        let _ = send.shutdown().await;
        Ok(())
    }

    async fn exchange(
        &self,
        machine: Option<&str>,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let line = encode_request(&serde_json::json!({
            "id": format!("relay-{}", method.replace('.', "-")),
            "method": method,
            "params": params,
        }))
        .map_err(|err| err.to_string())?;
        if let Some(machine) = machine {
            let backend = Arc::clone(&self.machines);
            let machine = machine.to_string();
            let bytes = tokio::task::spawn_blocking(move || {
                let mut out = Vec::new();
                backend.forward(
                    &machine,
                    line.as_bytes(),
                    &AtomicBool::new(false),
                    &mut |chunk| {
                        out.extend_from_slice(chunk);
                        out.len() < crate::protocol::MAX_RESPONSE_BYTES
                    },
                )?;
                Ok::<Vec<u8>, crate::gateway::MachineError>(out)
            })
            .await
            .map_err(|_| "saved-machine call failed".to_string())?
            .map_err(|err| err.message)?;
            first_json(&bytes)
        } else {
            local_exchange(&self.socket_path, &line).await
        }
    }

    async fn watch_statuses(self) {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<(String, String, Option<String>, String)>(64);
        let local = self.clone();
        let local_tx = tx.clone();
        tokio::spawn(async move {
            local.watch_local(local_tx).await;
        });
        let saved = self.clone();
        let saved_tx = tx.clone();
        tokio::spawn(async move {
            saved.watch_saved_machines(saved_tx).await;
        });
        drop(tx);
        let mut debounce = crate::notify::Debounce::default();
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        let host = self.notify.host.clone();
        loop {
            tokio::select! {
                event = rx.recv() => {
                    let Some((scope, pane, agent, status)) = event else { break };
                    debounce.push(&format!("{scope}\n{pane}"), &status, std::time::Instant::now());
                    let _ = agent;
                }
                _ = interval.tick() => {
                    let ready = debounce.due(std::time::Instant::now(), self.notify.debounce);
                    for (key, status, previous) in ready {
                        let Some((scope, pane)) = key.split_once('\n') else { continue };
                        self.post_status(scope, pane, &status, previous.as_deref(), &host).await;
                    }
                }
            }
        }
    }

    async fn watch_local(
        &self,
        tx: tokio::sync::mpsc::Sender<(String, String, Option<String>, String)>,
    ) {
        let host = self.notify.host.clone();
        loop {
            if self.follow_socket(None, &host, &tx).await.is_err() {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }

    async fn watch_saved_machines(
        &self,
        tx: tokio::sync::mpsc::Sender<(String, String, Option<String>, String)>,
    ) {
        let running = Arc::new(std::sync::Mutex::new(
            std::collections::HashSet::<String>::new(),
        ));
        loop {
            if self.gateway.load(Ordering::Acquire)
                && let Ok(machines) = self.machines.list()
            {
                for machine in machines.into_iter().filter(|machine| machine.enabled) {
                    let scope = format!("{}/{}", self.notify.host, machine.label);
                    {
                        let mut guard = running.lock().unwrap_or_else(|err| err.into_inner());
                        if !guard.insert(scope.clone()) {
                            continue;
                        }
                    }
                    let protocol = self.clone();
                    let tx = tx.clone();
                    let selector = machine.label.clone();
                    let running = Arc::clone(&running);
                    tokio::spawn(async move {
                        let _ = protocol.follow_socket(Some(selector), &scope, &tx).await;
                        running
                            .lock()
                            .unwrap_or_else(|err| err.into_inner())
                            .remove(&scope);
                    });
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    async fn follow_socket(
        &self,
        machine: Option<String>,
        scope: &str,
        tx: &tokio::sync::mpsc::Sender<(String, String, Option<String>, String)>,
    ) -> Result<(), ()> {
        let request = encode_request(&serde_json::json!({
            "id": "relay-status",
            "method": "events.subscribe",
            "params": {"subscriptions": [{"type": "pane.agent_status_changed"}]}
        }))
        .map_err(|_| ())?;
        if let Some(machine) = machine {
            let backend = Arc::clone(&self.machines);
            let scope = scope.to_string();
            let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
            let runner = tokio::task::spawn_blocking(move || {
                let cancel = AtomicBool::new(false);
                backend.forward(&machine, request.as_bytes(), &cancel, &mut |chunk| {
                    line_tx.blocking_send(chunk.to_vec()).is_ok()
                })
            });
            while let Some(chunk) = line_rx.recv().await {
                if let Some(event) = status_event(&chunk) {
                    let _ = tx.send((scope.clone(), event.0, event.1, event.2)).await;
                }
            }
            let _ = runner.await;
            Err(())
        } else {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(|_| ())?;
            stream.write_all(request.as_bytes()).await.map_err(|_| ())?;
            let mut reader = BufReader::new(stream);
            loop {
                let line = read_line_limited(&mut reader, MAX_RESPONSE_BYTES)
                    .await
                    .map_err(|_| ())?;
                let Some(line) = line else { return Err(()) };
                if let Some(event) = status_event(&line) {
                    let _ = tx
                        .send((scope.to_string(), event.0, event.1, event.2))
                        .await;
                }
            }
        }
    }

    async fn post_status(
        &self,
        scope: &str,
        pane: &str,
        status: &str,
        previous: Option<&str>,
        host_label: &str,
    ) {
        let machine = scope
            .strip_prefix(&format!("{host_label}/"))
            .filter(|rest| !rest.is_empty());
        let (agent, cwd, recap) = self.status_context(machine, pane).await;
        let note = crate::notify::StatusNote {
            host: scope.to_string(),
            pane_id: pane.to_string(),
            agent,
            status: status.to_string(),
            cwd,
            recap,
        };
        let body = serde_json::to_vec(&crate::notify::payload(&note, previous)).unwrap_or_default();
        let Some(signature) = self.notify.sign(&body) else {
            return;
        };
        for url in self.notify.urls() {
            if let Err(err) = crate::notify::post_curl(url, &body, &signature) {
                tracing::warn!(error = %err, "webhook post failed");
            }
        }
    }

    async fn status_context(
        &self,
        machine: Option<&str>,
        pane: &str,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let Ok(agent) = self
            .exchange(machine, "agent.get", serde_json::json!({"target": pane}))
            .await
        else {
            return (None, None, None);
        };
        let info = agent_info(&agent);
        let name = info["name"]
            .as_str()
            .or_else(|| info["agent"].as_str())
            .map(str::to_string);
        let cwd = info["cwd"].as_str().map(str::to_string);
        let session = &info["agent_session"];
        let recap = (|| {
            let kind = session["agent"].as_str().unwrap_or("");
            let path_kind = session["kind"].as_str().unwrap_or("");
            let path = session["value"].as_str().unwrap_or("");
            crate::omp::session_path_allowed(kind, path_kind, path).ok()?;
            let bytes = if let Some(machine) = machine {
                self.machines
                    .read_file(machine, path, crate::omp::MAX_SESSION_BYTES)
                    .ok()?
            } else {
                read_local_session(std::path::Path::new(path)).ok()?
            };
            crate::omp::parse_session(&bytes, 1)
                .recap
                .map(|recap| recap.text)
        })();
        (name, cwd, recap)
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

fn is_relay_method(method: &str) -> bool {
    matches!(method, "relay.agent_session" | "relay.answer")
}

fn object_params(text: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    match value.get("params") {
        Some(serde_json::Value::Object(map)) => Some(serde_json::Value::Object(map.clone())),
        None => Some(serde_json::json!({})),
        _ => None,
    }
}

fn top_message_id(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value
        .get("message_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn error_value(id: &str, code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "error": {"code": code, "message": message}})
}

/// The `AgentInfo` object of an `agent.get` reply.
///
/// Herdr answers `agent.get` with `{"result": {"type": "agent_info", "agent": {..}}}`
/// (protocol 22 `success_response`). `agent_session`, `cwd` and `name` live on that
/// inner object, not on `result`.
fn agent_info(response: &serde_json::Value) -> &serde_json::Value {
    &response["result"]["agent"]
}

fn status_in(value: &serde_json::Value) -> Option<String> {
    value
        .pointer("/result/agent_status")
        .or_else(|| value.pointer("/result/status"))
        .or_else(|| value.pointer("/result/agent/agent_status"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn ask_choice(params: &serde_json::Value) -> Result<crate::omp::AskChoice, &'static str> {
    let index = params
        .get("option_index")
        .and_then(serde_json::Value::as_u64);
    let label = params
        .get("option_label")
        .and_then(serde_json::Value::as_str)
        .filter(|label| !label.is_empty());
    match (index, label) {
        (Some(_), Some(_)) | (None, None) => Err("pass option_index or option_label, not both"),
        (Some(index), None) => Ok(crate::omp::AskChoice::Index(index as usize)),
        (None, Some(label)) => Ok(crate::omp::AskChoice::Label(label.to_string())),
    }
}

fn status_event(bytes: &[u8]) -> Option<(String, Option<String>, String)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let value: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let (pane, agent, status) =
        if let Some(event) = value.get("event").and_then(|event| event.as_object()) {
            let kind = event
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if kind != "pane.agent_status_changed" && kind != "pane_agent_status_changed" {
                return None;
            }
            (
                event.get("pane_id")?.as_str()?.to_string(),
                event
                    .get("agent")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                event.get("agent_status")?.as_str()?.to_string(),
            )
        } else if value.get("event").and_then(serde_json::Value::as_str)
            == Some("pane.agent_status_changed")
        {
            let data = value.get("data")?.as_object()?;
            (
                data.get("pane_id")?.as_str()?.to_string(),
                data.get("agent")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                data.get("agent_status")?.as_str()?.to_string(),
            )
        } else {
            return None;
        };
    Some((pane, agent, status))
}

fn first_json(bytes: &[u8]) -> Result<serde_json::Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "herdr response is not utf-8".to_string())?;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('{') {
            return serde_json::from_str(trimmed)
                .map_err(|_| "herdr response is not json".to_string());
        }
    }
    Err("herdr closed the stream without a response".to_string())
}

async fn local_exchange(path: &std::path::Path, line: &str) -> Result<serde_json::Value, String> {
    let mut stream = UnixStream::connect(path)
        .await
        .map_err(|_| "cannot connect to herdr socket".to_string())?;
    stream
        .write_all(line.as_bytes())
        .await
        .map_err(|_| "herdr write failed".to_string())?;
    let mut reader = BufReader::new(stream);
    let line = tokio::time::timeout(
        Duration::from_secs(30),
        read_line_limited(&mut reader, MAX_RESPONSE_BYTES),
    )
    .await
    .map_err(|_| "timed out waiting for herdr".to_string())?
    .map_err(|err| err.to_string())?
    .ok_or_else(|| "herdr closed the socket".to_string())?;
    serde_json::from_slice(&line).map_err(|_| "herdr response is not json".to_string())
}

fn read_local_session(path: &std::path::Path) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0o400000)
        .open(path)
        .map_err(|_| "cannot read the omp session file".to_string())?;
    let len = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    if len > crate::omp::MAX_SESSION_BYTES as u64 {
        let _ = file.seek(SeekFrom::End(-(crate::omp::MAX_SESSION_BYTES as i64)));
    }
    let mut buf = Vec::new();
    file.take(crate::omp::MAX_SESSION_BYTES as u64)
        .read_to_end(&mut buf)
        .map_err(|_| "cannot read the omp session file".to_string())?;
    Ok(buf)
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
