//! Dial a herdr-iroh host and exchange one herdr request.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, bail};
use iroh::endpoint::{Connection, RelayMode, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use iroh_tickets::endpoint::EndpointTicket;
use serde_json::Value;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::config::HostConfig;
use crate::protocol::{self, MAX_RESPONSE_BYTES, encode_request, parse_response_line};
use crate::stream::{Flushing, read_line_limited};

pub struct CallOptions {
    pub timeout: Duration,
    pub max_lines: usize,
}

impl Default for CallOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            max_lines: 1,
        }
    }
}

#[derive(Clone)]
pub struct DialTarget {
    pub endpoint_id: EndpointId,
    pub addr: EndpointAddr,
}

/// Resolve a configured host to an address this node can dial.
///
/// # Errors
///
/// Returns an error when the endpoint id is invalid, the ticket does not match
/// it, or a direct-only dial has no ticket.
pub fn dial_target(host: &HostConfig, relays_enabled: bool) -> anyhow::Result<DialTarget> {
    let endpoint_id: EndpointId = host.endpoint_id.parse().map_err(|_| {
        anyhow::anyhow!(
            "endpoint id {} is not an iroh endpoint id",
            host.endpoint_id
        )
    })?;
    if host.ticket.is_none() && (!host.relays || !relays_enabled) {
        bail!(
            "host endpoint {} has no ticket, and relays are off; direct dial needs a ticket",
            host.endpoint_id
        );
    }
    let addr = if let Some(ticket) = &host.ticket {
        let parsed = EndpointTicket::from_str(ticket)
            .map_err(|err| anyhow::anyhow!("invalid endpoint ticket: {err}"))?;
        let addr = parsed.endpoint_addr().clone();
        if addr.id != endpoint_id {
            bail!(
                "ticket is for endpoint {}, configured id is {endpoint_id}",
                addr.id
            );
        }
        addr
    } else {
        EndpointAddr::new(endpoint_id)
    };
    Ok(DialTarget { endpoint_id, addr })
}

pub struct Node {
    endpoint: Endpoint,
    relays: bool,
    conns: Mutex<HashMap<EndpointId, Connection>>,
}

impl Node {
    /// Bind the bot's endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when iroh cannot bind a socket.
    pub async fn bind(
        secret_key: SecretKey,
        relays: bool,
        bind_addr: Option<SocketAddr>,
    ) -> anyhow::Result<Self> {
        let mut builder = Endpoint::builder(presets::N0).secret_key(secret_key);
        if !relays {
            builder = builder.relay_mode(RelayMode::Disabled);
        }
        if let Some(addr) = bind_addr {
            builder = builder
                .bind_addr(addr)
                .map_err(|err| anyhow::anyhow!("iroh bind address {addr}: {err}"))?;
        } else if !relays {
            builder = builder
                .bind_addr((Ipv4Addr::LOCALHOST, 0))
                .map_err(|err| anyhow::anyhow!("iroh loopback bind: {err}"))?;
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|err| anyhow::anyhow!("bind iroh endpoint: {err}"))?;
        Ok(Self {
            endpoint,
            relays,
            conns: Mutex::new(HashMap::new()),
        })
    }

    #[must_use]
    pub fn relays_enabled(&self) -> bool {
        self.relays
    }

    /// Close the endpoint so drop does not abort active connections.
    pub async fn close(&self) {
        self.endpoint.close().await;
    }

    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Send one herdr request and collect response lines.
    ///
    /// `max_lines` stops the read without waiting for herdr to close. That is
    /// how a short `events.subscribe` capture returns. `1` is a normal call.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer cannot be dialed, the stream fails, or
    /// `timeout` elapses before a response line.
    pub async fn call(
        &self,
        target: &DialTarget,
        request: &Value,
        opts: CallOptions,
    ) -> anyhow::Result<Vec<Value>> {
        let line = encode_request(request)?;
        let run = async {
            match self.call_on(&line, target, opts.max_lines, false).await {
                Ok(lines) => Ok(lines),
                Err(err) => {
                    tracing::debug!(error = %err, "retrying herdr-iroh call on a new connection");
                    self.call_on(&line, target, opts.max_lines, true).await
                }
            }
        };
        match tokio::time::timeout(opts.timeout, run).await {
            Ok(result) => result,
            Err(_) => bail!("timed out waiting for herdr"),
        }
    }

    async fn call_on(
        &self,
        line: &str,
        target: &DialTarget,
        max_lines: usize,
        fresh: bool,
    ) -> anyhow::Result<Vec<Value>> {
        let connection = self.connection(target, fresh).await?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|err| anyhow::anyhow!("open herdr stream: {err}"))?;
        let mut send = Flushing::new(send);
        send.write_all(line.as_bytes())
            .await
            .context("sending herdr request")?;
        send.flush().await.context("flushing herdr request")?;

        let mut reader = BufReader::new(recv);
        let mut lines = Vec::new();
        loop {
            if max_lines > 0 && lines.len() >= max_lines {
                break;
            }
            let Some(bytes) = read_line_limited(&mut reader, MAX_RESPONSE_BYTES).await? else {
                break;
            };
            lines.push(parse_response_line(&bytes)?);
        }
        drop(send);
        if lines.is_empty() {
            bail!("herdr closed the stream without a response");
        }
        Ok(lines)
    }

    async fn connection(&self, target: &DialTarget, fresh: bool) -> anyhow::Result<Connection> {
        let mut guard = self.conns.lock().await;
        if fresh {
            guard.remove(&target.endpoint_id);
        } else if let Some(existing) = guard.get(&target.endpoint_id)
            && existing.close_reason().is_none()
        {
            return Ok(existing.clone());
        }
        let connection = self
            .endpoint
            .connect(target.addr.clone(), protocol::ALPN)
            .await
            .map_err(|err| anyhow::anyhow!("iroh connect: {err}"))?;
        guard.insert(target.endpoint_id, connection.clone());
        Ok(connection)
    }
}
