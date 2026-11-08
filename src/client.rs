//! Dial a herdr-iroh host and exchange one herdr request.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::PoisonError;
use std::time::{Duration, Instant};

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

/// Quiet time after which the next call binds a fresh endpoint.
///
/// A bot host can run several `herdr-iroh mcp` processes with one key, one per
/// session. An iroh relay delivers an endpoint id's packets only to the
/// endpoint that connected last, and the older ones stop hearing replies
/// without any error. Binding again when a burst of calls starts makes the
/// calling process the newest endpoint.
const IDLE_REBIND: Duration = Duration::from_secs(10);

/// Longest wait for the home relay after a bind before dialing anyway.
const ONLINE_WAIT: Duration = Duration::from_secs(5);

pub struct Node {
    secret_key: SecretKey,
    relays: bool,
    bind_addr: Option<SocketAddr>,
    slot: Mutex<Slot>,
    usage: std::sync::Mutex<Usage>,
}

/// The bound endpoint and its cached connections.
#[derive(Default)]
struct Slot {
    endpoint: Option<Endpoint>,
    conns: HashMap<EndpointId, Connection>,
}

struct Usage {
    in_flight: usize,
    last_used: Instant,
    /// A call timed out, so the relay may have moved this key to another process.
    stale: bool,
}

/// Whether the next call should replace the bound endpoint.
///
/// Calls in flight keep it. Otherwise a timeout or a quiet spell replaces it.
fn should_rebind(usage: &Usage, now: Instant) -> bool {
    usage.in_flight == 0
        && (usage.stale || now.saturating_duration_since(usage.last_used) >= IDLE_REBIND)
}

/// Counts one call as in flight until dropped, including when the caller
/// cancels it.
struct InFlight<'a> {
    usage: &'a std::sync::Mutex<Usage>,
    timed_out: bool,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let mut usage = self.usage.lock().unwrap_or_else(PoisonError::into_inner);
        usage.in_flight = usage.in_flight.saturating_sub(1);
        usage.last_used = Instant::now();
        if self.timed_out {
            usage.stale = true;
        }
    }
}

impl Node {
    /// Create the bot's node. The endpoint binds on the first call, so an
    /// idle process does not take the relay from a busy one with the same key.
    #[must_use]
    pub fn new(secret_key: SecretKey, relays: bool, bind_addr: Option<SocketAddr>) -> Self {
        Self {
            secret_key,
            relays,
            bind_addr,
            slot: Mutex::new(Slot::default()),
            usage: std::sync::Mutex::new(Usage {
                in_flight: 0,
                last_used: Instant::now(),
                stale: false,
            }),
        }
    }

    #[must_use]
    pub fn relays_enabled(&self) -> bool {
        self.relays
    }

    /// Close the endpoint so drop does not abort active connections.
    pub async fn close(&self) {
        let endpoint = self.slot.lock().await.endpoint.take();
        if let Some(endpoint) = endpoint {
            endpoint.close().await;
        }
    }

    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.secret_key.public()
    }

    /// Send one herdr request and collect response lines.
    ///
    /// `max_lines` stops the read without waiting for herdr to close. That is
    /// how a short `events.subscribe` capture returns. `1` is a normal call.
    ///
    /// # Errors
    ///
    /// Returns an error when iroh cannot bind a socket, the peer cannot be
    /// dialed, the stream fails, or `timeout` elapses before a response line.
    pub async fn call(
        &self,
        target: &DialTarget,
        request: &Value,
        opts: CallOptions,
    ) -> anyhow::Result<Vec<Value>> {
        let line = encode_request(request)?;
        let (endpoint, mut in_flight) = self.acquire().await?;
        let run = async {
            match self
                .call_on(&endpoint, &line, target, opts.max_lines, false)
                .await
            {
                Ok(lines) => Ok(lines),
                Err(err) => {
                    tracing::debug!(error = %err, "retrying herdr-iroh call on a new connection");
                    self.call_on(&endpoint, &line, target, opts.max_lines, true)
                        .await
                }
            }
        };
        let Ok(result) = tokio::time::timeout(opts.timeout, run).await else {
            in_flight.timed_out = true;
            bail!("timed out waiting for herdr");
        };
        result
    }

    /// Return the endpoint for one call, binding a fresh one when none is bound
    /// or [`should_rebind`] says the current one may have lost the relay.
    ///
    /// Rebinding needs relays and an ephemeral port: without relays nothing can
    /// take the key's packets away, and a fixed `--bind` port is still held
    /// while the old endpoint closes.
    async fn acquire(&self) -> anyhow::Result<(Endpoint, InFlight<'_>)> {
        let mut slot = self.slot.lock().await;
        let rebind =
            self.relays && self.bind_addr.is_none() && should_rebind(&self.usage(), Instant::now());
        let endpoint = match slot.endpoint.take() {
            Some(current) if !rebind => current,
            stale => {
                if let Some(old) = stale {
                    // A closing endpoint waits for peers to acknowledge, and one
                    // the relay dropped never hears them, so do not wait here.
                    tokio::spawn(async move { old.close().await });
                }
                slot.conns.clear();
                let fresh = self.bind_endpoint().await?;
                self.usage().stale = false;
                fresh
            }
        };
        slot.endpoint = Some(endpoint.clone());
        self.usage().in_flight += 1;
        Ok((
            endpoint,
            InFlight {
                usage: &self.usage,
                timed_out: false,
            },
        ))
    }

    fn usage(&self) -> std::sync::MutexGuard<'_, Usage> {
        self.usage.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn bind_endpoint(&self) -> anyhow::Result<Endpoint> {
        let mut builder = Endpoint::builder(presets::N0).secret_key(self.secret_key.clone());
        if !self.relays {
            builder = builder.relay_mode(RelayMode::Disabled);
        }
        if let Some(addr) = self.bind_addr {
            builder = builder
                .bind_addr(addr)
                .map_err(|err| anyhow::anyhow!("iroh bind address {addr}: {err}"))?;
        } else if !self.relays {
            builder = builder
                .bind_addr((Ipv4Addr::LOCALHOST, 0))
                .map_err(|err| anyhow::anyhow!("iroh loopback bind: {err}"))?;
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|err| anyhow::anyhow!("bind iroh endpoint: {err}"))?;
        // Replies through the relay need the home relay connection. Dial anyway
        // after a while: a host with a ticket may answer on a direct path.
        if self.relays
            && tokio::time::timeout(ONLINE_WAIT, endpoint.online())
                .await
                .is_err()
        {
            tracing::debug!("home relay not connected after {ONLINE_WAIT:?}; dialing anyway");
        }
        Ok(endpoint)
    }

    async fn call_on(
        &self,
        endpoint: &Endpoint,
        line: &str,
        target: &DialTarget,
        max_lines: usize,
        fresh: bool,
    ) -> anyhow::Result<Vec<Value>> {
        let connection = self.connection(endpoint, target, fresh).await?;
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

    async fn connection(
        &self,
        endpoint: &Endpoint,
        target: &DialTarget,
        fresh: bool,
    ) -> anyhow::Result<Connection> {
        let mut slot = self.slot.lock().await;
        if fresh {
            slot.conns.remove(&target.endpoint_id);
        } else if let Some(existing) = slot.conns.get(&target.endpoint_id)
            && existing.close_reason().is_none()
        {
            return Ok(existing.clone());
        }
        let connection = endpoint
            .connect(target.addr.clone(), protocol::ALPN)
            .await
            .map_err(|err| anyhow::anyhow!("iroh connect: {err}"))?;
        slot.conns.insert(target.endpoint_id, connection.clone());
        Ok(connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(in_flight: usize, stale: bool, last_used: Instant) -> Usage {
        Usage {
            in_flight,
            last_used,
            stale,
        }
    }

    #[test]
    fn calls_in_flight_keep_the_endpoint() {
        let start = Instant::now();
        let busy = usage(1, true, start);
        assert!(!should_rebind(&busy, start + IDLE_REBIND * 6));
    }

    #[test]
    fn a_quiet_spell_rebinds_from_the_threshold() {
        let start = Instant::now();
        let idle = usage(0, false, start);
        assert!(!should_rebind(
            &idle,
            start + IDLE_REBIND - Duration::from_millis(1)
        ));
        assert!(should_rebind(&idle, start + IDLE_REBIND));
    }

    #[test]
    fn a_timeout_rebinds_without_waiting() {
        let start = Instant::now();
        assert!(should_rebind(&usage(0, true, start), start));
    }

    #[test]
    fn a_dropped_call_releases_and_records_its_timeout() {
        let shared = std::sync::Mutex::new(usage(2, false, Instant::now()));
        drop(InFlight {
            usage: &shared,
            timed_out: false,
        });
        {
            let after = shared.lock().unwrap();
            assert_eq!(after.in_flight, 1);
            assert!(!after.stale);
        }
        drop(InFlight {
            usage: &shared,
            timed_out: true,
        });
        let after = shared.lock().unwrap();
        assert_eq!(after.in_flight, 0);
        assert!(after.stale);
    }
}
