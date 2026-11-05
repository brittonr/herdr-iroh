//! `server.toml` on a herdr host and `client.toml` on the bot box.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use std::str::FromStr;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::policy::{Allowlist, PeerConfig};

pub const SERVER_FILE: &str = "server.toml";
pub const CLIENT_FILE: &str = "client.toml";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerFile {
    #[serde(default)]
    pub socket_path: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub relays: bool,
    /// Cap on one relayed call, including waits and subscriptions. `0` waits
    /// until herdr closes the socket.
    #[serde(default = "default_relay_timeout_ms")]
    pub relay_timeout_ms: u64,
    #[serde(default)]
    pub peers: BTreeMap<String, PeerConfig>,
}

impl Default for ServerFile {
    fn default() -> Self {
        Self {
            socket_path: None,
            relays: true,
            relay_timeout_ms: default_relay_timeout_ms(),
            peers: BTreeMap::new(),
        }
    }
}

impl ServerFile {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: Self =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Allowlist::try_from_config(&file.peers)
            .map_err(|err| anyhow::anyhow!("{path}: {err}", path = path.display()))?;
        Ok(file)
    }

    pub fn allowlist(&self) -> anyhow::Result<Allowlist> {
        Allowlist::try_from_config(&self.peers).map_err(|err| anyhow::anyhow!("allowlist: {err}"))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientFile {
    #[serde(default)]
    pub default_host: Option<String>,
    #[serde(default)]
    pub hosts: BTreeMap<String, HostConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub endpoint_id: String,
    #[serde(default)]
    pub ticket: Option<String>,
    #[serde(default = "default_true")]
    pub relays: bool,
}

impl ClientFile {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: Self =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        file.validate()?;
        Ok(file)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(name) = &self.default_host
            && !self.hosts.contains_key(name)
        {
            anyhow::bail!("default_host {name:?} is not listed under [hosts]");
        }
        for (name, host) in &self.hosts {
            if !crate::policy::peer_label_ok(name) {
                anyhow::bail!("host name {name:?} must be letters, digits, '.', '_' or '-'");
            }
            let id: iroh::EndpointId = host.endpoint_id.parse().map_err(|_| {
                anyhow::anyhow!("host {name} endpoint_id is not an iroh endpoint id")
            })?;
            if let Some(ticket) = &host.ticket {
                let parsed = iroh_tickets::endpoint::EndpointTicket::from_str(ticket)
                    .map_err(|err| anyhow::anyhow!("host {name} ticket: {err}"))?;
                let ticket_id = parsed.endpoint_addr().id;
                if ticket_id != id {
                    anyhow::bail!(
                        "host {name} ticket is for endpoint {ticket_id}, not {}",
                        host.endpoint_id
                    );
                }
            } else if !host.relays {
                anyhow::bail!(
                    "host {name} sets relays = false and has no ticket; direct dial needs a ticket"
                );
            }
        }
        Ok(())
    }

    pub fn resolve<'a>(&'a self, host: Option<&str>) -> anyhow::Result<(String, &'a HostConfig)> {
        let name = match host {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => self.default_host.clone().ok_or_else(|| {
                anyhow::anyhow!("pass host, or set default_host in the client config")
            })?,
        };
        let config = self
            .hosts
            .get(&name)
            .ok_or_else(|| anyhow::anyhow!("unknown host {name:?}"))?;
        Ok((name, config))
    }
}

fn default_true() -> bool {
    true
}

fn default_relay_timeout_ms() -> u64 {
    900_000
}

#[must_use]
pub fn config_dir() -> PathBuf {
    xdg_dir("XDG_CONFIG_HOME", ".config").join("herdr-iroh")
}

#[must_use]
pub fn state_dir() -> PathBuf {
    xdg_dir("XDG_STATE_HOME", ".local/state").join("herdr-iroh")
}

fn xdg_dir(var: &str, fallback: &str) -> PathBuf {
    if let Some(dir) = std::env::var_os(var)
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    home().join(fallback)
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Where a release build of herdr listens, unless the operator overrides it.
///
/// Order: `HERDR_SOCKET_PATH`, then `HERDR_SESSION` under the herdr config
/// directory, then `$XDG_CONFIG_HOME/herdr/herdr.sock`. Debug builds of herdr
/// itself use `herdr-dev` instead of `herdr`; point `socket_path` at that
/// socket when you are running one.
#[must_use]
pub fn default_herdr_socket() -> PathBuf {
    if let Ok(path) = std::env::var("HERDR_SOCKET_PATH")
        && !path.is_empty()
    {
        return PathBuf::from(path);
    }
    let root = xdg_dir("XDG_CONFIG_HOME", ".config").join("herdr");
    if let Ok(session) = std::env::var("HERDR_SESSION")
        && !session.is_empty()
        && !session.contains(['/', '\\'])
    {
        return root.join("sessions").join(session).join("herdr.sock");
    }
    root.join("herdr.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_file_roundtrip_and_full_peer() {
        let key = iroh::SecretKey::generate();
        let id = key.public().to_string();
        let text = format!(
            r#"
            socket_path = "/tmp/herdr.sock"
            relay_timeout_ms = 1000

            [peers.britton-grok]
            endpoint_id = "{id}"
            methods = "full"
            "#
        );
        let file: ServerFile = toml::from_str(&text).unwrap();
        let allow = file.allowlist().unwrap();
        let parsed: iroh::EndpointId = id.parse().unwrap();
        assert_eq!(
            allow.decide(&parsed, "agent.prompt"),
            crate::policy::Decision::Allow
        );
        assert!(file.relays);
    }

    #[test]
    fn client_file_rejects_ticket_for_a_different_endpoint() {
        let a = iroh::SecretKey::generate();
        let b = iroh::SecretKey::generate();
        use iroh::EndpointAddr;
        use iroh_tickets::Ticket;
        use iroh_tickets::endpoint::EndpointTicket;
        let addr = EndpointAddr::new(a.public());
        let ticket = EndpointTicket::new(addr).encode_string();
        let text = format!(
            r#"
            default_host = "box"

            [hosts.box]
            endpoint_id = "{}"
            ticket = "{ticket}"
            "#,
            b.public()
        );
        let err = toml::from_str::<ClientFile>(&text)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("ticket is for endpoint"), "{err}");
    }
}
