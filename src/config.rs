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
    /// Forward API calls to SSH machines saved on this host. `herdr machine list`
    /// is the catalog. The default is on.
    #[serde(default = "default_true")]
    pub gateway: bool,
    /// `herdr` binary used for the saved-machine catalog and remote bridge.
    /// Omit to use `herdr` on `PATH`.
    #[serde(default)]
    pub herdr_bin: Option<PathBuf>,
    #[serde(default)]
    pub peers: BTreeMap<String, PeerConfig>,
}

impl Default for ServerFile {
    fn default() -> Self {
        Self {
            socket_path: None,
            relays: true,
            relay_timeout_ms: default_relay_timeout_ms(),
            gateway: true,
            herdr_bin: None,
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
        if let Some(bin) = &file.herdr_bin {
            let text = bin.to_string_lossy();
            if text.is_empty() || text.chars().any(char::is_control) {
                anyhow::bail!(
                    "{} herdr_bin is empty or contains a control character",
                    path.display()
                );
            }
        }
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

    /// Resolve `host` or `default_host`.
    ///
    /// `gateway/machine` addresses a saved SSH machine on that gateway. The
    /// machine selector is everything after the first slash, so a label may
    /// itself contain slashes. The gateway name must be a configured host.
    pub fn resolve_route(&self, host: Option<&str>) -> anyhow::Result<HostRoute> {
        let raw = match host {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => self.default_host.clone().ok_or_else(|| {
                anyhow::anyhow!("pass host, or set default_host in the client config")
            })?,
        };
        if let Some((gateway, machine)) = raw.split_once('/') {
            if gateway.is_empty() || machine.is_empty() {
                anyhow::bail!("host {raw:?} is missing a gateway or a saved machine");
            }
            if !self.hosts.contains_key(gateway) {
                anyhow::bail!("unknown host {gateway:?}");
            }
            if machine.len() > 256
                || machine.chars().any(char::is_control)
                || machine.starts_with('-')
            {
                anyhow::bail!("machine name is not allowed");
            }
            return Ok(HostRoute {
                name: gateway.to_string(),
                machine: Some(machine.to_string()),
            });
        }
        self.resolve(Some(&raw))?;
        Ok(HostRoute {
            name: raw,
            machine: None,
        })
    }
}

/// A configured iroh host, and an optional saved machine on that host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRoute {
    pub name: String,
    pub machine: Option<String>,
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

    #[test]
    fn gateway_defaults_on_and_can_be_disabled() {
        let key = iroh::SecretKey::generate();
        let id = key.public();
        let text = format!(
            r#"
            [peers.bot]
            endpoint_id = "{id}"
            "#
        );
        let file: ServerFile = toml::from_str(&text).unwrap();
        assert!(file.gateway);
        assert!(file.herdr_bin.is_none());
        let off: ServerFile = toml::from_str(&format!(
            r#"
            gateway = false
            herdr_bin = "/usr/bin/herdr"

            [peers.bot]
            endpoint_id = "{id}"
            "#
        ))
        .unwrap();
        assert!(!off.gateway);
        assert_eq!(
            off.herdr_bin.as_deref(),
            Some(std::path::Path::new("/usr/bin/herdr"))
        );
    }

    #[test]
    fn route_splits_a_saved_machine_from_its_gateway() {
        let id = iroh::SecretKey::generate().public();
        let text = format!(
            r#"
            default_host = "box"

            [hosts.box]
            endpoint_id = "{id}"
            "#
        );
        let file = toml::from_str::<ClientFile>(&text).unwrap();
        file.validate().unwrap();
        assert_eq!(
            file.resolve_route(None).unwrap(),
            HostRoute {
                name: "box".into(),
                machine: None,
            }
        );
        assert_eq!(
            file.resolve_route(Some("box/instant-fill")).unwrap(),
            HostRoute {
                name: "box".into(),
                machine: Some("instant-fill".into()),
            }
        );
        assert_eq!(
            file.resolve_route(Some("box/workbox/agents"))
                .unwrap()
                .machine
                .as_deref(),
            Some("workbox/agents")
        );
        assert!(file.resolve_route(Some("missing/instant-fill")).is_err());
        assert!(file.resolve_route(Some("box/")).is_err());
        assert!(file.resolve_route(Some("box/-lead")).is_err());
    }
}
