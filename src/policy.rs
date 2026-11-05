//! Endpoint allowlist and per-peer method policy.
//!
//! `server.stop` and `server.live_handoff` stop or replace the herdr process.
//! They are refused for every remote peer, including a peer whose config says
//! `methods = "full"` or names those methods explicitly.

use std::collections::BTreeMap;

use iroh::EndpointId;
use serde::{Deserialize, Serialize};

/// Methods a remote peer can never call, even when the allowlist grants them.
pub const ALWAYS_DENIED: &[&str] = &["server.stop", "server.live_handoff"];

/// Whether a method would stop or replace the herdr server.
#[must_use]
pub fn is_always_denied(method: &str) -> bool {
    ALWAYS_DENIED.iter().any(|denied| {
        method == *denied
            || method
                .strip_prefix(*denied)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

/// What one allowlisted peer may call, before the always-denied filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodPolicy {
    /// Every herdr method except [`ALWAYS_DENIED`].
    Full,
    /// Exact names, `prefix.*` globs, or a single `*`.
    Only(Vec<MethodPattern>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodPattern {
    Exact(String),
    /// `agent.*` is stored as the prefix `agent.` so `agent.view.set` matches.
    Prefix(String),
    All,
}

impl MethodPattern {
    fn matches(&self, method: &str) -> bool {
        match self {
            Self::Exact(name) => name == method,
            Self::Prefix(prefix) => method.starts_with(prefix),
            Self::All => true,
        }
    }
}

impl MethodPolicy {
    /// Parse a config value. `"full"` is the wide policy. A list is exact.
    ///
    /// # Errors
    ///
    /// Returns an error when a string is not `"full"` or a glob is malformed.
    pub fn parse(field: &MethodsField) -> Result<Self, String> {
        match field {
            MethodsField::Word(word) => {
                if word.trim().eq_ignore_ascii_case("full") {
                    Ok(Self::Full)
                } else {
                    Err(format!("methods must be \"full\" or a list, not {word:?}"))
                }
            }
            MethodsField::List(items) => {
                let mut patterns = Vec::with_capacity(items.len());
                for item in items {
                    patterns.push(MethodPattern::parse(item)?);
                }
                Ok(Self::Only(patterns))
            }
        }
    }

    fn allows_method(&self, method: &str) -> bool {
        match self {
            Self::Full => true,
            Self::Only(patterns) => patterns.iter().any(|pattern| pattern.matches(method)),
        }
    }
}

impl MethodPattern {
    fn parse(raw: &str) -> Result<Self, String> {
        let item = raw.trim();
        if item.is_empty() || item.chars().any(char::is_whitespace) {
            return Err(format!("invalid method pattern {raw:?}"));
        }
        if item == "*" {
            return Ok(Self::All);
        }
        if let Some(prefix) = item.strip_suffix(".*") {
            if !prefix.is_empty()
                && !prefix.contains('*')
                && prefix.split('.').all(crate::protocol::valid_method_name)
            {
                return Ok(Self::Prefix(format!("{prefix}.")));
            }
            return Err(format!("invalid method pattern {raw:?}"));
        }
        if crate::protocol::valid_method_name(item) {
            Ok(Self::Exact(item.to_string()))
        } else {
            Err(format!("invalid method pattern {raw:?}"))
        }
    }
}

/// TOML `methods` field: the word `full`, or a list of patterns.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MethodsField {
    Word(String),
    List(Vec<String>),
}

/// One peer entry after the endpoint id has been parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicy {
    pub name: String,
    pub methods: MethodPolicy,
}

/// Allowlist keyed by iroh endpoint id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    peers: BTreeMap<EndpointId, PeerPolicy>,
}

impl Allowlist {
    /// Build an allowlist from config names.
    ///
    /// # Errors
    ///
    /// Returns an error when an endpoint id is not 64 hex characters, two
    /// names share an id, or a method pattern is invalid.
    pub fn try_from_config(peers: &BTreeMap<String, PeerConfig>) -> Result<Self, String> {
        let mut allow = Self::default();
        for (name, peer) in peers {
            if !peer_label_ok(name) {
                return Err(format!(
                    "peer name {name:?} must be letters, digits, '.', '_' or '-'"
                ));
            }
            let id: EndpointId = peer
                .endpoint_id
                .parse()
                .map_err(|_| format!("peer {name} endpoint_id is not an iroh endpoint id"))?;
            if allow.peers.contains_key(&id) {
                return Err(format!(
                    "endpoint id for peer {name} is listed more than once"
                ));
            }
            let methods = match &peer.methods {
                Some(field) => MethodPolicy::parse(field)?,
                None => MethodPolicy::Full,
            };
            allow.peers.insert(
                id,
                PeerPolicy {
                    name: name.clone(),
                    methods,
                },
            );
        }
        Ok(allow)
    }

    #[must_use]
    pub fn allows_peer(&self, id: &EndpointId) -> bool {
        self.peers.contains_key(id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    #[must_use]
    pub fn peer_name(&self, id: &EndpointId) -> Option<&str> {
        self.peers.get(id).map(|peer| peer.name.as_str())
    }

    /// Decide a single method call. Always-denied methods lose to nothing.
    #[must_use]
    pub fn decide(&self, id: &EndpointId, method: &str) -> Decision {
        let Some(peer) = self.peers.get(id) else {
            return Decision::Denied(DenyReason::NotOnAllowlist);
        };
        if is_always_denied(method) {
            return Decision::Denied(DenyReason::AlwaysDenied);
        }
        if peer.methods.allows_method(method) {
            Decision::Allow
        } else {
            Decision::Denied(DenyReason::MethodNotAllowed)
        }
    }
}

/// Unparsed peer from `server.toml`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub endpoint_id: String,
    #[serde(default)]
    pub methods: Option<MethodsField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Denied(DenyReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    NotOnAllowlist,
    AlwaysDenied,
    MethodNotAllowed,
}

impl Decision {
    #[must_use]
    pub fn error_code(self) -> &'static str {
        "forbidden"
    }

    #[must_use]
    pub fn message(self, method: &str) -> String {
        match self {
            Self::Allow => String::new(),
            Self::Denied(DenyReason::NotOnAllowlist) => "endpoint is not on the allowlist".into(),
            Self::Denied(DenyReason::AlwaysDenied) => {
                format!("{method} is denied to every remote peer")
            }
            Self::Denied(DenyReason::MethodNotAllowed) => {
                format!("{method} is not allowed for this peer")
            }
        }
    }
}

pub(crate) fn peer_label_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[byte; 32]).public()
    }

    fn allow(methods: Option<MethodsField>) -> Allowlist {
        let endpoint = id(1);
        let mut peers = BTreeMap::new();
        peers.insert(
            "bot".to_string(),
            PeerConfig {
                endpoint_id: endpoint.to_string(),
                methods,
            },
        );
        Allowlist::try_from_config(&peers).unwrap()
    }

    #[test]
    fn full_access_still_denies_stop_and_live_handoff() {
        let allow = allow(Some(MethodsField::Word("full".into())));
        let peer = id(1);
        assert_eq!(allow.decide(&peer, "agent.prompt"), Decision::Allow);
        assert_eq!(allow.decide(&peer, "pane.send_text"), Decision::Allow);
        assert_eq!(allow.decide(&peer, "layout.apply"), Decision::Allow);
        assert_eq!(allow.decide(&peer, "tab.rename"), Decision::Allow);
        assert_eq!(allow.decide(&peer, "server.reload_config"), Decision::Allow);
        assert_eq!(
            allow.decide(&peer, "server.stop"),
            Decision::Denied(DenyReason::AlwaysDenied)
        );
        assert_eq!(
            allow.decide(&peer, "server.live_handoff"),
            Decision::Denied(DenyReason::AlwaysDenied)
        );
        assert_eq!(
            allow.decide(&peer, "server.stop.now"),
            Decision::Denied(DenyReason::AlwaysDenied)
        );
        assert_eq!(allow.decide(&peer, "server.stopped"), Decision::Allow);
    }

    #[test]
    fn explicit_grant_cannot_override_always_denied() {
        let allow = allow(Some(MethodsField::List(vec![
            "server.stop".into(),
            "server.live_handoff".into(),
            "server.*".into(),
            "*".into(),
            "agent.list".into(),
        ])));
        let peer = id(1);
        assert_eq!(allow.decide(&peer, "agent.list"), Decision::Allow);
        assert_eq!(allow.decide(&peer, "pane.read"), Decision::Allow);
        assert_eq!(
            allow.decide(&peer, "server.stop"),
            Decision::Denied(DenyReason::AlwaysDenied)
        );
        assert_eq!(
            allow.decide(&peer, "server.live_handoff"),
            Decision::Denied(DenyReason::AlwaysDenied)
        );
    }

    #[test]
    fn listed_methods_are_exact_and_globs_are_prefixes() {
        let allow = allow(Some(MethodsField::List(vec![
            "agent.*".into(),
            "pane.read".into(),
        ])));
        let peer = id(1);
        assert_eq!(allow.decide(&peer, "agent.prompt"), Decision::Allow);
        assert_eq!(allow.decide(&peer, "agent.view.set"), Decision::Allow);
        assert_eq!(allow.decide(&peer, "pane.read"), Decision::Allow);
        assert_eq!(
            allow.decide(&peer, "pane.send_text"),
            Decision::Denied(DenyReason::MethodNotAllowed)
        );
        assert_eq!(
            allow.decide(&id(2), "agent.list"),
            Decision::Denied(DenyReason::NotOnAllowlist)
        );
    }

    #[test]
    fn omitted_methods_mean_full_except_the_hard_denies() {
        let allow = allow(None);
        assert_eq!(allow.decide(&id(1), "events.subscribe"), Decision::Allow);
        assert!(is_always_denied("server.stop"));
        assert!(is_always_denied("server.live_handoff"));
        assert!(!is_always_denied("server.reload_config"));
    }

    #[test]
    fn empty_list_allows_nothing() {
        let allow = allow(Some(MethodsField::List(vec![])));
        assert_eq!(
            allow.decide(&id(1), "ping"),
            Decision::Denied(DenyReason::MethodNotAllowed)
        );
    }

    #[test]
    fn duplicate_endpoint_ids_are_rejected() {
        let endpoint = id(7).to_string();
        let mut peers = BTreeMap::new();
        peers.insert(
            "a".into(),
            PeerConfig {
                endpoint_id: endpoint.clone(),
                methods: None,
            },
        );
        peers.insert(
            "b".into(),
            PeerConfig {
                endpoint_id: endpoint,
                methods: None,
            },
        );
        let err = Allowlist::try_from_config(&peers).unwrap_err();
        assert!(err.contains("more than once"), "{err}");
    }

    #[test]
    fn bad_patterns_are_rejected() {
        let err = MethodPattern::parse("agent.*.read").unwrap_err();
        assert!(err.contains("invalid"));
        assert!(MethodPattern::parse(".*").is_err());
        assert!(MethodPolicy::parse(&MethodsField::Word("write".into())).is_err());
    }
}
