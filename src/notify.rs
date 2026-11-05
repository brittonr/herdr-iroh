//! Agent-status webhooks.
//!
//! `server.toml` names the URLs and a secret file. The secret is never written
//! to a log. Each POST body is signed with HMAC-SHA256.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const SIGNATURE_HEADER: &str = "X-Herdr-Signature-256";

#[derive(Clone)]
pub struct NotifyConfig {
    pub host: String,
    pub debounce: Duration,
    pub urls: Vec<String>,
    secret: Option<Vec<u8>>,
}

impl std::fmt::Debug for NotifyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyConfig")
            .field("host", &self.host)
            .field("debounce_ms", &self.debounce.as_millis())
            .field("urls", &self.urls.len())
            .field("has_secret", &self.secret.is_some())
            .finish()
    }
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            host: "herdr".to_string(),
            debounce: Duration::from_millis(1500),
            urls: Vec::new(),
            secret: None,
        }
    }
}

impl NotifyConfig {
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.urls.is_empty() && self.secret.is_some()
    }

    #[must_use]
    pub fn sign(&self, body: &[u8]) -> Option<String> {
        self.secret.as_ref().map(|secret| sign_sha256(secret, body))
    }

    #[must_use]
    pub fn urls(&self) -> &[String] {
        &self.urls
    }
}

/// Read a webhook secret. The returned error never includes the file contents.
pub fn load_secret(path: &Path) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| anyhow::anyhow!("webhook secret file is missing or unreadable"))?;
    if meta.file_type().is_symlink() {
        anyhow::bail!("webhook secret file must not be a symlink");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("webhook secret file must not be group or world accessible");
        }
    }
    let bytes =
        std::fs::read(path).map_err(|_| anyhow::anyhow!("webhook secret file is unreadable"))?;
    let text =
        String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("webhook secret must be utf-8"))?;
    let secret = text.trim();
    if secret.is_empty() || secret.len() > 512 {
        anyhow::bail!("webhook secret is empty or too long");
    }
    Ok(secret.as_bytes().to_vec())
}

pub fn config_from_parts(
    host: String,
    debounce_ms: u64,
    urls: Vec<String>,
    secret: Option<Vec<u8>>,
) -> NotifyConfig {
    let debounce_ms = debounce_ms.clamp(0, 60_000);
    NotifyConfig {
        host,
        debounce: Duration::from_millis(debounce_ms),
        urls,
        secret,
    }
}

#[must_use]
pub fn sign_sha256(secret: &[u8], body: &[u8]) -> String {
    let mac = hmac_sha256(secret, body);
    let mut hex = String::with_capacity(mac.len() * 2);
    for byte in mac {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("sha256={hex}")
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0_u8; BLOCK];
    let mut outer = [0_u8; BLOCK];
    for i in 0..BLOCK {
        inner[i] = key_block[i] ^ 0x36;
        outer[i] = key_block[i] ^ 0x5c;
    }
    let mut inner_hash = Sha256::new();
    inner_hash.update(inner);
    inner_hash.update(message);
    let inner_digest = inner_hash.finalize();
    let mut outer_hash = Sha256::new();
    outer_hash.update(outer);
    outer_hash.update(inner_digest);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&outer_hash.finalize());
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusNote {
    pub host: String,
    pub pane_id: String,
    pub agent: Option<String>,
    pub status: String,
    pub cwd: Option<String>,
    pub recap: Option<String>,
}

pub fn payload(note: &StatusNote, previous: Option<&str>) -> Value {
    json!({
        "host": note.host,
        "pane_id": note.pane_id,
        "agent": note.agent,
        "status": note.status,
        "previous_status": previous,
        "cwd": note.cwd,
        "recap": note.recap,
    })
}

#[derive(Debug, Default)]
pub struct Debounce {
    panes: HashMap<String, PaneSlot>,
}

#[derive(Debug)]
struct PaneSlot {
    last_sent: Option<String>,
    pending: Option<String>,
    pending_at: Option<Instant>,
}

impl Debounce {
    pub fn push(&mut self, key: &str, status: &str, now: Instant) {
        let slot = self.panes.entry(key.to_string()).or_insert(PaneSlot {
            last_sent: None,
            pending: None,
            pending_at: None,
        });
        if slot.last_sent.as_deref() == Some(status) && slot.pending.is_none() {
            return;
        }
        if slot.pending.as_deref() != Some(status) {
            slot.pending = Some(status.to_string());
            slot.pending_at = Some(now);
        }
    }

    pub fn due(
        &mut self,
        now: Instant,
        debounce: Duration,
    ) -> Vec<(String, String, Option<String>)> {
        let mut ready = Vec::new();
        for (key, slot) in &mut self.panes {
            let Some(pending) = slot.pending.clone() else {
                continue;
            };
            let Some(at) = slot.pending_at else {
                continue;
            };
            if now.saturating_duration_since(at) < debounce {
                continue;
            }
            slot.pending = None;
            slot.pending_at = None;
            if slot.last_sent.as_deref() == Some(pending.as_str()) {
                continue;
            }
            let previous = slot.last_sent.clone();
            slot.last_sent = Some(pending.clone());
            ready.push((key.clone(), pending, previous));
        }
        ready
    }
}

/// POST one signed body. The secret is not placed on the command line; the
/// signature header is. `curl` is the transport so this crate does not grow an
/// HTTP stack. Tests use [`post_signed`] with a stand-in.
pub fn post_curl(url: &str, body: &[u8], signature: &str) -> Result<(), String> {
    let header = format!("{SIGNATURE_HEADER}: {signature}");
    let mut child = std::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--fail-with-body",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-H",
            &header,
            "--data-binary",
            "@-",
            url,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| "curl is not available for webhook delivery".to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(body);
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "webhook post failed".to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err("webhook post failed".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231_case_1() {
        // RFC 4231 test case 1.
        let key = [0x0b_u8; 20];
        let data = b"Hi There";
        let mac = sign_sha256(&key, data);
        assert_eq!(
            mac,
            "sha256=b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn debounce_keeps_only_the_settled_status() {
        let mut debounce = Debounce::default();
        let start = Instant::now();
        debounce.push("box/w1:p1", "working", start);
        debounce.push("box/w1:p1", "done", start + Duration::from_millis(10));
        assert!(
            debounce
                .due(start + Duration::from_millis(20), Duration::from_millis(50))
                .is_empty()
        );
        let ready = debounce.due(start + Duration::from_millis(80), Duration::from_millis(50));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].1, "done");
        assert_eq!(ready[0].2, None);
        debounce.push("box/w1:p1", "done", start + Duration::from_millis(90));
        assert!(
            debounce
                .due(
                    start + Duration::from_millis(200),
                    Duration::from_millis(50)
                )
                .is_empty()
        );
    }

    #[test]
    fn debug_output_does_not_include_the_secret() {
        let config = config_from_parts(
            "britton-desktop".into(),
            1500,
            vec!["https://example.com/hook".into()],
            Some(b"super-secret-value".to_vec()),
        );
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret-value"), "{rendered}");
        assert!(rendered.contains("has_secret"));
        let body = br#"{"status":"done"}"#;
        let signature = config.sign(body).unwrap();
        assert!(signature.starts_with("sha256="));
        assert!(!signature.contains("super-secret-value"));
    }
}
