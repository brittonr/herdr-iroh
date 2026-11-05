//! Herdr's socket API, as carried on one iroh bi-stream.
//!
//! One request line goes client to server. Herdr's response lines come back
//! in order. `events.subscribe` keeps the herdr socket open, so those later
//! lines are forwarded on the same stream. Nothing here interprets pane text.

use anyhow::{anyhow, bail};
use serde_json::{Value, json};

/// ALPN for the herdr API relay. Same `/onix/<name>/1` shape as iroh-news.
pub const ALPN: &[u8] = b"/onix/herdr-api/1";

/// Largest accepted request line. Prompts are JSON strings, so this is the
/// encoded size, not the visible text size.
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// Largest response line forwarded to a peer. Local herdr is trusted, but a
/// pane read can still be enormous.
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// A herdr request reduced to the fields the relay is allowed to look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMeta {
    pub id: String,
    pub method: String,
}

/// Pull `id` and `method` out of one request line.
///
/// # Errors
///
/// Returns an error when the line is not a JSON object, the method is missing,
/// or the method is not a herdr-style name. The error text never includes the
/// line, so a rejected prompt cannot land in a log by accident.
pub fn request_meta(line: &str) -> Result<RequestMeta, RequestParseError> {
    let value: Value = match serde_json::from_str(line.trim()) {
        Ok(value) => value,
        Err(_) => return Err(RequestParseError::InvalidJson),
    };
    let Some(obj) = value.as_object() else {
        return Err(RequestParseError::InvalidJson);
    };
    let id = match obj.get("id") {
        Some(Value::String(id)) if id.len() <= 256 && !id.contains(['\n', '\r']) => id.clone(),
        Some(Value::String(_)) => return Err(RequestParseError::BadId),
        _ => String::new(),
    };
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return Err(RequestParseError::MissingMethod { id });
    };
    if !valid_method_name(method) {
        return Err(RequestParseError::BadMethod { id });
    }
    Ok(RequestMeta {
        id,
        method: method.to_string(),
    })
}

/// Herdr method names are lowercase dotted words: `ping`, `agent.list`,
/// `pane.wait_for_output`.
#[must_use]
pub fn valid_method_name(method: &str) -> bool {
    if method.is_empty() || method.len() > 128 {
        return false;
    }
    method.split('.').all(valid_method_part)
}

fn valid_method_part(part: &str) -> bool {
    let mut chars = part.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Encode one herdr request as a single JSON line, including the newline.
///
/// # Errors
///
/// Returns an error when the encoded line exceeds [`MAX_REQUEST_BYTES`].
pub fn encode_request(value: &Value) -> anyhow::Result<String> {
    let mut line = serde_json::to_string(value)?;
    if line.contains('\n') || line.contains('\r') {
        bail!("refusing to send a herdr request that is not one line");
    }
    line.push('\n');
    if line.len() > MAX_REQUEST_BYTES {
        bail!(
            "herdr request is {} bytes; the maximum is {MAX_REQUEST_BYTES}",
            line.len()
        );
    }
    Ok(line)
}

/// Herdr-shaped error line. `message` must already be free of pane contents.
#[must_use]
pub fn error_line(id: &str, code: &str, message: &str) -> String {
    let value = json!({
        "id": id,
        "error": { "code": code, "message": message }
    });
    format!("{value}\n")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestParseError {
    InvalidJson,
    BadId,
    MissingMethod { id: String },
    BadMethod { id: String },
}

impl RequestParseError {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::MissingMethod { id } | Self::BadMethod { id } => id,
            Self::InvalidJson | Self::BadId => "",
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        "invalid_request"
    }

    #[must_use]
    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidJson | Self::BadId => "request must be one JSON object",
            Self::MissingMethod { .. } => "request is missing a method string",
            Self::BadMethod { .. } => "method name is not allowed on this relay",
        }
    }
}

impl std::fmt::Display for RequestParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for RequestParseError {}

/// Build a herdr request value with a fresh id.
#[must_use]
pub fn request_value(method: &str, params: Value) -> Value {
    json!({
        "id": next_request_id(),
        "method": method,
        "params": params,
    })
}

fn next_request_id() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("hio-{n}")
}

/// JSON value error used when a line cannot be parsed on the client.
pub fn parse_response_line(bytes: &[u8]) -> anyhow::Result<Value> {
    let text = std::str::from_utf8(bytes).map_err(|_| anyhow!("herdr response is not utf-8"))?;
    serde_json::from_str(text.trim()).map_err(|_| anyhow!("herdr response is not json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_method_without_keeping_params_in_the_meta() {
        let meta =
            request_meta(r#"{"id":"req_1","method":"pane.read","params":{"text":"secret pane"}}"#)
                .unwrap();
        assert_eq!(meta.id, "req_1");
        assert_eq!(meta.method, "pane.read");
        let rendered = format!("{meta:?}");
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn rejects_odd_method_names() {
        assert!(valid_method_name("ping"));
        assert!(valid_method_name("server.live_handoff"));
        assert!(valid_method_name("client_shell.surface.set"));
        assert!(!valid_method_name(""));
        assert!(!valid_method_name("Server.stop"));
        assert!(!valid_method_name("pane read"));
        assert!(!valid_method_name("pane.*"));
        assert!(!valid_method_name(".ping"));
        assert!(request_meta(r#"{"id":"1","method":"server.stop\n"}"#).is_err());
    }

    #[test]
    fn encode_is_one_line() {
        let line = encode_request(&request_value(
            "agent.prompt",
            json!({"target": "w1:p1", "text": "line\nbreak"}),
        ))
        .unwrap();
        assert_eq!(line.lines().count(), 1);
        assert!(line.contains("line\\nbreak"));
        assert!(line.ends_with('\n'));
    }
}
