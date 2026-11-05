//! Saved-machine gateway.
//!
//! Herdr keeps SSH machines in the client catalog, not in the server socket.
//! `herdr --machine` forwards a JSON API call over SSH to
//! `herdr --session <session> remote-api-bridge`, which copies that payload
//! onto the machine's socket. The payload stays on a side channel (fd 3). It
//! is not interpolated into the shell command.
//!
//! Enumeration runs `herdr machine list --json`. A forwarded call uses the
//! same noninteractive bridge. This module does not write the catalog, read
//! SSH keys, or send the SSH target to a peer.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use iroh::EndpointId;
use serde::Serialize;
use serde_json::Value;

use crate::policy::{Allowlist, Decision, DenyReason, is_always_denied};
use crate::protocol::MAX_RESPONSE_BYTES;

const READY_MARKER: &str = "herdr-remote-output-ready:1";
const LIST_TIMEOUT: Duration = Duration::from_secs(15);
const PROFILE_ID_LEN: usize = 32;
const MAX_LABEL_BYTES: usize = 128;
const MAX_TARGET_BYTES: usize = 1024;
const MAX_SESSION_LEN: usize = 64;
const MAX_STDERR_BYTES: usize = 2 * 1024;
const MAX_METADATA_BYTES: u64 = 16 * 1024;

/// One saved machine a peer is allowed to see.
///
/// The SSH target and the remote session stay on the gateway host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SavedMachine {
    pub id: String,
    pub label: String,
    pub enabled: bool,
    /// Set only when it is known without opening SSH. Disabled machines are
    /// not reachable. Enabled machines are probed by the caller, if at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
}

/// Failure of a catalog read or a forwarded call.
///
/// `message` is safe to return to a remote peer: it does not include the SSH
/// target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineError {
    pub code: &'static str,
    pub message: String,
}

impl MachineError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for MachineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MachineError {}

/// How `serve` reads the host's saved machines and forwards one API call.
///
/// `on_line` is invoked for each response line, including its trailing
/// newline. Return `false` when the peer is gone; the bridge must stop.
pub trait MachineBackend: Send + Sync {
    /// # Errors
    ///
    /// Returns an error when the catalog cannot be read.
    fn list(&self) -> Result<Vec<SavedMachine>, MachineError>;

    /// # Errors
    ///
    /// Returns an error when the machine cannot be resolved or the bridge
    /// fails before a response line.
    fn forward(
        &self,
        selector: &str,
        request_line: &[u8],
        cancel: &AtomicBool,
        on_line: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(), MachineError>;
}

/// Backend used when a caller has no catalog. `serve` also checks the gateway
/// flag before it calls this.
#[derive(Debug, Default)]
pub struct InactiveGateway;

impl MachineBackend for InactiveGateway {
    fn list(&self) -> Result<Vec<SavedMachine>, MachineError> {
        Ok(Vec::new())
    }

    fn forward(
        &self,
        _selector: &str,
        _request_line: &[u8],
        _cancel: &AtomicBool,
        _on_line: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(), MachineError> {
        Err(MachineError::new(
            "gateway_disabled",
            "saved-machine gateway is off",
        ))
    }
}

/// Host `herdr` binary and `ssh`.
pub struct CliMachines {
    herdr: PathBuf,
    ssh: PathBuf,
    /// When set, herdr's state directory is `<root>/herdr` instead of the
    /// process owner's XDG state dir. Tests use this.
    state_root: Option<PathBuf>,
}

impl CliMachines {
    #[must_use]
    pub fn new(herdr: impl Into<PathBuf>) -> Self {
        Self {
            herdr: herdr.into(),
            ssh: PathBuf::from("ssh"),
            state_root: None,
        }
    }

    #[cfg(test)]
    fn for_test(herdr: PathBuf, ssh: PathBuf, state_root: PathBuf) -> Self {
        Self {
            herdr,
            ssh,
            state_root: Some(state_root),
        }
    }

    fn run_herdr(&self, args: &[&str]) -> Result<std::process::Output, MachineError> {
        let mut child = Command::new(&self.herdr)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| {
                MachineError::new(
                    "gateway_unavailable",
                    "herdr CLI is not available on this host",
                )
            })?;
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    return child
                        .wait_with_output()
                        .map_err(|_| MachineError::new("gateway_unavailable", "herdr CLI failed"));
                }
                Ok(None) if started.elapsed() > LIST_TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(MachineError::new(
                        "gateway_unavailable",
                        "herdr machine list timed out",
                    ));
                }
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => {
                    let _ = child.kill();
                    return Err(MachineError::new("gateway_unavailable", "herdr CLI failed"));
                }
            }
        }
    }

    fn load_catalog(&self) -> Result<Vec<CatalogMachine>, MachineError> {
        let output = self.run_herdr(&["machine", "list", "--json"])?;
        if !output.status.success() {
            return Err(MachineError::new(
                "gateway_unavailable",
                "herdr machine list failed",
            ));
        }
        let stdout = String::from_utf8(output.stdout).map_err(|_| {
            MachineError::new(
                "gateway_unavailable",
                "herdr machine list did not return a machine catalog",
            )
        })?;
        parse_catalog(&stdout)
    }

    fn remote_executable(&self, profile: &CatalogMachine) -> Result<String, MachineError> {
        match read_cached_executable(
            &self.state_dirs(),
            &profile.id,
            &profile.target,
            &profile.session,
        ) {
            CacheHit::Windows => Err(MachineError::new(
                "gateway_unavailable",
                format!(
                    "machine '{}' uses a Windows SSH target; this gateway forwards through the POSIX API bridge",
                    profile.label
                ),
            )),
            CacheHit::Posix(path) => Ok(path),
            CacheHit::Miss => Ok("herdr".to_string()),
        }
    }

    fn state_dirs(&self) -> Vec<PathBuf> {
        let Some(root) = self.state_root.clone().or_else(default_state_root) else {
            return Vec::new();
        };
        vec![root.join("herdr"), root.join("herdr-dev")]
    }
}

impl MachineBackend for CliMachines {
    fn list(&self) -> Result<Vec<SavedMachine>, MachineError> {
        Ok(self
            .load_catalog()?
            .iter()
            .map(CatalogMachine::to_saved)
            .collect())
    }

    fn forward(
        &self,
        selector: &str,
        request_line: &[u8],
        cancel: &AtomicBool,
        on_line: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(), MachineError> {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        let catalog = self.load_catalog()?;
        let profile = select_profile(&catalog, selector)?;
        let executable = self.remote_executable(profile)?;
        let remote = posix_bridge_command(&executable, &profile.session);
        let args = ssh_args(&profile.target, &remote);
        ssh_forward(
            &self.ssh,
            &profile.target,
            &args,
            request_line,
            cancel,
            on_line,
        )
    }
}

/// Why a forwarded method is refused before any SSH connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForwardBlock {
    Policy(DenyReason),
    /// Catalog edits, install, update, replace, handoff, or agent registration.
    Refused(&'static str),
}

impl ForwardBlock {
    #[must_use]
    pub(crate) fn code(self) -> &'static str {
        "forbidden"
    }

    #[must_use]
    pub(crate) fn message(self, method: &str) -> String {
        match self {
            Self::Policy(reason) => Decision::Denied(reason).message(method),
            Self::Refused(message) => message.to_string(),
        }
    }
}

/// Inner call carried by `gateway.forward`.
pub(crate) struct ForwardRequest {
    pub machine: String,
    pub method: String,
    pub params: Value,
}

/// Pull the saved-machine selector and the inner herdr call out of one request.
///
/// # Errors
///
/// Returns an error when `params` is not an object or the inner method name is
/// not a herdr method. The error does not include the request body.
pub(crate) fn parse_forward(text: &str) -> Result<ForwardRequest, MachineError> {
    let value: Value = serde_json::from_str(text)
        .map_err(|_| MachineError::new("invalid_request", "request must be one JSON object"))?;
    let params = match value.get("params") {
        None => serde_json::Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => {
            return Err(MachineError::new(
                "invalid_request",
                "params must be a JSON object",
            ));
        }
    };
    let machine = params
        .get("machine")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let method = params
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if !crate::protocol::valid_method_name(&method) {
        return Err(MachineError::new(
            "invalid_request",
            "method name is not allowed on this relay",
        ));
    }
    let inner = match params.get("params") {
        None => Value::Object(serde_json::Map::new()),
        Some(Value::Object(map)) => Value::Object(map.clone()),
        Some(_) => {
            return Err(MachineError::new(
                "invalid_request",
                "forwarded params must be a JSON object",
            ));
        }
    };
    Ok(ForwardRequest {
        machine,
        method,
        params: inner,
    })
}

/// Allowlist check plus the gateway denylist.
///
/// Always-denied server methods keep the same message as a local relay.
pub(crate) fn screen_forward(
    allow: &Allowlist,
    peer: &EndpointId,
    method: &str,
) -> Result<(), ForwardBlock> {
    if is_always_denied(method) {
        return Err(ForwardBlock::Policy(DenyReason::AlwaysDenied));
    }
    if let Some(message) = extra_block(method) {
        return Err(ForwardBlock::Refused(message));
    }
    match allow.decide(peer, method) {
        Decision::Allow => Ok(()),
        Decision::Denied(reason) => Err(ForwardBlock::Policy(reason)),
    }
}

fn extra_block(method: &str) -> Option<&'static str> {
    if method == "machine" || method.starts_with("machine.") {
        return Some("saved-machine catalog changes are not forwarded");
    }
    if method == "gateway" || method.starts_with("gateway.") {
        return Some("gateway methods are not forwarded to a saved machine");
    }
    const EXACT: &[&str] = &[
        "integration.install",
        "integration.uninstall",
        "plugin.install",
        "plugin.update",
        "plugin.uninstall",
        "server.install",
        "server.update",
        "server.replace",
        "server.handoff",
        "server.ssh_agent.register",
    ];
    if EXACT.contains(&method)
        || method.starts_with("server.update.")
        || method.starts_with("server.install.")
        || method.starts_with("server.replace.")
        || method.starts_with("server.handoff.")
    {
        return Some("installing, updating, replacing, or handing off a server is not forwarded");
    }
    None
}

/// Pick the `host` string for one saved machine.
///
/// A unique label is used. An ambiguous label, or a label that equals another
/// profile id, uses the profile id. Herdr resolves an id before a label.
#[must_use]
pub fn machine_route_key(machine: &SavedMachine, all: &[SavedMachine]) -> String {
    let label_unique = all
        .iter()
        .filter(|other| other.label == machine.label)
        .count()
        == 1;
    let collides_with_id = all
        .iter()
        .any(|other| other.id == machine.label && other.id != machine.id);
    let label_ok = label_unique
        && !collides_with_id
        && !machine.label.is_empty()
        && !machine.label.chars().any(char::is_control);
    if label_ok {
        machine.label.clone()
    } else {
        machine.id.clone()
    }
}

/// Resolve `selector` the way `herdr --machine` does.
pub(crate) fn select_saved<'a>(
    machines: &'a [SavedMachine],
    selector: &str,
) -> Result<&'a SavedMachine, MachineError> {
    select_by(
        machines,
        selector,
        |machine| machine.id.as_str(),
        |machine| machine.label.as_str(),
        |machine| machine.enabled,
    )
}

struct CatalogMachine {
    id: String,
    label: String,
    enabled: bool,
    target: String,
    session: String,
}

impl CatalogMachine {
    fn to_saved(&self) -> SavedMachine {
        SavedMachine {
            id: self.id.clone(),
            label: self.label.clone(),
            enabled: self.enabled,
            reachable: if self.enabled { None } else { Some(false) },
        }
    }
}

impl std::fmt::Debug for CatalogMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CatalogMachine")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("enabled", &self.enabled)
            .field("session", &self.session)
            .finish()
    }
}

fn select_profile<'a>(
    machines: &'a [CatalogMachine],
    selector: &str,
) -> Result<&'a CatalogMachine, MachineError> {
    select_by(
        machines,
        selector,
        |machine| machine.id.as_str(),
        |machine| machine.label.as_str(),
        |machine| machine.enabled,
    )
}

fn select_by<'a, T>(
    machines: &'a [T],
    selector: &str,
    id: impl Fn(&T) -> &str,
    label: impl Fn(&T) -> &str,
    enabled: impl Fn(&T) -> bool,
) -> Result<&'a T, MachineError> {
    if selector.is_empty()
        || selector.len() > 256
        || selector.starts_with('-')
        || selector.chars().any(char::is_control)
        || selector.trim().is_empty()
    {
        return Err(MachineError::new(
            "invalid_request",
            "machine must be a saved label or profile id",
        ));
    }
    let machine = if let Some(machine) = machines.iter().find(|machine| id(machine) == selector) {
        machine
    } else {
        let mut matches = machines.iter().filter(|machine| label(machine) == selector);
        let Some(machine) = matches.next() else {
            return Err(MachineError::new(
                "not_found",
                format!("unknown machine '{selector}'"),
            ));
        };
        if matches.next().is_some() {
            return Err(MachineError::new(
                "ambiguous",
                format!("machine label '{selector}' is ambiguous; use its profile id"),
            ));
        }
        machine
    };
    if !enabled(machine) {
        return Err(MachineError::new(
            "forbidden",
            format!("machine '{}' is disabled", label(machine)),
        ));
    }
    Ok(machine)
}

fn parse_catalog(stdout: &str) -> Result<Vec<CatalogMachine>, MachineError> {
    let value: Value = serde_json::from_str(stdout.trim()).map_err(|_| {
        MachineError::new(
            "gateway_unavailable",
            "herdr machine list did not return a machine catalog",
        )
    })?;
    let Some(rows) = value.as_array() else {
        return Err(MachineError::new(
            "gateway_unavailable",
            "herdr machine list did not return a machine catalog",
        ));
    };
    let mut machines = Vec::with_capacity(rows.len());
    for row in rows {
        machines.push(parse_row(row)?);
    }
    Ok(machines)
}

fn parse_row(row: &Value) -> Result<CatalogMachine, MachineError> {
    let unusable = || {
        MachineError::new(
            "gateway_unavailable",
            "herdr machine list returned an unusable profile",
        )
    };
    let Some(obj) = row.as_object() else {
        return Err(unusable());
    };
    let id = obj.get("id").and_then(Value::as_str).unwrap_or("");
    let label = obj.get("label").and_then(Value::as_str).unwrap_or("");
    let target = obj.get("target").and_then(Value::as_str).unwrap_or("");
    let session = obj.get("session").and_then(Value::as_str).unwrap_or("");
    let Some(enabled) = obj.get("enabled").and_then(Value::as_bool) else {
        return Err(unusable());
    };
    if !valid_profile_id(id)
        || !valid_label(label)
        || !valid_target(target)
        || !valid_session(session)
    {
        return Err(unusable());
    }
    Ok(CatalogMachine {
        id: id.to_string(),
        label: label.to_string(),
        enabled,
        target: target.to_string(),
        session: session.to_string(),
    })
}

fn valid_profile_id(id: &str) -> bool {
    id.len() == PROFILE_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= MAX_LABEL_BYTES && !label.chars().any(char::is_control)
}

fn valid_target(target: &str) -> bool {
    !target.is_empty()
        && target.len() <= MAX_TARGET_BYTES
        && !target.starts_with('-')
        && !target.chars().any(char::is_control)
}

fn valid_session(session: &str) -> bool {
    !session.is_empty()
        && session.len() <= MAX_SESSION_LEN
        && session != "."
        && session != ".."
        && session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_posix_executable(path: &str) -> bool {
    if path == "herdr" {
        return true;
    }
    !path.is_empty()
        && path.len() <= 4096
        && path.starts_with('/')
        && !path.ends_with("/mise/shims/herdr")
        && !path.chars().any(char::is_control)
}

enum CacheHit {
    Miss,
    Posix(String),
    Windows,
}

fn read_cached_executable(dirs: &[PathBuf], id: &str, target: &str, session: &str) -> CacheHit {
    if !valid_profile_id(id) {
        return CacheHit::Miss;
    }
    for dir in dirs {
        let path = dir.join("client/ssh-metadata").join(format!("{id}.json"));
        match read_one_cache(&path, target, session) {
            CacheHit::Miss => {}
            other => return other,
        }
    }
    CacheHit::Miss
}

fn read_one_cache(path: &Path, target: &str, session: &str) -> CacheHit {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return CacheHit::Miss;
    };
    if !meta.file_type().is_file() || meta.len() > MAX_METADATA_BYTES {
        return CacheHit::Miss;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return CacheHit::Miss;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return CacheHit::Miss;
    };
    if value.get("version").and_then(Value::as_u64) != Some(1) {
        return CacheHit::Miss;
    }
    if value.get("target").and_then(Value::as_str) != Some(target) {
        return CacheHit::Miss;
    }
    if value.get("session").and_then(Value::as_str) != Some(session) {
        return CacheHit::Miss;
    }
    let Some(os) = value
        .get("metadata")
        .and_then(|metadata| metadata.get("os"))
        .and_then(Value::as_str)
    else {
        return CacheHit::Miss;
    };
    let Some(executable) = value
        .get("metadata")
        .and_then(|metadata| metadata.get("executable"))
        .and_then(Value::as_str)
    else {
        return CacheHit::Miss;
    };
    if os == "windows" {
        return CacheHit::Windows;
    }
    if (os == "linux" || os == "macos") && valid_posix_executable(executable) {
        return CacheHit::Posix(executable.to_string());
    }
    CacheHit::Miss
}

fn default_state_root() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME").filter(|dir| !dir.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").filter(|dir| !dir.is_empty())?;
    Some(PathBuf::from(home).join(".local/state"))
}

/// SSH argv for one API bridge. The request body is not an argument.
fn ssh_args(target: &str, remote_command: &str) -> Vec<String> {
    vec![
        "-C".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "NumberOfPasswordPrompts=0".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-o".to_string(),
        "ConnectionAttempts=1".to_string(),
        "-o".to_string(),
        "ServerAliveInterval=15".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=4".to_string(),
        "-o".to_string(),
        "ForwardAgent=no".to_string(),
        "-o".to_string(),
        "ClearAllForwardings=yes".to_string(),
        "-T".to_string(),
        target.to_string(),
        remote_command.to_string(),
    ]
}

/// Remote command herdr uses for a cached POSIX API bridge.
///
/// The script is base64 so a login shell cannot expand it. The API payload
/// arrives on stdin, is saved on fd 3, and is what `remote-api-bridge` reads.
fn posix_bridge_command(executable: &str, session: &str) -> String {
    let exe = shell_quote(executable);
    let session = shell_quote(session);
    let script = format!(
        "set -f\nif capability=$({exe} --session {session} remote-api-bridge --check </dev/null 2>/dev/null) && [ \"$capability\" = herdr-api-bridge-v1 ]; then\nprintf '\\n%s\\n' '{READY_MARKER}'\nexec {exe} --session {session} remote-api-bridge <&3\nelse\nprintf '%s\\n' 'remote Herdr does not support machine API forwarding; update Herdr on this machine' >&2\nexit 78\nfi\n"
    );
    let encoded = base64_encode(script.as_bytes());
    format!(
        "/bin/sh -c 'exec 3<&0; echo {encoded} | (base64 --decode 2>/dev/null || base64 -d 2>/dev/null || base64 -D 2>/dev/null) | /bin/sh -s'"
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= data.len() {
        let chunk =
            ((data[index] as u32) << 16) | ((data[index + 1] as u32) << 8) | data[index + 2] as u32;
        out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 6) & 63) as usize] as char);
        out.push(TABLE[(chunk & 63) as usize] as char);
        index += 3;
    }
    match data.len() - index {
        1 => {
            let chunk = (data[index] as u32) << 16;
            out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
            out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let chunk = ((data[index] as u32) << 16) | ((data[index + 1] as u32) << 8);
            out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
            out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
            out.push(TABLE[((chunk >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

fn ssh_forward(
    ssh: &Path,
    target: &str,
    args: &[String],
    request_line: &[u8],
    cancel: &AtomicBool,
    on_line: &mut dyn FnMut(&[u8]) -> bool,
) -> Result<(), MachineError> {
    let mut command = Command::new(ssh);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| {
        MachineError::new("gateway_unavailable", "ssh is not available on this host")
    })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| MachineError::new("gateway_unavailable", "ssh bridge stdin is missing"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| MachineError::new("gateway_unavailable", "ssh bridge stdout is missing"))?;
    let stderr = child.stderr.take();
    let stderr_task = stderr.map(|pipe| thread::spawn(move || read_capped(pipe, MAX_STDERR_BYTES)));
    let wrote = stdin.write_all(request_line);
    drop(stdin);
    if wrote.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(bridge_failure("", target));
    }

    let child = Arc::new(Mutex::new(Some(child)));
    let stop = AtomicBool::new(false);
    let read = thread::scope(|scope| {
        scope.spawn(|| watch_child(Arc::clone(&child), &stop, cancel));
        let read = read_bridge_stdout(stdout, on_line);
        stop.store(true, Ordering::Release);
        read
    });
    let stderr_text = stderr_task
        .map(|task| task.join().unwrap_or_default())
        .unwrap_or_default();
    reap_child(&child);
    match read {
        Ok(count) if count > 0 => Ok(()),
        Ok(_) => Err(bridge_failure(&stderr_text, target)),
        Err(error) if stderr_text.trim().is_empty() => Err(error),
        Err(_) => Err(bridge_failure(&stderr_text, target)),
    }
}

fn watch_child(
    child: Arc<Mutex<Option<std::process::Child>>>,
    stop: &AtomicBool,
    cancel: &AtomicBool,
) {
    loop {
        if cancel.load(Ordering::Acquire) || stop.load(Ordering::Acquire) {
            if let Some(mut child) = child
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let _ = child.kill();
                let _ = child.wait();
            }
            return;
        }
        let mut guard = child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(child) = guard.as_mut() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                guard.take();
                return;
            }
            Ok(None) => {}
            Err(_) => {
                guard.take();
                return;
            }
        }
        drop(guard);
        thread::sleep(Duration::from_millis(50));
    }
}

fn reap_child(child: &Mutex<Option<std::process::Child>>) {
    if let Some(mut child) = child
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        let _ = child.wait();
    }
}

/// Read response lines that follow herdr's banner marker.
///
/// Returns the number of lines delivered.
fn read_bridge_stdout(
    stdout: impl Read,
    on_line: &mut dyn FnMut(&[u8]) -> bool,
) -> Result<usize, MachineError> {
    let mut reader = BufReader::new(stdout);
    let mut saw_marker = false;
    let mut delivered = 0;
    loop {
        let line = read_line_capped(&mut reader, MAX_RESPONSE_BYTES).map_err(|_| {
            MachineError::new("bad_response", "saved machine response line is too large")
        })?;
        let Some(line) = line else {
            break;
        };
        if !saw_marker {
            if line_text(&line) == READY_MARKER {
                saw_marker = true;
            }
            continue;
        }
        if line_text(&line).is_empty() {
            continue;
        }
        delivered += 1;
        if !on_line(&line) {
            break;
        }
    }
    if !saw_marker {
        return Err(MachineError::new(
            "bad_response",
            "saved machine API bridge produced no response",
        ));
    }
    Ok(delivered)
}

fn line_text(line: &[u8]) -> &str {
    std::str::from_utf8(line)
        .unwrap_or("")
        .trim_end_matches(['\n', '\r'])
}

fn read_line_capped(reader: &mut impl BufRead, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            return Ok(Some(buf));
        }
        if let Some(pos) = available.iter().position(|byte| *byte == b'\n') {
            let take = pos + 1;
            if buf.len().saturating_add(take) > max {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("line exceeds {max} bytes"),
                ));
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            return Ok(Some(buf));
        }
        if buf.len().saturating_add(available.len()) > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("line exceeds {max} bytes"),
            ));
        }
        let len = available.len();
        buf.extend_from_slice(available);
        reader.consume(len);
    }
}

fn read_capped(mut reader: impl Read, max: usize) -> String {
    let mut capped = Vec::new();
    let mut buf = [0_u8; 1024];
    while let Ok(count) = reader.read(&mut buf) {
        if count == 0 {
            break;
        }
        if capped.len() < max {
            let take = (max - capped.len()).min(count);
            capped.extend_from_slice(&buf[..take]);
        }
    }
    String::from_utf8_lossy(&capped).into_owned()
}

fn bridge_failure(stderr: &str, target: &str) -> MachineError {
    let scrubbed = scrub_peer_text(stderr, target);
    let detail = scrubbed.trim();
    let message = if detail.is_empty() {
        "saved machine API bridge failed".to_string()
    } else {
        format!("saved machine API bridge failed: {detail}")
    };
    MachineError::new("gateway_unavailable", message)
}

fn scrub_peer_text(text: &str, target: &str) -> String {
    let mut cleaned = if target.is_empty() {
        text.to_string()
    } else {
        text.replace(target, "[redacted]")
    };
    cleaned.retain(|ch| ch == '\n' || ch == '\t' || !ch.is_control());
    if cleaned.len() > 300 {
        cleaned.truncate(300);
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{MethodsField, PeerConfig};
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const OTHER: &str = "fedcba9876543210fedcba9876543210";
    const TARGET: &str = "secret-host.example";

    fn catalog_json(enabled: bool) -> String {
        format!(
            r#"[{{"id":"{ID}","label":"instant-fill","target":"{TARGET}","session":"fleet","enabled":{enabled},"selected":false}}]"#
        )
    }

    fn saved(id: &str, label: &str, enabled: bool) -> SavedMachine {
        SavedMachine {
            id: id.to_string(),
            label: label.to_string(),
            enabled,
            reachable: if enabled { None } else { Some(false) },
        }
    }

    fn allow(methods: &[&str]) -> (Allowlist, EndpointId) {
        let secret = iroh::SecretKey::from_bytes(&[9; 32]);
        let endpoint = secret.public();
        let mut peers = BTreeMap::new();
        let field = if methods == ["full"] {
            MethodsField::Word("full".into())
        } else {
            MethodsField::List(methods.iter().map(|method| (*method).to_string()).collect())
        };
        peers.insert(
            "bot".to_string(),
            PeerConfig {
                endpoint_id: endpoint.to_string(),
                methods: Some(field),
            },
        );
        (Allowlist::try_from_config(&peers).unwrap(), endpoint)
    }

    fn write_exe(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn public_list_drops_the_ssh_target_and_session() {
        let machines = parse_catalog(&catalog_json(true)).unwrap();
        let public: Vec<_> = machines.iter().map(CatalogMachine::to_saved).collect();
        let text = serde_json::to_string(&public).unwrap();
        assert!(text.contains("instant-fill"), "{text}");
        assert!(!text.contains(TARGET), "{text}");
        assert!(!text.contains("fleet"), "{text}");
        assert!(public[0].reachable.is_none());
        let disabled = parse_catalog(&catalog_json(false)).unwrap();
        assert_eq!(disabled[0].to_saved().reachable, Some(false));
        let rendered = format!("{:?}", machines[0]);
        assert!(!rendered.contains(TARGET), "{rendered}");
    }

    #[test]
    fn catalog_failures_do_not_echo_the_target() {
        let err = parse_catalog(&format!(
            r#"[{{"id":"nope","label":"x","target":"{TARGET}"}}]"#
        ))
        .unwrap_err();
        assert!(!err.message.contains(TARGET), "{}", err.message);
        assert_eq!(err.code, "gateway_unavailable");
    }

    #[test]
    fn selector_matches_herdr_rules() {
        let machines = vec![
            saved(ID, "instant-fill", true),
            saved(OTHER, "other", false),
        ];
        assert_eq!(select_saved(&machines, "instant-fill").unwrap().id, ID);
        assert_eq!(select_saved(&machines, ID).unwrap().label, "instant-fill");
        let disabled = select_saved(&machines, "other").unwrap_err();
        assert_eq!(disabled.code, "forbidden");
        assert!(select_saved(&machines, "missing").is_err());
        let ambiguous = vec![saved(ID, "same", true), saved(OTHER, "same", true)];
        assert_eq!(
            select_saved(&ambiguous, "same").unwrap_err().code,
            "ambiguous"
        );
        assert_eq!(select_saved(&ambiguous, OTHER).unwrap().id, OTHER);
        assert!(select_saved(&machines, "-instant-fill").is_err());
    }

    #[test]
    fn route_key_uses_a_unique_label_otherwise_the_id() {
        let unique = vec![saved(ID, "instant-fill", true)];
        assert_eq!(machine_route_key(&unique[0], &unique), "instant-fill");
        let ambiguous = vec![saved(ID, "same", true), saved(OTHER, "same", true)];
        assert_eq!(machine_route_key(&ambiguous[0], &ambiguous), ID);
        let mut colliding = vec![saved(ID, OTHER, true), saved(OTHER, "plain", true)];
        colliding[0].reachable = None;
        assert_eq!(machine_route_key(&colliding[0], &colliding), ID);
    }

    #[test]
    fn screen_blocks_stop_handoff_catalog_and_installs() {
        let (full, peer) = allow(&["full"]);
        assert!(screen_forward(&full, &peer, "agent.list").is_ok());
        assert!(screen_forward(&full, &peer, "server.reload_config").is_ok());
        assert!(screen_forward(&full, &peer, "plugin.enable").is_ok());
        for method in [
            "server.stop",
            "server.live_handoff",
            "server.stop.now",
            "machine.remove",
            "machine.add",
            "machine.rename",
            "machine.enable",
            "machine.disable",
            "integration.install",
            "plugin.update",
            "server.ssh_agent.register",
            "gateway.forward",
        ] {
            let err = screen_forward(&full, &peer, method).unwrap_err();
            let message = err.message(method);
            assert!(!message.is_empty(), "{method}");
            if is_always_denied(method) {
                assert!(message.contains("denied to every remote peer"), "{message}");
            }
        }
        let (narrow, peer) = allow(&["pane.read"]);
        assert!(screen_forward(&narrow, &peer, "pane.read").is_ok());
        assert_eq!(
            screen_forward(&narrow, &peer, "agent.list"),
            Err(ForwardBlock::Policy(DenyReason::MethodNotAllowed))
        );
        let stranger = iroh::SecretKey::from_bytes(&[3; 32]).public();
        assert_eq!(
            screen_forward(&full, &stranger, "ping"),
            Err(ForwardBlock::Policy(DenyReason::NotOnAllowlist))
        );
    }

    #[test]
    fn bridge_command_keeps_the_payload_and_the_target_out_of_the_shell_text() {
        let command = posix_bridge_command("/opt/herdr", "fleet");
        assert!(!command.contains('$'), "{command}");
        assert!(!command.contains('`'), "{command}");
        assert!(!command.contains('"'), "{command}");
        assert!(!command.contains("secret-pane"), "{command}");
        assert!(!command.contains(TARGET), "{command}");
        let encoded = command.split_whitespace().nth(5).unwrap();
        let script = String::from_utf8(base64_decode(encoded)).unwrap();
        assert!(script.contains("remote-api-bridge <&3"), "{script}");
        assert!(script.contains("herdr-api-bridge-v1"), "{script}");
        assert!(script.contains("/opt/herdr"), "{script}");
        assert!(script.contains(READY_MARKER), "{script}");
        assert!(!script.contains("secret-pane"), "{script}");
        assert!(!script.contains(TARGET), "{script}");
        let args = ssh_args(TARGET, &command);
        let joined = args.join("\n");
        assert!(joined.contains("BatchMode=yes"));
        assert!(joined.contains("StrictHostKeyChecking=yes"));
        assert!(joined.contains("ForwardAgent=no"));
        assert!(joined.contains("ClearAllForwardings=yes"));
        assert!(!joined.contains("IdentityFile"));
        assert!(!joined.contains("secret-pane"));
    }

    #[test]
    fn cli_lists_without_the_target_and_forwards_the_raw_request_on_stdin() {
        let dir = tempfile::tempdir().unwrap();
        let list = catalog_json(true);
        let herdr = write_exe(
            dir.path(),
            "herdr",
            &format!("#!/bin/sh\nprintf '%s\\n' '{list}'\n"),
        );
        let ssh = write_exe(
            dir.path(),
            "ssh",
            &format!(
                "#!/bin/sh\n: > '{}/ssh-args'\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\" >> '{}/ssh-args'; done\ncat > '{}/ssh-stdin'\nprintf '\\n%s\\n' '{READY_MARKER}'\nprintf '%s\\n' '{{\"id\":\"1\",\"result\":{{\"type\":\"pong\"}}}}'\n",
                dir.path().display(),
                dir.path().display(),
                dir.path().display(),
            ),
        );
        let cli = CliMachines::for_test(herdr, ssh, dir.path().join("empty-state"));
        let listed = cli.list().unwrap();
        let text = serde_json::to_string(&listed).unwrap();
        assert!(!text.contains(TARGET), "{text}");
        assert_eq!(listed[0].label, "instant-fill");

        let request =
            b"{\"id\":\"1\",\"method\":\"pane.read\",\"params\":{\"text\":\"secret-pane\"}}\n";
        let mut lines = Vec::new();
        cli.forward(ID, request, &AtomicBool::new(false), &mut |line| {
            lines.push(line.to_vec());
            true
        })
        .unwrap();
        assert_eq!(lines.len(), 1);
        assert!(std::str::from_utf8(&lines[0]).unwrap().contains("pong"));
        let args = std::fs::read_to_string(dir.path().join("ssh-args")).unwrap();
        let stdin = std::fs::read(dir.path().join("ssh-stdin")).unwrap();
        assert_eq!(stdin, request);
        assert!(!args.contains("secret-pane"), "{args}");
        assert!(args.contains("BatchMode=yes"), "{args}");
        assert!(args.contains("StrictHostKeyChecking=yes"), "{args}");
        assert!(!args.contains("IdentityFile"), "{args}");
        let remote = args.lines().last().unwrap();
        let encoded = remote.split_whitespace().nth(5).unwrap();
        let script = String::from_utf8(base64_decode(encoded)).unwrap();
        assert!(!script.contains(TARGET), "{script}");
        assert!(!script.contains("secret-pane"), "{script}");
        assert!(script.contains("remote-api-bridge <&3"), "{script}");
    }

    #[test]
    fn bridge_errors_scrub_the_ssh_target_and_a_symlink_cache_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let herdr = write_exe(
            dir.path(),
            "herdr",
            &format!(
                "#!/bin/sh\nprintf '%s\\n' '{list}'\n",
                list = catalog_json(true)
            ),
        );
        let ssh = write_exe(
            dir.path(),
            "ssh",
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}/called'\necho '{TARGET}' >&2\nexit 255\n",
                dir.path().display()
            ),
        );
        let cli = CliMachines::for_test(herdr, ssh, dir.path().join("no-cache"));
        let err = cli
            .forward(
                "instant-fill",
                b"{}\n",
                &AtomicBool::new(false),
                &mut |_| true,
            )
            .unwrap_err();
        assert!(!err.message.contains(TARGET), "{}", err.message);
        assert!(err.message.contains("[redacted]"), "{}", err.message);

        let state = dir.path().join("state");
        let meta_dir = state.join("herdr/client/ssh-metadata");
        std::fs::create_dir_all(&meta_dir).unwrap();
        let real = dir.path().join("real.json");
        std::fs::write(
            &real,
            serde_json::json!({
                "version": 1,
                "target": TARGET,
                "session": "fleet",
                "metadata": {"os": "linux", "executable": "/opt/secret-binary"}
            })
            .to_string(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&real, meta_dir.join(format!("{ID}.json"))).unwrap();
        let ssh = write_exe(
            dir.path(),
            "ssh2",
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}/called2'\nprintf '\\n%s\\n' '{READY_MARKER}'\nprintf '%s\\n' '{{}}'\n",
                dir.path().display()
            ),
        );
        let cli = CliMachines::for_test(dir.path().join("herdr"), ssh, state);
        cli.forward(ID, b"{}\n", &AtomicBool::new(false), &mut |_| true)
            .unwrap();
        let called = std::fs::read_to_string(dir.path().join("called2")).unwrap();
        assert!(!called.contains("secret-binary"), "{called}");
    }

    #[test]
    fn cached_executable_is_used_and_windows_is_refused_before_ssh() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let meta_dir = state.join("herdr/client/ssh-metadata");
        std::fs::create_dir_all(&meta_dir).unwrap();
        std::fs::write(
            meta_dir.join(format!("{ID}.json")),
            serde_json::json!({
                "version": 1,
                "target": TARGET,
                "session": "fleet",
                "metadata": {"os": "linux", "executable": "/opt/custom-herdr"}
            })
            .to_string(),
        )
        .unwrap();
        let herdr = write_exe(
            dir.path(),
            "herdr",
            &format!(
                "#!/bin/sh\nprintf '%s\\n' '{list}'\n",
                list = catalog_json(true)
            ),
        );
        let ssh = write_exe(
            dir.path(),
            "ssh",
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}/called'\nprintf '\\n%s\\n' '{READY_MARKER}'\nprintf '%s\\n' '{{}}'\n",
                dir.path().display()
            ),
        );
        let cli = CliMachines::for_test(herdr.clone(), ssh.clone(), state.clone());
        cli.forward(ID, b"{}\n", &AtomicBool::new(false), &mut |_| true)
            .unwrap();
        let called = std::fs::read_to_string(dir.path().join("called")).unwrap();
        let remote = called.lines().next_back().unwrap();
        let encoded = remote.split_whitespace().nth(5).unwrap();
        let script = String::from_utf8(base64_decode(encoded)).unwrap();
        assert!(script.contains("/opt/custom-herdr"), "{script}");

        std::fs::write(
            meta_dir.join(format!("{ID}.json")),
            serde_json::json!({
                "version": 1,
                "target": TARGET,
                "session": "fleet",
                "metadata": {"os": "windows", "executable": "C:\\\\herdr.exe"}
            })
            .to_string(),
        )
        .unwrap();
        let marker = dir.path().join("windows-called");
        let ssh = write_exe(
            dir.path(),
            "ssh-win",
            &format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        );
        let cli = CliMachines::for_test(herdr, ssh, state);
        let err = cli
            .forward(ID, b"{}\n", &AtomicBool::new(false), &mut |_| true)
            .unwrap_err();
        assert!(err.message.contains("Windows"), "{}", err.message);
        assert!(!err.message.contains(TARGET), "{}", err.message);
        assert!(!marker.exists(), "ssh must not start for a Windows target");
    }

    fn base64_decode(text: &str) -> Vec<u8> {
        fn val(byte: u8) -> u8 {
            match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => 0,
            }
        }
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut index = 0;
        while index + 4 <= bytes.len() {
            let chunk = ((val(bytes[index]) as u32) << 18)
                | ((val(bytes[index + 1]) as u32) << 12)
                | ((val(bytes[index + 2]) as u32) << 6)
                | val(bytes[index + 3]) as u32;
            out.push((chunk >> 16) as u8);
            if bytes[index + 2] != b'=' {
                out.push((chunk >> 8) as u8);
            }
            if bytes[index + 3] != b'=' {
                out.push(chunk as u8);
            }
            index += 4;
        }
        out
    }
}
