//! Read-only view of an [oh-my-pi](https://github.com/can1357/oh-my-pi) session.
//!
//! omp writes `~/.omp/agent/sessions/<project>/<timestamp>_<id>.jsonl`. Herdr
//! reports that path on `agent_session` when `agent` is `omp` and `kind` is
//! `path`. This parser follows omp's session format (logical version 3):
//!
//! - assistant prose is `type: message` with `message.role: assistant` and
//!   `content[]` text blocks
//! - tool calls are `content` blocks `{type: toolCall, name, arguments}`
//! - a pending ask is an `ask` tool call with no later `toolResult`
//! - todos are the latest successful `todo` tool result `details.phases`, or
//!   a later `custom` entry `customType: user_todo_edit`
//! - the durable recap in the file is the latest compaction `shortSummary`
//!   (else `summary`). Idle recaps live in omp's `history.db`, not this file
//! - reported commits are successful bash/shell tool calls that run `git commit`
//!
//! The active branch is the parent chain ending at the last entry. Unknown
//! lines are skipped.

use serde_json::Value;

pub const MAX_SESSION_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_MESSAGES: usize = 8;
const MAX_MESSAGES: usize = 20;
const MESSAGE_CHARS: usize = 4_000;
const TOOL_CALLS: usize = 12;
const COMMITS: usize = 8;
const RECAP_CHARS: usize = 1_000;
const TASK_CHARS: usize = 240;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    pub supported: bool,
    pub reason: Option<String>,
    pub agent: Option<String>,
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    pub title: Option<String>,
    pub messages: Vec<AssistantMessage>,
    pub recap: Option<Recap>,
    pub todos: Vec<TodoPhase>,
    pub tool_calls: Vec<ToolCallSummary>,
    pub commits: Vec<ReportedCommit>,
    pub ask: Option<PendingAsk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssistantMessage {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recap {
    pub text: String,
    /// `compaction` is the only recap stored in the session jsonl.
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TodoPhase {
    pub name: String,
    pub tasks: Vec<TodoTask>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TodoTask {
    pub content: String,
    pub status: String,
    pub blocker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallSummary {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub pending: bool,
    pub is_error: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedCommit {
    pub hash: Option<String>,
    pub summary: String,
    pub tool: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskOption {
    pub label: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAsk {
    pub tool_call_id: String,
    pub question_id: String,
    pub question: String,
    pub options: Vec<AskOption>,
    pub multi: bool,
    pub recommended: Option<usize>,
    pub question_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskChoice {
    Index(usize),
    Label(String),
}

/// Whether herdr's `agent_session` value is an omp file this relay may read.
pub fn session_path_allowed(agent: &str, kind: &str, path: &str) -> Result<(), &'static str> {
    if agent != "omp" {
        return Err("agent kind is not omp");
    }
    if kind != "path" {
        return Err("herdr did not report an omp session file path");
    }
    if path.len() > 4096 || path.chars().any(char::is_control) {
        return Err("session path is not allowed");
    }
    if !path.starts_with('/') || path.contains("//") {
        return Err("session path is not an absolute omp session file");
    }
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if parts.iter().any(|part| *part == "." || *part == "..") {
        return Err("session path is not an absolute omp session file");
    }
    if !path.ends_with(".jsonl") || !path.contains("/.omp/agent/sessions/") {
        return Err("session path is not an omp session file");
    }
    Ok(())
}

/// Keep the tail of a session file so a long transcript stays bounded.
#[must_use]
pub fn tail_bytes(bytes: &[u8], max: usize) -> &[u8] {
    if bytes.len() <= max {
        return bytes;
    }
    let start = bytes.len() - max;
    match bytes[start..].iter().position(|byte| *byte == b'\n') {
        Some(pos) if start + pos + 1 < bytes.len() => &bytes[start + pos + 1..],
        _ => &bytes[start..],
    }
}

/// Parse one omp session file. `messages` is how many assistant texts to keep.
pub fn parse_session(bytes: &[u8], messages: usize) -> SessionView {
    let messages = messages.clamp(1, MAX_MESSAGES);
    let text = String::from_utf8_lossy(tail_bytes(bytes, MAX_SESSION_BYTES));
    let mut entries = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if value.get("type").and_then(Value::as_str).is_some() {
            entries.push(value);
        }
    }
    let branch = active_branch(&entries);
    let mut view = SessionView {
        supported: true,
        reason: None,
        agent: Some("omp".to_string()),
        session_id: None,
        cwd: None,
        title: None,
        messages: Vec::new(),
        recap: None,
        todos: Vec::new(),
        tool_calls: Vec::new(),
        commits: Vec::new(),
        ask: None,
    };
    if let Some(header) = branch.iter().find(|entry| entry_type(entry) == "session") {
        view.session_id = header.get("id").and_then(Value::as_str).map(str::to_string);
        view.cwd = header
            .get("cwd")
            .and_then(Value::as_str)
            .map(str::to_string);
        view.title = header
            .get("title")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    let mut assistant = Vec::new();
    let mut tools = Vec::new();
    let mut results: Vec<(String, bool, Value)> = Vec::new();
    let mut commits = Vec::new();
    for entry in &branch {
        match entry_type(entry) {
            "message" => {
                if let Some(phases) = todo_phases_from_result(entry) {
                    view.todos = phases;
                }
                collect_message(entry, &mut assistant, &mut tools, &mut results);
            }
            "compaction" => {
                if let Some(text) = compaction_recap(entry) {
                    view.recap = Some(Recap {
                        text: clip(&text, RECAP_CHARS),
                        source: "compaction",
                    });
                }
            }
            "custom"
                if entry.get("customType").and_then(Value::as_str) == Some("user_todo_edit") =>
            {
                if let Some(phases) = entry
                    .get("data")
                    .and_then(|data| data.get("phases"))
                    .and_then(parse_phases)
                {
                    view.todos = phases;
                }
            }
            _ => {}
        }
    }
    for (id, is_error, _) in &results {
        if let Some(tool) = tools.iter_mut().find(|tool| tool.id == *id && tool.pending) {
            tool.pending = false;
            tool.is_error = Some(*is_error);
        }
    }
    for tool in &tools {
        if tool.is_error == Some(true) || tool.pending {
            continue;
        }
        if let Some(mut commit) = tool.commit.clone() {
            if let Some((hash, summary)) = commit_from_result(tool) {
                commit.hash = Some(hash);
                if !summary.is_empty() {
                    commit.summary = summary;
                }
            }
            commits.push(commit);
        }
    }
    if assistant.len() > messages {
        assistant = assistant.split_off(assistant.len() - messages);
    }
    view.messages = assistant;
    if tools.len() > TOOL_CALLS {
        tools = tools.split_off(tools.len() - TOOL_CALLS);
    }
    view.tool_calls = tools
        .into_iter()
        .map(|tool| ToolCallSummary {
            id: tool.id,
            name: tool.name,
            summary: tool.summary,
            pending: tool.pending,
            is_error: tool.is_error,
        })
        .collect();
    if commits.len() > COMMITS {
        commits = commits.split_off(commits.len() - COMMITS);
    }
    view.commits = commits;
    view.ask = pending_ask(&branch);
    view
}

pub fn unsupported(agent: Option<&str>, reason: &str) -> SessionView {
    SessionView {
        supported: false,
        reason: Some(reason.to_string()),
        agent: agent.map(str::to_string),
        session_id: None,
        cwd: None,
        title: None,
        messages: Vec::new(),
        recap: None,
        todos: Vec::new(),
        tool_calls: Vec::new(),
        commits: Vec::new(),
        ask: None,
    }
}

/// Keystrokes for omp's ask selector.
///
/// The selector opens on `recommended`, or on the first option when that field
/// is absent. `up` / `down` move, then `enter` confirms. Multi-select asks are
/// refused: one enter cannot express several labels.
pub fn answer_keys(ask: &PendingAsk, choice: &AskChoice) -> Result<Vec<String>, &'static str> {
    if ask.multi {
        return Err("multi-select asks are not answered by this relay");
    }
    if ask.options.is_empty() {
        return Err("the ask has no options");
    }
    let target = match choice {
        AskChoice::Index(index) => {
            if *index >= ask.options.len() {
                return Err("option index is outside the ask");
            }
            *index
        }
        AskChoice::Label(label) => {
            let matches: Vec<_> = ask
                .options
                .iter()
                .enumerate()
                .filter(|(_, option)| option.label == *label)
                .map(|(index, _)| index)
                .collect();
            match matches.as_slice() {
                [index] => *index,
                [] => return Err("option label is not on the ask"),
                _ => return Err("option label matches more than one option"),
            }
        }
    };
    let start = ask
        .recommended
        .filter(|index| *index < ask.options.len())
        .unwrap_or(0);
    let mut keys = Vec::new();
    if target > start {
        keys.extend(std::iter::repeat_n("down".to_string(), target - start));
    } else {
        keys.extend(std::iter::repeat_n("up".to_string(), start - target));
    }
    keys.push("enter".to_string());
    Ok(keys)
}

/// Same ask still on screen: tool call, question id, text, and option labels.
#[must_use]
pub fn ask_fingerprint(ask: &PendingAsk) -> String {
    let labels: Vec<&str> = ask
        .options
        .iter()
        .map(|option| option.label.as_str())
        .collect();
    format!(
        "{}|{}|{}|{}",
        ask.tool_call_id,
        ask.question_id,
        ask.question,
        labels.join("\u{1f}")
    )
}

#[derive(Clone)]
struct RawTool {
    id: String,
    name: String,
    summary: String,
    pending: bool,
    is_error: Option<bool>,
    commit: Option<ReportedCommit>,
    result_text: String,
}

fn collect_message(
    entry: &Value,
    assistant: &mut Vec<AssistantMessage>,
    tools: &mut Vec<RawTool>,
    results: &mut Vec<(String, bool, Value)>,
) {
    let Some(message) = entry.get("message") else {
        return;
    };
    let role = message.get("role").and_then(Value::as_str).unwrap_or("");
    let id = entry
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    match role {
        "assistant" => {
            let text = content_text(message.get("content"));
            if !text.is_empty() {
                assistant.push(AssistantMessage {
                    id: id.clone(),
                    text: clip(&text, MESSAGE_CHARS),
                });
            }
            if let Some(blocks) = message.get("content").and_then(Value::as_array) {
                for block in blocks {
                    if block.get("type").and_then(Value::as_str) != Some("toolCall") {
                        continue;
                    }
                    let name = block
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let call_id = block
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let args = block
                        .get("arguments")
                        .or_else(|| block.get("input"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    tools.push(RawTool {
                        id: call_id,
                        summary: tool_summary(&name, &args),
                        commit: commit_from_call(&name, &args),
                        name,
                        pending: true,
                        is_error: None,
                        result_text: String::new(),
                    });
                }
            }
        }
        "toolResult" => {
            let call_id = message
                .get("toolCallId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let is_error = message
                .get("isError")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let details = message
                .get("details")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new()));
            let text = content_text(message.get("content"));
            if let Some(tool) = tools.iter_mut().rev().find(|tool| tool.id == call_id) {
                tool.result_text = text;
            }
            results.push((call_id, is_error, details));
        }
        _ => {}
    }
}

fn todo_phases_from_result(entry: &Value) -> Option<Vec<TodoPhase>> {
    let message = entry.get("message")?;
    if message.get("role").and_then(Value::as_str) != Some("toolResult") {
        return None;
    }
    if message.get("toolName").and_then(Value::as_str) != Some("todo") {
        return None;
    }
    if message.get("isError").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    message
        .get("details")
        .and_then(|details| details.get("phases"))
        .and_then(parse_phases)
}

fn pending_ask(branch: &[Value]) -> Option<PendingAsk> {
    let mut calls = Vec::new();
    let mut answered = Vec::new();
    for entry in branch {
        let Some(message) = entry.get("message") else {
            continue;
        };
        match message.get("role").and_then(Value::as_str)? {
            "assistant" => {
                let blocks = message.get("content")?.as_array()?;
                for block in blocks {
                    if block.get("type").and_then(Value::as_str) != Some("toolCall") {
                        continue;
                    }
                    if block.get("name").and_then(Value::as_str) != Some("ask") {
                        continue;
                    }
                    let id = block.get("id").and_then(Value::as_str).unwrap_or("");
                    let args = block
                        .get("arguments")
                        .or_else(|| block.get("input"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    calls.push((id.to_string(), args));
                }
            }
            "toolResult" if message.get("toolName").and_then(Value::as_str) == Some("ask") => {
                if let Some(id) = message.get("toolCallId").and_then(Value::as_str) {
                    answered.push(id.to_string());
                }
            }
            _ => {}
        }
    }
    let (id, args) = calls
        .into_iter()
        .rev()
        .find(|(id, _)| !answered.iter().any(|done| done == id))?;
    let questions = args.get("questions")?.as_array()?;
    let first = questions.first()?;
    let options = first
        .get("options")?
        .as_array()?
        .iter()
        .filter_map(|option| {
            let label = option.get("label")?.as_str()?.to_string();
            let description = option
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_string);
            Some(AskOption { label, description })
        })
        .collect::<Vec<_>>();
    if options.is_empty() {
        return None;
    }
    Some(PendingAsk {
        tool_call_id: id,
        question_id: first.get("id").and_then(Value::as_str)?.to_string(),
        question: first.get("question").and_then(Value::as_str)?.to_string(),
        options,
        multi: first.get("multi").and_then(Value::as_bool).unwrap_or(false),
        recommended: first
            .get("recommended")
            .and_then(Value::as_u64)
            .map(|index| index as usize),
        question_count: questions.len(),
    })
}

fn commit_from_call(name: &str, args: &Value) -> Option<ReportedCommit> {
    if !is_shell(name) {
        return None;
    }
    let command = args
        .get("command")
        .or_else(|| args.get("cmd"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !command_is_git_commit(command) {
        return None;
    }
    let summary = commit_message_flag(command).unwrap_or_else(|| clip(command, 160));
    Some(ReportedCommit {
        hash: None,
        summary,
        tool: name.to_string(),
    })
}

fn commit_from_result(tool: &RawTool) -> Option<(String, String)> {
    let line = tool.result_text.lines().next().unwrap_or("").trim();
    // git's default: `[main a1b2c3d] subject`
    let rest = line.strip_prefix('[')?;
    let (head, subject) = rest.split_once(']')?;
    let hash = head.split_whitespace().next_back()?.to_string();
    if !hash.chars().all(|ch| ch.is_ascii_hexdigit()) || hash.len() < 7 {
        return None;
    }
    Some((hash, clip(subject.trim(), 160)))
}

fn command_is_git_commit(command: &str) -> bool {
    command.split([';', '\n', '|', '&']).any(|part| {
        let mut words = part.split_whitespace();
        match words.next() {
            Some("git") => words.next() == Some("commit"),
            Some(other) => other.ends_with("/git") && words.next() == Some("commit"),
            None => false,
        }
    })
}

fn commit_message_flag(command: &str) -> Option<String> {
    let marker = "-m";
    let pos = command.find(marker)?;
    let mut rest = command[pos + marker.len()..].trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"')?;
        return Some(clip(&quoted[..end], 160));
    }
    if let Some(quoted) = rest.strip_prefix('\'') {
        let end = quoted.find('\'')?;
        return Some(clip(&quoted[..end], 160));
    }
    rest = rest.split_whitespace().next().unwrap_or("");
    if rest.is_empty() {
        None
    } else {
        Some(clip(rest, 160))
    }
}

fn is_shell(name: &str) -> bool {
    matches!(name, "bash" | "shell" | "exec" | "run")
}

fn tool_summary(name: &str, args: &Value) -> String {
    if name == "ask" {
        let question = args
            .pointer("/questions/0/question")
            .and_then(Value::as_str)
            .unwrap_or("ask");
        return clip(question, 160);
    }
    if let Some(command) = args
        .get("command")
        .or_else(|| args.get("cmd"))
        .and_then(Value::as_str)
    {
        return clip(command, 160);
    }
    if let Some(path) = args.get("path").and_then(Value::as_str) {
        return clip(path, 160);
    }
    clip(name, 160)
}

fn compaction_recap(entry: &Value) -> Option<String> {
    entry
        .get("shortSummary")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .or_else(|| {
            entry
                .get("summary")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
        })
}

fn parse_phases(value: &Value) -> Option<Vec<TodoPhase>> {
    let rows = value.as_array()?;
    let mut phases = Vec::new();
    for row in rows.iter().take(20) {
        let name = row
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let mut tasks = Vec::new();
        if let Some(items) = row.get("tasks").and_then(Value::as_array) {
            for task in items.iter().take(50) {
                let content = task.get("content").and_then(Value::as_str).unwrap_or("");
                if content.is_empty() {
                    continue;
                }
                tasks.push(TodoTask {
                    content: clip(content, TASK_CHARS),
                    status: task
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("pending")
                        .to_string(),
                    blocker: task
                        .get("blocker")
                        .and_then(Value::as_str)
                        .map(|text| clip(text, TASK_CHARS)),
                });
            }
        }
        phases.push(TodoPhase { name, tasks });
    }
    Some(phases)
}

fn content_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|block| {
                if block.get("type").and_then(Value::as_str) == Some("text") {
                    block.get("text").and_then(Value::as_str)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn active_branch(entries: &[Value]) -> Vec<Value> {
    let mut by_id: Vec<(&str, &Value)> = Vec::new();
    for entry in entries {
        if let Some(id) = entry.get("id").and_then(Value::as_str) {
            by_id.push((id, entry));
        }
    }
    let Some((mut cursor, _)) = by_id.last().copied() else {
        return entries.to_vec();
    };
    let mut chain = Vec::new();
    let mut guard = 0;
    while guard < 10_000 {
        guard += 1;
        let Some((_, entry)) = by_id.iter().rev().find(|(id, _)| *id == cursor) else {
            break;
        };
        chain.push((*entry).clone());
        match entry.get("parentId").and_then(Value::as_str) {
            Some(parent) => cursor = parent,
            None => break,
        }
    }
    if chain.is_empty() {
        return entries.to_vec();
    }
    chain.reverse();
    // The header has no parent link from the first entry when parentId is null
    // on the root message. Include a session header that was not on the chain.
    if !chain.iter().any(|entry| entry_type(entry) == "session")
        && let Some(header) = entries.iter().find(|entry| entry_type(entry) == "session")
    {
        chain.insert(0, header.clone());
    }
    chain
}

fn entry_type(entry: &Value) -> &str {
    entry.get("type").and_then(Value::as_str).unwrap_or("")
}

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('…');
    out
}

pub fn view_json(view: &SessionView) -> Value {
    serde_json::json!({
        "type": "agent_session",
        "supported": view.supported,
        "reason": view.reason,
        "agent": view.agent,
        "session_id": view.session_id,
        "cwd": view.cwd,
        "title": view.title,
        "messages": view.messages.iter().map(|message| serde_json::json!({
            "id": message.id,
            "text": message.text,
        })).collect::<Vec<_>>(),
        "recap": view.recap.as_ref().map(|recap| serde_json::json!({
            "text": recap.text,
            "source": recap.source,
        })),
        "todos": view.todos.iter().map(|phase| serde_json::json!({
            "name": phase.name,
            "tasks": phase.tasks.iter().map(|task| serde_json::json!({
                "content": task.content,
                "status": task.status,
                "blocker": task.blocker,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "tool_calls": view.tool_calls.iter().map(|tool| serde_json::json!({
            "id": tool.id,
            "name": tool.name,
            "summary": tool.summary,
            "pending": tool.pending,
            "is_error": tool.is_error,
        })).collect::<Vec<_>>(),
        "commits": view.commits.iter().map(|commit| serde_json::json!({
            "hash": commit.hash,
            "summary": commit.summary,
            "tool": commit.tool,
        })).collect::<Vec<_>>(),
        "ask": view.ask.as_ref().map(|ask| serde_json::json!({
            "tool_call_id": ask.tool_call_id,
            "question_id": ask.question_id,
            "question": ask.question,
            "options": ask.options.iter().map(|option| serde_json::json!({
                "label": option.label,
                "description": option.description,
            })).collect::<Vec<_>>(),
            "multi": ask.multi,
            "recommended": ask.recommended,
            "question_count": ask.question_count,
        })),
    })
}

pub fn default_message_count() -> usize {
    DEFAULT_MESSAGES
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        [
            r#"{"type":"session","version":3,"id":"sess-1","timestamp":"2026-05-14T10:12:03.000Z","cwd":"/work/app","title":"importer"}"#,
            r#"{"type":"message","id":"m1","parentId":null,"timestamp":"2026-05-14T10:12:05.000Z","message":{"role":"assistant","content":[{"type":"text","text":"Older note."}],"timestamp":1}}"#,
            r#"{"type":"message","id":"m2","parentId":"m1","timestamp":"2026-05-14T10:12:06.000Z","message":{"role":"assistant","content":[{"type":"text","text":"Reading first."},{"type":"toolCall","id":"t1","name":"bash","arguments":{"command":"git commit -m \"fix importer\""}}],"timestamp":2}}"#,
            r#"{"type":"message","id":"m3","parentId":"m2","timestamp":"2026-05-14T10:12:07.000Z","message":{"role":"toolResult","toolCallId":"t1","toolName":"bash","content":[{"type":"text","text":"[main a1b2c3d] fix importer\n 1 file changed"}],"isError":false,"timestamp":3}}"#,
            r#"{"type":"message","id":"oldask","parentId":"m3","timestamp":"2026-05-14T10:12:08.000Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"told","name":"ask","arguments":{"questions":[{"id":"old","question":"Old?","options":[{"label":"No"}]}]}}],"timestamp":4}}"#,
            r#"{"type":"message","id":"oldres","parentId":"oldask","timestamp":"2026-05-14T10:12:09.000Z","message":{"role":"toolResult","toolCallId":"told","toolName":"ask","content":[{"type":"text","text":"No"}],"isError":false,"timestamp":5}}"#,
            r#"{"type":"message","id":"m5","parentId":"oldres","timestamp":"2026-05-14T10:12:10.000Z","message":{"role":"toolResult","toolCallId":"t2","toolName":"todo","content":[{"type":"text","text":"Todos"}],"isError":false,"details":{"phases":[{"name":"Old","tasks":[{"content":"stale","status":"pending"}]}]},"timestamp":6}}"#,
            r#"{"type":"custom","id":"todo1","parentId":"m5","timestamp":"2026-05-14T10:12:11.000Z","customType":"user_todo_edit","data":{"phases":[{"name":"Ship","tasks":[{"content":"write tests","status":"in_progress"},{"content":"ship it","status":"completed"}]}]}}"#,
            r#"{"type":"compaction","id":"c1","parentId":"todo1","timestamp":"2026-05-14T10:13:00.000Z","summary":"Long summary.","shortSummary":"Importer streams now."}"#,
            r#"not json"#,
            r#"{"type":"message","id":"m6","parentId":"c1","timestamp":"2026-05-14T10:14:00.000Z","message":{"role":"assistant","content":[{"type":"text","text":"Need a database."},{"type":"toolCall","id":"t3","name":"ask","arguments":{"questions":[{"id":"db","question":"Which database?","options":[{"label":"Postgres","description":"server"},{"label":"SQLite"}],"recommended":0}]}}],"timestamp":7}}"#,
        ]
        .join("\n")
    }

    #[test]
    fn parses_omp_session_branch() {
        let view = parse_session(fixture().as_bytes(), 8);
        assert!(view.supported);
        assert_eq!(view.cwd.as_deref(), Some("/work/app"));
        assert_eq!(view.session_id.as_deref(), Some("sess-1"));
        assert_eq!(view.messages.last().unwrap().text, "Need a database.");
        assert!(
            view.messages
                .iter()
                .any(|message| message.text == "Reading first.")
        );
        assert_eq!(view.recap.unwrap().text, "Importer streams now.");
        assert_eq!(view.todos[0].name, "Ship");
        assert_eq!(view.todos[0].tasks[0].status, "in_progress");
        assert_eq!(view.commits.len(), 1);
        assert_eq!(view.commits[0].hash.as_deref(), Some("a1b2c3d"));
        assert_eq!(view.commits[0].summary, "fix importer");
        let ask = view.ask.unwrap();
        assert_eq!(ask.question_id, "db");
        assert_eq!(ask.options.len(), 2);
        assert_eq!(ask.recommended, Some(0));
        assert!(
            !view
                .tool_calls
                .iter()
                .any(|tool| tool.id == "told" && tool.pending)
        );
        let keys = answer_keys(&ask, &AskChoice::Label("SQLite".into())).unwrap();
        assert_eq!(keys, ["down", "enter"]);
        let same = answer_keys(&ask, &AskChoice::Index(0)).unwrap();
        assert_eq!(same, ["enter"]);
    }

    #[test]
    fn refuses_paths_the_client_might_substitute() {
        assert!(
            session_path_allowed("omp", "path", "/home/a/.omp/agent/sessions/proj/1_x.jsonl")
                .is_ok()
        );
        assert!(
            session_path_allowed(
                "claude",
                "path",
                "/home/a/.omp/agent/sessions/proj/1_x.jsonl"
            )
            .is_err()
        );
        assert!(session_path_allowed("omp", "id", "abc").is_err());
        assert!(session_path_allowed("omp", "path", "/tmp/not-a-session.jsonl").is_err());
        assert!(
            session_path_allowed(
                "omp",
                "path",
                "/home/a/.omp/agent/sessions/../../etc/passwd.jsonl"
            )
            .is_err()
        );
        assert!(session_path_allowed("omp", "path", "home/a/.omp/agent/sessions/x.jsonl").is_err());
    }

    #[test]
    fn multi_select_is_not_a_single_enter() {
        let ask = PendingAsk {
            tool_call_id: "t".into(),
            question_id: "q".into(),
            question: "which?".into(),
            options: vec![AskOption {
                label: "A".into(),
                description: None,
            }],
            multi: true,
            recommended: Some(0),
            question_count: 1,
        };
        assert!(answer_keys(&ask, &AskChoice::Index(0)).is_err());
    }

    #[test]
    fn tail_drops_a_partial_first_line() {
        let bytes = b"XXXXXXXXXXXXXXXXXXXXXXXX\n{\"ok\":true}\n";
        let tail = tail_bytes(bytes, 16);
        let text = std::str::from_utf8(tail).unwrap();
        assert!(text.contains("ok"), "{text}");
        assert!(!text.contains('X'), "{text}");
    }
}
