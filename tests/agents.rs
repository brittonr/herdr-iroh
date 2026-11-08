//! omp session reads, idempotent prompts, and ask answers against a fake herdr.

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use herdr_iroh::InactiveGateway;
use herdr_iroh::client::{CallOptions, Node, dial_target};
use herdr_iroh::config::HostConfig;
use herdr_iroh::keys;
use herdr_iroh::notify::NotifyConfig;
use herdr_iroh::policy::{Allowlist, MethodsField, PeerConfig};
use herdr_iroh::protocol::request_value;
use herdr_iroh::serve::{ServeOptions, serve};
use iroh::SecretKey;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::RwLock;

fn session_file(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join(".omp/agent/sessions/app/1_sess.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        r#"{"type":"session","version":3,"id":"sess-1","cwd":"/work/app","title":"importer"}
{"type":"message","id":"m1","parentId":null,"message":{"role":"assistant","content":[{"type":"text","text":"Reading first."},{"type":"toolCall","id":"t1","name":"bash","arguments":{"command":"git commit -m \"fix importer\""}}]}}
{"type":"message","id":"m2","parentId":"m1","message":{"role":"toolResult","toolCallId":"t1","toolName":"bash","content":[{"type":"text","text":"[main a1b2c3d] fix importer"}],"isError":false}}
{"type":"compaction","id":"c1","parentId":"m2","summary":"Long.","shortSummary":"Importer streams now."}
{"type":"message","id":"m3","parentId":"c1","message":{"role":"assistant","content":[{"type":"text","text":"Need a database."},{"type":"toolCall","id":"t3","name":"ask","arguments":{"questions":[{"id":"db","question":"Which database?","options":[{"label":"Postgres"},{"label":"SQLite"}],"recommended":0}]}}]}}
"#,
    )
    .unwrap();
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_prompt_and_answer_use_the_reported_omp_file() {
    let dir = tempfile::tempdir().unwrap();
    let session = session_file(dir.path());
    let socket = dir.path().join("herdr.sock");
    let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
    spawn_socket(
        socket.clone(),
        session.display().to_string(),
        Arc::clone(&seen),
    )
    .await;

    let client_key = keys::generate(&dir.path().join("state").join("secret_key"), false).unwrap();
    let mut peers = BTreeMap::new();
    peers.insert(
        "bot".into(),
        PeerConfig {
            endpoint_id: client_key.public().to_string(),
            methods: Some(MethodsField::Word("full".into())),
        },
    );
    let running = serve(ServeOptions {
        secret_key: SecretKey::generate(),
        socket_path: socket,
        allow: Arc::new(RwLock::new(Allowlist::try_from_config(&peers).unwrap())),
        gateway: Arc::new(AtomicBool::new(false)),
        machines: Arc::new(InactiveGateway),
        notify: NotifyConfig::default(),
        dedupe_ttl: Duration::from_secs(60),
        relays: false,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        relay_timeout: Duration::from_secs(8),
    })
    .await
    .unwrap();
    let host = HostConfig {
        endpoint_id: running.endpoint_id.to_string(),
        ticket: Some(running.ticket.clone()),
        relays: false,
    };
    let target = dial_target(&host, false).unwrap();
    let node = Node::bind(client_key, false, Some("127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();

    let mut session_req = request_value(
        "relay.agent_session",
        json!({"target": "w1:p1", "messages": 4}),
    );
    let view = node
        .call(
            &target,
            &session_req,
            CallOptions {
                timeout: Duration::from_secs(15),
                max_lines: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(view[0]["result"]["supported"], true, "{view:?}");
    assert_eq!(view[0]["result"]["recap"]["text"], "Importer streams now.");
    assert_eq!(view[0]["result"]["ask"]["question_id"], "db");
    assert_eq!(view[0]["result"]["commits"][0]["hash"], "a1b2c3d");
    assert_eq!(
        view[0]["result"]["messages"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["text"],
        "Need a database."
    );
    let _ = &mut session_req;

    let prompt = |text: &str| {
        let mut value = request_value("agent.prompt", json!({"target": "w1:p1", "text": text}));
        value["message_id"] = json!("prompt-1");
        value
    };
    let first = node
        .call(
            &target,
            &prompt("hello"),
            CallOptions {
                timeout: Duration::from_secs(15),
                max_lines: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(first[0]["result"]["delivery"], "delivered", "{first:?}");
    assert_eq!(first[0]["result"]["agent_status"], "working");
    let second = node
        .call(
            &target,
            &prompt("hello"),
            CallOptions {
                timeout: Duration::from_secs(15),
                max_lines: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(second[0]["result"]["delivery"], "duplicate");
    assert_eq!(second[0]["result"]["payload_match"], true);

    let wrong = node
        .call(
            &target,
            &request_value(
                "relay.answer",
                json!({"target": "w1:p1", "question_id": "other", "option_index": 1}),
            ),
            CallOptions {
                timeout: Duration::from_secs(15),
                max_lines: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(wrong[0]["error"]["code"], "conflict", "{wrong:?}");

    let answered = node
        .call(
            &target,
            &request_value(
                "relay.answer",
                json!({"target": "w1:p1", "question_id": "db", "option_label": "SQLite"}),
            ),
            CallOptions {
                timeout: Duration::from_secs(15),
                max_lines: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(answered[0]["result"]["sent"], true, "{answered:?}");
    assert_eq!(answered[0]["result"]["keys"], json!(["down", "enter"]));

    let recorded = seen.lock().unwrap().clone();
    let prompts = recorded
        .iter()
        .filter(|req| req["method"] == "agent.prompt")
        .count();
    assert_eq!(
        prompts, 1,
        "duplicate message_id must not type twice: {recorded:?}"
    );
    assert!(
        recorded.iter().all(|req| req.get("message_id").is_none()),
        "message_id must be stripped before herdr: {recorded:?}"
    );
    let keys: Vec<_> = recorded
        .iter()
        .filter(|req| req["method"] == "agent.send_keys")
        .collect();
    assert_eq!(keys.len(), 1, "{recorded:?}");
    assert_eq!(keys[0]["params"]["keys"], json!(["down", "enter"]));

    node.close().await;
    running.shutdown().await.unwrap();
}

async fn spawn_socket(path: std::path::PathBuf, session: String, seen: Arc<Mutex<Vec<Value>>>) {
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let seen = Arc::clone(&seen);
            let session = session.clone();
            tokio::spawn(async move {
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                if AsyncBufReadExt::read_line(&mut stream, &mut line)
                    .await
                    .unwrap_or(0)
                    == 0
                {
                    return;
                }
                let req: Value = serde_json::from_str(line.trim()).unwrap_or(Value::Null);
                seen.lock().unwrap().push(req.clone());
                let id = req["id"].as_str().unwrap_or("");
                let method = req["method"].as_str().unwrap_or("");
                // Reply shapes follow herdr's protocol 22 `success_response` schema:
                // agent methods wrap an `AgentInfo` object under `result.agent`.
                let body = match method {
                    "agent.get" => json!({
                        "id": id,
                        "result": {
                            "type": "agent_info",
                            "agent": {
                                "name": "pi",
                                "agent": "omp",
                                "agent_status": "blocked",
                                "cwd": "/work/app",
                                "pane_id": "w1:p1",
                                "agent_session": {
                                    "source": "herdr:omp",
                                    "agent": "omp",
                                    "kind": "path",
                                    "value": session,
                                }
                            }
                        }
                    }),
                    "agent.prompt" => json!({
                        "id": id,
                        "result": {
                            "type": "agent_prompted",
                            "agent": {"agent": "omp", "agent_status": "working", "pane_id": "w1:p1"}
                        }
                    }),
                    "agent.send_keys" => json!({"id": id, "result": {"type": "ok"}}),
                    _ => json!({"id": id, "result": {"type": "ok", "echo_method": method}}),
                };
                let mut out = stream.into_inner();
                let _ = out.write_all(format!("{body}\n").as_bytes()).await;
            });
        }
    });
}
