//! Serve against a fake herdr socket and drive it from the MCP client.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use herdr_iroh::client::{CallOptions, Node, dial_target};
use herdr_iroh::config::{ClientFile, HostConfig};
use herdr_iroh::keys;
use herdr_iroh::policy::{Allowlist, MethodsField, PeerConfig};
use herdr_iroh::protocol::request_value;
use herdr_iroh::serve::{ServeOptions, serve};
use iroh::SecretKey;
use rmcp::model::{CallToolRequestParams, ContentBlock};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::{ServiceExt, model::CallToolResult};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, RwLock};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_client_drives_serve_through_a_fake_herdr_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("herdr.sock");
    let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
    spawn_mock(socket.clone(), Arc::clone(&seen)).await;

    let client_key_path = dir.path().join("client-state").join("secret_key");
    let client_key = keys::generate(&client_key_path, false).unwrap();
    let mut peers = BTreeMap::new();
    peers.insert(
        "bot".into(),
        PeerConfig {
            endpoint_id: client_key.public().to_string(),
            methods: Some(MethodsField::Word("full".into())),
        },
    );
    let allow = Allowlist::try_from_config(&peers).unwrap();

    let running = serve(ServeOptions {
        secret_key: SecretKey::generate(),
        socket_path: socket,
        allow: Arc::new(RwLock::new(allow)),
        gateway: Arc::new(AtomicBool::new(false)),
        machines: Arc::new(herdr_iroh::InactiveGateway),
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

    let pong = node
        .call(
            &target,
            &request_value("ping", json!({})),
            CallOptions {
                timeout: Duration::from_secs(15),
                max_lines: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(pong[0]["result"]["type"], "pong");
    assert_eq!(pong[0]["result"]["protocol"], 22);

    let prompted = node
        .call(
            &target,
            &request_value(
                "agent.prompt",
                json!({"target": "w1:p1", "text": "direct-prompt"}),
            ),
            CallOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(prompted[0]["result"]["echo_method"], "agent.prompt");

    let denied = node
        .call(
            &target,
            &request_value("server.stop", json!({})),
            CallOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(denied[0]["error"]["code"], "forbidden");
    assert!(
        denied[0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("denied to every remote peer")
    );

    let streamed = node
        .call(
            &target,
            &request_value(
                "events.subscribe",
                json!({"subscriptions": [{"type": "workspace.created"}]}),
            ),
            CallOptions {
                timeout: Duration::from_secs(15),
                max_lines: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(streamed.len(), 2);
    assert_eq!(streamed[0]["result"]["type"], "subscription_started");
    assert_eq!(streamed[1]["event"]["type"], "workspace_created");

    let stranger = Node::bind(
        SecretKey::generate(),
        false,
        Some("127.0.0.1:0".parse().unwrap()),
    )
    .await
    .unwrap();
    let rejected = stranger
        .call(
            &target,
            &request_value("ping", json!({})),
            CallOptions {
                timeout: Duration::from_secs(15),
                max_lines: 1,
            },
        )
        .await;
    assert!(rejected.is_err(), "an unknown endpoint must not be relayed");

    node.close().await;
    stranger.close().await;
    drop(node);
    drop(stranger);

    let client_toml = dir.path().join("client.toml");
    let file = ClientFile {
        default_host: Some("box".into()),
        hosts: BTreeMap::from([("box".into(), host)]),
    };
    std::fs::write(&client_toml, toml::to_string_pretty(&file).unwrap()).unwrap();

    let bin = std::env::var("CARGO_BIN_EXE_herdr_iroh")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_herdr-iroh"))
        .unwrap_or_else(|_| format!("{}/target/debug/herdr-iroh", env!("CARGO_MANIFEST_DIR")));
    let transport = TokioChildProcess::new(tokio::process::Command::new(bin).configure(|cmd| {
        cmd.arg("mcp")
            .arg("--config")
            .arg(&client_toml)
            .arg("--state-dir")
            .arg(dir.path().join("client-state"))
            .arg("--no-relays")
            .arg("--bind")
            .arg("127.0.0.1:0")
            .env("RUST_LOG", "herdr_iroh=warn,iroh=error");
    }))
    .unwrap();
    let client = ().serve(transport).await.expect("mcp initialize");
    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<_> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    for required in [
        "herdr_hosts",
        "herdr_status",
        "herdr_list_agents",
        "herdr_prompt_agent",
        "herdr_send_text",
        "herdr_wait_event",
        "herdr_wait_for_output",
        "herdr_call",
    ] {
        assert!(names.contains(&required), "missing tool {required}");
    }

    let status = call_tool(&client, "herdr_status", json!({})).await;
    let status_body = tool_json(&status);
    assert_ne!(status.is_error, Some(true), "{status_body}");
    assert_eq!(status_body["result"]["version"], "0.9.5");

    let prompt = call_tool(
        &client,
        "herdr_prompt_agent",
        json!({"target": "w1:p1", "text": "from-mcp"}),
    )
    .await;
    assert_ne!(prompt.is_error, Some(true), "{}", tool_text(&prompt));
    assert_eq!(tool_json(&prompt)["result"]["echo_method"], "agent.prompt");

    let stop = call_tool(
        &client,
        "herdr_call",
        json!({"method": "server.stop", "params": {}}),
    )
    .await;
    assert_eq!(stop.is_error, Some(true));
    assert!(tool_text(&stop).contains("denied to every remote peer"));

    let too_many = {
        let mut params = CallToolRequestParams::new("herdr_read_pane");
        params.arguments = json!({"pane_id": "w1:p1", "lines": 9000})
            .as_object()
            .cloned();
        client.call_tool(params).await
    };
    let too_many = too_many.expect_err("over-limit reads are rejected");
    assert!(too_many.to_string().contains("at most 500"), "{too_many}");

    let events = call_tool(
        &client,
        "herdr_call",
        json!({
            "method": "events.subscribe",
            "params": {"subscriptions": [{"type": "workspace.created"}]},
            "max_lines": 2
        }),
    )
    .await;
    assert_ne!(events.is_error, Some(true), "{}", tool_text(&events));
    let lines = &tool_json(&events)["lines"];
    assert_eq!(lines[0]["result"]["type"], "subscription_started");
    assert_eq!(lines[1]["event"]["type"], "workspace_created");

    let recorded = seen.lock().await;
    let methods: Vec<&str> = recorded
        .iter()
        .filter_map(|req| req.get("method").and_then(Value::as_str))
        .collect();
    assert!(methods.contains(&"agent.prompt"));
    assert!(methods.contains(&"events.subscribe"));
    assert!(
        !methods.contains(&"server.stop"),
        "server.stop must not reach herdr: {methods:?}"
    );
    assert!(
        recorded
            .iter()
            .any(|req| req["params"]["text"] == "from-mcp"),
        "mcp prompt was not forwarded"
    );
    assert!(
        recorded
            .iter()
            .all(|req| req.get("method").and_then(Value::as_str) != Some("pane.read")),
        "over-limit read must fail before the socket"
    );

    client.cancel().await.unwrap();
    running.shutdown().await.unwrap();
}

async fn call_tool(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &str,
    arguments: Value,
) -> CallToolResult {
    let mut params = CallToolRequestParams::new(name.to_string());
    params.arguments = arguments.as_object().cloned();
    client
        .call_tool(params)
        .await
        .unwrap_or_else(|err| panic!("tools/call {name}: {err}"))
}

fn tool_text(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text(text) => Some(text.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn tool_json(result: &CallToolResult) -> Value {
    serde_json::from_str(&tool_text(result))
        .unwrap_or_else(|err| panic!("tool result is not json ({err}): {}", tool_text(result)))
}

async fn spawn_mock(path: std::path::PathBuf, seen: Arc<Mutex<Vec<Value>>>) {
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let seen = Arc::clone(&seen);
            tokio::spawn(handle_mock(stream, seen));
        }
    });
}

async fn handle_mock(stream: UnixStream, seen: Arc<Mutex<Vec<Value>>>) {
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
    seen.lock().await.push(req.clone());
    let id = req.get("id").and_then(Value::as_str).unwrap_or("");
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let mut out = stream.into_inner();
    let body = match method {
        "ping" => json!({"id": id, "result": {"type": "pong", "version": "0.9.5", "protocol": 22}}),
        "events.subscribe" => {
            let ack = json!({"id": id, "result": {"type": "subscription_started"}});
            let event = json!({"id": id, "event": {"type": "workspace_created"}});
            let payload = format!("{ack}\n{event}\n");
            let _ = out.write_all(payload.as_bytes()).await;
            let _ = out.flush().await;
            return;
        }
        _ => json!({"id": id, "result": {"type": "ok", "echo_method": method}}),
    };
    let _ = out.write_all(format!("{body}\n").as_bytes()).await;
}
