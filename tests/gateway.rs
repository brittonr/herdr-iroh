//! Saved-machine routing over a real iroh connection, with the herdr CLI mocked.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use herdr_iroh::client::{CallOptions, Node, dial_target};
use herdr_iroh::config::{ClientFile, HostConfig};
use herdr_iroh::gateway::{MachineBackend, MachineError, SavedMachine};
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
use tokio::net::UnixListener;
use tokio::sync::RwLock;

const MACHINE_ID: &str = "0123456789abcdef0123456789abcdef";

struct MockMachines {
    lists: AtomicUsize,
    forwards: Mutex<Vec<Value>>,
}

impl MockMachines {
    fn recorded(&self) -> Vec<Value> {
        self.forwards.lock().unwrap().clone()
    }
}

impl MachineBackend for MockMachines {
    fn list(&self) -> Result<Vec<SavedMachine>, MachineError> {
        self.lists.fetch_add(1, Ordering::Relaxed);
        Ok(vec![
            SavedMachine {
                id: MACHINE_ID.into(),
                label: "instant-fill".into(),
                enabled: true,
                reachable: None,
            },
            SavedMachine {
                id: "fedcba9876543210fedcba9876543210".into(),
                label: "sleepy".into(),
                enabled: false,
                reachable: Some(false),
            },
        ])
    }

    fn forward(
        &self,
        selector: &str,
        request_line: &[u8],
        _cancel: &AtomicBool,
        on_line: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(), MachineError> {
        let request: Value = serde_json::from_slice(request_line).unwrap();
        assert!(
            !request.to_string().contains("secret-host"),
            "SSH target must not be in the forwarded request"
        );
        self.forwards.lock().unwrap().push(json!({
            "selector": selector,
            "method": request["method"],
        }));
        let id = request["id"].as_str().unwrap_or("");
        let method = request["method"].as_str().unwrap_or("");
        if method == "events.subscribe" {
            let started = format!(
                "{}\n",
                json!({"id": id, "result": {"type": "subscription_started"}})
            );
            let event = format!(
                "{}\n",
                json!({"id": id, "event": {"type": "workspace_created"}})
            );
            if !on_line(started.as_bytes()) {
                return Ok(());
            }
            let _ = on_line(event.as_bytes());
            return Ok(());
        }
        let body = if method == "ping" {
            json!({"id": id, "result": {"type": "pong", "version": "0.9.5", "protocol": 22}})
        } else {
            json!({"id": id, "result": {"type": "ok", "echo_method": method}})
        };
        let line = format!("{body}\n");
        let _ = on_line(line.as_bytes());
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_routes_saved_machines_and_blocks_dangerous_calls() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("herdr.sock");
    let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
    spawn_socket(socket.clone(), Arc::clone(&seen)).await;

    let client_key =
        keys::generate(&dir.path().join("client-state").join("secret_key"), false).unwrap();
    let mut peers = BTreeMap::new();
    peers.insert(
        "bot".into(),
        PeerConfig {
            endpoint_id: client_key.public().to_string(),
            methods: Some(MethodsField::Word("full".into())),
        },
    );
    let gateway = Arc::new(AtomicBool::new(true));
    let machines = Arc::new(MockMachines {
        lists: AtomicUsize::new(0),
        forwards: Mutex::new(Vec::new()),
    });
    let running = serve(ServeOptions {
        secret_key: SecretKey::generate(),
        socket_path: socket,
        allow: Arc::new(RwLock::new(Allowlist::try_from_config(&peers).unwrap())),
        gateway: Arc::clone(&gateway),
        machines: Arc::clone(&machines) as Arc<dyn MachineBackend>,
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

    let local = call(&node, &target, "ping", json!({}), 1).await;
    assert_eq!(local[0]["result"]["type"], "pong");

    let listed = call(&node, &target, "gateway.machines", json!({}), 1).await;
    let text = listed[0].to_string();
    assert!(text.contains("instant-fill"), "{text}");
    assert!(!text.contains("secret-host"), "{text}");
    assert!(!text.contains("fleet"), "{text}");
    assert_eq!(listed[0]["result"]["enabled"], true);
    assert_eq!(listed[0]["result"]["machines"][1]["reachable"], false);

    let forwarded = call(
        &node,
        &target,
        "gateway.forward",
        json!({"machine": "instant-fill", "method": "agent.list", "params": {}}),
        1,
    )
    .await;
    assert_eq!(forwarded[0]["result"]["echo_method"], "agent.list");

    let streamed = call(
        &node,
        &target,
        "gateway.forward",
        json!({"machine": MACHINE_ID, "method": "events.subscribe", "params": {}}),
        2,
    )
    .await;
    assert_eq!(streamed.len(), 2);
    assert_eq!(streamed[0]["result"]["type"], "subscription_started");
    assert_eq!(streamed[1]["event"]["type"], "workspace_created");

    for (method, needle) in [
        ("server.stop", "denied to every remote peer"),
        ("server.live_handoff", "denied to every remote peer"),
        ("machine.remove", "catalog changes are not forwarded"),
        ("machine.add", "catalog changes are not forwarded"),
        ("integration.install", "not forwarded"),
        ("server.ssh_agent.register", "not forwarded"),
    ] {
        let denied = call(
            &node,
            &target,
            "gateway.forward",
            json!({"machine": "instant-fill", "method": method, "params": {}}),
            1,
        )
        .await;
        assert_eq!(denied[0]["error"]["code"], "forbidden", "{method}");
        let message = denied[0]["error"]["message"].as_str().unwrap();
        assert!(message.contains(needle), "{method}: {message}");
    }

    let missing = call(
        &node,
        &target,
        "gateway.forward",
        json!({"machine": "nope", "method": "ping", "params": {}}),
        1,
    )
    .await;
    assert_eq!(missing[0]["error"]["code"], "not_found");

    let disabled = call(
        &node,
        &target,
        "gateway.forward",
        json!({"machine": "sleepy", "method": "ping", "params": {}}),
        1,
    )
    .await;
    assert_eq!(disabled[0]["error"]["code"], "forbidden");

    let selectors: Vec<_> = machines
        .recorded()
        .iter()
        .map(|row| row["method"].as_str().unwrap().to_string())
        .collect();
    assert!(
        selectors.contains(&"agent.list".to_string()),
        "{selectors:?}"
    );
    assert!(
        selectors.contains(&"events.subscribe".to_string()),
        "{selectors:?}"
    );
    for blocked in [
        "server.stop",
        "server.live_handoff",
        "machine.remove",
        "machine.add",
        "integration.install",
        "server.ssh_agent.register",
        "ping",
    ] {
        // ping is not forwarded until herdr_hosts. sleepy must not be probed.
        if blocked == "ping" {
            assert!(
                !machines
                    .recorded()
                    .iter()
                    .any(|row| row["method"] == "ping" && row["selector"] == "sleepy"),
                "disabled machine was forwarded"
            );
            continue;
        }
        assert!(
            !selectors.iter().any(|method| method == blocked),
            "{blocked} reached the machine layer: {selectors:?}"
        );
    }

    let lists_before_off = machines.lists.load(Ordering::Relaxed);
    gateway.store(false, Ordering::Release);
    let off = call(&node, &target, "gateway.machines", json!({}), 1).await;
    assert_eq!(off[0]["result"]["enabled"], false);
    assert_eq!(off[0]["result"]["machines"].as_array().unwrap().len(), 0);
    let blocked = call(
        &node,
        &target,
        "gateway.forward",
        json!({"machine": "instant-fill", "method": "agent.list", "params": {}}),
        1,
    )
    .await;
    assert_eq!(blocked[0]["error"]["code"], "gateway_disabled");
    assert_eq!(machines.lists.load(Ordering::Relaxed), lists_before_off);
    assert_eq!(machines.recorded().len(), selectors.len());

    let socket_methods: Vec<_> = seen
        .lock()
        .unwrap()
        .iter()
        .filter_map(|req| req["method"].as_str().map(str::to_string))
        .collect();
    assert!(
        socket_methods.contains(&"ping".to_string()),
        "{socket_methods:?}"
    );
    assert!(
        !socket_methods
            .iter()
            .any(|method| method.starts_with("gateway")),
        "{socket_methods:?}"
    );
    assert!(!socket_methods.contains(&"agent.list".to_string()));
    assert!(!socket_methods.contains(&"server.stop".to_string()));

    gateway.store(true, Ordering::Release);
    let client_toml = dir.path().join("client.toml");
    std::fs::write(
        &client_toml,
        toml::to_string_pretty(&ClientFile {
            default_host: Some("box".into()),
            hosts: BTreeMap::from([("box".into(), host)]),
        })
        .unwrap(),
    )
    .unwrap();
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

    let hosts = tool_json(&call_tool(&client, "herdr_hosts", json!({})).await);
    let names: Vec<_> = hosts
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["host"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"box".to_string()), "{names:?}");
    assert!(names.contains(&"box/instant-fill".to_string()), "{names:?}");
    assert!(names.contains(&"box/sleepy".to_string()), "{names:?}");
    let saved = hosts
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["host"] == "box/instant-fill")
        .unwrap();
    assert_eq!(saved["reachable"], true);
    assert_eq!(saved["machine_id"], MACHINE_ID);
    assert!(!saved.to_string().contains("secret-host"));
    let sleepy = hosts
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["host"] == "box/sleepy")
        .unwrap();
    assert_eq!(sleepy["reachable"], false);
    assert_eq!(sleepy["enabled"], false);

    let agents = call_tool(
        &client,
        "herdr_list_agents",
        json!({"host": "box/instant-fill"}),
    )
    .await;
    assert_ne!(agents.is_error, Some(true), "{}", tool_text(&agents));
    assert_eq!(tool_json(&agents)["result"]["echo_method"], "agent.list");

    let stop = call_tool(
        &client,
        "herdr_call",
        json!({"host": "box/instant-fill", "method": "server.stop", "params": {}}),
    )
    .await;
    assert_eq!(stop.is_error, Some(true));
    assert!(tool_text(&stop).contains("denied to every remote peer"));

    let methods: Vec<_> = machines
        .recorded()
        .iter()
        .map(|row| row["method"].as_str().unwrap().to_string())
        .collect();
    assert!(!methods.iter().any(|method| method == "server.stop"));

    client.cancel().await.unwrap();
    node.close().await;
    running.shutdown().await.unwrap();
}

async fn call(
    node: &Node,
    target: &herdr_iroh::client::DialTarget,
    method: &str,
    params: Value,
    lines: usize,
) -> Vec<Value> {
    node.call(
        target,
        &request_value(method, params),
        CallOptions {
            timeout: Duration::from_secs(15),
            max_lines: lines,
        },
    )
    .await
    .unwrap()
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
    serde_json::from_str(&tool_text(result)).unwrap()
}

async fn spawn_socket(path: std::path::PathBuf, seen: Arc<Mutex<Vec<Value>>>) {
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let seen = Arc::clone(&seen);
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
                let id = req.get("id").and_then(Value::as_str).unwrap_or("");
                let method = req.get("method").and_then(Value::as_str).unwrap_or("");
                let body = if method == "ping" {
                    json!({"id": id, "result": {"type": "pong", "version": "0.9.5", "protocol": 22}})
                } else {
                    json!({"id": id, "result": {"type": "ok", "echo_method": method}})
                };
                let mut out = stream.into_inner();
                let _ = out.write_all(format!("{body}\n").as_bytes()).await;
            });
        }
    });
}
