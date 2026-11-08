//! `herdr-iroh` — herdr's socket API over iroh, plus a stdio MCP server.
//!
//! `id`, `keygen`, `ping`, and the `serve` ready line print one JSON object
//! on stdout. Logs go to stderr. `mcp` uses stdout for the MCP protocol.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use herdr_iroh::client::{CallOptions, Node, dial_target};
use herdr_iroh::config::{self, ClientFile, ServerFile};
use herdr_iroh::gateway::CliMachines;
use herdr_iroh::keys;
use herdr_iroh::protocol::request_value;
use herdr_iroh::serve::{ServeOptions, serve};
use serde::Serialize;
use serde_json::json;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "herdr-iroh",
    version,
    about = "Relay a local herdr socket over iroh, or drive remote herdr hosts from MCP"
)]
struct Cli {
    /// Config file. `serve` defaults to `~/.config/herdr-iroh/server.toml`.
    /// `mcp` and `ping` default to `~/.config/herdr-iroh/client.toml`.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Directory for this node's iroh secret key. Defaults to `~/.local/state/herdr-iroh`.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    /// Secret key file. Defaults to `secret_key` inside the state directory.
    #[arg(long, global = true)]
    secret_key_file: Option<PathBuf>,
    /// Do not use n0 relays. Without `--bind`, the endpoint listens on 127.0.0.1.
    #[arg(long, global = true)]
    no_relays: bool,
    /// UDP address to bind. Example: `127.0.0.1:0`.
    #[arg(long, global = true)]
    bind: Option<SocketAddr>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print this node's endpoint id. Creates a secret key if you do not have one yet.
    Id,
    /// Create a secret key. Refuses to replace an existing key unless `--force` is set.
    Keygen {
        /// Replace the existing key. Peers that allowlisted the old id must be updated.
        #[arg(long)]
        force: bool,
    },
    /// Accept iroh connections and relay them to the local herdr socket.
    Serve {
        /// Herdr Unix socket. Overrides `socket_path` in the config file.
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// stdio MCP server. Does not listen on a TCP port.
    Mcp,
    /// Dial a configured host and call herdr `ping`.
    Ping {
        /// Host name from `client.toml`.
        host: String,
    },
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn real_main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match &cli.command {
        Command::Id => {
            let path = key_path(&cli);
            let key = keys::load_or_create(&path)?;
            print_json(&json!({
                "endpoint_id": keys::endpoint_id(&key),
                "secret_key_path": path,
            }))
        }
        Command::Keygen { force } => {
            let path = key_path(&cli);
            let existed = path.exists();
            let key = keys::generate(&path, *force)?;
            print_json(&json!({
                "endpoint_id": keys::endpoint_id(&key),
                "secret_key_path": path,
                "created": !existed,
                "rotated": existed && *force,
            }))
        }
        Command::Serve { socket } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(cmd_serve(&cli, socket.clone()))
        }
        Command::Mcp => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(cmd_mcp(&cli))
        }
        Command::Ping { host } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(cmd_ping(&cli, host))
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("herdr_iroh=info,iroh=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .init();
}

fn state_dir(cli: &Cli) -> PathBuf {
    cli.state_dir.clone().unwrap_or_else(config::state_dir)
}

fn key_path(cli: &Cli) -> PathBuf {
    cli.secret_key_file
        .clone()
        .unwrap_or_else(|| keys::secret_key_path(&state_dir(cli)))
}

fn server_config_path(cli: &Cli) -> PathBuf {
    cli.config
        .clone()
        .unwrap_or_else(|| config::config_dir().join(config::SERVER_FILE))
}

fn client_config_path(cli: &Cli) -> PathBuf {
    cli.config
        .clone()
        .unwrap_or_else(|| config::config_dir().join(config::CLIENT_FILE))
}

async fn cmd_serve(cli: &Cli, socket: Option<PathBuf>) -> anyhow::Result<()> {
    let config_path = server_config_path(cli);
    let file = ServerFile::load(&config_path).with_context(|| {
        format!(
            "loading {} (an empty peers table rejects every connection)",
            config_path.display()
        )
    })?;
    let allow = Arc::new(RwLock::new(file.allowlist()?));
    let gateway = Arc::new(AtomicBool::new(file.gateway));
    let notify = file.notify_config()?;
    let herdr_bin = file
        .herdr_bin
        .clone()
        .unwrap_or_else(|| PathBuf::from("herdr"));
    let socket_path = socket
        .or(file.socket_path.clone())
        .unwrap_or_else(config::default_herdr_socket);
    let relays = file.relays && !cli.no_relays;
    let key = keys::load_or_create(&key_path(cli))?;
    let peer_count = allow.read().await.len();
    if peer_count == 0 {
        tracing::warn!("allowlist is empty; every iroh peer will be rejected");
    }
    tracing::info!(
        socket = %socket_path.display(),
        peers = peer_count,
        relays,
        gateway = file.gateway,
        "iroh does not need an open inbound port; peers use relays unless relays are disabled"
    );
    let running = serve(ServeOptions {
        secret_key: key,
        socket_path: socket_path.clone(),
        allow: Arc::clone(&allow),
        gateway: Arc::clone(&gateway),
        machines: Arc::new(CliMachines::new(herdr_bin)),
        notify,
        dedupe_ttl: Duration::from_millis(file.prompt_dedupe_ttl_ms),
        relays,
        bind_addr: cli.bind,
        relay_timeout: Duration::from_millis(file.relay_timeout_ms),
    })
    .await?;
    let ticket_path = write_ticket(&state_dir(cli), &running.ticket)?;
    print_json(&json!({
        "endpoint_id": running.endpoint_id.to_string(),
        "ticket": running.ticket,
        "socket_path": socket_path,
        "ticket_path": ticket_path,
        "allowed_peers": peer_count,
        "gateway": gateway.load(Ordering::Acquire),
    }))?;

    wait_for_shutdown(&config_path, &allow, &gateway).await;
    running.shutdown().await
}

async fn wait_for_shutdown(
    config_path: &Path,
    allow: &RwLock<herdr_iroh::Allowlist>,
    gateway: &AtomicBool,
) {
    use tokio::signal::unix::{SignalKind, signal};
    let mut hangup = match signal(SignalKind::hangup()) {
        Ok(signal) => signal,
        Err(err) => {
            tracing::warn!(error = %err, "SIGHUP reload is unavailable");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(err) => {
            tracing::warn!(error = %err, "SIGTERM handling is unavailable");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            _ = hangup.recv() => reload_server_config(config_path, allow, gateway).await,
        }
    }
}

async fn reload_server_config(
    config_path: &Path,
    allow: &RwLock<herdr_iroh::Allowlist>,
    gateway: &AtomicBool,
) {
    match ServerFile::load(config_path) {
        Ok(file) => match file.allowlist() {
            Ok(next) => {
                let peers = next.len();
                let saved_machines = file.gateway;
                *allow.write().await = next;
                gateway.store(saved_machines, Ordering::Release);
                tracing::info!(peers, gateway = saved_machines, "reloaded server config");
            }
            Err(err) => tracing::error!(error = %err, "allowlist reload rejected"),
        },
        Err(err) => tracing::error!(error = %err, "server config reload failed"),
    }
}

async fn cmd_mcp(cli: &Cli) -> anyhow::Result<()> {
    let config_path = client_config_path(cli);
    let file = ClientFile::load(&config_path).with_context(|| {
        format!(
            "loading {} (list each herdr host under [hosts])",
            config_path.display()
        )
    })?;
    let relays = !cli.no_relays;
    let key = keys::load_or_create(&key_path(cli))?;
    let node = Node::new(key, relays, cli.bind);
    tracing::info!(
        endpoint_id = %node.endpoint_id(),
        hosts = file.hosts.len(),
        "mcp ready"
    );
    herdr_iroh::mcp::run(Arc::new(node), file).await
}

async fn cmd_ping(cli: &Cli, host: &str) -> anyhow::Result<()> {
    let file = ClientFile::load(&client_config_path(cli))?;
    let route = file.resolve_route(Some(host))?;
    let host_cfg = file
        .hosts
        .get(&route.name)
        .context("resolved host is missing")?;
    let (method, params) = if let Some(machine) = &route.machine {
        (
            "gateway.forward",
            json!({"machine": machine, "method": "ping", "params": {}}),
        )
    } else {
        ("ping", json!({}))
    };
    let relays = !cli.no_relays;
    let key = keys::load_or_create(&key_path(cli))?;
    let node = Node::new(key, relays, cli.bind);
    let target = dial_target(host_cfg, node.relays_enabled())?;
    let lines = node
        .call(
            &target,
            &request_value(method, params),
            CallOptions {
                timeout: Duration::from_secs(20),
                max_lines: 1,
            },
        )
        .await?;
    print_json(lines.first().context("ping returned no line")?)
}

fn write_ticket(state_dir: &Path, ticket: &str) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;
    let path = state_dir.join("endpoint.ticket");
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(ticket.as_bytes())?;
        file.write_all(b"\n")?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

fn print_json(value: &impl Serialize) -> anyhow::Result<()> {
    serde_json::to_writer(std::io::stdout(), value)?;
    println!();
    Ok(())
}
