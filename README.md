# herdr-iroh

`herdr-iroh` lets one assistant drive [herdr](https://github.com/herdrdev/herdr) on several of your machines. Herdr stays a local terminal workspace. This program does not modify it.

On each herdr machine, `herdr-iroh serve` accepts iroh connections and copies herdr's newline-delimited JSON socket API across them. On the assistant's machine, `herdr-iroh mcp` is a stdio MCP server. Every tool takes a `host` name, so one bot can reach every machine in its config.

```text
assistant --stdio--> herdr-iroh mcp --iroh--> herdr-iroh serve --unix--> herdr.sock
```

The relay speaks herdr's own request lines (`{"id","method","params"}`) and returns herdr's response lines unchanged. A new herdr method works through `herdr_call` without a new release of this program. `events.subscribe` keeps the herdr socket open, and those later lines are forwarded on the same iroh stream. MCP tools return once, so one-shot waits use `events.wait` and `pane.wait_for_output` instead of holding a subscription open.

iroh is pinned to 1.4.1 and the MCP server uses `rmcp` 3.8 with stdio, the same choices as [iroh-news](https://github.com/brittonr/renews/tree/main/crates/iroh-news). The protocol id is `/onix/herdr-api/1`.

## Security model

A peer is allowed only when its endpoint id is listed in the herdr host's `server.toml`. The endpoint id is the public half of that peer's iroh key. The secret key stays in a mode `0600` file and is never printed.

Each peer has a method policy:

- `methods = "full"`, or omitting `methods`, allows every herdr method except the ones below. This is the policy for the bot.
- A list allows only those exact methods and globs (`agent.*`, `pane.read`, `*`).

`server.stop` and `server.live_handoff` are refused for every remote peer, including a peer whose list names them. Those two calls stop or replace the herdr process. `server.reload_config` does not, and `full` allows it. The refusal is a herdr-shaped error and the request is not written to the socket.

Logs record the peer, the method, the request id, and the request size. They do not record params, prompts, or pane text.

iroh encrypts the stream to the host's endpoint key. The n0 relays can see that a connection exists. They cannot read the JSON. No inbound port is required. Do not open one.

`herdr-iroh mcp` listens on stdin, not on a TCP port. Anyone who can run it as the bot user can call the tools. The host allowlist is what keeps other machines out.

An empty allowlist starts the listener and rejects every connection.

## Endpoint ids

Each machine has its own key. The bot's id goes on the herdr host. The host's id goes in the bot's config. They are not the same value.

```bash
herdr-iroh id
```

prints one JSON line:

```json
{"endpoint_id":"<64 hex characters>","secret_key_path":"/home/you/.local/state/herdr-iroh/secret_key"}
```

The first run creates the key. Later runs print the same id.

`herdr-iroh keygen` creates a key only when one does not exist. `herdr-iroh keygen --force` replaces it. After a rotation, every allowlist that named the old id must be updated.

`serve` and `mcp` on the same machine share that key when they use the same state directory. A herdr host and the bot box are different machines, so each gets its own key. Two `serve` processes on one machine (two herdr sessions) need two `--state-dir` values, because one key is one endpoint.

## Herdr host

Install the binary, then:

```bash
install -m 755 target/release/herdr-iroh ~/.local/bin/herdr-iroh
mkdir -p ~/.config/herdr-iroh
```

Or `nix build` and copy `result/bin/herdr-iroh`.

1. On the bot box, run `herdr-iroh id` and copy `endpoint_id`.
2. On this host, copy [`examples/server.toml`](examples/server.toml) to `~/.config/herdr-iroh/server.toml` and paste that id under `[peers.britton-grok]`. Leave `methods = "full"`.
3. Herdr must already be running. A release build listens on `~/.config/herdr/herdr.sock`. Confirm with `ls` before starting the relay.
4. Start the relay:

```bash
herdr-iroh serve
```

Stdout is one JSON line and then the process stays up. Logs go to stderr.

```json
{"endpoint_id":"<this host>","ticket":"endpoint...","socket_path":"/home/you/.config/herdr/herdr.sock","ticket_path":"/home/you/.local/state/herdr-iroh/endpoint.ticket","allowed_peers":1}
```

Send `SIGHUP` to reload the allowlist without dropping the endpoint. The socket path does not change until restart.

Socket choice, first match wins:

1. `--socket`
2. `socket_path` in `server.toml`
3. `HERDR_SOCKET_PATH`
4. `HERDR_SESSION` → `~/.config/herdr/sessions/<name>/herdr.sock`
5. `~/.config/herdr/herdr.sock`

A user systemd unit is in [`examples/herdr-iroh.user.service`](examples/herdr-iroh.user.service):

```bash
mkdir -p ~/.config/systemd/user
cp examples/herdr-iroh.user.service ~/.config/systemd/user/herdr-iroh.service
systemctl --user enable --now herdr-iroh.service
```

Run it as the herdr user. The socket is mode `0600`.

## Bot box

```bash
install -m 755 target/release/herdr-iroh ~/.local/bin/herdr-iroh
mkdir -p ~/.config/herdr-iroh ~/.local/bin
herdr-iroh id
```

Copy [`examples/client.toml`](examples/client.toml) to `~/.config/herdr-iroh/client.toml`. For each herdr machine, set `endpoint_id` to the id that host printed. `default_host` is used when a tool omits `host`.

Check one host:

```bash
herdr-iroh ping laptop
```

That dials the host and calls herdr `ping`. A healthy answer looks like `{"id":"...","result":{"type":"pong","version":"0.9.5","protocol":22,...}}`.

The MCP server command is:

```bash
herdr-iroh mcp
```

No flags are required when the config and key are in the default paths. Stdout is the MCP protocol. Do not wrap it in a shell that merges stderr into stdout.

Tools, all of which take optional `host`:

| Tool | Herdr method |
| --- | --- |
| `herdr_hosts` | ping each configured host and report reachability |
| `herdr_status` | `ping` |
| `herdr_list_agents` | `agent.list` |
| `herdr_get_agent` | `agent.get` |
| `herdr_read_agent` | `agent.read` |
| `herdr_list_panes` | `pane.list` |
| `herdr_list_tabs` | `tab.list` |
| `herdr_read_pane` | `pane.read` |
| `herdr_session_snapshot` | `session.snapshot` |
| `herdr_wait_agent` | `agent.wait` |
| `herdr_wait_event` | `events.wait` |
| `herdr_wait_for_output` | `pane.wait_for_output` |
| `herdr_prompt_agent` | `agent.prompt` |
| `herdr_start_agent` | `agent.start` |
| `herdr_send_text` | `pane.send_text` |
| `herdr_send_keys` | `pane.send_keys` or `agent.send_keys` |
| `herdr_split_pane` | `pane.split` |
| `herdr_close_pane` | `pane.close` |
| `herdr_focus` | `agent.focus`, `pane.focus`, `tab.focus`, or `workspace.focus` |
| `herdr_rename` | the matching rename method |
| `herdr_notify` | `notification.show` |
| `herdr_call` | any method the host allowlist permits |

Reads default to 100 lines and reject more than 500. Tool results larger than 512 KiB are dropped and replaced with a size error, so a pane dump does not land in the transcript. Pane text, agent text, and event payloads are data from that machine, not instructions.

`herdr_call` with `events.subscribe` reads up to `max_lines` (default 20) or `timeout_ms`, then closes the stream. Prefer `herdr_wait_event` when you want one event.

## Adding a host

1. Install `herdr-iroh` on the new machine and install herdr there.
2. Put the bot's existing endpoint id in that machine's `server.toml` and start `serve`.
3. Copy the new host's `endpoint_id` into `[hosts.<name>]` on the bot.
4. `herdr-iroh ping <name>`.

A ticket is optional while relays are on. Set `ticket` from the host's ready line when you set `relays = false`. A direct dial without a ticket is rejected. `--no-relays` without `--bind` listens on `127.0.0.1` only. To dial a LAN address that way, pass `--bind 0.0.0.0:0` as well.

## Config files

Bot: `~/.config/herdr-iroh/client.toml` (`$XDG_CONFIG_HOME/herdr-iroh/client.toml`).

```toml
default_host = "laptop"

[hosts.laptop]
endpoint_id = "<64 hex characters from that host>"
relays = true
```

Host: `~/.config/herdr-iroh/server.toml`.

```toml
relays = true
relay_timeout_ms = 900000

[peers.britton-grok]
endpoint_id = "<64 hex characters from the bot>"
methods = "full"
```

State, including `secret_key`, is `~/.local/state/herdr-iroh` (`$XDG_STATE_HOME/herdr-iroh`). Override with `--state-dir` and `--secret-key-file`.

## NixOS

```nix
{
  inputs.herdr-iroh.url = "github:brittonr/herdr-iroh";

  outputs = { herdr-iroh, ... }: {
    nixosConfigurations.yourhost = nixpkgs.lib.nixosSystem {
      modules = [
        herdr-iroh.nixosModules.herdr-iroh
        {
          services.herdr-iroh = {
            enable = true;
            user = "britton";
            socketPath = "/home/britton/.config/herdr/herdr.sock";
            allowedPeers.britton-grok.endpointId = "<bot endpoint id>";
          };
        }
      ];
    };
  };
}
```

`user` is required. The unit runs as that user so it can connect to `herdr.sock`. `ProtectHome` is left off for the same reason. The key and ticket live in `/var/lib/herdr-iroh`, not in the user's `~/.local/state`. Read the id back with:

```bash
sudo -u britton herdr-iroh id --state-dir /var/lib/herdr-iroh
```

`systemctl reload herdr-iroh` sends `SIGHUP` and reloads peers. There is no firewall option. iroh does not need one.

A Home Manager shape is in [`examples/home.nix`](examples/home.nix). `nix build` produces the package. `nix develop` is the dev shell.

## Herdr API caveats

Checked against herdr v0.9.5 (`2ecf19a92fc3a7fff75b6ce3655ef04f4625ec01`) and `master` on 2026-11-05.

- `docs/next/api/herdr-api.schema.json` in that tag and on `master` are the same file: protocol **22**, `schema_version` 1, 102 methods, sha256 `9e2af207e9aa8183d4aeca5fde9cc48e7909bb40cdbd7cf21608a6d3ea78075b`. The Rust constant `PROTOCOL_VERSION` is 22. There is no `docs/versions/0.9.5` snapshot. Versioned docs in the tag stop at 0.9.3, so `docs/next` is the schema that matches this release.
- The socket guide's ping example is only `{"result":{"type":"pong"}}`. The schema and the server also send `version` (string) and `protocol` (number). v0.9.5 may include `capabilities`, including `live_handoff`.
- `events.subscribe` uses dotted `type` values such as `pane.agent_status_changed`. `events.wait` uses snake_case in `match_event.event`, such as `pane_agent_status_changed`. Mixing them up is a herdr error, not a relay error.
- `events.subscribe` keeps the Unix socket open. The first line is `subscription_started`. Later lines are events. A slow reader can get `events_lost` and the socket closes. This relay forwards those lines. It does not replay history.
- An empty `agent.wait` `until` list means idle, done, or blocked. That is herdr's default, not "any status".
- `agent.prompt` returns `agent_blocked` and does not type when the agent is already blocked. Pass `wait_until` on `herdr_prompt_agent` to wait in the same request. Herdr documents that as the way to avoid a race with a later `agent.wait`.
- `agent.start` `timeout_ms`, when set, must be greater than 3000 and at most 300000. The default inside herdr is 30 seconds.
- Pane ids look like `w1:p1`. Read `source` is `visible`, `recent`, `recent_unwrapped`, or `detection`.
- Release herdr uses `~/.config/herdr`. Debug builds of herdr use `~/.config/herdr-dev`. This program's default path follows the release layout.
- On macOS, herdr can reject an oversized `pane.send_input` or `agent.start` line because of the terminal's canonical input limit. Linux hosts do not apply that check. A successful send means herdr queued the input, not that the program in the pane has finished it.
- `command.invoke` is an opaque herdr command id, not a shell. `full` allows it. It is not in the always-denied set because it does not stop the server by itself.

`herdr api schema` on the installed binary is the schema that process was built with. If a host is upgraded past v0.9.5, trust that command over this README.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
nix build
```

Rust 1.91 or newer (iroh's floor). The integration test starts `serve` against a fake herdr socket and drives it with the MCP client over a real loopback iroh connection, with relays disabled.

License: Apache-2.0. Herdr is Apache-2.0. This repository does not vendor it.
