# Kontext CLI

Governed agent sessions for Claude Code, Cursor, and other AI agents. One command to run any agent with scoped credentials and policy enforcement.

## How it works

```bash
kontext start --agent claude
```

1. **Authenticates** — loads your identity from the system keyring (set up via `kontext login`)
2. **Resolves credentials** — reads `.env.kontext`, exchanges placeholders for short-lived tokens via Kontext
3. **Launches the agent** — spawns Claude Code with credentials injected as env vars
4. **Enforces policy** — every tool call is evaluated against your org's OpenFGA policy (via a local sidecar)
5. **Logs everything** — full audit trail streamed to the Kontext backend via gRPC

Credentials are ephemeral — scoped to the session, gone when it ends.

## Install

```bash
brew install kontext-dev/tap/kontext
```

Or build from source:

```bash
go build -o bin/kontext ./cmd/kontext
```

## Usage

### First-time setup

```bash
kontext login
```

Opens a browser for OIDC authentication. Stores your refresh token in the system keyring (macOS Keychain / Linux secret service). No client IDs or secrets to manage.

### Declare credentials

Create a `.env.kontext` file in your project:

```
GITHUB_TOKEN={{kontext:github}}
STRIPE_KEY={{kontext:stripe}}
DATABASE_URL={{kontext:postgres/prod-readonly}}
```

### Run

```bash
kontext start --agent claude
```

The CLI resolves each placeholder, injects the credentials as env vars, and launches Claude Code with governance hooks active.

### Supported agents

| Agent | Flag | Status |
|---|---|---|
| Claude Code | `--agent claude` | Active |
| Cursor | `--agent cursor` | Planned |
| Codex | `--agent codex` | Planned |

## Architecture

```
kontext start --agent claude
  │
  ├── Auth: OIDC refresh token from keyring → ephemeral session token
  ├── Credentials: .env.kontext → ExchangeCredential RPC → env vars
  ├── Sidecar: Unix socket server for hook ↔ backend communication
  ├── Agent: spawn claude with injected env + hook config
  │     │
  │     ├── [PreToolUse]  → hook binary → sidecar → policy eval → allow/deny
  │     └── [PostToolUse] → hook binary → sidecar → audit log
  │
  └── Backend: bidirectional gRPC stream (ProcessHookEvent, SyncPolicy)
```

**Hook handlers** are the compiled `kontext hook` binary — <5ms startup, communicates with the sidecar over a Unix socket. No per-hook HTTP requests.

**Policy evaluation** uses OpenFGA tuples cached locally by the sidecar. The backend streams policy updates in real-time via `SyncPolicy`.

## Protocol

Service definitions: [`proto/kontext/agent/v1/agent.proto`](proto/kontext/agent/v1/agent.proto)

Uses [ConnectRPC](https://connectrpc.com/) (gRPC-compatible) for backend communication.

## Development

```bash
# Build
go build -o bin/kontext ./cmd/kontext

# Generate protobuf (requires buf)
buf generate

# Test
go test ./...
```

## License

MIT
