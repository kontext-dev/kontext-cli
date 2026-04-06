# Kontext CLI

## The problem

AI coding agents (Claude Code, Cursor, Codex) run on your laptop with whatever credentials you have lying around — long-lived API keys in `.env` files, GitHub tokens in your shell, database passwords in your config. There's no scoping, no audit trail, no way for a team lead to see what agents are doing across the org.

## What the CLI does

One command:

```bash
kontext start --agent claude
```

This launches Claude Code, but with two things added:

1. **Scoped credentials** — instead of using whatever's in your shell, the agent gets short-lived tokens resolved from your Kontext account. They expire when the session ends.

2. **Telemetry** — every tool call (file edits, shell commands, API calls) is logged to the Kontext dashboard. The team sees who did what, when, and whether it was allowed.

## How it works (the 30-second version)

```
You run: kontext start --agent claude

1. CLI checks your identity (OIDC token in your system keychain)
2. CLI reads .env.kontext to see what credentials the project needs
3. CLI resolves each credential from the Kontext backend
4. CLI launches Claude Code with those credentials as env vars
5. Every tool call Claude makes gets logged to your team's dashboard
6. When you exit, credentials expire, session ends
```

## The codebase

### Three binaries in one

The CLI is a single Go binary that runs in three modes:

- **`kontext start`** — the main command. Orchestrates everything, stays alive for the session.
- **`kontext hook`** — called by Claude Code automatically on every tool call. You never run this yourself.
- **`kontext login`** — one-time browser login. Stores your identity in the system keychain.

They're the same binary because Claude Code needs to spawn hook handlers by command name. One binary = no install issues.

### Why Go

The hook handler (`kontext hook`) gets spawned on every single tool call — every file edit, every shell command, every API request. Node.js takes 50-100ms to start. Go takes 5ms. Over a session with hundreds of tool calls, this matters.

Go also compiles to a single binary with zero dependencies. `brew install` and you're done.

### Project structure

```
cmd/kontext/main.go         — CLI entry point (start, login, hook commands)
internal/
  agent/                    — agent adapter interface
    claude/claude.go        — Claude Code hook I/O format
  auth/                     — OIDC login + keychain storage
  backend/                  — ConnectRPC client for the Kontext API
  credential/               — .env.kontext template parser
  hook/                     — hook event processor (stdin → evaluate → stdout)
  run/                      — the start command orchestrator
    hooks.go                — generates Claude Code hook config
  sidecar/                  — local Unix socket server
    protocol.go             — wire format for hook ↔ sidecar communication
gen/                        — generated protobuf code (from kontext-dev/proto)
```

### The sidecar — why it exists

When Claude Code makes a tool call, it spawns `kontext hook` as a new process. That process needs to log the event and get a policy decision. If it made a network call to the backend every time, that's 100-300ms per tool call — unacceptable.

The sidecar solves this. It's a small server that starts alongside Claude Code and listens on a Unix socket file. The hook handler connects to it locally (sub-millisecond), and the sidecar maintains a persistent connection to the backend.

```
Claude Code → spawns kontext hook → Unix socket → sidecar → backend
                 (5ms)              (0ms)          (already connected)
```

The sidecar also sends heartbeats every 30 seconds to keep the session alive in the dashboard.

### Agent adapters

Each agent (Claude Code, Cursor, Codex) has a different format for hook events. The adapter translates:

```go
type Agent interface {
    Name() string                                    // "claude"
    DecodeHookInput([]byte) (*HookEvent, error)      // parse agent's JSON
    EncodeAllow(*HookEvent, string) ([]byte, error)  // format allow response
    EncodeDeny(*HookEvent, string) ([]byte, error)   // format deny response
}
```

Everything else — the sidecar, telemetry, credential resolution, policy evaluation — is shared. Adding a new agent is one file with four methods.

### Credential injection

A `.env.kontext` file in the project declares what credentials the agent needs:

```
GITHUB_TOKEN={{kontext:github}}
STRIPE_KEY={{kontext:stripe}}
```

Before launching the agent, the CLI resolves each placeholder by calling the Kontext backend with the user's identity. The backend returns a short-lived credential (could be an OAuth token, could be an API key — the CLI doesn't distinguish). These become env vars in the agent's process.

The agent uses them naturally — `git push` reads `GITHUB_TOKEN`, `curl` reads `STRIPE_KEY`. No special SDK, no interception.

### Auth

No client secrets. The user logs in once via browser (`kontext login`), and a refresh token is stored in the system keychain (macOS Keychain / Linux secret service). Every `kontext start` loads and refreshes the token automatically. The backend verifies the JWT and knows who the user is and which org they belong to.

### Telemetry vs credentials — two separate things

The CLI has two backend integrations that are completely independent:

**Telemetry** — session lifecycle + hook events. Uses ConnectRPC (gRPC-compatible) with bidirectional streaming. The proto lives in `kontext-dev/proto`. This is what powers the dashboard.

**Credentials** — provider token resolution. Uses a plain REST endpoint (`POST /api/v1/credentials/exchange`). This is what populates the env vars.

They use different protocols because they have different needs. Telemetry needs streaming (hundreds of events per session over one connection). Credentials need a simple request/response (one call per provider at session start).

### What's working today

- `kontext login` — browser OIDC login, keychain storage, token refresh
- `kontext start --agent claude` — launches Claude Code, interactive `.env.kontext` setup on first run
- Agent adapter for Claude Code — full hook I/O encoding/decoding
- Sidecar with Unix socket — accepts hook connections, relays events
- Hook command — reads stdin, talks to sidecar, writes decision to stdout
- Settings generation — creates Claude Code hook config automatically

### What's blocked on the server

- **Telemetry** (#408) — needs ConnectRPC `AgentService` endpoint on the API + auth change to accept user bearer tokens
- **Credentials** (#410) — needs `POST /api/v1/credentials/exchange` endpoint authenticated with user tokens

Both are unblocked by the same server-side auth change: `UnifiedAuthGuard` learning to accept user OIDC tokens as bearer tokens, not just service account tokens.
