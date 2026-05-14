<div align="center">

<img src="assets/banner-cli.svg" alt="Kontext CLI banner" width="100%" />

<p>
  <a href="https://kontext.security">Website</a>
  ·
  <a href="https://docs.kontext.security/getting-started/welcome">Documentation</a>
  ·
  <a href="https://app.kontext.security">Dashboard</a>
  ·
  <a href="https://discord.gg/gw9UpFUhyY">Discord</a>
</p>

<p>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-152822?labelColor=0d1714"></a>
  <a href="https://github.com/kontext-security/kontext-cli/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/kontext-security/kontext-cli?color=152822&labelColor=0d1714"></a>
  <img alt="Built with Go" src="https://img.shields.io/badge/Go-1.25-152822?labelColor=0d1714">
</p>

</div>

## What is Kontext CLI?

Kontext CLI is an open-source local safety runtime for AI coding agents.

It lets AI coding agents, starting with Claude Code, keep working from the developer's machine while Kontext evaluates tool calls locally, applies policy, records allow/deny decisions, and explains what happened in a local dashboard.

**Why we built it:** AI coding agents now run shell commands, edit code, open pull requests, and call provider APIs from your machine. Most of the time that is exactly what you want. Sometimes it is `rm -rf`, `gcloud sql databases delete prod`, `git push --force main`, or a command that leaks a secret before you notice, [like it happened here](https://x.com/lifeof_jer/status/2048103471019434248).

**How it works:** `kontext guard start` runs locally. Agent hooks send tool events into the local runtime, deterministic policy handles known hard boundaries first, and probabilistic risk scoring evaluates allowed-but-ambiguous actions before Kontext stores the final decision and reason.

## Quick Start

```bash
brew install kontext-security/tap/kontext
kontext guard start
claude
```

That is it: local-only, no login, local policy, local decisions. The dashboard opens at `http://127.0.0.1:4765`.

## Local Guard

| Command | What it does |
| --- | --- |
| `kontext guard start` | Starts the local runtime, installs agent hooks, opens the dashboard, and evaluates tool calls locally. |
| `kontext guard status` | Shows local Guard counters and daemon state. |
| `kontext guard doctor` | Checks local daemon and agent hook setup. |

## What You Get

Guard turns agent tool calls into local safety decisions before they touch the machine.

```text
agent tool call -> deterministic policy -> probabilistic risk -> safety decision -> dashboard
```

**Local by default**
Claude Code tool calls are evaluated on the developer machine. No account, cloud setup, Node, or Docker is required for the default Guard path.

**Hard rules for known risk**
Deterministic policy handles the obvious danger zones first: credentials, destructive commands, production resources, provider access, and risky paths. These boundaries stay stable and predictable.

**Probabilistic risk for gray areas**
When a tool call is not clearly safe or unsafe, the local risk model evaluates the action in context and turns it into a reasoned safety decision.

**A dashboard that explains the call**
Every decision shows the layer that shaped it, the matched policy when there was one, the probabilistic risk result when used, the reason, and the final outcome.

## Optional Team Layer

Guard is the default path. Teams can add managed sessions when they want browser login, short-lived scoped credentials, and shared traces on top of local safety.

```bash
kontext start --agent claude
```

Managed sessions keep credentials out of agent config and project files. The CLI creates `.env.kontext` with provider placeholders:

```dotenv
GITHUB_TOKEN={{kontext:github}}
LINEAR_API_KEY={{kontext:linear}}
```

At runtime, Kontext exchanges those placeholders for short-lived scoped credentials for the active agent session. Literal values you add stay untouched.

> **Scaling across an organization?**
>
> We help with enterprise identity, audit retention, organization controls, deployment planning, custom usage volume, and onboarding for security and platform teams. [Contact michel@kontext.security](mailto:michel@kontext.security) or [book here](https://calendar.superhuman.com/book/11W5Y8b5JsB8dOzQbd/YECs9).

## Security

- Guard is local-only by default: no login and no trace upload.
- Guard stores redacted events, policy decisions, matched rules, and risk metadata in local SQLite.
- Deterministic policy runs before probabilistic risk scoring, so known hard boundaries do not depend on model judgment.
- Probabilistic risk scoring returns an allow/deny decision plus a reason for dashboard diagnostics.
- Kontext captures tool events and outcomes. It does not capture LLM reasoning, token usage, or full conversation history.

## Supported Agents

| Agent | Guard command | Status |
| --- | --- | --- |
| Claude Code | `kontext guard start` | Active |
| Codex | Coming soon | In development |

Claude Desktop, Cursor, and Copilot support are planned, but they are not shipped in this repo yet.

## Architecture

Local Guard:

```text
kontext guard start
  │
  ├─ Hooks: Claude Code tool events
  │    │
  │    ├─ PreToolUse        → kontext hook --agent claude --mode observe
  │    ├─ PostToolUse       → kontext hook --agent claude --mode observe
  │
  ├─ Local runtime: Unix socket service + RuntimeCore
  ├─ Local daemon: 127.0.0.1:4765
  ├─ Deterministic policy: curated rule categories + active profile
  ├─ Probabilistic risk: allow/deny for ambiguous actions
  ├─ Store: local SQLite with redacted events and decision metadata
  └─ Dashboard: policy controls, decision diagnostics, notifications
```

## Useful Commands

```bash
kontext guard status      # show local Guard counters
kontext guard dashboard   # open or print the local dashboard URL
kontext guard doctor      # check daemon and agent hook state
kontext doctor            # inspect global Kontext CLI setup
```

## Development

```bash
go build -o bin/kontext ./cmd/kontext
go test ./...
go test -race ./...
go vet ./...
pnpm install --frozen-lockfile
pnpm build
make guard-e2e
```

Generate protobuf code with:

```bash
buf generate
```

Service definitions live in [kontext-security/proto `agent.proto`](https://github.com/kontext-security/proto/blob/main/proto/kontext/agent/v1/agent.proto).

## Community

- Read [SUPPORT.md](SUPPORT.md) for support channels.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a contribution.
- Kontext CLI is released under the [MIT License](LICENSE).
