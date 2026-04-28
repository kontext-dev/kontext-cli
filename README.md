<div align="center">

<img src="assets/banner-cli.svg" alt="Kontext CLI banner" width="100%" />

<p><strong>Run Claude Code with hosted governance or local-only guardrails.</strong></p>

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

Kontext CLI is an open-source command-line tool for running AI coding agents with better credential handling, trace visibility, and local safety checks.

There are two ways to run Claude Code with Kontext:

```bash
kontext start --agent claude
```

Hosted mode. Kontext authenticates you, injects short-lived scoped credentials, starts a governed Claude Code session, and streams tool events to the hosted Kontext dashboard.

```bash
kontext guard start
```

Local Guard mode. No login, no hosted API, no trace upload by default. Kontext runs a local daemon, installs local Claude Code hooks, scores tool calls locally, stores redacted events in SQLite, and opens a local dashboard.

## Install

```bash
brew install kontext-security/tap/kontext
```

Prefer a direct binary? Download the latest build from [GitHub Releases](https://github.com/kontext-security/kontext-cli/releases).

## Hosted Mode

Use hosted mode when you want managed credentials and team-visible traces:

```bash
kontext start --agent claude
```

On first run, Kontext opens your browser for login and provider connection. It creates `.env.kontext` when needed, exchanges placeholders such as `{{kontext:github}}` for short-lived credentials, launches Claude Code, and expires credentials when the session ends.

Example `.env.kontext`:

```dotenv
GITHUB_TOKEN={{kontext:github}}
LINEAR_API_KEY={{kontext:linear}}
```

Provider setup and trace review live in [app.kontext.security](https://app.kontext.security).

## Local Guard Mode

Use local Guard mode when you want local-only visibility and risk scoring:

```bash
kontext guard start
claude
```

`kontext guard start`:

- verifies Claude Code is installed
- installs or updates the local Claude Code Guard hooks
- starts a daemon on `127.0.0.1:4765`
- opens the local dashboard
- records decisions as `would allow`, `would ask`, or `would deny`

Guard mode defaults to observe mode, so it does not block Claude Code.

Local dashboard:

```text
http://127.0.0.1:4765
```

Useful commands:

```bash
kontext guard status
kontext guard dashboard
kontext guard doctor
kontext guard hooks install claude-code
kontext guard hooks uninstall claude-code
```

## Security Model

Hosted mode:

- OIDC browser login
- refresh token stored in the system keyring
- RFC 8693 token exchange for short-lived provider credentials
- traces stream to Kontext

Local Guard mode:

- no login required
- no hosted API required
- no trace upload by default
- local SQLite persistence
- local Markov-chain risk model, not an LLM

## Architecture

Hosted mode:

```text
kontext start --agent claude
  -> auth
  -> hosted session
  -> credential exchange
  -> sidecar
  -> Claude Code hooks
  -> hosted Kontext traces
```

Local Guard mode:

```text
kontext guard start
  -> local Claude Code hooks
  -> local daemon
  -> deterministic risk rules
  -> Markov-chain score
  -> SQLite
  -> local dashboard + notifications
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
