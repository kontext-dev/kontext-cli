<div align="center">

<img src="assets/banner-cli.svg" alt="Kontext CLI banner" width="100%" />

<p><strong>Local-first control for AI coding agents.</strong></p>

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

## Why Kontext exists

AI coding agents can now read code, run shell commands, open pull requests, call provider APIs, and touch production systems. But most teams still give them access the old way: long-lived tokens in `.env` files, copied credentials, and terminal sessions with almost no audit trail.

Kontext gives those agents a control layer without changing how developers work.

Use it locally to see what Claude Code is doing, which actions look risky, and why they were flagged. Use hosted mode when your team also wants short-lived scoped credentials, hosted traces, and governance across developers.

## What you get

- **Local-first Guard mode**: run Claude Code normally while Kontext records tool calls, scores risk locally, stores redacted traces in SQLite, and opens a local dashboard.
- **Short-lived credentials**: replace copied API keys with scoped credentials injected at session start and gone when the session ends.
- **Readable risk decisions**: every action is classified as `would allow`, `would ask`, or `would deny` in observe mode.
- **One CLI, two modes**: local-only guardrails for individual developers, hosted governance for teams.

## Fastest start

Install:

```bash
brew install kontext-security/tap/kontext
```

Start local Guard mode:

```bash
kontext guard start
```

Then run Claude Code as usual:

```bash
claude
```

Kontext installs the local Claude Code hooks, starts a daemon on `127.0.0.1:4765`, opens the dashboard, and stays in observe mode by default. Claude Code is not blocked.

## Two ways to run Kontext

### Local Guard mode

```bash
kontext guard start
```

Use this when you want local visibility and risk scoring without creating an account.

- no login
- no hosted API
- no trace upload by default
- local daemon
- local SQLite database
- local dashboard and notifications
- observe mode by default

Dashboard:

```text
http://127.0.0.1:4765
```

### Hosted mode

```bash
kontext start --agent claude
```

Use this when your team wants managed credentials and shared trace visibility.

On first run, Kontext authenticates you, prepares a `.env.kontext` file when needed, opens hosted connect for missing providers, exchanges placeholders such as `{{kontext:github}}` for short-lived scoped tokens, launches Claude Code, and expires credentials when the session ends.

Example `.env.kontext`:

```dotenv
GITHUB_TOKEN={{kontext:github}}
LINEAR_API_KEY={{kontext:linear}}
```

Provider setup and hosted traces live in [app.kontext.security](https://app.kontext.security).

## Architecture

Local Guard mode:

```text
Claude Code
  -> kontext guard hook claude-code
  -> local daemon
  -> deterministic risk rules
  -> Markov-chain risk model
  -> local SQLite
  -> local dashboard + notifications
```

Hosted mode:

```text
Claude Code
  -> kontext hook
  -> hosted session runtime
  -> scoped credential exchange
  -> hosted Kontext traces
  -> team governance
```

Guard mode is a local safety layer. It uses deterministic rules for obvious risk such as credential access, direct provider API calls, and destructive operations. The Markov-chain model adds sequence context for coding-agent workflows. It is local JSON, not an LLM and not a hosted scoring service.

## Useful commands

```bash
kontext guard status      # show local Guard counters
kontext guard dashboard   # open or print the local dashboard URL
kontext guard doctor      # check daemon and Claude Code hook state
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
