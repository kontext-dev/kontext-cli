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

Kontext is a local security guardrail for AI coding agents.

Agents like Claude Code can now run shell commands, edit code, open pull requests, and call provider APIs from your machine. Most of the time that is exactly what you want. Sometimes it is `rm -rf`, `gcloud sql databases delete prod`, `git push --force main`, or a command that leaks a secret before you notice.

Kontext gives you a seatbelt for that workflow. You stay in flow, but risky actions are surfaced while the agent is working instead of after the damage is done.

## What you get

- **Local by default**: `kontext guard start` runs a local daemon. No login, no hosted API, no trace upload by default.
- **A live feed of agent actions**: Claude Code tool calls are captured, redacted, scored, and shown in a local dashboard.
- **Risk notifications**: in observe mode, Kontext surfaces actions that look like `ask` or `deny` so you can review what your agent actually did.
- **A path to enforcement**: today Guard observes; next it can ask before risky commands run; later it can block the delete-prod class outright.
- **Hosted governance when you need it**: teams can use hosted mode for short-lived scoped credentials, shared traces, and policy across developers.

## Fastest start

```bash
brew install kontext-security/tap/kontext
kontext guard start
claude
```

That starts the local daemon, installs the Claude Code hooks, opens the dashboard, and leaves Claude Code running normally. Guard mode is observe-only by default.

Dashboard:

```text
http://127.0.0.1:4765
```

## Two ways to run Kontext

### Local Guard mode

```bash
kontext guard start
```

Best for individual developers who want local visibility and safety checks first.

```text
local daemon -> redacted traces -> risk scoring -> local dashboard + notifications
```

Local Guard mode does not require an account and does not upload your code or traces by default.

### Hosted mode

```bash
kontext start --agent claude
```

Best for teams that want governed credentials and shared trace visibility.

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
