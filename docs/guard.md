# Kontext Guard

Guard is the local safety mode inside `kontext`.

It lets a developer run Claude Code normally while Kontext watches tool calls locally, redacts captured data, scores risk, stores events in local SQLite, and shows a local dashboard with `would allow`, `would ask`, and `would deny` decisions.

## User path

```bash
brew install kontext-security/tap/kontext
kontext guard start
claude
```

Until the Guard PR is merged and released, test from source:

```bash
go run ./cmd/kontext guard start
claude
```

## Runtime boundary

Guard mode is local-first by default:

- no login
- no hosted Kontext API
- no trace upload by default
- local daemon on `127.0.0.1:4765`
- local SQLite database
- embedded local dashboard
- observe mode by default

Hosted mode remains separate:

```bash
kontext start --agent claude
```

Hosted mode owns login, provider connection, short-lived scoped credentials, hosted traces, and team governance.

## Flow

```text
Claude Code
  -> kontext hook --agent claude --mode observe
  -> local runtime Unix socket
  -> RuntimeCore
  -> deterministic risk rules
  -> optional local LLM judge or Markov-chain risk model
  -> local SQLite
  -> local dashboard + notifications
```

## Risk layers

Guard uses two layers:

1. Deterministic rules for obvious risk, such as credential access, direct provider API calls with credential material, production mutations, and destructive persistent-resource operations.
2. A local Markov-chain risk model for sequence context in coding-agent workflows.

The shipped model is a JSON artifact under `models/guard/`. Lab is the private pipeline that ingests datasets and local traces, evaluates candidate models, and produces improved JSON files. Accepted model files are committed back to this repo by PR.

## Local judge

Guard can optionally call a localhost OpenAI-compatible judge, such as `llama-server`, after deterministic rules allow a blocking tool call:

```bash
kontext guard start \
  --judge-url http://127.0.0.1:8080 \
  --judge-model qwen3-0.6b-q4
```

The judge receives a small redacted JSON input with tool metadata, normalized risk fields, deterministic policy context, and no full conversation history. It must return structured JSON with `decision` set to `allow` or `deny`. `ask` is not part of the judge contract.

Judge failures are fail-open for launch. If the local runtime is unavailable, times out, or returns invalid JSON, Guard records `judge_unavailable_allow` plus high-level metadata and allows the tool call. Judge URLs must point at localhost.

## Public/private boundary

Public in `kontext-cli`:

- `kontext guard ...` commands
- Claude Code local hook adapter
- local daemon, SQLite store, dashboard, notifications
- deterministic risk rules
- shipped baseline/candidate model JSON files

Private in Lab:

- dataset ingestion
- OpenTelemetry/Claude trace import
- weak labeling
- model training/evaluation
- model promotion gates
- unpublished datasets and experiments

## Work tracking

Linear is the front door for planning. GitHub issues and Linear issues should sync.

- Linear project: `Kontext CLI`
- GitHub label: `area:kontext`
- Private pipeline project: `Lab / Model Pipeline`

Done means:

- issue has acceptance criteria
- PR links the issue
- tests pass
- this file or the Linear Excalidraw link is updated if architecture changed
