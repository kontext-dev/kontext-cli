# Hermes Agent Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `kontext start --agent hermes` support — launches Nous Research's Hermes agent with short-lived Kontext credentials in env and routes MCP tool calls through a Kontext MCP server for governance/trace parity with the Claude integration.

**Architecture:** A new `internal/agent/hermes` adapter implements the existing `agent.Agent` interface. A session-scoped `HERMES_HOME` temp dir is seeded with `config.yaml` (user base config merged with a `kontext` stdio MCP server entry) and `.env` (resolved credentials). A new hidden `kontext mcp-serve --agent hermes` subcommand speaks MCP over stdio, bridges each `tools/call` to the existing Kontext sidecar (PreToolUse/PostToolUse), and executes the call using the credentials in its env.

**Tech Stack:** Go 1.25, cobra (CLI), existing Kontext sidecar (Unix socket, length-prefixed JSON), YAML (`gopkg.in/yaml.v3`), MCP over stdio using `github.com/mark3labs/mcp-go` (JSON-RPC 2.0 for MCP).

---

## File Structure

New files:

- `internal/agent/hermes/hermes.go` — `Agent` adapter; `DecodeHookInput` / `EncodeAllow` / `EncodeDeny`; `init()` registers via `agent.Register`.
- `internal/agent/hermes/hermes_test.go` — table-driven unit tests.
- `internal/run/hermes_config.go` — `BuildHermesHome(sessionDir, kontextBin, socketPath string, resolved []credential.Resolved) (hermesHome string, err error)`; writes `config.yaml` + `.env` under `<sessionDir>/hermes/`.
- `internal/run/hermes_config_test.go` — unit tests for config merge + `.env` writer.
- `internal/mcpserve/server.go` — stdio MCP server, `Run(ctx, agentName, socketPath) error`; exposes one tool (`kontext.invoke`), bridges to sidecar.
- `internal/mcpserve/server_test.go` — integration test against a fake sidecar.
- `cmd/kontext/mcpserve.go` — `mcp-serve` cobra subcommand; hidden.

Modified files:

- `internal/run/run.go` — extract an agent-shaped launch adapter; branch Claude vs Hermes for session prep + launch argv/env.
- `cmd/kontext/main.go` — register `mcp-serve` subcommand; blank-import `internal/agent/hermes`; update `--agent` flag help text.
- `go.mod` / `go.sum` — add `gopkg.in/yaml.v3` and `github.com/mark3labs/mcp-go`.

---

## Task 1: Add dependencies

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add deps**

Run:

```bash
cd /Users/vishi/repos/kontext/kontext-cli
go get gopkg.in/yaml.v3@latest
go get github.com/mark3labs/mcp-go@latest
go mod tidy
```

- [ ] **Step 2: Verify build still passes**

Run: `go build ./...`
Expected: exits 0 with no output.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add yaml.v3 and mcp-go deps for hermes integration"
```

---

## Task 2: Hermes agent adapter — skeleton and registration

**Files:**
- Create: `internal/agent/hermes/hermes.go`
- Create: `internal/agent/hermes/hermes_test.go`

The Kontext MCP server constructs the hook envelope itself (not Hermes), so the adapter's decode/encode shape is what we define. Use a JSON envelope that mirrors Claude's fields: `session_id`, `hook_event_name`, `tool_name`, `tool_input`, `tool_response`, `tool_use_id`, `cwd`. Allow/deny encoding uses a simple shape: `{"permission": "allow|deny", "reason": "..."}`.

- [ ] **Step 1: Write the failing tests**

`internal/agent/hermes/hermes_test.go`:

```go
package hermes

import (
	"encoding/json"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

func TestDecodeHookInput(t *testing.T) {
	raw := []byte(`{
		"session_id": "sess-1",
		"hook_event_name": "PreToolUse",
		"tool_name": "kontext.invoke",
		"tool_input": {"provider": "github"},
		"tool_use_id": "tu-1",
		"cwd": "/tmp"
	}`)
	h := &Hermes{}
	ev, err := h.DecodeHookInput(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.SessionID != "sess-1" || ev.HookEventName != "PreToolUse" || ev.ToolName != "kontext.invoke" {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if got := ev.ToolInput["provider"]; got != "github" {
		t.Fatalf("tool_input not decoded: %v", got)
	}
}

func TestEncodeAllowDeny(t *testing.T) {
	h := &Hermes{}
	ev := &agent.HookEvent{HookEventName: "PreToolUse"}

	allowBytes, err := h.EncodeAllow(ev, "ok")
	if err != nil {
		t.Fatalf("allow: %v", err)
	}
	var allow map[string]any
	if err := json.Unmarshal(allowBytes, &allow); err != nil {
		t.Fatalf("allow unmarshal: %v", err)
	}
	if allow["permission"] != "allow" || allow["reason"] != "ok" {
		t.Fatalf("unexpected allow: %v", allow)
	}

	denyBytes, err := h.EncodeDeny(ev, "nope")
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	var deny map[string]any
	if err := json.Unmarshal(denyBytes, &deny); err != nil {
		t.Fatalf("deny unmarshal: %v", err)
	}
	if deny["permission"] != "deny" || deny["reason"] != "nope" {
		t.Fatalf("unexpected deny: %v", deny)
	}
}

func TestRegistered(t *testing.T) {
	if _, ok := agent.Get("hermes"); !ok {
		t.Fatal("hermes not registered")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/agent/hermes/...`
Expected: FAIL (`package has no test files` or `undefined: Hermes`).

- [ ] **Step 3: Implement adapter**

`internal/agent/hermes/hermes.go`:

```go
package hermes

import (
	"encoding/json"
	"fmt"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

func init() {
	agent.Register(&Hermes{})
}

type Hermes struct{}

func (h *Hermes) Name() string { return "hermes" }

type hookInput struct {
	SessionID     string         `json:"session_id"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	ToolResponse  map[string]any `json:"tool_response"`
	ToolUseID     string         `json:"tool_use_id"`
	CWD           string         `json:"cwd"`
}

func (h *Hermes) DecodeHookInput(input []byte) (*agent.HookEvent, error) {
	var in hookInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("hermes: decode hook input: %w", err)
	}
	return &agent.HookEvent{
		SessionID:     in.SessionID,
		HookEventName: in.HookEventName,
		ToolName:      in.ToolName,
		ToolInput:     in.ToolInput,
		ToolResponse:  in.ToolResponse,
		ToolUseID:     in.ToolUseID,
		CWD:           in.CWD,
	}, nil
}

type decision struct {
	Permission string `json:"permission"`
	Reason     string `json:"reason,omitempty"`
}

func (h *Hermes) EncodeAllow(_ *agent.HookEvent, reason string) ([]byte, error) {
	return json.Marshal(decision{Permission: "allow", Reason: reason})
}

func (h *Hermes) EncodeDeny(_ *agent.HookEvent, reason string) ([]byte, error) {
	return json.Marshal(decision{Permission: "deny", Reason: reason})
}
```

- [ ] **Step 4: Verify tests pass**

Run: `go test ./internal/agent/hermes/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/hermes/
git commit -m "feat(agent): add hermes agent adapter"
```

---

## Task 3: Hermes session config builder — `.env` writer

**Files:**
- Create: `internal/run/hermes_config.go`
- Create: `internal/run/hermes_config_test.go`

Start with the `.env` file (simpler, no merge concerns). We'll layer config.yaml in the next task.

- [ ] **Step 1: Write the failing test**

`internal/run/hermes_config_test.go`:

```go
package run

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/credential"
)

func TestWriteHermesEnv(t *testing.T) {
	dir := t.TempDir()
	resolved := []credential.Resolved{
		{Entry: credential.Entry{EnvVar: "GITHUB_TOKEN"}, Value: "ghs_abc"},
		{Entry: credential.Entry{EnvVar: "LINEAR_API_KEY"}, Value: "lin_xyz"},
	}
	if err := writeHermesEnv(dir, resolved); err != nil {
		t.Fatalf("writeHermesEnv: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	got := string(b)
	if !containsLine(got, `GITHUB_TOKEN=ghs_abc`) {
		t.Errorf(".env missing GITHUB_TOKEN line: %q", got)
	}
	if !containsLine(got, `LINEAR_API_KEY=lin_xyz`) {
		t.Errorf(".env missing LINEAR_API_KEY line: %q", got)
	}
}

func containsLine(haystack, needle string) bool {
	for _, line := range splitLines(haystack) {
		if line == needle {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/run/ -run TestWriteHermesEnv`
Expected: FAIL (`undefined: writeHermesEnv`).

- [ ] **Step 3: Implement `writeHermesEnv`**

`internal/run/hermes_config.go`:

```go
package run

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/credential"
)

// writeHermesEnv writes resolved credentials into <dir>/.env in KEY=VALUE form,
// sorted by env var name for deterministic output. Values that contain
// whitespace, '#', or quotes are wrapped in double quotes with escaping.
func writeHermesEnv(dir string, resolved []credential.Resolved) error {
	entries := make([]credential.Resolved, len(resolved))
	copy(entries, resolved)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].EnvVar < entries[j].EnvVar
	})

	var b strings.Builder
	for _, r := range entries {
		fmt.Fprintf(&b, "%s=%s\n", r.EnvVar, dotenvQuote(r.Value))
	}

	path := filepath.Join(dir, ".env")
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func dotenvQuote(value string) string {
	if !strings.ContainsAny(value, " \t\"#'\\\n") {
		return value
	}
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}
```

- [ ] **Step 4: Verify test passes**

Run: `go test ./internal/run/ -run TestWriteHermesEnv`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/run/hermes_config.go internal/run/hermes_config_test.go
git commit -m "feat(run): add hermes .env writer"
```

---

## Task 4: Hermes session config builder — config.yaml merge

**Files:**
- Modify: `internal/run/hermes_config.go`
- Modify: `internal/run/hermes_config_test.go`

Merge strategy: load user's base `~/.hermes/config.yaml` as a generic `map[string]any` (preserves unknown fields), then set/overwrite `mcp_servers.kontext` with the Kontext stdio entry. Write to `<sessionDir>/config.yaml`.

- [ ] **Step 1: Write the failing test**

Append to `internal/run/hermes_config_test.go`:

```go
import (
	"gopkg.in/yaml.v3"
)

func TestMergeHermesConfig_NoBase(t *testing.T) {
	dir := t.TempDir()
	err := writeHermesConfig(dir, "", "/bin/kontext", "/tmp/x.sock", "sess-1", []string{"GITHUB_TOKEN"})
	if err != nil {
		t.Fatalf("writeHermesConfig: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	servers, ok := doc["mcp_servers"].(map[string]any)
	if !ok {
		t.Fatalf("mcp_servers missing: %v", doc)
	}
	k, ok := servers["kontext"].(map[string]any)
	if !ok {
		t.Fatalf("kontext entry missing: %v", servers)
	}
	if k["command"] != "/bin/kontext" {
		t.Errorf("command: got %v", k["command"])
	}
	args, _ := k["args"].([]any)
	if len(args) == 0 || args[0] != "mcp-serve" {
		t.Errorf("args: got %v", args)
	}
	env, _ := k["env"].(map[string]any)
	if env["KONTEXT_SESSION_ID"] != "sess-1" {
		t.Errorf("env session id: got %v", env)
	}
}

func TestMergeHermesConfig_WithBase(t *testing.T) {
	baseDir := t.TempDir()
	basePath := filepath.Join(baseDir, "config.yaml")
	base := []byte(`
model:
  provider: openai
mcp_servers:
  github:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
  kontext:
    command: /old/binary
`)
	if err := os.WriteFile(basePath, base, 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := writeHermesConfig(dir, basePath, "/bin/kontext", "/tmp/x.sock", "sess-2", nil); err != nil {
		t.Fatalf("writeHermesConfig: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	var doc map[string]any
	_ = yaml.Unmarshal(b, &doc)

	// Preserved unrelated fields
	model, _ := doc["model"].(map[string]any)
	if model["provider"] != "openai" {
		t.Errorf("model.provider lost")
	}
	// Preserved user's github server
	servers := doc["mcp_servers"].(map[string]any)
	if _, ok := servers["github"]; !ok {
		t.Errorf("github server lost")
	}
	// Overwrote kontext entry
	k := servers["kontext"].(map[string]any)
	if k["command"] != "/bin/kontext" {
		t.Errorf("kontext command not overwritten: %v", k["command"])
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/run/ -run TestMergeHermesConfig`
Expected: FAIL (`undefined: writeHermesConfig`).

- [ ] **Step 3: Implement `writeHermesConfig`**

Append to `internal/run/hermes_config.go`:

```go
import (
	"gopkg.in/yaml.v3"
)

// writeHermesConfig writes <sessionDir>/config.yaml, merging the user's base
// config (if basePath != "" and exists) with a `kontext` entry under
// mcp_servers. passthroughEnv is the list of env var names whose resolved
// values will be forwarded to the mcp-serve subprocess via the yaml env block.
func writeHermesConfig(sessionDir, basePath, kontextBin, socketPath, sessionID string, passthroughEnv []string) error {
	doc := map[string]any{}
	if basePath != "" {
		if data, err := os.ReadFile(basePath); err == nil {
			if err := yaml.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("parse base hermes config: %w", err)
			}
			if doc == nil {
				doc = map[string]any{}
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("read base hermes config: %w", err)
		}
	}

	servers, _ := doc["mcp_servers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}

	envMap := map[string]any{
		"KONTEXT_SESSION_ID": sessionID,
		"KONTEXT_SOCKET":     socketPath,
	}
	for _, name := range passthroughEnv {
		envMap[name] = "${" + name + "}"
	}

	servers["kontext"] = map[string]any{
		"command": kontextBin,
		"args":    []any{"mcp-serve", "--agent", "hermes", "--socket", socketPath},
		"env":     envMap,
	}
	doc["mcp_servers"] = servers

	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal hermes config: %w", err)
	}
	path := filepath.Join(sessionDir, "config.yaml")
	return os.WriteFile(path, out, 0o600)
}
```

Note: credential passthrough is represented as `${VAR}` placeholders so Hermes expands them from the session `.env` when launching `mcp-serve`. Confirm Hermes supports this expansion; if not, inline the resolved values directly in a follow-up. (See Task 4b if the Hermes docs contradict.)

- [ ] **Step 4: Verify tests pass**

Run: `go test ./internal/run/ -run TestMergeHermesConfig`
Expected: PASS.

- [ ] **Step 5: Add the public `BuildHermesHome` entry point**

Append to `internal/run/hermes_config.go`:

```go
// BuildHermesHome seeds a session-scoped HERMES_HOME under parentDir and
// returns the absolute path to use as HERMES_HOME.
func BuildHermesHome(parentDir, kontextBin, socketPath, sessionID string, resolved []credential.Resolved) (string, error) {
	dir := filepath.Join(parentDir, "hermes")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create hermes home: %w", err)
	}

	if err := writeHermesEnv(dir, resolved); err != nil {
		return "", err
	}

	basePath := ""
	if home, err := os.UserHomeDir(); err == nil {
		basePath = filepath.Join(home, ".hermes", "config.yaml")
	}

	passthrough := make([]string, 0, len(resolved))
	for _, r := range resolved {
		passthrough = append(passthrough, r.EnvVar)
	}

	if err := writeHermesConfig(dir, basePath, kontextBin, socketPath, sessionID, passthrough); err != nil {
		return "", err
	}
	return dir, nil
}
```

- [ ] **Step 6: Run full package tests**

Run: `go test ./internal/run/...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/run/hermes_config.go internal/run/hermes_config_test.go
git commit -m "feat(run): add hermes config merge + BuildHermesHome"
```

---

## Task 5: `kontext mcp-serve` — stdio MCP server skeleton

**Files:**
- Create: `internal/mcpserve/server.go`
- Create: `internal/mcpserve/server_test.go`

Expose one MCP tool: `kontext.invoke(provider, action, params)`. For the MVP, the tool simply bridges Pre/PostToolUse events to the sidecar and, on allow, returns a placeholder result `{"status": "ok", "provider": <provider>, "action": <action>}`. Actual per-provider HTTP dispatch is out of scope for this plan (see spec §10). This keeps the governance seam testable end-to-end.

Use `github.com/mark3labs/mcp-go/server` for the MCP protocol layer.

- [ ] **Step 1: Write the failing test**

`internal/mcpserve/server_test.go`:

```go
package mcpserve

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/sidecar"
)

// fakeSidecar accepts one EvaluateRequest, returns the given response, and records the request.
func fakeSidecar(t *testing.T, resp sidecar.EvaluateResult) (string, chan sidecar.EvaluateRequest) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close(); os.Remove(sock) })

	reqs := make(chan sidecar.EvaluateRequest, 8)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req sidecar.EvaluateRequest
				if err := sidecar.ReadMessage(c, &req); err != nil {
					return
				}
				reqs <- req
				_ = sidecar.WriteMessage(c, resp)
			}(conn)
		}
	}()
	return sock, reqs
}

func TestInvokeToolAllowed(t *testing.T) {
	sock, reqs := fakeSidecar(t, sidecar.EvaluateResult{Allowed: true, Reason: ""})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := newHandler("hermes", sock, "sess-t")
	payload := map[string]any{"provider": "github", "action": "ping"}
	result, err := h.invoke(ctx, payload)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("result parse: %v (raw=%s)", err, result)
	}
	if parsed["status"] != "ok" || parsed["provider"] != "github" {
		t.Fatalf("unexpected result: %v", parsed)
	}

	// Expect PreToolUse then PostToolUse.
	select {
	case r := <-reqs:
		if r.HookEvent != "PreToolUse" {
			t.Fatalf("expected PreToolUse, got %s", r.HookEvent)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no pre request")
	}
	select {
	case r := <-reqs:
		if r.HookEvent != "PostToolUse" {
			t.Fatalf("expected PostToolUse, got %s", r.HookEvent)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no post request")
	}
}

func TestInvokeToolDenied(t *testing.T) {
	sock, _ := fakeSidecar(t, sidecar.EvaluateResult{Allowed: false, Reason: "policy blocked"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := newHandler("hermes", sock, "sess-t")
	_, err := h.invoke(ctx, map[string]any{"provider": "github", "action": "ping"})
	if err == nil {
		t.Fatal("expected deny error")
	}
	if !contains(err.Error(), "policy blocked") {
		t.Fatalf("expected deny reason in error, got %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/mcpserve/...`
Expected: FAIL (`undefined: newHandler`).

- [ ] **Step 3: Implement the handler (no MCP loop yet; just the bridge)**

`internal/mcpserve/server.go`:

```go
// Package mcpserve implements `kontext mcp-serve`: an MCP server that bridges
// tool calls to the Kontext sidecar for governance and tracing.
package mcpserve

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/kontext-security/kontext-cli/internal/sidecar"
)

type handler struct {
	agent     string
	socket    string
	sessionID string
}

func newHandler(agent, socket, sessionID string) *handler {
	return &handler{agent: agent, socket: socket, sessionID: sessionID}
}

// invoke runs PreToolUse -> execute -> PostToolUse. Returns the JSON result
// string on allow, or an error containing the deny reason on deny.
func (h *handler) invoke(ctx context.Context, params map[string]any) (string, error) {
	provider, _ := params["provider"].(string)
	action, _ := params["action"].(string)

	allowed, reason, err := h.sendHook(ctx, "PreToolUse", params, nil)
	if err != nil {
		return "", fmt.Errorf("sidecar pre: %w", err)
	}
	if !allowed {
		return "", fmt.Errorf("kontext denied: %s", reason)
	}

	result := map[string]any{
		"status":   "ok",
		"provider": provider,
		"action":   action,
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("marshal result: %w", err)
	}

	if _, _, err := h.sendHook(ctx, "PostToolUse", params, result); err != nil {
		// Do not fail the call on post-hook error; log-and-continue path
		// would be added here in a structured logger. For MVP we swallow.
	}
	return string(resultBytes), nil
}

func (h *handler) sendHook(ctx context.Context, eventName string, toolInput, toolResponse map[string]any) (bool, string, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", h.socket)
	if err != nil {
		return false, "sidecar unreachable", nil // fail-closed at the caller
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	req := sidecar.EvaluateRequest{
		Type:      "evaluate",
		Agent:     h.agent,
		HookEvent: eventName,
		ToolName:  "kontext.invoke",
	}
	if toolInput != nil {
		b, err := json.Marshal(toolInput)
		if err != nil {
			return false, "marshal input", err
		}
		req.ToolInput = b
	}
	if toolResponse != nil {
		b, err := json.Marshal(toolResponse)
		if err != nil {
			return false, "marshal response", err
		}
		req.ToolResponse = b
	}

	if err := sidecar.WriteMessage(conn, req); err != nil {
		return false, "write", err
	}
	var res sidecar.EvaluateResult
	if err := sidecar.ReadMessage(conn, &res); err != nil {
		return false, "read", err
	}
	return res.Allowed, res.Reason, nil
}
```

- [ ] **Step 4: Verify tests pass**

Run: `go test ./internal/mcpserve/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserve/
git commit -m "feat(mcpserve): bridge tool calls through sidecar (no stdio loop yet)"
```

---

## Task 6: `kontext mcp-serve` — stdio MCP loop

**Files:**
- Modify: `internal/mcpserve/server.go`

Wire `handler.invoke` into an actual MCP server exposed over stdio.

- [ ] **Step 1: Implement `Run`**

Append to `internal/mcpserve/server.go`:

```go
import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Run starts an MCP server over stdio. Blocks until stdin is closed.
func Run(ctx context.Context, agentName, socketPath, sessionID string) error {
	h := newHandler(agentName, socketPath, sessionID)

	s := server.NewMCPServer("kontext", "0.1.0",
		server.WithToolCapabilities(false),
	)

	tool := mcp.NewTool(
		"kontext.invoke",
		mcp.WithDescription("Invoke a Kontext-managed provider action. Governed by the Kontext policy engine."),
		mcp.WithString("provider", mcp.Required(), mcp.Description("Provider handle, e.g. 'github'.")),
		mcp.WithString("action", mcp.Required(), mcp.Description("Action name to perform on the provider.")),
		mcp.WithObject("params", mcp.Description("Action-specific parameters.")),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, _ := req.Params.Arguments.(map[string]any)
		out, err := h.invoke(ctx, args)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(out), nil
	})

	return server.ServeStdio(s)
}
```

Note: MCP-go API names may shift between minor versions. If compilation fails, consult the version pinned in `go.mod` and adjust — the semantics above (register tool, handle call, serve stdio) are stable.

- [ ] **Step 2: Build**

Run: `go build ./internal/mcpserve/...`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add internal/mcpserve/server.go
git commit -m "feat(mcpserve): expose handler over stdio MCP"
```

---

## Task 7: Register `mcp-serve` cobra subcommand

**Files:**
- Create: `cmd/kontext/mcpserve.go`
- Modify: `cmd/kontext/main.go`

- [ ] **Step 1: Create subcommand**

`cmd/kontext/mcpserve.go`:

```go
package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext-cli/internal/mcpserve"
)

func mcpServeCmd() *cobra.Command {
	var agentName, socketPath string
	cmd := &cobra.Command{
		Use:    "mcp-serve",
		Short:  "Run Kontext as an MCP server (invoked by host agents)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := os.Getenv("KONTEXT_SESSION_ID")
			return mcpserve.Run(cmd.Context(), agentName, socketPath, sessionID)
		},
	}
	cmd.Flags().StringVar(&agentName, "agent", "hermes", "Agent label used for hook events")
	cmd.Flags().StringVar(&socketPath, "socket", "", "Path to Kontext sidecar Unix socket")
	return cmd
}
```

- [ ] **Step 2: Wire into root**

Edit `cmd/kontext/main.go`:

Replace:

```go
	root.AddCommand(hookCmd())
```

with:

```go
	root.AddCommand(hookCmd())
	root.AddCommand(mcpServeCmd())
```

- [ ] **Step 3: Build**

Run: `go build ./...`
Expected: exits 0.

- [ ] **Step 4: Commit**

```bash
git add cmd/kontext/mcpserve.go cmd/kontext/main.go
git commit -m "feat(cli): add hidden mcp-serve subcommand"
```

---

## Task 8: Register hermes adapter via blank import + update flag help

**Files:**
- Modify: `cmd/kontext/main.go`

- [ ] **Step 1: Add blank import**

Add to the imports in `cmd/kontext/main.go`:

```go
	_ "github.com/kontext-security/kontext-cli/internal/agent/hermes"
```

- [ ] **Step 2: Update `--agent` flag description**

In `startCmd()`, replace:

```go
	cmd.Flags().StringVar(&agentName, "agent", "claude", "Agent to launch (currently: claude)")
```

with:

```go
	cmd.Flags().StringVar(&agentName, "agent", "claude", "Agent to launch (claude, hermes)")
```

- [ ] **Step 3: Verify hermes shows up as registered**

Run: `go test ./internal/agent/hermes/ -run TestRegistered`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add cmd/kontext/main.go
git commit -m "feat(cli): register hermes agent"
```

---

## Task 9: Split launch logic by agent in `run.Start`

**Files:**
- Modify: `internal/run/run.go`

The current `launchAgentWithSettings` hard-codes `--settings <path>` (Claude-only). Introduce a small per-agent launch helper and branch in `Start`.

- [ ] **Step 1: Read the current launch block**

Confirm at `internal/run/run.go:212-228` the sequence: `GenerateSettings` → `buildEnv` → `launchAgentWithSettings`.

- [ ] **Step 2: Write a test for the new branch**

Append to `internal/run/run_test.go` (or create a new `hermes_launch_test.go`):

```go
func TestBuildHermesLaunch(t *testing.T) {
	dir := t.TempDir()
	kontextBin := "/bin/kontext"
	sessionID := "sess-launch"
	socket := filepath.Join(dir, "s.sock")
	resolved := []credential.Resolved{
		{Entry: credential.Entry{EnvVar: "GITHUB_TOKEN"}, Value: "x"},
	}
	home, args, extraEnv, err := buildHermesLaunch(dir, kontextBin, socket, sessionID, resolved)
	if err != nil {
		t.Fatalf("buildHermesLaunch: %v", err)
	}
	if home == "" || !strings.HasPrefix(home, dir) {
		t.Errorf("unexpected home: %q", home)
	}
	if len(args) != 0 {
		t.Errorf("expected no extra args for hermes, got %v", args)
	}
	found := false
	for _, e := range extraEnv {
		if e == "HERMES_HOME="+home {
			found = true
		}
	}
	if !found {
		t.Errorf("HERMES_HOME not in extraEnv: %v", extraEnv)
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/run/ -run TestBuildHermesLaunch`
Expected: FAIL (`undefined: buildHermesLaunch`).

- [ ] **Step 4: Add the helper**

Append to `internal/run/hermes_config.go`:

```go
// buildHermesLaunch prepares the HERMES_HOME directory and returns
// (hermesHome, extraArgs, extraEnv). Hermes takes zero extra launch args;
// config is discovered via HERMES_HOME.
func buildHermesLaunch(parentDir, kontextBin, socket, sessionID string, resolved []credential.Resolved) (string, []string, []string, error) {
	home, err := BuildHermesHome(parentDir, kontextBin, socket, sessionID, resolved)
	if err != nil {
		return "", nil, nil, err
	}
	return home, nil, []string{"HERMES_HOME=" + home}, nil
}
```

- [ ] **Step 5: Branch in `run.Start`**

In `internal/run/run.go`, replace the block at lines ~212-228 (steps 7-9) with:

```go
	// 7-9: per-agent session prep + launch
	kontextBin, _ := os.Executable()

	env := buildEnv(templateDoc, resolved)
	env = append(env, "KONTEXT_SOCKET="+sc.SocketPath())
	env = append(env, "KONTEXT_SESSION_ID="+sessionID)

	var launchArgs []string
	switch opts.Agent {
	case "claude":
		settingsPath, err := GenerateSettings(sessionDir, kontextBin, opts.Agent)
		if err != nil {
			return fmt.Errorf("generate settings: %w", err)
		}
		launchArgs = []string{"--settings", settingsPath}
	case "hermes":
		_, _, extraEnv, err := buildHermesLaunch(sessionDir, kontextBin, sc.SocketPath(), sessionID, resolved)
		if err != nil {
			return fmt.Errorf("build hermes home: %w", err)
		}
		env = append(env, extraEnv...)
	default:
		return fmt.Errorf("unsupported agent: %s", opts.Agent)
	}

	fmt.Fprintf(os.Stderr, "\nLaunching %s...\n\n", opts.Agent)
	agentErr := launchAgent(ctx, opts.Agent, agentPath, env, opts.Args, launchArgs)

	return agentErr
```

- [ ] **Step 6: Rename `launchAgentWithSettings` to `launchAgent` and generalize**

In `internal/run/run.go`, replace:

```go
func launchAgentWithSettings(_ context.Context, agentName, binaryPath string, env, extraArgs []string, settingsPath string) error {
	var args []string
	if settingsPath != "" {
		args = append(args, "--settings", settingsPath)
	}
	args = append(args, filterArgs(extraArgs)...)
```

with:

```go
func launchAgent(_ context.Context, agentName, binaryPath string, env, extraArgs, prefixArgs []string) error {
	var args []string
	args = append(args, prefixArgs...)
	args = append(args, filterArgs(extraArgs)...)
```

Update the single call site in `Start` (already updated in Step 5).

- [ ] **Step 7: Run all tests**

Run: `go test ./...`
Expected: PASS.

Note: the Claude branch still passes `--settings <path>` via `prefixArgs`, so its existing tests should keep passing. If `filterArgs` strips `--settings` for the Claude path, adjust by threading the settings path through a separate parameter that bypasses the filter. Read `run_test.go:TestLaunchAgentPassesSettings*` (or equivalent) and adjust accordingly.

- [ ] **Step 8: Commit**

```bash
git add internal/run/run.go internal/run/hermes_config.go internal/run/run_test.go
git commit -m "feat(run): branch launch args by agent; add hermes path"
```

---

## Task 10: End-to-end smoke test (manual)

**Files:** none (manual verification)

- [ ] **Step 1: Build**

Run: `go build -o bin/kontext ./cmd/kontext`
Expected: binary produced.

- [ ] **Step 2: Verify `mcp-serve` responds to an MCP initialize**

In a scratch shell, pipe an MCP initialize request into `bin/kontext mcp-serve --agent hermes --socket /tmp/nope.sock` and confirm it responds with server capabilities (use any MCP inspector or a minimal Python script). Expected: initialize succeeds; subsequent `tools/list` returns the `kontext.invoke` tool.

- [ ] **Step 3: Smoke test with Hermes (requires Hermes installed)**

Prerequisites:

```bash
curl -fsSL https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.sh | bash
hermes setup --non-interactive
```

Run:

```bash
bin/kontext start --agent hermes
```

Expected:
1. OIDC browser prompt on first run.
2. Stderr shows session creation, credential resolution, sidecar start, and "Launching hermes...".
3. Hermes TUI loads; `hermes mcp list` (in another shell, pointed at the session's `HERMES_HOME`) shows the `kontext` entry.
4. Ask Hermes to "call the kontext invoke tool with provider=github action=ping"; tool result returns `{"status":"ok", ...}`.
5. The Kontext dashboard Traces view shows matching PreToolUse + PostToolUse events.

- [ ] **Step 4: Document gotchas in README**

Append a row to the Supported Agents table in `README.md`:

```md
| Hermes Agent | `--agent hermes` | Active |
```

Commit:

```bash
git add README.md
git commit -m "docs: mark hermes agent as supported"
```

---

## Coverage check

- Spec §1 Goal & UX → Task 9 (launch wiring), Task 10 (smoke).
- Spec §3 Architecture → Tasks 2, 3, 4, 5, 6, 7, 9 combined.
- Spec §4.1 Hermes adapter → Task 2.
- Spec §4.2 Session config builder → Tasks 3, 4.
- Spec §4.3 `kontext mcp-serve` → Tasks 5, 6, 7.
- Spec §4.4 `run.Start` branching → Task 9.
- Spec §5 Data flow → exercised in Task 5 tests.
- Spec §6 Credential injection → Tasks 3, 4 (.env + env passthrough).
- Spec §7 Teardown → already handled by existing `defer os.RemoveAll(sessionDir)` in `run.Start` — the hermes session dir lives under `sessionDir/hermes`, so it's swept automatically. No change required.
- Spec §8 Error handling → covered ad-hoc across tasks; a follow-up task can add targeted tests once the happy path is green.
- Spec §9 Testing → unit tests in Tasks 2, 3, 4, 5; integration in Task 5; manual E2E in Task 10.
- Spec §10 Scope cuts → respected (MVP exposes only `kontext.invoke`; no middleware mode; no `UserPromptSubmit`).
