// Package codex implements the agent adapter for OpenAI Codex CLI.
//
// Codex's hook system is near-identical to Claude's: the stdin payload
// uses the same field names (session_id, hook_event_name, tool_name,
// tool_input, tool_response, cwd) and the same decision contract
// (exit 2 = deny, or {"decision":"deny","reason":"..."} on stdout).
//
// Codex config lives in $CODEX_HOME (default ~/.codex). The hooks feature
// is experimental and gated by [features] codex_hooks = true in config.toml.
// Hook definitions live in a sibling hooks.json with a Claude-shaped schema.
//
// Known coverage gap: PreToolUse fires for shell, local_shell, apply_patch,
// and MCP tool calls. Codex does not expose separate read_file / write_file
// tools today — edits route through apply_patch which IS covered.
package codex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

func init() {
	agent.Register(&Codex{})
}

// Codex implements the agent.Agent interface for OpenAI Codex CLI.
type Codex struct{}

func (c *Codex) Name() string   { return "codex" }
func (c *Codex) Binary() string { return "codex" }

const configTOML = `# Managed by kontext — do not edit.
[features]
codex_hooks = true
`

type hooksFile struct {
	Hooks map[string][]hookGroup `json:"hooks"`
}

type hookGroup struct {
	Matcher string    `json:"matcher,omitempty"`
	Hooks   []hookDef `json:"hooks"`
}

type hookDef struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

func (c *Codex) Prepare(sessionDir, kontextBin string) (*agent.PrepareResult, error) {
	codexHome := filepath.Join(sessionDir, ".codex")
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		return nil, fmt.Errorf("codex: create config dir: %w", err)
	}

	configPath := filepath.Join(codexHome, "config.toml")
	if err := os.WriteFile(configPath, []byte(configTOML), 0o600); err != nil {
		return nil, fmt.Errorf("codex: write config.toml: %w", err)
	}

	hookCmd := fmt.Sprintf("%s hook --agent %s", kontextBin, c.Name())
	cmd := hookDef{Type: "command", Command: hookCmd, Timeout: 10}
	file := hooksFile{
		Hooks: map[string][]hookGroup{
			"PreToolUse": {{
				Matcher: "*",
				Hooks:   []hookDef{cmd},
			}},
			"PostToolUse": {{
				Matcher: "*",
				Hooks:   []hookDef{cmd},
			}},
			"UserPromptSubmit": {{
				Hooks: []hookDef{cmd},
			}},
		},
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("codex: marshal hooks.json: %w", err)
	}
	hooksPath := filepath.Join(codexHome, "hooks.json")
	if err := os.WriteFile(hooksPath, data, 0o600); err != nil {
		return nil, fmt.Errorf("codex: write hooks.json: %w", err)
	}

	return &agent.PrepareResult{
		Env: []string{"CODEX_HOME=" + codexHome},
	}, nil
}

func (c *Codex) Cleanup() error { return nil }

// hookInput mirrors the stdin schema Codex emits. tool_input and tool_response
// are decoded as RawMessage because Codex emits them as either a JSON object
// (e.g. shell with structured fields) or a raw string (e.g. shell stdout),
// depending on the tool and event. We normalize to map[string]any downstream.
type hookInput struct {
	SessionID     string          `json:"session_id"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"`
	ToolUseID     string          `json:"tool_use_id"`
	CWD           string          `json:"cwd"`
}

func (c *Codex) DecodeHookInput(input []byte) (*agent.HookEvent, error) {
	var h hookInput
	if err := json.Unmarshal(input, &h); err != nil {
		return nil, fmt.Errorf("codex: decode hook input: %w", err)
	}
	toolInput := normalizePayload(h.ToolInput)
	toolUseID := h.ToolUseID
	if toolUseID == "" && (h.HookEventName == "PreToolUse" || h.HookEventName == "PostToolUse") {
		toolUseID = synthesizeToolUseID(h.SessionID, h.ToolName, h.ToolInput)
	}
	return &agent.HookEvent{
		SessionID:     h.SessionID,
		HookEventName: h.HookEventName,
		ToolName:      h.ToolName,
		ToolInput:     toolInput,
		ToolResponse:  normalizePayload(h.ToolResponse),
		ToolUseID:     toolUseID,
		CWD:           h.CWD,
	}, nil
}

// synthesizeToolUseID derives a stable pairing ID for Pre/Post events when
// Codex leaves tool_use_id empty. Pre and Post carry the same tool_input, so
// hashing (session, tool, input) lets the backend pair them without shared
// state across hook invocations. Collides if the identical tool+input is
// issued twice in the same session; acceptable given Codex's current schema.
func synthesizeToolUseID(sessionID, toolName string, toolInput json.RawMessage) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(toolName))
	h.Write([]byte{0})
	h.Write(toolInput)
	return "codex-syn-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// normalizePayload accepts a tool_input / tool_response field that may be a
// JSON object, string, number, bool, null, or missing, and returns a
// map[string]any with the value placed under a conventional key so downstream
// consumers always get a map. Objects pass through as-is.
func normalizePayload(raw json.RawMessage) map[string]any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	trimmed := bytesTrim(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err == nil {
			return obj
		}
	}
	var scalar any
	if err := json.Unmarshal(raw, &scalar); err != nil {
		return map[string]any{"raw": string(raw)}
	}
	return map[string]any{"value": scalar}
}

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	return b
}

type decision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// EncodeAllow returns the "allow" output Codex expects for the event.
//
// Codex rejects structured allow JSON across all event types ("invalid
// pre-tool-use / post-tool-use / user-prompt-submit JSON output") and
// treats empty stdout + exit 0 as allow. Only deny needs a JSON body.
func (c *Codex) EncodeAllow(event *agent.HookEvent, reason string) ([]byte, error) {
	return nil, nil
}

// EncodeDeny returns the deny/block output Codex expects for the event.
//
// UserPromptSubmit uses {"decision":"block","reason":...}; tool events use
// {"decision":"deny","reason":...}.
func (c *Codex) EncodeDeny(event *agent.HookEvent, reason string) ([]byte, error) {
	if event.HookEventName == "UserPromptSubmit" {
		return json.Marshal(decision{Decision: "block", Reason: reason})
	}
	return json.Marshal(decision{Decision: "deny", Reason: reason})
}

// dangerousValue reports whether the given --flag=value (or --flag, value)
// combination would disable governance guarantees.
func dangerousValue(name, value string) bool {
	switch name {
	case "--sandbox", "-s":
		return value == "danger-full-access"
	case "--ask-for-approval", "-a":
		return value == "never"
	}
	return false
}

func (c *Codex) FilterUserArgs(args []string) []string {
	var filtered []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, inlineValue, hasInline := splitFlag(arg)

		if hasInline {
			if dangerousValue(name, inlineValue) {
				fmt.Fprintf(os.Stderr, "⚠ Stripped blocked flag: %s\n", arg)
				continue
			}
			filtered = append(filtered, arg)
			continue
		}

		// No inline value. Peek at next arg if this is one of the flags we gate.
		if name == "--sandbox" || name == "-s" || name == "--ask-for-approval" || name == "-a" {
			if i+1 < len(args) && dangerousValue(name, args[i+1]) {
				fmt.Fprintf(os.Stderr, "⚠ Stripped blocked flag: %s %s\n", arg, args[i+1])
				i++ // skip the value too
				continue
			}
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

func splitFlag(arg string) (name, value string, hasInline bool) {
	if i := strings.Index(arg, "="); i != -1 {
		return arg[:i], arg[i+1:], true
	}
	return arg, "", false
}
