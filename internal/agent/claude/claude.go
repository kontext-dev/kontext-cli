// Package claude implements the agent adapter for Claude Code.
package claude

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

func init() {
	agent.Register(&Claude{})
}

// Claude implements the agent.Agent interface for Claude Code.
type Claude struct{}

func (c *Claude) Name() string   { return "claude" }
func (c *Claude) Binary() string { return "claude" }

// settingsFile is the JSON structure Claude Code loads via --settings.
type settingsFile struct {
	Hooks map[string][]hookGroup `json:"hooks"`
}

type hookGroup struct {
	Hooks []hookDef `json:"hooks"`
}

type hookDef struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

func (c *Claude) Prepare(sessionDir, kontextBin string) (*agent.PrepareResult, error) {
	hookCmd := fmt.Sprintf("%s hook --agent %s", kontextBin, c.Name())

	settings := settingsFile{
		Hooks: map[string][]hookGroup{
			"PreToolUse": {{
				Hooks: []hookDef{{Type: "command", Command: hookCmd, Timeout: 10}},
			}},
			"PostToolUse": {{
				Hooks: []hookDef{{Type: "command", Command: hookCmd, Timeout: 10}},
			}},
			"UserPromptSubmit": {{
				Hooks: []hookDef{{Type: "command", Command: hookCmd, Timeout: 10}},
			}},
		},
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("claude: marshal settings: %w", err)
	}

	settingsPath := filepath.Join(sessionDir, "settings.json")
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		return nil, fmt.Errorf("claude: write settings: %w", err)
	}

	return &agent.PrepareResult{Args: []string{"--settings", settingsPath}}, nil
}

func (c *Claude) Cleanup() error { return nil }

// hookInput is the JSON structure Claude Code sends on hook stdin.
type hookInput struct {
	SessionID      string         `json:"session_id"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolResponse   map[string]any `json:"tool_response"`
	ToolUseID      string         `json:"tool_use_id"`
	CWD            string         `json:"cwd"`
	PermissionMode string         `json:"permission_mode"`
}

func (c *Claude) DecodeHookInput(input []byte) (*agent.HookEvent, error) {
	var h hookInput
	if err := json.Unmarshal(input, &h); err != nil {
		return nil, fmt.Errorf("claude: decode hook input: %w", err)
	}
	return &agent.HookEvent{
		SessionID:     h.SessionID,
		HookEventName: h.HookEventName,
		ToolName:      h.ToolName,
		ToolInput:     h.ToolInput,
		ToolResponse:  h.ToolResponse,
		ToolUseID:     h.ToolUseID,
		CWD:           h.CWD,
	}, nil
}

// hookOutput is the JSON structure Claude Code expects on hook stdout.
type hookOutput struct {
	HookSpecificOutput *hookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string `json:"additionalContext,omitempty"`
}

func (c *Claude) EncodeAllow(event *agent.HookEvent, reason string) ([]byte, error) {
	out := hookOutput{
		HookSpecificOutput: &hookSpecificOutput{
			HookEventName:            event.HookEventName,
			PermissionDecision:       "allow",
			PermissionDecisionReason: reason,
		},
	}
	return json.Marshal(out)
}

func (c *Claude) EncodeDeny(event *agent.HookEvent, reason string) ([]byte, error) {
	out := hookOutput{
		HookSpecificOutput: &hookSpecificOutput{
			HookEventName:            event.HookEventName,
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		},
	}
	return json.Marshal(out)
}

func (c *Claude) FilterUserArgs(args []string) []string {
	blocked := map[string]bool{
		"--bare":                         true,
		"--dangerously-skip-permissions": true,
	}
	blockedWithValue := map[string]bool{
		"--settings":        true,
		"--setting-sources": true,
	}

	var filtered []string
	skip := false
	for _, arg := range args {
		if skip {
			skip = false
			continue
		}
		name := flagName(arg)
		if blocked[name] {
			fmt.Fprintf(os.Stderr, "⚠ Stripped blocked flag: %s\n", arg)
			continue
		}
		if blockedWithValue[name] {
			fmt.Fprintf(os.Stderr, "⚠ Stripped blocked flag: %s\n", arg)
			if !strings.Contains(arg, "=") {
				skip = true
			}
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

func flagName(arg string) string {
	if i := strings.Index(arg, "="); i != -1 {
		return arg[:i]
	}
	return arg
}
