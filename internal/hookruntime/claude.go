package hookruntime

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ClaudeHookInput struct {
	SessionID      string         `json:"session_id"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolResponse   map[string]any `json:"tool_response"`
	ToolUseID      string         `json:"tool_use_id"`
	CWD            string         `json:"cwd"`
	PermissionMode *string        `json:"permission_mode"`
	DurationMs     *int64         `json:"duration_ms"`
	Error          *string        `json:"error"`
	IsInterrupt    *bool          `json:"is_interrupt"`
}

type claudeHookOutput struct {
	HookSpecificOutput *claudeHookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	SuppressOutput     bool                      `json:"suppressOutput,omitempty"`
}

type claudeHookSpecificOutput struct {
	HookEventName            string         `json:"hookEventName"`
	PermissionDecision       string         `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string         `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string         `json:"additionalContext,omitempty"`
	UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
}

func DecodeClaudeEvent(input []byte, agentName string) (Event, error) {
	var h ClaudeHookInput
	if err := json.Unmarshal(input, &h); err != nil {
		return Event{}, fmt.Errorf("claude: decode hook input: %w", err)
	}
	return Event{
		SessionID:      h.SessionID,
		Agent:          agentName,
		HookEventName:  h.HookEventName,
		ToolName:       h.ToolName,
		ToolInput:      h.ToolInput,
		ToolResponse:   h.ToolResponse,
		ToolUseID:      h.ToolUseID,
		CWD:            h.CWD,
		PermissionMode: stringPtrValue(h.PermissionMode),
		DurationMs:     h.DurationMs,
		Error:          stringPtrValue(h.Error),
		IsInterrupt:    h.IsInterrupt,
	}, nil
}

func EncodeClaudeResult(hookEventName string, result Result) ([]byte, error) {
	permissionDecision := "allow"
	if result.Decision == DecisionAsk || result.Decision == DecisionDeny {
		permissionDecision = "deny"
	}
	reason := result.ClaudeReason()
	if permissionDecision == "allow" && strings.EqualFold(strings.TrimSpace(reason), "allowed") {
		reason = ""
	}
	out := claudeHookOutput{
		HookSpecificOutput: &claudeHookSpecificOutput{
			HookEventName:            hookEventName,
			PermissionDecision:       permissionDecision,
			PermissionDecisionReason: reason,
			UpdatedInput:             result.UpdatedInput,
		},
		SuppressOutput: result.UpdatedInput != nil,
	}
	return json.Marshal(out)
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
