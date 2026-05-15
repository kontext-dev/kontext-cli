package hookruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

type ClaudeHookInput struct {
	SessionID        string          `json:"session_id"`
	SessionIDAlt     string          `json:"sessionId"`
	HookEventName    string          `json:"hook_event_name"`
	HookEventNameAlt string          `json:"hookEventName"`
	HookEventLegacy  string          `json:"hook_event"`
	ToolName         string          `json:"tool_name"`
	ToolNameAlt      string          `json:"toolName"`
	ToolInput        json.RawMessage `json:"tool_input"`
	ToolInputAlt     json.RawMessage `json:"toolInput"`
	ToolResponse     json.RawMessage `json:"tool_response"`
	ToolResponseAlt  json.RawMessage `json:"toolResponse"`
	ToolUseID        string          `json:"tool_use_id"`
	ToolUseIDAlt     string          `json:"toolUseId"`
	ToolUseIDUpper   string          `json:"toolUseID"`
	CWD              string          `json:"cwd"`
	PermissionMode   *string         `json:"permission_mode"`
	DurationMs       *int64          `json:"duration_ms"`
	Error            *string         `json:"error"`
	IsInterrupt      *bool           `json:"is_interrupt"`
}

type claudeHookOutput struct {
	HookSpecificOutput *claudeHookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	SuppressOutput     bool                      `json:"suppressOutput,omitempty"`
}

type claudeHookSpecificOutput struct {
	HookEventName            string          `json:"hookEventName"`
	PermissionDecision       string          `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string          `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string          `json:"additionalContext,omitempty"`
	UpdatedInput             json.RawMessage `json:"updatedInput,omitempty"`
}

func DecodeClaudeEvent(input []byte, agentName string) (hook.Event, error) {
	var h ClaudeHookInput
	if err := json.Unmarshal(input, &h); err != nil {
		return hook.Event{}, fmt.Errorf("claude: decode hook input: %w", err)
	}
	hookName := firstString(h.HookEventName, h.HookEventNameAlt, h.HookEventLegacy)
	if hookName == "" {
		return hook.Event{}, fmt.Errorf("claude: hook event name missing")
	}
	toolInput, err := decodeJSONMapObject(firstRawMessage(h.ToolInput, h.ToolInputAlt))
	if err != nil {
		return hook.Event{}, fmt.Errorf("claude: decode tool input: %w", err)
	}
	toolResponse, err := decodeJSONMapObject(firstRawMessage(h.ToolResponse, h.ToolResponseAlt))
	if err != nil {
		return hook.Event{}, fmt.Errorf("claude: decode tool response: %w", err)
	}
	return hook.Event{
		SessionID:      firstString(h.SessionID, h.SessionIDAlt),
		Agent:          agentName,
		HookName:       hook.HookName(hookName),
		ToolName:       firstString(h.ToolName, h.ToolNameAlt),
		ToolInput:      toolInput,
		ToolResponse:   toolResponse,
		ToolUseID:      firstString(h.ToolUseID, h.ToolUseIDAlt, h.ToolUseIDUpper),
		CWD:            h.CWD,
		PermissionMode: stringPtrValue(h.PermissionMode),
		DurationMs:     h.DurationMs,
		Error:          stringPtrValue(h.Error),
		IsInterrupt:    h.IsInterrupt,
	}, nil
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstRawMessage(values ...json.RawMessage) json.RawMessage {
	for _, value := range values {
		if len(value) != 0 {
			return value
		}
	}
	return nil
}

func EncodeClaudeResult(hookEventName string, result hook.Result) ([]byte, error) {
	if hook.HookName(hookEventName) != hook.HookPreToolUse {
		return json.Marshal(claudeHookOutput{SuppressOutput: true})
	}

	permissionDecision := result.Decision
	switch permissionDecision {
	case hook.DecisionAllow, hook.DecisionAsk, hook.DecisionDeny:
	default:
		permissionDecision = hook.DecisionDeny
	}
	reason := result.ClaudeReason()
	if permissionDecision == hook.DecisionAllow && strings.EqualFold(strings.TrimSpace(reason), "allowed") {
		reason = ""
	}
	var updatedInput json.RawMessage
	if result.UpdatedInput != nil {
		data, err := json.Marshal(result.UpdatedInput)
		if err != nil {
			return nil, fmt.Errorf("claude: encode updated input: %w", err)
		}
		updatedInput = data
	}
	out := claudeHookOutput{
		HookSpecificOutput: &claudeHookSpecificOutput{
			HookEventName:            hookEventName,
			PermissionDecision:       string(permissionDecision),
			PermissionDecisionReason: reason,
			UpdatedInput:             updatedInput,
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

func decodeJSONMapObject(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("expected JSON object, got null")
	}

	var out map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("expected JSON object")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON after object")
		}
		return nil, err
	}
	return out, nil
}
