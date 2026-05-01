package hookruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

type ClaudeAdapter struct{}

func (ClaudeAdapter) Decode(r io.Reader) (Event, error) {
	var raw map[string]any
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return Event{}, err
	}
	event := risk.HookEvent{
		SessionID:     stringValue(raw, "session_id", "sessionId"),
		Agent:         "claude-code",
		HookEventName: stringValue(raw, "hook_event_name", "hookEventName"),
		ToolName:      stringValue(raw, "tool_name", "toolName"),
		ToolUseID:     stringValue(raw, "tool_use_id", "toolUseID", "toolUseId"),
		CWD:           stringValue(raw, "cwd"),
		Timestamp:     time.Now().UTC(),
	}
	if event.HookEventName == "" {
		event.HookEventName = stringValue(raw, "hook_event")
	}
	if input, ok := raw["tool_input"].(map[string]any); ok {
		event.ToolInput = input
	} else if input, ok := raw["toolInput"].(map[string]any); ok {
		event.ToolInput = input
	}
	if response, ok := raw["tool_response"].(map[string]any); ok {
		event.ToolResponse = response
	} else if response, ok := raw["toolResponse"].(map[string]any); ok {
		event.ToolResponse = response
	}
	if event.HookEventName == "" {
		return Event{}, errors.New("hook event name missing")
	}
	if event.SessionID == "" {
		event.SessionID = "local"
	}
	return Event{
		HookName:  event.HookEventName,
		CanBlock:  event.HookEventName == "PreToolUse",
		RiskEvent: event,
	}, nil
}

func (ClaudeAdapter) Encode(out io.Writer, result Result) error {
	permissionDecision := "allow"
	if result.Mode == ModeEnforce && result.CanBlock && (result.Decision == risk.DecisionAsk || result.Decision == risk.DecisionDeny) {
		permissionDecision = "deny"
	}
	payload := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            result.HookName,
			"permissionDecision":       permissionDecision,
			"permissionDecisionReason": formatReason(result.Decision, result.Reason, result.Mode),
		},
	}
	return json.NewEncoder(out).Encode(payload)
}

func (ClaudeAdapter) MalformedHookName() string {
	return "PreToolUse"
}

func formatReason(decision risk.Decision, reason string, mode Mode) string {
	if reason == "" {
		reason = "no reason provided"
	}
	if mode == ModeObserve {
		return fmt.Sprintf("Kontext observe mode: would %s; %s", decision, reason)
	}
	return reason
}

func stringValue(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := raw[key].(string); ok {
			return value
		}
	}
	return ""
}

var _ Adapter = ClaudeAdapter{}
