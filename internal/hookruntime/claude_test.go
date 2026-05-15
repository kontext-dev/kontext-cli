package hookruntime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestDecodeClaudeEventPreservesLargeJSONNumbers(t *testing.T) {
	t.Parallel()

	event, err := DecodeClaudeEvent([]byte(`{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_123",
		"cwd": "/tmp",
		"tool_input": {"id": 9007199254740993}
	}`), "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent() error = %v", err)
	}

	got, ok := event.ToolInput["id"].(json.Number)
	if !ok {
		t.Fatalf("id type = %T, want json.Number", event.ToolInput["id"])
	}
	if got.String() != "9007199254740993" {
		t.Fatalf("id = %s, want exact large number", got.String())
	}
}

func TestDecodeClaudeEventRejectsNullToolInput(t *testing.T) {
	t.Parallel()

	_, err := DecodeClaudeEvent([]byte(`{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_123",
		"cwd": "/tmp",
		"tool_input": null
	}`), "claude")
	if err == nil {
		t.Fatal("DecodeClaudeEvent() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "decode tool input") {
		t.Fatalf("DecodeClaudeEvent() error = %v, want tool input decode error", err)
	}
}

func TestEncodeClaudeResultFailsOnInvalidUpdatedInput(t *testing.T) {
	t.Parallel()

	_, err := EncodeClaudeResult("PreToolUse", hook.Result{
		Decision: hook.DecisionAllow,
		UpdatedInput: map[string]any{
			"bad": func() {},
		},
	})
	if err == nil {
		t.Fatal("EncodeClaudeResult() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "encode updated input") {
		t.Fatalf("EncodeClaudeResult() error = %v, want updated input encode error", err)
	}
}
