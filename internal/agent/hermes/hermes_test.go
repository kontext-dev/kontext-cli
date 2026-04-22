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
