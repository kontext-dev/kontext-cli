package hookruntime

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/agent/claude"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

func TestAgentAdapterDecodePreservesHookEvent(t *testing.T) {
	t.Parallel()

	input := strings.NewReader(`{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":".env"},"tool_use_id":"toolu_123","cwd":"/tmp/project"}`)
	event, err := AgentAdapter{Agent: &claude.Claude{}, AgentName: "claude-code"}.Decode(input)
	if err != nil {
		t.Fatal(err)
	}
	if event.HookName != "PreToolUse" || !event.CanBlock {
		t.Fatalf("event = %+v, want blocking PreToolUse", event)
	}
	if event.RiskEvent.Agent != "claude-code" ||
		event.RiskEvent.SessionID != "s1" ||
		event.RiskEvent.ToolName != "Read" ||
		event.RiskEvent.ToolUseID != "toolu_123" ||
		event.RiskEvent.CWD != "/tmp/project" {
		t.Fatalf("risk event = %+v, want decoded metadata", event.RiskEvent)
	}
	if event.RiskEvent.ToolInput["file_path"] != ".env" {
		t.Fatalf("tool input = %+v", event.RiskEvent.ToolInput)
	}
}

func TestAgentAdapterEncodeObserveModeAllowsWouldDeny(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := AgentAdapter{Agent: &claude.Claude{}, AgentName: "claude-code"}.Encode(&out, Result{
		HookName: "PreToolUse",
		CanBlock: true,
		Decision: risk.DecisionDeny,
		Reason:   "blocked",
		Mode:     ModeObserve,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"permissionDecision":"allow"`) {
		t.Fatalf("output = %s", out.String())
	}
	if !strings.Contains(out.String(), `would deny; blocked`) {
		t.Fatalf("output = %s", out.String())
	}
}

func TestAgentAdapterEncodeEnforceModeDeniesAsk(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := AgentAdapter{Agent: &claude.Claude{}, AgentName: "claude-code"}.Encode(&out, Result{
		HookName: "PreToolUse",
		CanBlock: true,
		Decision: risk.DecisionAsk,
		Reason:   "needs review",
		Mode:     ModeEnforce,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("output = %s", out.String())
	}
}
