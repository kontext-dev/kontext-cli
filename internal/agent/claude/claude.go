package claude

import (
	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/hookruntime"
)

func init() {
	agent.Register(&Claude{})
}

type Claude struct{}

func (c *Claude) Name() string { return "claude" }

func (c *Claude) DecodeHookInput(input []byte) (*agent.HookEvent, error) {
	event, err := hookruntime.DecodeClaudeEvent(input, c.Name())
	if err != nil {
		return nil, err
	}
	return &agent.HookEvent{
		SessionID:      event.SessionID,
		HookEventName:  event.HookEventName,
		ToolName:       event.ToolName,
		ToolInput:      event.ToolInput,
		ToolResponse:   event.ToolResponse,
		ToolUseID:      event.ToolUseID,
		CWD:            event.CWD,
		PermissionMode: event.PermissionMode,
		DurationMs:     event.DurationMs,
		Error:          event.Error,
		IsInterrupt:    event.IsInterrupt,
	}, nil
}

func (c *Claude) EncodeAllow(event *agent.HookEvent, reason string, updatedInput map[string]any) ([]byte, error) {
	return hookruntime.EncodeClaudeResult(event.HookEventName, hookruntime.Result{
		Decision:     hookruntime.DecisionAllow,
		Reason:       reason,
		UpdatedInput: updatedInput,
	})
}

func (c *Claude) EncodeDeny(event *agent.HookEvent, reason string) ([]byte, error) {
	return hookruntime.EncodeClaudeResult(event.HookEventName, hookruntime.Result{
		Decision: hookruntime.DecisionDeny,
		Reason:   reason,
	})
}
