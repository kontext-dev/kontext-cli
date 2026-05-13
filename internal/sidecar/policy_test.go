package sidecar

import (
	"context"
	"testing"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestBackendPolicyProviderAddsHostedSessionContext(t *testing.T) {
	t.Parallel()

	client := &recordingPolicyClient{
		result: &backend.ProcessHookEventResult{
			Response: &agentv1.ProcessHookEventResponse{
				Decision: agentv1.Decision_DECISION_ALLOW,
			},
		},
	}
	provider := backendPolicyProvider{
		client:    client,
		sessionID: "session-123",
		agentName: "claude",
	}
	if _, err := provider.DecideHook(context.Background(), hook.Event{
		HookName:  hook.HookPreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "git status"},
	}); err != nil {
		t.Fatalf("DecideHook() error = %v", err)
	}
	if client.request == nil {
		t.Fatal("request = nil, want backend request")
	}
	if client.request.SessionId != "session-123" || client.request.Agent != "claude" {
		t.Fatalf("request session=%q agent=%q, want hosted context", client.request.SessionId, client.request.Agent)
	}
	if client.request.HookEvent != hook.HookPreToolUse.String() || client.request.ToolName != "Bash" {
		t.Fatalf("request = %+v, want hook metadata preserved", client.request)
	}
}

type recordingPolicyClient struct {
	request *agentv1.ProcessHookEventRequest
	result  *backend.ProcessHookEventResult
	err     error
}

func (c *recordingPolicyClient) ProcessHookEvent(_ context.Context, req *agentv1.ProcessHookEventRequest) (*backend.ProcessHookEventResult, error) {
	c.request = req
	if c.err != nil {
		return nil, c.err
	}
	return c.result, nil
}

func (c *recordingPolicyClient) Heartbeat(context.Context, string) error { return nil }
