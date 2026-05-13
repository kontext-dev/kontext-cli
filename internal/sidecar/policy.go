package sidecar

import (
	"context"

	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

type hostedPolicyProvider interface {
	DecideHook(context.Context, hook.Event) (*backend.ProcessHookEventResult, error)
}

type backendPolicyProvider struct {
	client    sidecarClient
	sessionID string
	agentName string
}

func (p backendPolicyProvider) DecideHook(ctx context.Context, event hook.Event) (*backend.ProcessHookEventResult, error) {
	return p.client.ProcessHookEvent(ctx, buildHookEventRequestFromEvent(withHostedSession(event, p.sessionID, p.agentName)))
}
