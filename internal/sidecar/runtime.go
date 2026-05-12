package sidecar

import (
	"context"

	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

type hostedHookRuntime struct {
	client            sidecarClient
	sessionID         string
	agentName         string
	diagnostic        diagnostic.Logger
	currentAccessMode func() backend.HostedAccessMode
	refreshAccessMode func(backend.HostedAccessMode) error
}

func (r hostedHookRuntime) EvaluateHook(ctx context.Context, event hook.Event) (hook.Result, error) {
	evalCtx, cancel := context.WithTimeout(ctx, hookEvalTimeout)
	defer cancel()

	result, err := r.processHostedHookEvent(evalCtx, event)
	if err != nil {
		r.diagnostic.Printf("sidecar enforce: %v\n", err)
		accessMode := r.currentAccessMode()
		if accessMode != backend.HostedAccessModeEnforce {
			return hook.Result{
				Decision: hook.DecisionAllow,
				Reason:   "Kontext hosted access is not enforcing.",
				Mode:     string(accessMode),
			}, nil
		}
		return hook.Result{
			Decision: hook.DecisionDeny,
			Reason:   "Kontext access policy could not be evaluated.",
		}, nil
	}

	if err := r.refreshAccessMode(result.AccessMode); err != nil {
		r.diagnostic.Printf("sidecar access mode persist: %v\n", err)
		if result.AccessMode == backend.HostedAccessModeEnforce {
			return hook.Result{
				Decision: hook.DecisionDeny,
				Reason:   "Kontext access policy mode could not be persisted.",
				Mode:     string(result.AccessMode),
			}, nil
		}
	}

	accessMode := result.AccessMode
	if accessMode == "" {
		accessMode = r.currentAccessMode()
	}
	return HookResultFromHostedResult(result, accessMode), nil
}

func (r hostedHookRuntime) IngestEvent(ctx context.Context, event hook.Event) (hook.Result, error) {
	result, err := r.processHostedHookEvent(ctx, event)
	if err != nil {
		return hook.Result{}, err
	}
	if err := r.refreshAccessMode(result.AccessMode); err != nil {
		return hook.Result{}, err
	}
	accessMode := result.AccessMode
	if accessMode == "" {
		accessMode = r.currentAccessMode()
	}
	return HookResultFromHostedResult(result, accessMode), nil
}

func (r hostedHookRuntime) processHostedHookEvent(ctx context.Context, event hook.Event) (*backend.ProcessHookEventResult, error) {
	return r.client.ProcessHookEvent(ctx, buildHookEventRequestFromEvent(withHostedSession(event, r.sessionID, r.agentName)))
}

func withHostedSession(event hook.Event, sessionID, agentName string) hook.Event {
	event.SessionID = sessionID
	if event.Agent == "" {
		event.Agent = agentName
	}
	return event
}
