package server

import (
	"context"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/app/notify"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

type guardHookRuntime struct {
	store  *sqlite.Store
	policy PolicyProvider
}

func newGuardHookRuntime(store *sqlite.Store, policy PolicyProvider) guardHookRuntime {
	return guardHookRuntime{store: store, policy: policy}
}

func (r guardHookRuntime) EvaluateHook(ctx context.Context, event hook.Event) (hook.Result, error) {
	return r.decideAndRecord(ctx, riskEventFromHookEvent(event))
}

func (r guardHookRuntime) IngestEvent(ctx context.Context, event hook.Event) (hook.Result, error) {
	return r.decideAndRecord(ctx, riskEventFromHookEvent(event))
}

func (r guardHookRuntime) decideAndRecord(ctx context.Context, event risk.HookEvent) (hook.Result, error) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	decision, err := r.policy.DecideHook(ctx, event)
	if err != nil {
		return hook.Result{}, err
	}
	record, err := r.store.SaveDecision(ctx, event, decision)
	if err != nil {
		return hook.Result{}, err
	}
	decision.EventID = record.ID
	notify.Decision(decision)
	return hookResultFromRiskDecision(decision), nil
}

func riskEventFromHookEvent(event hook.Event) risk.HookEvent {
	return risk.HookEvent{
		SessionID:     event.SessionID,
		Agent:         event.Agent,
		HookEventName: event.HookName.String(),
		ToolName:      event.ToolName,
		ToolInput:     event.ToolInput,
		ToolResponse:  event.ToolResponse,
		ToolUseID:     event.ToolUseID,
		CWD:           event.CWD,
	}
}

func hookEventFromRiskEvent(event risk.HookEvent) hook.Event {
	return hook.Event{
		SessionID:    event.SessionID,
		Agent:        event.Agent,
		HookName:     hook.HookName(event.HookEventName),
		ToolName:     event.ToolName,
		ToolInput:    event.ToolInput,
		ToolResponse: event.ToolResponse,
		ToolUseID:    event.ToolUseID,
		CWD:          event.CWD,
	}
}

func hookResultFromRiskDecision(decision risk.RiskDecision) hook.Result {
	return hook.Result{
		Decision:   hook.Decision(decision.Decision),
		Reason:     decision.Reason,
		ReasonCode: decision.ReasonCode,
		EventID:    decision.EventID,
	}
}

func riskDecisionFromHookResult(result hook.Result) risk.RiskDecision {
	return risk.RiskDecision{
		Decision:   risk.Decision(result.Decision),
		Reason:     result.Reason,
		ReasonCode: result.ReasonCode,
		EventID:    result.EventID,
	}
}
