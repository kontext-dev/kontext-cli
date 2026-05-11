package hookruntime

import (
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func RiskEventFromHookEvent(event hook.Event, timestamp time.Time) risk.HookEvent {
	sessionID := event.SessionID
	if sessionID == "" {
		sessionID = "local"
	}
	return risk.HookEvent{
		SessionID:     sessionID,
		Agent:         event.Agent,
		HookEventName: event.HookName.String(),
		ToolName:      event.ToolName,
		ToolInput:     event.ToolInput,
		ToolResponse:  event.ToolResponse,
		ToolUseID:     event.ToolUseID,
		CWD:           event.CWD,
		Timestamp:     timestamp,
	}
}

func HookResultFromProcessResponse(resp server.ProcessResponse) hook.Result {
	return hook.Result{
		Decision:   decisionFromRisk(resp.Decision),
		Reason:     resp.Reason,
		ReasonCode: resp.ReasonCode,
		EventID:    resp.EventID,
	}
}

func decisionFromRisk(decision risk.Decision) hook.Decision {
	normalized, ok := hook.NormalizeDecision(string(decision))
	if !ok {
		return hook.DecisionDeny
	}
	return normalized
}
