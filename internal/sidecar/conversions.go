package sidecar

import (
	"encoding/json"
	"strings"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

func EvaluateRequestFromEvent(event hook.Event) (EvaluateRequest, error) {
	return localruntime.EvaluateRequestFromEvent(event)
}

func EventFromEvaluateRequest(sessionID, fallbackAgent string, req *EvaluateRequest) (hook.Event, error) {
	return localruntime.EventFromEvaluateRequest(sessionID, fallbackAgent, req)
}

func EvaluateResultFromResult(result hook.Result) EvaluateResult {
	return localruntime.EvaluateResultFromResult(result)
}

func ResultFromEvaluateResult(result EvaluateResult) hook.Result {
	return localruntime.ResultFromEvaluateResult(result)
}

func HookResultFromHostedResult(result *backend.ProcessHookEventResult, accessMode backend.HostedAccessMode) hook.Result {
	if result == nil {
		return hook.Result{
			Decision: hook.DecisionDeny,
			Reason:   "Kontext access policy could not be evaluated.",
			Mode:     string(accessMode),
		}
	}
	resp := result.Response
	out := hook.Result{
		Reason:     resp.GetReason(),
		ReasonCode: result.ReasonCode,
		RequestID:  result.RequestID,
		Mode:       string(accessMode),
		Epoch:      result.PolicySetEpoch,
	}
	if accessMode != backend.HostedAccessModeEnforce {
		out.Decision = hook.DecisionAllow
		return out
	}
	switch resp.GetDecision() {
	case agentv1.Decision_DECISION_ALLOW:
		out.Decision = hook.DecisionAllow
	case agentv1.Decision_DECISION_ASK:
		out.Decision = hook.DecisionAsk
	case agentv1.Decision_DECISION_DENY:
		fallthrough
	default:
		out.Decision = hook.DecisionDeny
	}
	return out
}

func marshalMap(value map[string]any) (json.RawMessage, error) {
	if value == nil {
		return nil, nil
	}
	return json.Marshal(value)
}

func normalizeHookName(value string) (hook.HookName, bool) {
	switch hookName := hook.HookName(strings.TrimSpace(value)); hookName {
	case hook.HookPreToolUse, hook.HookPostToolUse, hook.HookPostToolUseFailed, hook.HookUserPromptSubmit:
		return hookName, true
	default:
		return "", false
	}
}
