package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func EvaluateRequestFromEvent(event hook.Event) (EvaluateRequest, error) {
	req := EvaluateRequest{
		Type:           "evaluate",
		Agent:          event.Agent,
		HookEvent:      event.HookName.String(),
		ToolName:       event.ToolName,
		ToolUseID:      event.ToolUseID,
		CWD:            event.CWD,
		PermissionMode: event.PermissionMode,
		DurationMs:     event.DurationMs,
		Error:          event.Error,
		IsInterrupt:    event.IsInterrupt,
	}

	if event.ToolInput != nil {
		data, err := marshalMap(event.ToolInput)
		if err != nil {
			return EvaluateRequest{}, fmt.Errorf("marshal tool input: %w", err)
		}
		req.ToolInput = data
	}
	if event.ToolResponse != nil {
		data, err := marshalMap(event.ToolResponse)
		if err != nil {
			return EvaluateRequest{}, fmt.Errorf("marshal tool response: %w", err)
		}
		req.ToolResponse = data
	}
	return req, nil
}

func EventFromEvaluateRequest(sessionID, fallbackAgent string, req *EvaluateRequest) (hook.Event, error) {
	if req == nil {
		return hook.Event{}, errors.New("evaluate request missing")
	}
	if req.HookEvent == "" {
		return hook.Event{}, errors.New("hook event missing")
	}
	hookName, ok := normalizeHookName(req.HookEvent)
	if !ok {
		return hook.Event{}, fmt.Errorf("unknown hook event %q", req.HookEvent)
	}
	agent := req.Agent
	if agent == "" {
		agent = fallbackAgent
	}
	event := hook.Event{
		SessionID:      sessionID,
		Agent:          agent,
		HookName:       hookName,
		ToolName:       req.ToolName,
		ToolUseID:      req.ToolUseID,
		CWD:            req.CWD,
		PermissionMode: req.PermissionMode,
		DurationMs:     req.DurationMs,
		Error:          req.Error,
		IsInterrupt:    req.IsInterrupt,
	}

	var err error
	event.ToolInput, err = rawMap(req.ToolInput)
	if err != nil {
		return hook.Event{}, fmt.Errorf("decode tool input: %w", err)
	}
	event.ToolResponse, err = rawMap(req.ToolResponse)
	if err != nil {
		return hook.Event{}, fmt.Errorf("decode tool response: %w", err)
	}
	return event, nil
}

func EvaluateResultFromResult(result hook.Result) EvaluateResult {
	return EvaluateResult{
		Type:         "result",
		Decision:     string(result.Decision),
		Allowed:      result.Allowed(),
		Reason:       result.Reason,
		ReasonCode:   result.ReasonCode,
		RequestID:    result.RequestID,
		Mode:         result.Mode,
		Epoch:        result.Epoch,
		UpdatedInput: result.UpdatedInput,
	}
}

func ResultFromEvaluateResult(result EvaluateResult) hook.Result {
	decision, ok := hook.NormalizeDecision(result.Decision)
	if !ok {
		decision = resultFromBool(result.Allowed).Decision
	}
	return hook.Result{
		Decision:     decision,
		Reason:       result.Reason,
		ReasonCode:   result.ReasonCode,
		RequestID:    result.RequestID,
		Mode:         result.Mode,
		Epoch:        result.Epoch,
		UpdatedInput: result.UpdatedInput,
	}
}

func resultFromBool(allowed bool) hook.Result {
	if allowed {
		return hook.Result{Decision: hook.DecisionAllow}
	}
	return hook.Result{Decision: hook.DecisionDeny}
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

func rawMap(data json.RawMessage) (map[string]any, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func normalizeHookName(value string) (hook.HookName, bool) {
	switch hookName := hook.HookName(strings.TrimSpace(value)); hookName {
	case hook.HookPreToolUse, hook.HookPostToolUse, hook.HookPostToolUseFailed, hook.HookUserPromptSubmit:
		return hookName, true
	default:
		return "", false
	}
}
