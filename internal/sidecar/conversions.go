package sidecar

import (
	"encoding/json"
	"fmt"

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
		data, err := hook.MarshalMap(event.ToolInput)
		if err != nil {
			return EvaluateRequest{}, fmt.Errorf("marshal tool input: %w", err)
		}
		req.ToolInput = data
	}
	if event.ToolResponse != nil {
		data, err := hook.MarshalMap(event.ToolResponse)
		if err != nil {
			return EvaluateRequest{}, fmt.Errorf("marshal tool response: %w", err)
		}
		req.ToolResponse = data
	}
	return req, nil
}

func EventFromEvaluateRequest(sessionID, fallbackAgent string, req *EvaluateRequest) (hook.Event, error) {
	if req == nil {
		return hook.Event{SessionID: sessionID, Agent: fallbackAgent}, nil
	}
	agent := req.Agent
	if agent == "" {
		agent = fallbackAgent
	}
	event := hook.Event{
		SessionID:      sessionID,
		Agent:          agent,
		HookName:       hook.HookName(req.HookEvent),
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
		decision = hook.ResultFromBool(result.Allowed, result.Reason).Decision
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

func rawMap(data json.RawMessage) (map[string]any, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return value, nil
}
