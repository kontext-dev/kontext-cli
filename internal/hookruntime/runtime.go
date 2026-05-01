package hookruntime

import (
	"encoding/json"
	"fmt"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

type Decision string

const (
	DecisionAllow Decision = "ALLOW"
	DecisionAsk   Decision = "ASK"
	DecisionDeny  Decision = "DENY"
)

type Event struct {
	SessionID      string
	Agent          string
	HookEventName  string
	ToolName       string
	ToolInput      map[string]any
	ToolResponse   map[string]any
	ToolUseID      string
	CWD            string
	PermissionMode string
	DurationMs     *int64
	Error          string
	IsInterrupt    *bool
}

type Result struct {
	Decision     Decision
	Reason       string
	ReasonCode   string
	RequestID    string
	Mode         string
	Epoch        string
	UpdatedInput map[string]any
}

type Processor interface {
	ProcessHookEvent(Event) (Result, error)
}

func EventFromAgent(agentName string, event *agent.HookEvent) Event {
	if event == nil {
		return Event{Agent: agentName}
	}
	return Event{
		SessionID:      event.SessionID,
		Agent:          agentName,
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
	}
}

func ResultFromBool(allowed bool, reason string) Result {
	if allowed {
		return Result{Decision: DecisionAllow, Reason: reason}
	}
	return Result{Decision: DecisionDeny, Reason: reason}
}

func (r Result) Allowed() bool {
	return r.Decision == DecisionAllow
}

func (r Result) ClaudeReason() string {
	reason := r.Reason
	if r.Decision == DecisionAsk && r.RequestID != "" {
		if reason != "" {
			return fmt.Sprintf("%s Request ID: %s", reason, r.RequestID)
		}
		return fmt.Sprintf("Kontext access policy requires approval. Request ID: %s", r.RequestID)
	}
	if reason == "" && r.Decision == DecisionAsk {
		return "Kontext access policy requires approval."
	}
	if reason == "" && r.Decision == DecisionDeny {
		return "Blocked by Kontext access policy."
	}
	return reason
}

func MarshalMap(value map[string]any) (json.RawMessage, error) {
	if value == nil {
		return nil, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return data, nil
}
