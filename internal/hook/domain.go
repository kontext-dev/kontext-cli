package hook

import (
	"encoding/json"
	"fmt"
	"strings"
)

type HookName string

const (
	HookPreToolUse        HookName = "PreToolUse"
	HookPostToolUse       HookName = "PostToolUse"
	HookPostToolUseFailed HookName = "PostToolUseFailure"
	HookUserPromptSubmit  HookName = "UserPromptSubmit"
)

func (h HookName) String() string {
	return string(h)
}

func (h HookName) CanBlock() bool {
	return h == HookPreToolUse
}

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionAsk   Decision = "ask"
	DecisionDeny  Decision = "deny"
)

func NormalizeDecision(value string) (Decision, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(DecisionAllow):
		return DecisionAllow, true
	case string(DecisionAsk):
		return DecisionAsk, true
	case string(DecisionDeny):
		return DecisionDeny, true
	default:
		return "", false
	}
}

type Event struct {
	SessionID      string
	Agent          string
	HookName       HookName
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
	EventID      string
	Mode         string
	Epoch        string
	UpdatedInput map[string]any
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

func (r Result) Blocking() bool {
	return r.Decision == DecisionAsk || r.Decision == DecisionDeny
}

func (r Result) ClaudeReason() string {
	reason := r.Reason
	if r.Decision == DecisionAsk && r.RequestID != "" {
		if reason != "" {
			if containsRequestID(reason) {
				return reason
			}
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

func containsRequestID(reason string) bool {
	return strings.Contains(strings.ToLower(reason), "request id")
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
