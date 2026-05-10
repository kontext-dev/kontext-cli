package hookruntime

import (
	"encoding/json"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

type HookName = hook.HookName

const (
	HookPreToolUse        = hook.HookPreToolUse
	HookPostToolUse       = hook.HookPostToolUse
	HookPostToolUseFailed = hook.HookPostToolUseFailed
	HookUserPromptSubmit  = hook.HookUserPromptSubmit
)

type Decision = hook.Decision

const (
	DecisionAllow = hook.DecisionAllow
	DecisionAsk   = hook.DecisionAsk
	DecisionDeny  = hook.DecisionDeny
)

type Event = hook.Event
type Result = hook.Result

func ResultFromBool(allowed bool, reason string) Result {
	return hook.ResultFromBool(allowed, reason)
}

func NormalizeDecision(value string) (Decision, bool) {
	return hook.NormalizeDecision(value)
}

func MarshalMap(value map[string]any) (json.RawMessage, error) {
	return hook.MarshalMap(value)
}
