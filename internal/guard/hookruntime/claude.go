package hookruntime

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

type AgentAdapter struct {
	Agent     agent.Agent
	AgentName string
}

func (a AgentAdapter) Decode(r io.Reader) (Event, error) {
	if a.Agent == nil {
		return Event{}, errors.New("agent adapter missing agent")
	}
	input, err := io.ReadAll(r)
	if err != nil {
		return Event{}, err
	}
	agentEvent, err := a.Agent.DecodeHookInput(input)
	if err != nil {
		return Event{}, err
	}
	event := risk.HookEvent{
		SessionID:     agentEvent.SessionID,
		Agent:         a.outputAgentName(),
		HookEventName: agentEvent.HookName.String(),
		ToolName:      agentEvent.ToolName,
		ToolInput:     agentEvent.ToolInput,
		ToolResponse:  agentEvent.ToolResponse,
		ToolUseID:     agentEvent.ToolUseID,
		CWD:           agentEvent.CWD,
		Timestamp:     time.Now().UTC(),
	}
	if event.HookEventName == "" {
		return Event{}, errors.New("hook event name missing")
	}
	if event.SessionID == "" {
		event.SessionID = "local"
	}
	return Event{
		HookName:  event.HookEventName,
		CanBlock:  event.HookEventName == "PreToolUse",
		RiskEvent: event,
	}, nil
}

func (a AgentAdapter) Encode(out io.Writer, result Result) error {
	if a.Agent == nil {
		return errors.New("agent adapter missing agent")
	}
	reason := formatReason(result.Decision, result.Reason, result.Mode)
	hookResult := hook.Result{Reason: reason}
	if result.Mode == ModeEnforce && result.CanBlock {
		switch result.Decision {
		case risk.DecisionAsk, risk.DecisionDeny:
			hookResult.Decision = hook.DecisionDeny
		default:
			hookResult.Decision = hook.DecisionAllow
		}
	} else {
		hookResult.Decision = hook.DecisionAllow
	}
	payload, err := a.Agent.EncodeHookResult(hook.Event{HookName: hook.HookName(result.HookName)}, hookResult)
	if err != nil {
		return err
	}
	_, err = out.Write(append(payload, '\n'))
	return err
}

func (a AgentAdapter) MalformedHookName() string {
	return "PreToolUse"
}

func (a AgentAdapter) outputAgentName() string {
	if a.AgentName != "" {
		return a.AgentName
	}
	if a.Agent != nil {
		return a.Agent.Name()
	}
	return ""
}

func formatReason(decision risk.Decision, reason string, mode Mode) string {
	if reason == "" {
		reason = "no reason provided"
	}
	if mode == ModeObserve {
		return fmt.Sprintf("Kontext observe mode: would %s; %s", decision, reason)
	}
	return reason
}

var _ Adapter = AgentAdapter{}
