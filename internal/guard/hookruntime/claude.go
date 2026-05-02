package hookruntime

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	sharedhook "github.com/kontext-security/kontext-cli/internal/hookruntime"
)

type ClaudeAdapter struct{}

func (ClaudeAdapter) Decode(r io.Reader) (Event, error) {
	input, err := io.ReadAll(r)
	if err != nil {
		return Event{}, err
	}
	sharedEvent, err := sharedhook.DecodeClaudeEvent(input, "claude-code")
	if err != nil {
		return Event{}, err
	}
	event := risk.HookEvent{
		SessionID:     sharedEvent.SessionID,
		Agent:         sharedEvent.Agent,
		HookEventName: sharedEvent.HookEventName,
		ToolName:      sharedEvent.ToolName,
		ToolInput:     sharedEvent.ToolInput,
		ToolResponse:  sharedEvent.ToolResponse,
		ToolUseID:     sharedEvent.ToolUseID,
		CWD:           sharedEvent.CWD,
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

func (ClaudeAdapter) Encode(out io.Writer, result Result) error {
	decision := sharedhook.DecisionAllow
	if result.Mode == ModeEnforce && result.CanBlock {
		switch result.Decision {
		case risk.DecisionAsk:
			decision = sharedhook.DecisionDeny
		case risk.DecisionDeny:
			decision = sharedhook.DecisionDeny
		}
	}
	payload, err := sharedhook.EncodeClaudeResult(result.HookName, sharedhook.Result{
		Decision: decision,
		Reason:   formatReason(result.Decision, result.Reason, result.Mode),
	})
	if err != nil {
		return err
	}
	_, err = out.Write(append(payload, '\n'))
	return err
}

func (ClaudeAdapter) MalformedHookName() string {
	return "PreToolUse"
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

var _ Adapter = ClaudeAdapter{}
