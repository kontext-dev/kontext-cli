package hermes

import (
	"encoding/json"
	"fmt"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

func init() {
	agent.Register(&Hermes{})
}

type Hermes struct{}

func (h *Hermes) Name() string { return "hermes" }

type hookInput struct {
	SessionID     string         `json:"session_id"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	ToolResponse  map[string]any `json:"tool_response"`
	ToolUseID     string         `json:"tool_use_id"`
	CWD           string         `json:"cwd"`
}

func (h *Hermes) DecodeHookInput(input []byte) (*agent.HookEvent, error) {
	var in hookInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("hermes: decode hook input: %w", err)
	}
	return &agent.HookEvent{
		SessionID:     in.SessionID,
		HookEventName: in.HookEventName,
		ToolName:      in.ToolName,
		ToolInput:     in.ToolInput,
		ToolResponse:  in.ToolResponse,
		ToolUseID:     in.ToolUseID,
		CWD:           in.CWD,
	}, nil
}

type decision struct {
	Permission string `json:"permission"`
	Reason     string `json:"reason,omitempty"`
}

func (h *Hermes) EncodeAllow(_ *agent.HookEvent, reason string) ([]byte, error) {
	return json.Marshal(decision{Permission: "allow", Reason: reason})
}

func (h *Hermes) EncodeDeny(_ *agent.HookEvent, reason string) ([]byte, error) {
	return json.Marshal(decision{Permission: "deny", Reason: reason})
}
