package hook

import (
	"io"
	"os"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/hookruntime"
)

func Run(a agent.Agent, evaluate func(*agent.HookEvent) (hookruntime.Result, error)) {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr, a, evaluate))
}

func run(stdin io.Reader, stdout, stderr io.Writer, a agent.Agent, evaluate func(*agent.HookEvent) (hookruntime.Result, error)) int {
	codec := agentCodec{agentName: a.Name(), agent: a}
	sink := hookruntime.SinkFunc(func(event hookruntime.Event) (hookruntime.Result, error) {
		return evaluate(agentEventFromRuntime(event))
	})
	return hookruntime.Run(stdin, stdout, stderr, codec, sink)
}

type agentCodec struct {
	agentName string
	agent     agent.Agent
}

func (c agentCodec) DecodeHookEvent(input []byte) (hookruntime.Event, error) {
	event, err := c.agent.DecodeHookInput(input)
	if err != nil {
		return hookruntime.Event{}, err
	}
	return hookruntime.EventFromAgent(c.agentName, event), nil
}

func (c agentCodec) EncodeHookResult(event hookruntime.Event, result hookruntime.Result) ([]byte, error) {
	agentEvent := agentEventFromRuntime(event)
	if result.Allowed() {
		return c.agent.EncodeAllow(agentEvent, result.ClaudeReason(), result.UpdatedInput)
	}
	return c.agent.EncodeDeny(agentEvent, result.ClaudeReason())
}

func agentEventFromRuntime(event hookruntime.Event) *agent.HookEvent {
	return &agent.HookEvent{
		SessionID:      event.SessionID,
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
