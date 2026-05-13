package hookcmd

import (
	"io"
	"os"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/hookruntime"
)

func Run(a agent.Agent, evaluate func(hook.Event) (hook.Result, error)) {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr, a, evaluate))
}

func run(stdin io.Reader, stdout, stderr io.Writer, a agent.Agent, evaluate func(hook.Event) (hook.Result, error)) int {
	codec := agentCodec{agentName: a.Name(), agent: a}
	sink := hookruntime.SinkFunc(evaluate)
	return hookruntime.Run(stdin, stdout, stderr, codec, sink)
}

type agentCodec struct {
	agentName string
	agent     agent.Agent
}

func (c agentCodec) DecodeHookEvent(input []byte) (hook.Event, error) {
	event, err := c.agent.DecodeHookInput(input)
	if err != nil {
		return hook.Event{}, err
	}
	if event.Agent == "" {
		event.Agent = c.agentName
	}
	return event, nil
}

func (c agentCodec) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return c.agent.EncodeHookResult(event, result)
}
