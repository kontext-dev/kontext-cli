package hookruntime

import (
	"fmt"
	"io"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

type Codec interface {
	DecodeHookEvent([]byte) (hook.Event, error)
	EncodeHookResult(hook.Event, hook.Result) ([]byte, error)
}

type Sink interface {
	ProcessHookEvent(hook.Event) (hook.Result, error)
}

type SinkFunc func(hook.Event) (hook.Result, error)

func (f SinkFunc) ProcessHookEvent(event hook.Event) (hook.Result, error) {
	return f(event)
}

func Run(stdin io.Reader, stdout, stderr io.Writer, codec Codec, sink Sink) int {
	input, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: failed to read stdin: %v\n", err)
		return 2
	}

	event, err := codec.DecodeHookEvent(input)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: failed to decode hook input: %v\n", err)
		return 2
	}

	result, err := sink.ProcessHookEvent(event)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: evaluation error: %v\n", err)
		return 2
	}

	out, err := codec.EncodeHookResult(event, result)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: failed to encode hook output: %v\n", err)
		return 2
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintf(stderr, "kontext: failed to write hook output: %v\n", err)
		return 2
	}
	return 0
}
