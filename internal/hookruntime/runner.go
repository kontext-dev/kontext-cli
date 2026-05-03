package hookruntime

import (
	"fmt"
	"io"
)

type Codec interface {
	DecodeHookEvent([]byte) (Event, error)
	EncodeHookResult(Event, Result) ([]byte, error)
}

type Sink interface {
	ProcessHookEvent(Event) (Result, error)
}

type SinkFunc func(Event) (Result, error)

func (f SinkFunc) ProcessHookEvent(event Event) (Result, error) {
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
	if result.Decision == DecisionAsk || result.Decision == DecisionDeny {
		if reason := result.ClaudeReason(); reason != "" {
			fmt.Fprintln(stderr, reason)
		}
		return 2
	}
	return 0
}
