package hookruntime

import (
	"bytes"
	"testing"
)

func TestRunWritesStructuredDenyResult(t *testing.T) {
	t.Parallel()

	codec := stubCodec{
		event: Event{HookName: HookPreToolUse},
		out:   []byte(`{"hookSpecificOutput":{"permissionDecision":"deny"}}`),
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	code := Run(
		bytes.NewBufferString(`{"hook_event_name":"PreToolUse"}`),
		stdout,
		stderr,
		codec,
		SinkFunc(func(Event) (Result, error) {
			return Result{Decision: DecisionDeny, Reason: "blocked by policy"}, nil
		}),
	)

	if code != 0 {
		t.Fatalf("Run() exit code = %d, want 0", code)
	}
	if stdout.String() != string(codec.out) {
		t.Fatalf("stdout = %q, want encoded output", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunWritesStructuredAskResult(t *testing.T) {
	t.Parallel()

	codec := stubCodec{
		event: Event{HookName: HookPreToolUse},
		out:   []byte(`{"hookSpecificOutput":{"permissionDecision":"ask"}}`),
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	code := Run(
		bytes.NewBufferString(`{"hook_event_name":"PreToolUse"}`),
		stdout,
		stderr,
		codec,
		SinkFunc(func(Event) (Result, error) {
			return Result{Decision: DecisionAsk, Reason: "approval required"}, nil
		}),
	)

	if code != 0 {
		t.Fatalf("Run() exit code = %d, want 0", code)
	}
	if stdout.String() != string(codec.out) {
		t.Fatalf("stdout = %q, want encoded output", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

type stubCodec struct {
	event Event
	out   []byte
}

func (s stubCodec) DecodeHookEvent([]byte) (Event, error) {
	return s.event, nil
}

func (s stubCodec) EncodeHookResult(Event, Result) ([]byte, error) {
	return s.out, nil
}
