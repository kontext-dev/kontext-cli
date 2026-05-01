package hook

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

type stubAgent struct {
	decodeErr         error
	allowErr          error
	denyErr           error
	allowUpdatedInput map[string]any
}

func (s *stubAgent) Name() string { return "stub" }

func (s *stubAgent) DecodeHookInput(input []byte) (*agent.HookEvent, error) {
	if s.decodeErr != nil {
		return nil, s.decodeErr
	}
	return &agent.HookEvent{HookEventName: "PreToolUse"}, nil
}

func (s *stubAgent) EncodeAllow(event *agent.HookEvent, reason string, updatedInput map[string]any) ([]byte, error) {
	if s.allowErr != nil {
		return nil, s.allowErr
	}
	s.allowUpdatedInput = updatedInput
	return []byte("ALLOW"), nil
}

func (s *stubAgent) EncodeDeny(event *agent.HookEvent, reason string) ([]byte, error) {
	if s.denyErr != nil {
		return nil, s.denyErr
	}
	return []byte("DENY"), nil
}

func TestRunAllowsAndWritesOutput(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	stub := &stubAgent{}
	updatedInput := map[string]any{"command": "echo ok"}
	code := run(strings.NewReader(`{"hook_event_name":"PreToolUse"}`), stdout, stderr, stub, func(event *agent.HookEvent) (bool, string, map[string]any, error) {
		if event.HookEventName != "PreToolUse" {
			t.Fatalf("event.HookEventName = %q, want %q", event.HookEventName, "PreToolUse")
		}
		return true, "ok", updatedInput, nil
	})

	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0", code)
	}
	if got := stdout.String(); got != "ALLOW" {
		t.Fatalf("stdout = %q, want %q", got, "ALLOW")
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr = %q, want empty", got)
	}
	if stub.allowUpdatedInput["command"] != "echo ok" {
		t.Fatalf("updated input = %#v, want command", stub.allowUpdatedInput)
	}
}

func TestRunReturnsErrorWhenAllowEncodingFails(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	code := run(strings.NewReader(`{"hook_event_name":"PreToolUse"}`), stdout, stderr, &stubAgent{allowErr: errors.New("encode failed")}, func(*agent.HookEvent) (bool, string, map[string]any, error) {
		return true, "ok", nil, nil
	})

	if code != 2 {
		t.Fatalf("run() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "failed to encode allow output") {
		t.Fatalf("stderr = %q, want encode failure", stderr.String())
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunReturnsErrorWhenWriteFails(t *testing.T) {
	t.Parallel()

	stderr := &bytes.Buffer{}

	code := run(strings.NewReader(`{"hook_event_name":"PreToolUse"}`), errWriter{}, stderr, &stubAgent{}, func(*agent.HookEvent) (bool, string, map[string]any, error) {
		return true, "ok", nil, nil
	})

	if code != 2 {
		t.Fatalf("run() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "failed to write hook output") {
		t.Fatalf("stderr = %q, want write failure", stderr.String())
	}
}

func TestRunReturnsErrorWhenDenyEncodingFails(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	code := run(strings.NewReader(`{"hook_event_name":"PreToolUse"}`), stdout, stderr, &stubAgent{denyErr: errors.New("encode failed")}, func(*agent.HookEvent) (bool, string, map[string]any, error) {
		return false, "blocked", nil, nil
	})

	if code != 2 {
		t.Fatalf("run() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "failed to encode deny output") {
		t.Fatalf("stderr = %q, want encode failure", stderr.String())
	}
}

type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}
