package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
)

func newTestLogger(buf *bytes.Buffer) diagnostic.Logger {
	return diagnostic.New(buf, true)
}

func TestHeartbeatDeduplication(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	state := newHeartbeatState()
	now := time.Unix(100, 0)

	state.record(now, errors.New("connection refused"), logger.Printf)
	state.record(now.Add(time.Second), errors.New("connection refused"), logger.Printf)
	state.record(now.Add(5*time.Second), nil, logger.Printf)

	output := buf.String()
	errCount := strings.Count(output, "sidecar heartbeat:")
	recoveryCount := strings.Count(output, "heartbeat recovered")
	if errCount != 1 {
		t.Fatalf("expected 1 deduplicated error log, got %d:\n%s", errCount, output)
	}
	if recoveryCount != 1 {
		t.Fatalf("expected 1 recovery log, got %d:\n%s", recoveryCount, output)
	}
}

func TestHeartbeatDifferentErrorsBothLogged(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	state := newHeartbeatState()
	now := time.Unix(100, 0)

	state.record(now, errors.New("error A"), logger.Printf)
	state.record(now.Add(time.Second), errors.New("error B"), logger.Printf)

	output := buf.String()
	errCount := strings.Count(output, "sidecar heartbeat:")
	if errCount != 2 {
		t.Fatalf("expected 2 error logs for different errors, got %d:\n%s", errCount, output)
	}
}

func TestHeartbeatBackoffIntervalCalculation(t *testing.T) {
	t.Parallel()

	state := newHeartbeatState()
	now := time.Unix(100, 0)
	want := []time.Duration{
		60 * time.Second,
		120 * time.Second,
		240 * time.Second,
		heartbeatMaxInterval,
		heartbeatMaxInterval,
	}
	for i, interval := range want {
		state.record(now.Add(time.Duration(i)*time.Second), errors.New("offline"), func(string, ...any) {})
		if got := state.nextInterval(); got != interval {
			t.Fatalf("after failure %d: interval = %v, want %v", i+1, got, interval)
		}
	}
	state.record(now.Add(10*time.Second), nil, func(string, ...any) {})
	if got := state.nextInterval(); got != heartbeatMinInterval {
		t.Fatalf("after success: interval = %v, want %v", got, heartbeatMinInterval)
	}
}

func TestAcceptLoopReturnsOnListenerError(t *testing.T) {
	t.Parallel()

	ln := &stubListener{acceptErr: errors.New("accept failed")}
	s := &Server{listener: ln}

	done := make(chan struct{})
	go func() {
		s.acceptLoop(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("acceptLoop did not return after listener error")
	}

	if got := ln.accepts; got != 1 {
		t.Fatalf("Accept() calls = %d, want 1", got)
	}
}

func TestDefaultAllowResultOmitsPlaceholderReason(t *testing.T) {
	t.Parallel()

	result := defaultAllowResult()
	if !result.Allowed {
		t.Fatal("defaultAllowResult().Allowed = false, want true")
	}
	if result.Reason != "" {
		t.Fatalf("defaultAllowResult().Reason = %q, want empty", result.Reason)
	}
}

func TestBuildHookEventRequestPreservesTelemetryPayload(t *testing.T) {
	t.Parallel()

	toolInput := json.RawMessage(`{"command":"pwd"}`)
	toolResponse := json.RawMessage(`{"stdout":"/tmp/project"}`)
	isInterrupt := true
	durationMs := int64(42)
	req := &EvaluateRequest{
		HookEvent:      "PostToolUse",
		ToolName:       "Bash",
		ToolInput:      toolInput,
		ToolResponse:   toolResponse,
		ToolUseID:      "toolu_123",
		CWD:            "/tmp/project",
		PermissionMode: "acceptEdits",
		DurationMs:     &durationMs,
		Error:          "failed",
		IsInterrupt:    &isInterrupt,
	}

	got := buildHookEventRequest("session-123", "claude", req)
	if got.SessionId != "session-123" ||
		got.Agent != "claude" ||
		got.HookEvent != req.HookEvent ||
		got.ToolName != req.ToolName ||
		got.ToolUseId != req.ToolUseID ||
		got.Cwd != req.CWD {
		t.Fatalf("buildHookEventRequest() = %+v, want copied metadata", got)
	}
	if got.GetPermissionMode() != req.PermissionMode {
		t.Fatalf("PermissionMode = %q, want %q", got.GetPermissionMode(), req.PermissionMode)
	}
	if got.GetDurationMs() != *req.DurationMs {
		t.Fatalf("DurationMs = %d, want %d", got.GetDurationMs(), *req.DurationMs)
	}
	if got.GetError() != req.Error {
		t.Fatalf("Error = %q, want %q", got.GetError(), req.Error)
	}
	if got.GetIsInterrupt() != *req.IsInterrupt {
		t.Fatalf("IsInterrupt = %t, want %t", got.GetIsInterrupt(), *req.IsInterrupt)
	}
	if string(got.ToolInput) != string(toolInput) {
		t.Fatalf("ToolInput = %s, want %s", got.ToolInput, toolInput)
	}
	if string(got.ToolResponse) != string(toolResponse) {
		t.Fatalf("ToolResponse = %s, want %s", got.ToolResponse, toolResponse)
	}
}

func TestBuildHookEventRequestPreservesExplicitFalseInterrupt(t *testing.T) {
	t.Parallel()

	isInterrupt := false
	got := buildHookEventRequest("session-123", "claude", &EvaluateRequest{
		HookEvent:   "PostToolUseFailure",
		ToolName:    "Bash",
		ToolUseID:   "toolu_123",
		IsInterrupt: &isInterrupt,
	})

	if got.IsInterrupt == nil {
		t.Fatal("IsInterrupt = nil, want explicit false")
	}
	if got.GetIsInterrupt() {
		t.Fatal("IsInterrupt = true, want false")
	}
}

func TestBuildHookEventRequestPreservesExplicitZeroDuration(t *testing.T) {
	t.Parallel()

	durationMs := int64(0)
	got := buildHookEventRequest("session-123", "claude", &EvaluateRequest{
		HookEvent:  "PostToolUse",
		ToolName:   "Bash",
		ToolUseID:  "toolu_123",
		DurationMs: &durationMs,
	})

	if got.DurationMs == nil {
		t.Fatal("DurationMs = nil, want explicit zero")
	}
	if got.GetDurationMs() != 0 {
		t.Fatalf("DurationMs = %d, want 0", got.GetDurationMs())
	}
}

type stubListener struct {
	accepts   int
	acceptErr error
}

func (l *stubListener) Accept() (net.Conn, error) {
	l.accepts++
	return nil, l.acceptErr
}

func (l *stubListener) Close() error { return nil }

func (l *stubListener) Addr() net.Addr { return stubAddr("stub") }

type stubAddr string

func (a stubAddr) Network() string { return string(a) }

func (a stubAddr) String() string { return string(a) }
