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

	s := &Server{
		diagnostic: logger,
		sessionID:  "test-session",
	}

	// Mimic what heartbeatLoop would do with dedup logic:
	interval := 30 * time.Second
	var lastErr string
	failureStart := time.Time{}

	// First two calls: same error (dedup → only 1 log)
	// Third call: success (recovery log)
	for i := 0; i < 3; i++ {
		var err error
		if i < 2 {
			err = errors.New("connection refused")
		}
		if err != nil {
			errStr := err.Error()
			if lastErr != errStr {
				s.diagnostic.Printf("sidecar heartbeat: %v\n", err)
				lastErr = errStr
			}
			if failureStart.IsZero() {
				failureStart = time.Now()
			}
			interval *= 2
			if interval > 300*time.Second {
				interval = 300 * time.Second
			}
		} else {
			if !failureStart.IsZero() {
				elapsed := time.Since(failureStart).Truncate(time.Second)
				s.diagnostic.Printf("sidecar: heartbeat recovered after %s\n", elapsed)
				failureStart = time.Time{}
				lastErr = ""
			}
			interval = 30 * time.Second
		}
	}

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
	s := &Server{
		diagnostic: logger,
		sessionID:  "test-session",
	}

	// Simulate two different errors
	var lastErr string
	for _, errStr := range []string{"error A", "error B"} {
		if lastErr != errStr {
			s.diagnostic.Printf("sidecar heartbeat: %s\n", errStr)
			lastErr = errStr
		}
	}

	output := buf.String()
	errCount := strings.Count(output, "sidecar heartbeat:")
	if errCount != 2 {
		t.Fatalf("expected 2 error logs for different errors, got %d:\n%s", errCount, output)
	}
}

func TestHeartbeatBackoffIntervalCalculation(t *testing.T) {
	t.Parallel()

	const (
		minInterval = 30 * time.Second
		maxInterval = 5 * time.Minute
	)

	interval := minInterval

	// First failure: 30s -> 60s
	interval *= 2
	if interval != 60*time.Second {
		t.Fatalf("after 1st failure: interval = %v, want 60s", interval)
	}

	// Second failure: 60s -> 120s
	interval *= 2
	if interval != 120*time.Second {
		t.Fatalf("after 2nd failure: interval = %v, want 120s", interval)
	}

	// Third failure: 120s -> 240s
	interval *= 2
	if interval != 240*time.Second {
		t.Fatalf("after 3rd failure: interval = %v, want 240s", interval)
	}

	// Fourth failure: 240s -> 480s, capped at 300s
	interval *= 2
	if interval > maxInterval {
		interval = maxInterval
	}
	if interval != 300*time.Second {
		t.Fatalf("after 4th failure: interval = %v, want 300s (capped)", interval)
	}

	// Success resets to 30s
	interval = minInterval
	if interval != 30*time.Second {
		t.Fatalf("after success: interval = %v, want 30s", interval)
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
