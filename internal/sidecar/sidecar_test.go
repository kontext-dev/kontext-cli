package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/hookruntime"
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

func TestIngestEventRefreshesAccessMode(t *testing.T) {
	t.Parallel()

	modePath := filepath.Join(t.TempDir(), "access-mode")
	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		modePath:   modePath,
		accessMode: backend.HostedAccessModeNoPolicy,
		client:     &stubProcessor{result: &backend.ProcessHookEventResult{AccessMode: backend.HostedAccessModeEnforce}},
		diagnostic: diagnostic.New(io.Discard, false),
	}

	s.ingestEvent(context.Background(), &EvaluateRequest{HookEvent: "PostToolUse"})

	if got := s.currentAccessMode(); got != backend.HostedAccessModeEnforce {
		t.Fatalf("currentAccessMode() = %q, want enforce", got)
	}
	data, err := os.ReadFile(modePath)
	if err != nil {
		t.Fatalf("access mode file: %v", err)
	}
	if string(data) != string(backend.HostedAccessModeEnforce) {
		t.Fatalf("access mode file = %q, want enforce", data)
	}
}

func TestEvaluatePreToolUseUsesBackendDecision(t *testing.T) {
	t.Parallel()

	client := &stubProcessor{
		result: &backend.ProcessHookEventResult{
			Response: &agentv1.ProcessHookEventResponse{
				Decision: agentv1.Decision_DECISION_DENY,
				Reason:   "blocked",
			},
			ReasonCode:     "DENY_POLICY_CHECK",
			RequestID:      "request-1",
			AccessMode:     backend.HostedAccessModeEnforce,
			PolicySetEpoch: "4",
		},
	}
	s := &Server{
		sessionID: "session-123",
		agentName: "claude",
		modePath:  filepath.Join(t.TempDir(), "access-mode"),
		client:    client,
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"gh repo delete"}`),
	})

	if result.Allowed {
		t.Fatal("evaluate().Allowed = true, want false")
	}
	if result.Reason != "blocked" {
		t.Fatalf("evaluate().Reason = %q, want blocked", result.Reason)
	}
	if result.ReasonCode != "DENY_POLICY_CHECK" || result.RequestID != "request-1" || result.Mode != "enforce" || result.Epoch != "4" {
		t.Fatalf("evaluate() metadata = reasonCode:%q requestID:%q mode:%q epoch:%q", result.ReasonCode, result.RequestID, result.Mode, result.Epoch)
	}
	if client.processCalls != 1 {
		t.Fatalf("ProcessHookEvent calls = %d, want 1", client.processCalls)
	}
}

func TestEvaluatePreToolUseAskKeepsRawReasonAndRequestMetadata(t *testing.T) {
	t.Parallel()

	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		modePath:   filepath.Join(t.TempDir(), "access-mode"),
		accessMode: backend.HostedAccessModeEnforce,
		client: &stubProcessor{
			result: &backend.ProcessHookEventResult{
				Response: &agentv1.ProcessHookEventResponse{
					Decision: agentv1.Decision_DECISION_ASK,
					Reason:   "approval required",
				},
				RequestID:  "request-123",
				AccessMode: backend.HostedAccessModeEnforce,
			},
		},
		diagnostic: diagnostic.New(io.Discard, false),
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"gh pr merge 92"}`),
	})

	if result.Allowed {
		t.Fatal("evaluate().Allowed = true, want false")
	}
	if result.Reason != "approval required" {
		t.Fatalf("evaluate().Reason = %q, want raw backend reason", result.Reason)
	}
	if result.RequestID != "request-123" {
		t.Fatalf("evaluate().RequestID = %q, want request-123", result.RequestID)
	}

	claudeOutput, err := hookruntime.EncodeClaudeResult("PreToolUse", hookruntime.Result{
		Decision:  hookruntime.Decision(result.Decision),
		Reason:    result.Reason,
		RequestID: result.RequestID,
	})
	if err != nil {
		t.Fatalf("EncodeClaudeResult() error = %v", err)
	}
	if !strings.Contains(string(claudeOutput), `"permissionDecision":"ask"`) {
		t.Fatalf("claude output = %s, want ask", claudeOutput)
	}
	if strings.Count(string(claudeOutput), "Request ID: request-123") != 1 {
		t.Fatalf("claude output = %s, want one request id", claudeOutput)
	}
}

func TestEvaluatePreToolUseAllowsBackendBlocksWhenNotEnforcing(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		decision agentv1.Decision
	}{
		{name: "ask", decision: agentv1.Decision_DECISION_ASK},
		{name: "deny", decision: agentv1.Decision_DECISION_DENY},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := &Server{
				sessionID:  "session-123",
				agentName:  "claude",
				modePath:   filepath.Join(t.TempDir(), "access-mode"),
				accessMode: backend.HostedAccessModeEnforce,
				client: &stubProcessor{
					result: &backend.ProcessHookEventResult{
						Response: &agentv1.ProcessHookEventResponse{
							Decision: tc.decision,
							Reason:   "backend observed a block",
						},
						ReasonCode:     "OBSERVE_ONLY",
						RequestID:      "request-observe",
						AccessMode:     backend.HostedAccessModeNoPolicy,
						PolicySetEpoch: "7",
					},
				},
				diagnostic: diagnostic.New(io.Discard, false),
			}

			result := s.evaluate(context.Background(), &EvaluateRequest{
				HookEvent: "PreToolUse",
				ToolName:  "Bash",
				ToolInput: json.RawMessage(`{"command":"gh pr merge 92"}`),
			})

			if !result.Allowed {
				t.Fatalf("evaluate().Allowed = false, want true for %s in no_policy mode", tc.name)
			}
			if result.Decision != string(hookruntime.DecisionAllow) {
				t.Fatalf("evaluate().Decision = %q, want allow", result.Decision)
			}
			if result.Reason != "backend observed a block" {
				t.Fatalf("evaluate().Reason = %q, want backend reason", result.Reason)
			}
			if result.ReasonCode != "OBSERVE_ONLY" || result.RequestID != "request-observe" || result.Mode != "no_policy" || result.Epoch != "7" {
				t.Fatalf("evaluate() metadata = reasonCode:%q requestID:%q mode:%q epoch:%q", result.ReasonCode, result.RequestID, result.Mode, result.Epoch)
			}
		})
	}
}

func TestEvaluatePreToolUseUsesCachedModeWhenBackendOmitsMode(t *testing.T) {
	t.Parallel()

	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		modePath:   filepath.Join(t.TempDir(), "access-mode"),
		accessMode: backend.HostedAccessModeEnforce,
		client: &stubProcessor{
			result: &backend.ProcessHookEventResult{
				Response: &agentv1.ProcessHookEventResponse{
					Decision: agentv1.Decision_DECISION_DENY,
					Reason:   "blocked",
				},
				ReasonCode: "DENY_POLICY_CHECK",
			},
		},
		diagnostic: diagnostic.New(io.Discard, false),
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"gh repo delete"}`),
	})

	if result.Allowed {
		t.Fatal("evaluate().Allowed = true, want false")
	}
	if result.Decision != string(hookruntime.DecisionDeny) {
		t.Fatalf("evaluate().Decision = %q, want deny", result.Decision)
	}
	if result.Mode != string(backend.HostedAccessModeEnforce) {
		t.Fatalf("evaluate().Mode = %q, want enforce", result.Mode)
	}
}

func TestEvaluatePreToolUseFailsClosedOnBackendError(t *testing.T) {
	t.Parallel()

	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		accessMode: backend.HostedAccessModeEnforce,
		client:     &stubProcessor{err: errors.New("backend down")},
		diagnostic: diagnostic.New(io.Discard, false),
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{HookEvent: "PreToolUse"})

	if result.Allowed {
		t.Fatal("evaluate().Allowed = true, want false")
	}
	if result.Reason == "" {
		t.Fatal("evaluate().Reason = empty, want failure reason")
	}
}

func TestEvaluateFailsClosedWhenBlockingHookPayloadCannotDecode(t *testing.T) {
	t.Parallel()

	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		accessMode: backend.HostedAccessModeEnforce,
		client:     &stubProcessor{},
		diagnostic: diagnostic.New(io.Discard, false),
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolInput: json.RawMessage(`{`),
	})

	if result.Allowed {
		t.Fatal("evaluate().Allowed = true, want false")
	}
	if result.Decision != string(hook.DecisionDeny) {
		t.Fatalf("evaluate().Decision = %q, want deny", result.Decision)
	}
}

func TestEvaluateAllowsNonblockingHookPayloadDecodeFailure(t *testing.T) {
	t.Parallel()

	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		accessMode: backend.HostedAccessModeEnforce,
		client:     &stubProcessor{},
		diagnostic: diagnostic.New(io.Discard, false),
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{
		HookEvent: "PostToolUse",
		ToolInput: json.RawMessage(`{`),
	})

	if !result.Allowed {
		t.Fatal("evaluate().Allowed = false, want true")
	}
	if result.Decision != string(hook.DecisionAllow) {
		t.Fatalf("evaluate().Decision = %q, want allow", result.Decision)
	}
}

func TestEvaluatePreToolUseFailsClosedBeforeClaudeHookDeadline(t *testing.T) {
	t.Parallel()

	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		accessMode: backend.HostedAccessModeEnforce,
		client:     &stubProcessor{delay: hookEvalTimeout + time.Second},
		diagnostic: diagnostic.New(io.Discard, false),
	}

	start := time.Now()
	result := s.evaluate(context.Background(), &EvaluateRequest{HookEvent: "PreToolUse"})

	if result.Allowed {
		t.Fatal("evaluate().Allowed = true, want false")
	}
	if elapsed := time.Since(start); elapsed > hookEvalTimeout+time.Second {
		t.Fatalf("evaluate() took %s, want bounded by hook timeout", elapsed)
	}
}

func TestEvaluatePreToolUseFailsClosedWhenEnforceModeCannotPersist(t *testing.T) {
	t.Parallel()

	sessionDir := filepath.Join(t.TempDir(), "missing")
	s, err := New(
		sessionDir,
		&stubProcessor{
			result: &backend.ProcessHookEventResult{
				Response: &agentv1.ProcessHookEventResponse{
					Decision: agentv1.Decision_DECISION_ALLOW,
					Reason:   "allowed",
				},
				AccessMode: backend.HostedAccessModeEnforce,
			},
		},
		"session-123",
		"claude",
		backend.HostedAccessModeNoPolicy,
		diagnostic.New(io.Discard, false),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"gh pr view 92"}`),
	})

	if result.Allowed {
		t.Fatal("evaluate().Allowed = true, want false")
	}
	if result.Mode != string(backend.HostedAccessModeEnforce) {
		t.Fatalf("evaluate().Mode = %q, want enforce", result.Mode)
	}
}

func TestEvaluatePreToolUseFailsOpenWhenNotEnforcing(t *testing.T) {
	t.Parallel()

	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		accessMode: backend.HostedAccessModeNoPolicy,
		client:     &stubProcessor{err: errors.New("backend down")},
		diagnostic: diagnostic.New(io.Discard, false),
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{HookEvent: "PreToolUse"})

	if !result.Allowed {
		t.Fatal("evaluate().Allowed = false, want true")
	}
	if result.Mode != string(backend.HostedAccessModeNoPolicy) {
		t.Fatalf("evaluate().Mode = %q, want no_policy", result.Mode)
	}
}

func TestEvaluateRefreshesAccessModeForLaterFailures(t *testing.T) {
	t.Parallel()

	client := &stubProcessor{
		result: &backend.ProcessHookEventResult{
			Response: &agentv1.ProcessHookEventResponse{
				Decision: agentv1.Decision_DECISION_ALLOW,
			},
			AccessMode: backend.HostedAccessModeEnforce,
		},
	}
	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		modePath:   filepath.Join(t.TempDir(), "access-mode"),
		accessMode: backend.HostedAccessModeNoPolicy,
		client:     client,
		diagnostic: diagnostic.New(io.Discard, false),
	}

	first := s.evaluate(context.Background(), &EvaluateRequest{HookEvent: "PreToolUse"})
	if !first.Allowed {
		t.Fatal("first evaluate().Allowed = false, want true")
	}

	client.err = errors.New("backend down")
	second := s.evaluate(context.Background(), &EvaluateRequest{HookEvent: "PreToolUse"})
	if second.Allowed {
		t.Fatal("second evaluate().Allowed = true, want enforce-mode fail closed")
	}
}

func TestEvaluateRefreshesAccessModeBackToFailOpen(t *testing.T) {
	t.Parallel()

	client := &stubProcessor{
		result: &backend.ProcessHookEventResult{
			Response: &agentv1.ProcessHookEventResponse{
				Decision: agentv1.Decision_DECISION_ALLOW,
			},
			AccessMode: backend.HostedAccessModeNoPolicy,
		},
	}
	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		modePath:   filepath.Join(t.TempDir(), "access-mode"),
		accessMode: backend.HostedAccessModeEnforce,
		client:     client,
		diagnostic: diagnostic.New(io.Discard, false),
	}

	first := s.evaluate(context.Background(), &EvaluateRequest{HookEvent: "PreToolUse"})
	if !first.Allowed {
		t.Fatal("first evaluate().Allowed = false, want true")
	}

	client.err = errors.New("backend down")
	second := s.evaluate(context.Background(), &EvaluateRequest{HookEvent: "PreToolUse"})
	if !second.Allowed {
		t.Fatal("second evaluate().Allowed = false, want no-policy fail open")
	}
	if second.Mode != string(backend.HostedAccessModeNoPolicy) {
		t.Fatalf("second evaluate().Mode = %q, want no_policy", second.Mode)
	}
}

func TestEvaluateNonPreToolUseDoesNotCallBackend(t *testing.T) {
	t.Parallel()

	client := &stubProcessor{}
	s := &Server{client: client}
	result := s.evaluate(context.Background(), &EvaluateRequest{HookEvent: "PostToolUse"})

	if !result.Allowed {
		t.Fatal("evaluate().Allowed = false, want true")
	}
	if client.processCalls != 0 {
		t.Fatalf("ProcessHookEvent calls = %d, want 0", client.processCalls)
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

func TestBuildHookEventRequestEnrichesBashPreToolUseWithGitContext(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}

	repoDir := t.TempDir()
	runTestGit(t, repoDir, "init", "-b", "feature")
	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("test\n"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	runTestGit(t, repoDir, "add", "README.md")
	runTestGit(t, repoDir, "-c", "user.name=Kontext Test", "-c", "user.email=test@example.com", "commit", "-m", "init")
	runTestGit(t, repoDir, "remote", "add", "origin", "https://token:x-oauth-basic@github.com/kontext-security/kontext-cli.git")

	got := buildHookEventRequest("session-123", "claude", &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		CWD:       repoDir,
		ToolInput: json.RawMessage(`{"command":"git push --dry-run origin HEAD:test-kontext-access-smoke"}`),
	})

	var input map[string]any
	if err := json.Unmarshal(got.ToolInput, &input); err != nil {
		t.Fatalf("ToolInput JSON = %s: %v", got.ToolInput, err)
	}
	kontext := input["kontext"].(map[string]any)
	git := kontext["git"].(map[string]any)
	if git["branch"] != "feature" {
		t.Fatalf("git.branch = %v, want feature", git["branch"])
	}
	remotes := git["remotes"].(map[string]any)
	if remotes["origin"] != "https://github.com/kontext-security/kontext-cli.git" {
		t.Fatalf("origin remote = %v, want sanitized GitHub URL", remotes["origin"])
	}
	if strings.Contains(string(got.ToolInput), "token") || strings.Contains(string(got.ToolInput), "x-oauth-basic") {
		t.Fatalf("ToolInput leaked credential-bearing remote: %s", got.ToolInput)
	}
}

func TestBuildHookEventRequestUsesTrustedGitExecutableForContext(t *testing.T) {
	gitPath, ok := trustedGitPath()
	if !ok {
		t.Skip("trusted git unavailable")
	}

	repoDir := t.TempDir()
	runTestGitPath(t, gitPath, repoDir, "init", "-b", "trusted-branch")
	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("test\n"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	runTestGitPath(t, gitPath, repoDir, "add", "README.md")
	runTestGitPath(t, gitPath, repoDir, "-c", "user.name=Kontext Test", "-c", "user.email=test@example.com", "commit", "-m", "init")

	fakeBin := t.TempDir()
	fakeGit := filepath.Join(fakeBin, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\necho forged\n"), 0o700); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	got := buildHookEventRequest("session-123", "claude", &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		CWD:       repoDir,
		ToolInput: json.RawMessage(`{"command":"git status"}`),
	})

	var input map[string]any
	if err := json.Unmarshal(got.ToolInput, &input); err != nil {
		t.Fatalf("ToolInput JSON = %s: %v", got.ToolInput, err)
	}
	kontext := input["kontext"].(map[string]any)
	git := kontext["git"].(map[string]any)
	if git["worktreeRoot"] == "forged" {
		t.Fatal("git context used PATH-resolved fake git")
	}
	if git["branch"] != "trusted-branch" {
		t.Fatalf("git.branch = %v, want trusted-branch", git["branch"])
	}
}

func TestSanitizeGitRemoteURLStripsCredentialsFromAnyHost(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"https://token@gitlab.com/org/repo.git":            "https://gitlab.com/org/repo.git",
		"https://oauth2:secret@bitbucket.org/org/repo.git": "https://bitbucket.org/org/repo.git",
		"https://token@github.enterprise.local/org/repo":   "https://github.enterprise.local/org/repo",
		"https://git.example.com/team@prod/repo.git":       "https://git.example.com/team@prod/repo.git",
		"git@github.com:org/repo.git":                      "git@github.com:org/repo.git",
	}
	for input, want := range tests {
		if got := sanitizeGitRemoteURL(input); got != want {
			t.Fatalf("sanitizeGitRemoteURL(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBuildHookEventRequestDoesNotEnrichNonPreToolUsePayloads(t *testing.T) {
	t.Parallel()

	toolInput := json.RawMessage(`{"command":"git push origin main"}`)
	got := buildHookEventRequest("session-123", "claude", &EvaluateRequest{
		HookEvent: "PostToolUse",
		ToolName:  "Bash",
		CWD:       t.TempDir(),
		ToolInput: toolInput,
	})

	if string(got.ToolInput) != string(toolInput) {
		t.Fatalf("ToolInput = %s, want unchanged %s", got.ToolInput, toolInput)
	}
}

func runTestGit(t *testing.T, cwd string, args ...string) {
	t.Helper()

	gitPath, ok := trustedGitPath()
	if !ok {
		t.Skip("trusted git unavailable")
	}
	runTestGitPath(t, gitPath, cwd, args...)
}

func runTestGitPath(t *testing.T, gitPath, cwd string, args ...string) {
	t.Helper()

	cmd := exec.Command(gitPath, append([]string{"-C", cwd}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
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

type stubProcessor struct {
	result       *backend.ProcessHookEventResult
	err          error
	delay        time.Duration
	processCalls int
}

func (s *stubProcessor) ProcessHookEvent(ctx context.Context, _ *agentv1.ProcessHookEventRequest) (*backend.ProcessHookEventResult, error) {
	s.processCalls++
	if s.delay > 0 {
		timer := time.NewTimer(s.delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	if s.result != nil {
		return s.result, nil
	}
	return &backend.ProcessHookEventResult{
		Response: &agentv1.ProcessHookEventResponse{Decision: agentv1.Decision_DECISION_ALLOW},
	}, nil
}

func (s *stubProcessor) Heartbeat(context.Context, string) error { return nil }
