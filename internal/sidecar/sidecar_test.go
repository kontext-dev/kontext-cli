package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/credential"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
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

func TestEnrichToolInputRemovesUntrustedKontextContext(t *testing.T) {
	t.Parallel()

	req := &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		CWD:       t.TempDir(),
		ToolInput: json.RawMessage(`{"command":"git push origin main","kontext":{"git":{"branch":"main","remotes":{"origin":"https://github.com/evil/repo.git"}}}}`),
	}

	enrichToolInputWithLocalContext(context.Background(), req)

	var input map[string]any
	if err := json.Unmarshal(req.ToolInput, &input); err != nil {
		t.Fatalf("tool input JSON: %v", err)
	}
	if _, ok := input["kontext"]; ok {
		t.Fatalf("kontext context = %#v, want removed when local git context is unavailable", input["kontext"])
	}
	if input["command"] != "git push origin main" {
		t.Fatalf("command = %#v, want original command", input["command"])
	}
}

func TestEvaluatePreToolUseInjectsManagedCredentialOnlyAfterAllow(t *testing.T) {
	t.Parallel()

	client := &stubProcessor{
		result: &backend.ProcessHookEventResult{
			Response: &agentv1.ProcessHookEventResponse{
				Decision: agentv1.Decision_DECISION_ALLOW,
				Reason:   "allowed",
			},
			AccessMode: backend.HostedAccessModeEnforce,
		},
	}
	sessionDir := t.TempDir()
	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		modePath:   filepath.Join(t.TempDir(), "access-mode"),
		accessMode: backend.HostedAccessModeEnforce,
		client:     client,
		diagnostic: diagnostic.New(io.Discard, false),
		credentials: newCredentialInjector(
			sessionDir,
			[]credential.Entry{{EnvVar: "GITHUB_TOKEN", Provider: "github"}},
			func(context.Context, credential.Entry) (string, error) { return "managed-token", nil },
		),
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"gh pr view 92","description":"inspect pr"}`),
	})

	if !result.Allowed {
		t.Fatal("evaluate().Allowed = false, want true")
	}
	command, ok := result.UpdatedInput["command"].(string)
	if !ok {
		t.Fatalf("updated command missing: %#v", result.UpdatedInput)
	}
	if strings.Contains(command, "managed-token") {
		t.Fatalf("updated command leaked raw token: %q", command)
	}
	if !strings.Contains(command, `GITHUB_TOKEN="$(cat `) || !strings.Contains(command, "gh pr view 92") {
		t.Fatalf("updated command = %q, want credential file prefix and original command", command)
	}
	if got := result.UpdatedInput["description"]; got != "inspect pr" {
		t.Fatalf("updated input did not preserve unchanged fields: %#v", result.UpdatedInput)
	}
	raw, err := os.ReadFile(filepath.Join(sessionDir, "credentials", "GITHUB_TOKEN"))
	if err != nil {
		t.Fatalf("credential file missing: %v", err)
	}
	if string(raw) != "managed-token" {
		t.Fatalf("credential file = %q, want managed-token", raw)
	}
}

func TestEvaluatePreToolUseInjectsAllMatchingManagedCredentials(t *testing.T) {
	t.Parallel()

	client := &stubProcessor{
		result: &backend.ProcessHookEventResult{
			Response: &agentv1.ProcessHookEventResponse{
				Decision: agentv1.Decision_DECISION_ALLOW,
			},
			AccessMode: backend.HostedAccessModeEnforce,
		},
	}
	sessionDir := t.TempDir()
	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		modePath:   filepath.Join(t.TempDir(), "access-mode"),
		accessMode: backend.HostedAccessModeEnforce,
		client:     client,
		diagnostic: diagnostic.New(io.Discard, false),
		credentials: newCredentialInjector(
			sessionDir,
			[]credential.Entry{
				{EnvVar: "GITHUB_TOKEN", Provider: "github"},
				{EnvVar: "GIT_ASKPASS_TOKEN", Provider: "github"},
			},
			func(_ context.Context, entry credential.Entry) (string, error) {
				return "managed-" + entry.EnvVar, nil
			},
		),
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"gh pr view 92"}`),
	})

	command, ok := result.UpdatedInput["command"].(string)
	if !ok {
		t.Fatalf("updated command missing: %#v", result.UpdatedInput)
	}
	for _, envVar := range []string{"GITHUB_TOKEN", "GIT_ASKPASS_TOKEN"} {
		if !strings.Contains(command, envVar+`="$(cat `) {
			t.Fatalf("updated command = %q, want %s export", command, envVar)
		}
		raw, err := os.ReadFile(filepath.Join(sessionDir, "credentials", envVar))
		if err != nil {
			t.Fatalf("%s credential file missing: %v", envVar, err)
		}
		if string(raw) != "managed-"+envVar {
			t.Fatalf("%s credential file = %q", envVar, raw)
		}
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
	if !strings.Contains(string(claudeOutput), `"permissionDecision":"deny"`) {
		t.Fatalf("claude output = %s, want deny", claudeOutput)
	}
	if strings.Count(string(claudeOutput), "Request ID: request-123") != 1 {
		t.Fatalf("claude output = %s, want one request id", claudeOutput)
	}
}

func TestEvaluatePreToolUseSanitizesCredentialFileName(t *testing.T) {
	t.Parallel()

	sessionDir := t.TempDir()
	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		modePath:   filepath.Join(t.TempDir(), "access-mode"),
		accessMode: backend.HostedAccessModeEnforce,
		client: &stubProcessor{
			result: &backend.ProcessHookEventResult{
				Response: &agentv1.ProcessHookEventResponse{
					Decision: agentv1.Decision_DECISION_ALLOW,
				},
				AccessMode: backend.HostedAccessModeEnforce,
			},
		},
		diagnostic: diagnostic.New(io.Discard, false),
		credentials: newCredentialInjector(
			sessionDir,
			[]credential.Entry{{EnvVar: "../../escaped", Provider: "github"}},
			func(context.Context, credential.Entry) (string, error) { return "managed-token", nil },
		),
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"gh pr view 92"}`),
	})

	if !result.Allowed {
		t.Fatal("evaluate().Allowed = false, want true")
	}
	if _, err := os.Stat(filepath.Join(sessionDir, "escaped")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("escaped credential path stat error = %v, want not exist", err)
	}
	fallbackName := shellQuoteAssignmentName("../../escaped")
	if fallbackName == "KONTEXT_MANAGED_TOKEN" {
		t.Fatal("fallback credential name is not collision-resistant")
	}
	raw, err := os.ReadFile(filepath.Join(sessionDir, "credentials", fallbackName))
	if err != nil {
		t.Fatalf("sanitized credential file missing: %v", err)
	}
	if string(raw) != "managed-token" {
		t.Fatalf("credential file = %q, want managed-token", raw)
	}
	command, ok := result.UpdatedInput["command"].(string)
	if !ok || !strings.Contains(command, fallbackName+`="$(cat `) {
		t.Fatalf("updated command = %#v, want sanitized env assignment", result.UpdatedInput["command"])
	}
}

func TestEvaluatePreToolUseKeepsDistinctSanitizedCredentialNames(t *testing.T) {
	t.Parallel()

	sessionDir := t.TempDir()
	s := &Server{
		sessionID:  "session-123",
		agentName:  "claude",
		modePath:   filepath.Join(t.TempDir(), "access-mode"),
		accessMode: backend.HostedAccessModeEnforce,
		client: &stubProcessor{
			result: &backend.ProcessHookEventResult{
				Response: &agentv1.ProcessHookEventResponse{
					Decision: agentv1.Decision_DECISION_ALLOW,
				},
				AccessMode: backend.HostedAccessModeEnforce,
			},
		},
		diagnostic: diagnostic.New(io.Discard, false),
		credentials: newCredentialInjector(
			sessionDir,
			[]credential.Entry{
				{EnvVar: "../../first", Provider: "github"},
				{EnvVar: "../../second", Provider: "github"},
			},
			func(_ context.Context, entry credential.Entry) (string, error) {
				return "managed-" + entry.EnvVar, nil
			},
		),
	}

	result := s.evaluate(context.Background(), &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"gh pr view 92"}`),
	})

	command, ok := result.UpdatedInput["command"].(string)
	if !ok {
		t.Fatalf("updated command missing: %#v", result.UpdatedInput)
	}
	for _, envVar := range []string{"../../first", "../../second"} {
		name := shellQuoteAssignmentName(envVar)
		if !strings.Contains(command, name+`="$(cat `) {
			t.Fatalf("updated command = %q, want %s export", command, name)
		}
		raw, err := os.ReadFile(filepath.Join(sessionDir, "credentials", name))
		if err != nil {
			t.Fatalf("%s credential file missing: %v", name, err)
		}
		if string(raw) != "managed-"+envVar {
			t.Fatalf("%s credential file = %q", name, raw)
		}
	}
	if shellQuoteAssignmentName("../../first") == shellQuoteAssignmentName("../../second") {
		t.Fatal("sanitized credential names collided")
	}
}

func TestEvaluatePreToolUseDoesNotInjectManagedCredentialForAskOrDeny(t *testing.T) {
	t.Parallel()

	for _, decision := range []agentv1.Decision{
		agentv1.Decision_DECISION_ASK,
		agentv1.Decision_DECISION_DENY,
	} {
		t.Run(decision.String(), func(t *testing.T) {
			t.Parallel()
			called := false
			s := &Server{
				sessionID:  "session-123",
				agentName:  "claude",
				accessMode: backend.HostedAccessModeEnforce,
				client: &stubProcessor{
					result: &backend.ProcessHookEventResult{
						Response: &agentv1.ProcessHookEventResponse{
							Decision: decision,
							Reason:   "blocked",
						},
						AccessMode: backend.HostedAccessModeEnforce,
					},
				},
				diagnostic: diagnostic.New(io.Discard, false),
				credentials: newCredentialInjector(
					t.TempDir(),
					[]credential.Entry{{EnvVar: "GITHUB_TOKEN", Provider: "github"}},
					func(context.Context, credential.Entry) (string, error) {
						called = true
						return "managed-token", nil
					},
				),
			}

			result := s.evaluate(context.Background(), &EvaluateRequest{
				HookEvent: "PreToolUse",
				ToolName:  "Bash",
				ToolInput: json.RawMessage(`{"command":"gh pr merge 92"}`),
			})

			if result.Allowed {
				t.Fatal("evaluate().Allowed = true, want false")
			}
			if result.UpdatedInput != nil {
				t.Fatalf("UpdatedInput = %#v, want nil", result.UpdatedInput)
			}
			if called {
				t.Fatal("credential resolver was called for non-ALLOW decision")
			}
		})
	}
}

func TestLooksLikeProviderCommandDoesNotFallbackToSubstringMatching(t *testing.T) {
	t.Parallel()

	if looksLikeProviderCommand("echo notionally safe", "notion") {
		t.Fatal("looksLikeProviderCommand matched unsupported provider substring")
	}
}

func TestLooksLikeGitHubCommandRequiresGitHubEvidence(t *testing.T) {
	t.Parallel()

	if looksLikeProviderCommand("git push origin main", "github") {
		t.Fatal("looksLikeProviderCommand matched generic git command without GitHub target")
	}
	if !looksLikeProviderCommand("git push https://github.com/example/repo.git main", "github") {
		t.Fatal("looksLikeProviderCommand did not match explicit GitHub git target")
	}
	if !looksLikeProviderCommand("gh pr view 92", "github") {
		t.Fatal("looksLikeProviderCommand did not match gh command")
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

	got := buildHookEventRequest(context.Background(), "session-123", "claude", req)
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
	got := buildHookEventRequest(context.Background(), "session-123", "claude", &EvaluateRequest{
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
	got := buildHookEventRequest(context.Background(), "session-123", "claude", &EvaluateRequest{
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

func TestParseGitRemotesSanitizesGitHubURLs(t *testing.T) {
	t.Parallel()

	remotes := parseGitRemotes(strings.Join([]string{
		"origin\thttps://token@github.com/acme/repo.git (fetch)",
		"origin\thttps://token@github.com/acme/repo.git (push)",
		"upstream\tgit@github.com:other/repo.git (fetch)",
		"ignored\thttps://example.com/acme/repo.git (fetch)",
	}, "\n"))

	if got := remotes["origin"]; got != "https://github.com/acme/repo.git" {
		t.Fatalf("origin remote = %q, want sanitized GitHub URL", got)
	}
	if got := remotes["upstream"]; got != "https://github.com/other/repo.git" {
		t.Fatalf("upstream remote = %q, want normalized SSH GitHub URL", got)
	}
	if _, ok := remotes["ignored"]; ok {
		t.Fatal("non-GitHub remote was included")
	}
}

func TestSanitizeGitRemoteDropsCredentialsQueryAndFragment(t *testing.T) {
	t.Parallel()

	got := sanitizeGitRemote("https://user:secret@github.com/acme/repo.git?token=secret#frag")
	if got != "https://github.com/acme/repo.git" {
		t.Fatalf("sanitizeGitRemote() = %q, want credential-free URL", got)
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
	processCalls int
}

func (s *stubProcessor) ProcessHookEvent(context.Context, *agentv1.ProcessHookEventRequest) (*backend.ProcessHookEventResult, error) {
	s.processCalls++
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
