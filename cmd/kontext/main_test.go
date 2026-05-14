package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/zalando/go-keyring"
)

func TestLogoutCmdSuccess(t *testing.T) {
	cmd := newLogoutCmd(func() error { return nil })

	var stderr bytes.Buffer
	cmd.SetErr(&stderr)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE() error = %v", err)
	}

	if got, want := stderr.String(), "Logged out successfully.\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestStartCmdHasVerboseFlag(t *testing.T) {
	cmd := startCmd()
	flag := cmd.Flags().Lookup("verbose")
	if flag == nil {
		t.Fatal("start command missing --verbose flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("--verbose default = %q, want false", flag.DefValue)
	}
}

func TestGuardCmdRoutesToLocalGuardMode(t *testing.T) {
	cmd := guardCmd()
	if cmd.Use != "guard" {
		t.Fatalf("Use = %q, want guard", cmd.Use)
	}
	if !cmd.DisableFlagParsing {
		t.Fatal("guard command should pass flags through to the local Guard command parser")
	}
}

func TestLogoutCmdAlreadyLoggedOut(t *testing.T) {
	cmd := newLogoutCmd(func() error { return keyring.ErrNotFound })

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("RunE() error = nil, want non-nil")
	}
	if got, want := err.Error(), "already logged out"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestLogoutCmdWrapsUnexpectedErrors(t *testing.T) {
	boom := errors.New("boom")
	cmd := newLogoutCmd(func() error { return boom })

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("RunE() error = nil, want non-nil")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("errors.Is(err, boom) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), "logout failed: boom") {
		t.Fatalf("error = %q, want wrapped logout failure", err.Error())
	}
}

func TestEvaluateViaSidecarFailsOpenOnMarshalErrors(t *testing.T) {
	t.Parallel()

	socketPath := fmt.Sprintf("/tmp/kontext-test-%d.sock", time.Now().UnixNano())
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	tests := []struct {
		name  string
		event hook.Event
	}{
		{
			name: "tool input",
			event: hook.Event{
				Agent:     "claude",
				HookName:  hook.HookPreToolUse,
				ToolInput: map[string]any{"bad": func() {}},
			},
		},
		{
			name: "tool response",
			event: hook.Event{
				Agent:        "claude",
				HookName:     hook.HookPreToolUse,
				ToolResponse: map[string]any{"bad": func() {}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluateViaSidecar(socketPath, tt.event)
			if err != nil {
				t.Fatalf("evaluateViaSidecar() error = %v", err)
			}
			if !result.Allowed() {
				t.Fatal("evaluateViaSidecar() allowed = false, want true")
			}
			if result.Reason != "sidecar marshal error" {
				t.Fatalf("evaluateViaSidecar() reason = %q, want sidecar marshal error", result.Reason)
			}
		})
	}
}

func TestEvaluateViaSidecarFailsClosedWhenEnforceSidecarUnavailable(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "enforce")

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want DENY", result.Decision)
	}
	if result.Mode != "enforce" {
		t.Fatalf("mode = %q, want enforce", result.Mode)
	}
}

func TestEvaluateViaSidecarFailsClosedWhenAccessModePathSet(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE_PATH", "/tmp/kontext-missing-mode")

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want DENY", result.Decision)
	}
	if result.Mode != "enforce" {
		t.Fatalf("mode = %q, want enforce", result.Mode)
	}
	if result.Reason != "sidecar unreachable" {
		t.Fatalf("reason = %q, want sidecar failure reason", result.Reason)
	}
}

func TestEvaluateViaSidecarFailsOpenWhenNoPolicyModePathSet(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "no_policy")
	modePath := fmt.Sprintf("/tmp/kontext-mode-%d", time.Now().UnixNano())
	if err := os.WriteFile(modePath, []byte("no_policy\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(modePath) })
	t.Setenv("KONTEXT_ACCESS_MODE_PATH", modePath)

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %q, want ALLOW", result.Decision)
	}
}

func TestEvaluateViaSidecarUsesRefreshedEnforceModeFromPath(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "no_policy")
	modePath := fmt.Sprintf("/tmp/kontext-mode-%d", time.Now().UnixNano())
	if err := os.WriteFile(modePath, []byte("enforce\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(modePath) })
	t.Setenv("KONTEXT_ACCESS_MODE_PATH", modePath)

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want DENY", result.Decision)
	}
	if result.Mode != "enforce" {
		t.Fatalf("mode = %q, want enforce", result.Mode)
	}
}

func TestEvaluateHookWithSidecarFailsClosedWhenEnforceSocketMissing(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "enforce")

	result, err := evaluateHookWithSidecar("", hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateHookWithSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want DENY", result.Decision)
	}
	if result.Reason != "sidecar socket missing" {
		t.Fatalf("reason = %q, want missing socket", result.Reason)
	}
}

func TestEvaluateHookWithSidecarModeFailsClosedWhenEnforceSocketMissing(t *testing.T) {
	result, err := evaluateHookWithSidecarForMode("", hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	}, "enforce")
	if err != nil {
		t.Fatalf("evaluateHookWithSidecarForMode() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want DENY", result.Decision)
	}
	if result.Mode != "enforce" {
		t.Fatalf("mode = %q, want enforce", result.Mode)
	}
	if result.Reason != "sidecar socket missing" {
		t.Fatalf("reason = %q, want missing socket", result.Reason)
	}
}

func TestEvaluateHookWithSidecarAllowsPostToolUseWhenSocketMissing(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "enforce")

	result, err := evaluateHookWithSidecar("", hook.Event{
		Agent:    "claude",
		HookName: hook.HookPostToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateHookWithSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %q, want ALLOW", result.Decision)
	}
	if result.Reason != "sidecar socket missing" {
		t.Fatalf("reason = %q, want missing socket", result.Reason)
	}
}

func TestEvaluateViaSidecarUsesRefreshedNoPolicyModeFromPath(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "enforce")
	modePath := fmt.Sprintf("/tmp/kontext-mode-%d", time.Now().UnixNano())
	if err := os.WriteFile(modePath, []byte("no_policy\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(modePath) })
	t.Setenv("KONTEXT_ACCESS_MODE_PATH", modePath)

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %q, want ALLOW", result.Decision)
	}
}

func TestEvaluateViaSidecarFailsOpenWhenObserveSidecarUnavailable(t *testing.T) {
	t.Setenv("KONTEXT_ACCESS_MODE", "no_policy")

	socketPath := fmt.Sprintf("/tmp/kontext-missing-%d.sock", time.Now().UnixNano())
	result, err := evaluateViaSidecar(socketPath, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("evaluateViaSidecar() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %q, want ALLOW", result.Decision)
	}
}
