package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
	"github.com/kontext-security/kontext-cli/internal/runtimecore"

	_ "github.com/kontext-security/kontext-cli/internal/agent/claude"
)

func TestHookObserveModeFailsOpenForPreToolUse(t *testing.T) {
	input := strings.NewReader(`{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"README.md"}}`)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"hook", "claude-code",
		"--socket", missingTestSocket(t),
		"--daemon-url", "http://127.0.0.1:1",
	}, input, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"allow"`) {
		t.Fatalf("stdout = %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `would allow`) {
		t.Fatalf("stdout = %s", stdout.String())
	}
}

func TestHookEnforceModeFailsClosedForPreToolUse(t *testing.T) {
	input := strings.NewReader(`{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"README.md"}}`)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"hook", "claude-code",
		"--mode", "enforce",
		"--socket", missingTestSocket(t),
		"--daemon-url", "http://127.0.0.1:1",
	}, input, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %s", stdout.String())
	}
}

func TestHookUsesLocalRuntimeSocketBeforeHTTPFallback(t *testing.T) {
	runtime := &stubGuardRuntime{
		result: hook.Result{
			Decision: hook.DecisionDeny,
			Reason:   "blocked through socket",
		},
	}
	socketPath := startTestGuardSocket(t, runtime)

	input := strings.NewReader(`{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"README.md"}}`)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"hook", "claude-code",
		"--mode", "enforce",
		"--socket", socketPath,
		"--daemon-url", "http://127.0.0.1:1",
	}, input, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `blocked through socket`) {
		t.Fatalf("stdout = %s", stdout.String())
	}
	if got := atomic.LoadInt64(&runtime.evaluateCalls); got != 1 {
		t.Fatalf("EvaluateHook calls = %d, want 1", got)
	}
}

func TestGuardHookProcessorLogsSocketFallbackDiagnostic(t *testing.T) {
	var stderr bytes.Buffer
	processor := guardHookProcessor{
		socket: failingHookProcessor{
			err: errors.New("dial unix /tmp/kontext.sock: connect: no such file or directory"),
		},
		fallback: staticHookProcessor{
			result: hook.Result{Decision: hook.DecisionAllow},
		},
		diagnostic: diagnostic.New(&stderr, true),
	}

	result, err := processor.Process(context.Background(), hook.Event{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %s, want %s", result.Decision, hook.DecisionAllow)
	}
	if !strings.Contains(stderr.String(), "falling back to HTTP daemon") {
		t.Fatalf("stderr = %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "no such file or directory") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestHookMalformedInputReturnsFailSafeDecision(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{"hook", "claude-code"}, strings.NewReader(`{`), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"allow"`) {
		t.Fatalf("stdout = %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "malformed hook input") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func startTestGuardSocket(t *testing.T, runtime *stubGuardRuntime) string {
	t.Helper()

	core, err := runtimecore.New(runtime)
	if err != nil {
		t.Fatalf("runtimecore.New() error = %v", err)
	}
	dir, err := os.MkdirTemp("/tmp", "kontext-guard-cli-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "kontext.sock")
	service, err := localruntime.NewService(localruntime.Options{
		SocketPath: socketPath,
		Core:       core,
		AgentName:  "claude",
		Diagnostic: diagnostic.New(io.Discard, false),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(service.Stop)
	return socketPath
}

func missingTestSocket(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "kontext-guard-missing-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "missing.sock")
}

type stubGuardRuntime struct {
	result        hook.Result
	evaluateCalls int64
}

func (s *stubGuardRuntime) EvaluateHook(context.Context, hook.Event) (hook.Result, error) {
	atomic.AddInt64(&s.evaluateCalls, 1)
	return s.result, nil
}

func (s *stubGuardRuntime) IngestEvent(context.Context, hook.Event) (hook.Result, error) {
	return hook.Result{Decision: hook.DecisionAllow}, nil
}

type failingHookProcessor struct {
	err error
}

func (p failingHookProcessor) Process(context.Context, hook.Event) (hook.Result, error) {
	return hook.Result{}, p.err
}

type staticHookProcessor struct {
	result hook.Result
}

func (p staticHookProcessor) Process(context.Context, hook.Event) (hook.Result, error) {
	return p.result, nil
}

func TestHookMalformedInputFailsClosedInEnforceMode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{"hook", "claude-code", "--mode", "enforce"}, strings.NewReader(`{`), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %s", stdout.String())
	}
}

func TestInstalledHookCommandUsesStableLauncherOverride(t *testing.T) {
	t.Setenv("KONTEXT_GUARD_HOOK_COMMAND", "'/usr/local/bin/kontext' guard hook claude-code")

	got := installedHookCommand()
	if strings.Contains(got, "go-build") {
		t.Fatalf("hook command should not use transient Go build cache path: %s", got)
	}
	if !strings.Contains(got, "guard hook claude-code") {
		t.Fatalf("hook command did not use launcher override: %s", got)
	}
}

func TestMergeHooksInstallsOnlyToolHooks(t *testing.T) {
	t.Parallel()

	hooks := mergeHooks(map[string]any{
		"UserPromptSubmit": []any{
			map[string]any{
				"hooks": []any{
					map[string]any{
						"type":    "command",
						"command": "/usr/local/bin/kontext guard hook claude-code",
					},
				},
			},
		},
	}, "/usr/local/bin/kontext guard hook claude-code")

	if _, ok := hooks["PreToolUse"]; !ok {
		t.Fatal("PreToolUse hook missing")
	}
	if _, ok := hooks["PostToolUse"]; !ok {
		t.Fatal("PostToolUse hook missing")
	}
	if _, ok := hooks["UserPromptSubmit"]; ok {
		t.Fatal("UserPromptSubmit hook installed, want only tool hooks")
	}
}

func TestStartRejectsInvalidNumericEnvironment(t *testing.T) {
	t.Setenv("KONTEXT_THRESHOLD", "high")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{"start", "--model", "", "--skip-hook-install", "--no-open"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected invalid threshold error")
	}
	var numErr *strconv.NumError
	if !strings.Contains(err.Error(), "KONTEXT_THRESHOLD must be a number") || !errors.As(err, &numErr) {
		t.Fatalf("err = %v", err)
	}
}
