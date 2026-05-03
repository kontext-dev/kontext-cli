package cli

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	_ "github.com/kontext-security/kontext-cli/internal/agent/claude"
)

func TestHookObserveModeFailsOpenForPreToolUse(t *testing.T) {
	input := strings.NewReader(`{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"README.md"}}`)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{"hook", "claude-code", "--daemon-url", "http://127.0.0.1:1"}, input, &stdout, &stderr)
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
	err := Run(context.Background(), []string{"hook", "claude-code", "--mode", "enforce", "--daemon-url", "http://127.0.0.1:1"}, input, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %s", stdout.String())
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
