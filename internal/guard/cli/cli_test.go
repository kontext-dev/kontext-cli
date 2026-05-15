package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestGuardHookCompatibilityCommandIsRetired(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{"hook", "claude-code"}, strings.NewReader(`{}`), &stdout, &stderr)
	if err == nil {
		t.Fatal("Run() error = nil, want retired command error")
	}
	if !strings.Contains(err.Error(), `unknown command "hook"`) {
		t.Fatalf("error = %v, want unknown hook command", err)
	}
}

func TestInstalledHookCommandUsesStableLauncherOverride(t *testing.T) {
	t.Setenv("KONTEXT_GUARD_HOOK_COMMAND", "'/usr/local/bin/kontext' hook --agent claude --mode observe")

	got := installedHookCommand("/tmp/kontext-custom.sock")
	if strings.Contains(got, "go-build") {
		t.Fatalf("hook command should not use transient Go build cache path: %s", got)
	}
	if !strings.Contains(got, "hook --agent claude --mode observe") {
		t.Fatalf("hook command did not use launcher override: %s", got)
	}
}

func TestInstalledHookCommandUsesCanonicalRootHookHandler(t *testing.T) {
	t.Setenv("KONTEXT_GUARD_HOOK_COMMAND", "")

	got := installedHookCommand("/tmp/kontext-custom.sock")
	if strings.Contains(got, "guard hook claude-code") {
		t.Fatalf("hook command used legacy Guard handler: %s", got)
	}
	if !strings.Contains(got, "hook --agent claude") {
		t.Fatalf("hook command did not use canonical root handler: %s", got)
	}
	if !strings.Contains(got, `--mode "${KONTEXT_MODE:-observe}"`) {
		t.Fatalf("hook command did not leave mode overridable through KONTEXT_MODE: %s", got)
	}
	if strings.Contains(got, "--mode observe") {
		t.Fatalf("hook command hardcoded observe mode: %s", got)
	}
	if !strings.Contains(got, "--socket ") || !strings.Contains(got, "/tmp/kontext-custom.sock") {
		t.Fatalf("hook command did not carry custom socket path: %s", got)
	}
}

func TestIsGuardHookCommandRecognizesInstalledGuardHooks(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		"/usr/local/bin/kontext guard hook claude-code",
		"'/usr/local/bin/kontext' guard hook claude-code",
		"/usr/local/bin/kontext hook --agent claude --mode observe",
		"'/usr/local/bin/kontext' hook --agent claude --mode observe",
		"cd '/repo' && go run ./cmd/kontext hook --agent claude --mode observe",
		`/usr/local/bin/kontext hook --agent claude --mode "${KONTEXT_MODE:-observe}" --socket /tmp/kontext-custom.sock`,
	} {
		if !isGuardHookCommand(command) {
			t.Fatalf("isGuardHookCommand(%q) = false, want true", command)
		}
	}
	if isGuardHookCommand("/usr/local/bin/kontext hook --agent claude") {
		t.Fatal("hosted/pass-through hook should not be classified as Guard observe hook")
	}
}

func TestMergeHooksInstallsOnlyToolHooks(t *testing.T) {
	t.Parallel()

	legacyEntry, err := json.Marshal(claudeHookEntry{
		Hooks: []claudeHookAction{
			{Type: "command", Command: "/usr/local/bin/kontext guard hook claude-code"},
		},
	})
	if err != nil {
		t.Fatalf("marshal legacy hook entry: %v", err)
	}
	hooks, err := mergeHooks(claudeHooks{
		"UserPromptSubmit": {legacyEntry},
	}, `/usr/local/bin/kontext hook --agent claude --mode "${KONTEXT_MODE:-observe}" --socket /tmp/kontext.sock`)
	if err != nil {
		t.Fatalf("mergeHooks: %v", err)
	}

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
