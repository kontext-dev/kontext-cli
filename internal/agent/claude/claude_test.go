package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestClaudeFilterUserArgs(t *testing.T) {
	t.Parallel()

	c := &Claude{}
	args := []string{
		"--settings", "user-settings.json",
		"--dangerously-skip-permissions",
		"--setting-sources=local",
		"--allowed",
		"value",
		"--bare",
		"prompt",
	}

	got := c.FilterUserArgs(args)
	want := []string{"--allowed", "value", "prompt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterUserArgs() = %#v, want %#v", got, want)
	}
}

func TestClaudePrepareWritesSettings(t *testing.T) {
	t.Parallel()

	c := &Claude{}
	dir := t.TempDir()
	prep, err := c.Prepare(dir, "/usr/local/bin/kontext")
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	wantPath := filepath.Join(dir, "settings.json")
	wantArgs := []string{"--settings", wantPath}
	if !reflect.DeepEqual(prep.Args, wantArgs) {
		t.Fatalf("prep.Args = %#v, want %#v", prep.Args, wantArgs)
	}
	if len(prep.Env) != 0 {
		t.Fatalf("prep.Env = %#v, want empty", prep.Env)
	}

	data, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var parsed struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, event := range []string{"PreToolUse", "PostToolUse", "UserPromptSubmit"} {
		groups, ok := parsed.Hooks[event]
		if !ok {
			t.Fatalf("missing event %q in settings", event)
		}
		if len(groups) == 0 || len(groups[0].Hooks) == 0 {
			t.Fatalf("no hooks registered for %q", event)
		}
		cmd := groups[0].Hooks[0].Command
		if !strings.Contains(cmd, "/usr/local/bin/kontext") {
			t.Fatalf("hook command %q missing kontext binary path", cmd)
		}
		if !strings.Contains(cmd, "--agent claude") {
			t.Fatalf("hook command %q missing --agent claude", cmd)
		}
	}
}

func TestClaudeCleanupIsNoOp(t *testing.T) {
	t.Parallel()
	if err := (&Claude{}).Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
}
