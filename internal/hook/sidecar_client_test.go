package hook

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/kontext-dev/kontext-cli/internal/agent"
	"github.com/kontext-dev/kontext-cli/internal/policy"
	"github.com/kontext-dev/kontext-cli/internal/sidecar"
)

func TestEvaluateViaSidecar(t *testing.T) {
	engine := policy.NewEngine(true, []policy.Rule{
		{Action: "allow", Scope: "server", Level: "org"},
	})

	dir := t.TempDir()
	srv, err := sidecar.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetEngine(engine)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	allowed, reason, err := EvaluateViaSidecar(srv.SocketPath(), &agent.HookEvent{
		ToolName:      "Bash",
		HookEventName: "PreToolUse",
	})
	if err != nil {
		t.Fatalf("EvaluateViaSidecar: %v", err)
	}
	if !allowed {
		t.Errorf("expected allowed, got denied: %s", reason)
	}
}

func TestEvaluateViaSidecarUnreachable(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "nonexistent.sock")
	allowed, _, err := EvaluateViaSidecar(socketPath, &agent.HookEvent{ToolName: "Bash"})
	if err == nil {
		t.Fatal("expected error for unreachable socket")
	}
	if allowed {
		t.Error("should deny when sidecar is unreachable")
	}
}
