package sidecar

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/kontext-dev/kontext-cli/internal/agent"
	"github.com/kontext-dev/kontext-cli/internal/policy"
)

func TestSidecarEvaluate(t *testing.T) {
	engine := policy.NewEngine(true, []policy.Rule{
		{Action: "allow", Scope: "tool", Level: "org", ToolName: "Read"},
		{Action: "deny", Scope: "tool", Level: "org", ToolName: "Bash"},
	})

	dir := t.TempDir()
	srv, err := New(dir)
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

	// Test allowed tool
	resp := query(t, srv.SocketPath(), &agent.HookEvent{ToolName: "Read", HookEventName: "PreToolUse"})
	if !resp.Allowed {
		t.Errorf("Read should be allowed, got denied: %s", resp.Reason)
	}

	// Test denied tool
	resp = query(t, srv.SocketPath(), &agent.HookEvent{ToolName: "Bash", HookEventName: "PreToolUse"})
	if resp.Allowed {
		t.Errorf("Bash should be denied, got allowed: %s", resp.Reason)
	}
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

func query(t *testing.T, socketPath string, event *agent.HookEvent) Decision {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial sidecar: %v", err)
	}
	defer conn.Close()

	data, _ := json.Marshal(event)
	if err := WriteMessage(conn, data); err != nil {
		t.Fatalf("write: %v", err)
	}

	respData, err := ReadMessage(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var d Decision
	if err := json.Unmarshal(respData, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return d
}
