package mcpserve

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/mcpserve/providers"
	"github.com/kontext-security/kontext-cli/internal/sidecar"
)

func fakeSidecar(t *testing.T, resp sidecar.EvaluateResult) (string, chan sidecar.EvaluateRequest) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close(); os.Remove(sock) })

	reqs := make(chan sidecar.EvaluateRequest, 8)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req sidecar.EvaluateRequest
				if err := sidecar.ReadMessage(c, &req); err != nil {
					return
				}
				reqs <- req
				_ = sidecar.WriteMessage(c, resp)
			}(conn)
		}
	}()
	return sock, reqs
}

func TestDispatchAllowed(t *testing.T) {
	sock, reqs := fakeSidecar(t, sidecar.EvaluateResult{Allowed: true, Reason: ""})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := newHandler("hermes", sock, "sess-t")
	action := providers.Action{
		Name: "ping",
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return map[string]any{"status": "ok", "provider": args["_provider"]}, nil
		},
	}
	result, err := h.dispatch(ctx, "kontext.example.ping", action, map[string]any{"_provider": "example"})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("parse: %v raw=%s", err, result)
	}
	if parsed["status"] != "ok" {
		t.Fatalf("result: %v", parsed)
	}

	select {
	case r := <-reqs:
		if r.HookEvent != "PreToolUse" || r.ToolName != "kontext.example.ping" {
			t.Fatalf("pre event: %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no pre")
	}
	select {
	case r := <-reqs:
		if r.HookEvent != "PostToolUse" {
			t.Fatalf("post event: %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no post")
	}
}

func TestDispatchDenied(t *testing.T) {
	sock, _ := fakeSidecar(t, sidecar.EvaluateResult{Allowed: false, Reason: "policy blocked"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := newHandler("hermes", sock, "sess-t")
	called := false
	action := providers.Action{
		Name: "ping",
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			called = true
			return nil, nil
		},
	}
	_, err := h.dispatch(ctx, "kontext.example.ping", action, nil)
	if err == nil {
		t.Fatal("expected deny error")
	}
	if !strings.Contains(err.Error(), "policy blocked") {
		t.Fatalf("reason not in err: %v", err)
	}
	if called {
		t.Error("handler must not run on deny")
	}
}

func TestDispatchActionError(t *testing.T) {
	sock, _ := fakeSidecar(t, sidecar.EvaluateResult{Allowed: true})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := newHandler("hermes", sock, "sess-t")
	action := providers.Action{
		Name: "broken",
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return nil, fmt.Errorf("boom")
		},
	}
	_, err := h.dispatch(ctx, "kontext.example.broken", action, nil)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected boom error, got %v", err)
	}
}
