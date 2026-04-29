package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
)

func TestStorePersistsSummaryCounts(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := NewServer(store, risk.NoopScorer{})
	events := []risk.HookEvent{
		{SessionID: "s1", HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"file_path": "README.md"}},
		{SessionID: "s1", HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"file_path": ".env"}},
		{SessionID: "s1", HookEventName: "PreToolUse", ToolName: "Bash", ToolInput: map[string]any{"command": "drop database"}},
	}
	for _, event := range events {
		if _, err := server.ProcessHookEvent(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 3 || summary.Warnings != 1 || summary.Critical != 1 || summary.Sessions != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestProcessHookEventReturnsScorerError(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	want := errors.New("score failed")
	server := NewServer(store, failingScorer{err: want})
	_, err = server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 0 {
		t.Fatalf("summary = %+v, want no persisted action", summary)
	}
}

type failingScorer struct {
	err error
}

func (s failingScorer) Score(risk.RiskEvent) (risk.ScoreResult, error) {
	return risk.ScoreResult{}, s.err
}

func TestStoreListsSessions(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := NewServer(store, risk.NoopScorer{})
	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": ".env"},
	}); err != nil {
		t.Fatal(err)
	}
	sessions, err := store.Sessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].SessionID != "s1" || sessions[0].Warnings != 1 {
		t.Fatalf("sessions = %+v", sessions)
	}
}

func TestDemoModeAsksOnSourceControlWriteThenAllowsApprovedRetry(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := NewServerWithOptions(store, risk.NoopScorer{}, Options{DemoMode: true})
	if _, err := server.ProcessHookEvent(ctx, risk.HookEvent{
		SessionID:     "demo",
		HookEventName: "UserPromptSubmit",
		UserPrompt:    "what is this repo about, only inspect files",
	}); err != nil {
		t.Fatal(err)
	}
	first, err := server.ProcessHookEvent(ctx, risk.HookEvent{
		SessionID:     "demo",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git push origin main"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Decision != risk.DecisionAsk || first.ReasonCode != "demo_source_control_write_approval" {
		t.Fatalf("first decision = %+v", first)
	}
	if err := server.demo.Approve(ctx, store, first.EventID, "once"); err != nil {
		t.Fatal(err)
	}
	second, err := server.ProcessHookEvent(ctx, risk.HookEvent{
		SessionID:     "demo",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git push origin main"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Decision != risk.DecisionAllow || second.ReasonCode != "user_approved_action" {
		t.Fatalf("second decision = %+v", second)
	}
}

func TestDemoApprovalWaitReleasesPendingDecision(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := NewServerWithOptions(store, risk.NoopScorer{}, Options{DemoMode: true})
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	if _, err := server.ProcessHookEvent(ctx, risk.HookEvent{
		SessionID:     "demo",
		HookEventName: "UserPromptSubmit",
		UserPrompt:    "only inspect this repo",
	}); err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(ctx, risk.HookEvent{
		SessionID:     "demo",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git push origin HEAD:refs/heads/demo/test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionAsk || decision.ReasonCode != "demo_source_control_write_approval" {
		t.Fatalf("decision = %+v", decision)
	}

	waitDone := make(chan struct{})
	go func() {
		defer close(waitDone)
		resp, err := http.Get(httpServer.URL + "/api/demo/approvals/" + decision.EventID + "/wait")
		if err != nil {
			t.Errorf("wait request failed: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("wait status = %s", resp.Status)
		}
	}()

	select {
	case <-waitDone:
		t.Fatal("wait returned before approval")
	case <-time.After(100 * time.Millisecond):
	}
	if err := server.demo.Approve(ctx, store, decision.EventID, "once"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("wait did not return after approval")
	}
}
