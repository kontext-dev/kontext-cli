package server

import (
	"context"
	"errors"
	"testing"

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

func TestProcessHookEventUsesPolicyProvider(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy := recordingPolicy{
		decision: risk.RiskDecision{
			Decision:   risk.DecisionAsk,
			Reason:     "custom policy",
			ReasonCode: "custom_policy",
			RiskEvent: risk.RiskEvent{
				Type: risk.EventUnknown,
			},
		},
	}
	server := NewServerWithPolicy(store, &policy)
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "deploy prod"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.called {
		t.Fatal("policy provider was not called")
	}
	if decision.Decision != risk.DecisionAsk || decision.ReasonCode != "custom_policy" || decision.EventID == "" {
		t.Fatalf("decision = %+v", decision)
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 1 || summary.Warnings != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestEvaluateHookRejectsTelemetryEvents(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := NewServer(store, risk.NoopScorer{})
	_, err = server.EvaluateHook(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git status"},
	})
	if err == nil {
		t.Fatal("EvaluateHook() error = nil, want telemetry rejection")
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 0 {
		t.Fatalf("summary = %+v, want no persisted action", summary)
	}
}

func TestIngestEventRecordsTelemetry(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := NewServer(store, risk.NoopScorer{})
	decision, err := server.IngestEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git status"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionAllow || decision.ReasonCode != "async_telemetry" || decision.EventID == "" {
		t.Fatalf("decision = %+v, want telemetry allow decision", decision)
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 1 || summary.Warnings != 0 || summary.Critical != 0 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestIngestEventRejectsBlockingEvents(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := NewServer(store, risk.NoopScorer{})
	_, err = server.IngestEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "drop database"},
	})
	if err == nil {
		t.Fatal("IngestEvent() error = nil, want blocking event rejection")
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

type recordingPolicy struct {
	called   bool
	decision risk.RiskDecision
	err      error
}

func (p *recordingPolicy) DecideHook(_ context.Context, _ risk.HookEvent) (risk.RiskDecision, error) {
	p.called = true
	return p.decision, p.err
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
