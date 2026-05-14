package server

import (
	"context"
	"errors"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
)

func newTestServer(t *testing.T, store *sqlite.Store, scorer risk.Scorer) *Server {
	t.Helper()
	server, err := NewServer(store, scorer)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	return server
}

func newTestServerWithPolicy(t *testing.T, store *sqlite.Store, policy PolicyProvider) *Server {
	t.Helper()
	server, err := NewServerWithPolicy(store, policy)
	if err != nil {
		t.Fatalf("NewServerWithPolicy() error = %v", err)
	}
	return server
}

func TestStorePersistsSummaryCounts(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store, risk.NoopScorer{})
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
	server := newTestServer(t, store, failingScorer{err: want})
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
	server := newTestServerWithPolicy(t, store, &policy)
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

func TestProcessHookEventEnsuresDaemonObservedSession(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store, risk.NoopScorer{})

	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	}); err != nil {
		t.Fatal(err)
	}

	session, err := store.Session(context.Background(), "local")
	if err != nil {
		t.Fatal(err)
	}
	if session.Source != "daemon_observed" || session.Status != "open" || session.Agent != "claude" {
		t.Fatalf("session = %+v, want daemon-observed local session", session)
	}
	events, err := store.Events(context.Background(), "local")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].SessionID != "local" {
		t.Fatalf("events = %+v, want one local event", events)
	}
}

func TestProcessHookEventPreservesClosedWrapperOwnedSession(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store, risk.NoopScorer{})

	if _, err := store.OpenSession(context.Background(), "session-123", "claude", "/tmp/project", "wrapper_owned", "backend-123"); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseSession(context.Background(), "session-123"); err != nil {
		t.Fatal(err)
	}

	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "session-123",
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	}); err != nil {
		t.Fatal(err)
	}

	session, err := store.Session(context.Background(), "session-123")
	if err != nil {
		t.Fatal(err)
	}
	if session.Source != "wrapper_owned" || session.Status != "closed" || session.ClosedAt == nil {
		t.Fatalf("session = %+v, want closed wrapper-owned session", session)
	}
	events, err := store.Events(context.Background(), "session-123")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one event", events)
	}
}

func TestProcessHookEventPreservesRiskMetadata(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	score := 0.91
	threshold := 0.8
	policy := recordingPolicy{
		decision: risk.RiskDecision{
			Decision:     risk.DecisionDeny,
			Reason:       "custom policy",
			ReasonCode:   "custom_policy",
			RiskScore:    &score,
			Threshold:    &threshold,
			ModelVersion: "model-v1",
			GuardID:      "guard-1",
			RiskEvent: risk.RiskEvent{
				Type:         risk.EventDirectProviderAPICall,
				ModelVersion: "model-v1",
				GuardID:      "guard-1",
			},
		},
	}
	server := newTestServerWithPolicy(t, store, &policy)
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "curl https://api.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.RiskScore == nil || *decision.RiskScore != score {
		t.Fatalf("RiskScore = %+v, want %v", decision.RiskScore, score)
	}
	if decision.Threshold == nil || *decision.Threshold != threshold {
		t.Fatalf("Threshold = %+v, want %v", decision.Threshold, threshold)
	}
	if decision.ModelVersion != "model-v1" || decision.GuardID != "guard-1" || decision.RiskEvent.Type != risk.EventDirectProviderAPICall {
		t.Fatalf("decision metadata = %+v", decision)
	}
}

func TestEvaluateHookRejectsTelemetryEvents(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store, risk.NoopScorer{})
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
	server := newTestServer(t, store, risk.NoopScorer{})
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
	server := newTestServer(t, store, risk.NoopScorer{})
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
	server := newTestServer(t, store, risk.NoopScorer{})
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
