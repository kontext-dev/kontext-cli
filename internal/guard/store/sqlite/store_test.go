package sqlite

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

func TestEmptyCollectionsEncodeAsJSONArray(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	sessions, err := store.Sessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	encodedSessions, err := json.Marshal(sessions)
	if err != nil {
		t.Fatal(err)
	}
	if string(encodedSessions) != "[]" {
		t.Fatalf("empty sessions encoded as %s, want []", encodedSessions)
	}

	events, err := store.Events(context.Background(), "missing-session")
	if err != nil {
		t.Fatal(err)
	}
	encodedEvents, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if string(encodedEvents) != "[]" {
		t.Fatalf("empty events encoded as %s, want []", encodedEvents)
	}
}

func TestSaveDecisionGeneratesUniqueIDsConcurrently(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const total = 50
	ids := make(chan string, total)
	errs := make(chan error, total)
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record, err := store.SaveDecision(context.Background(), risk.HookEvent{
				SessionID:     "s1",
				Agent:         "claude-code",
				HookEventName: "PreToolUse",
				ToolName:      "Read",
			}, risk.RiskDecision{
				Decision:   risk.DecisionAllow,
				Reason:     "normal",
				ReasonCode: "normal_tool_call",
				RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
			})
			if err != nil {
				errs <- err
				return
			}
			ids <- record.ID
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for id := range ids {
		if !strings.HasPrefix(id, "evt_") {
			t.Fatalf("id = %q, want evt_ prefix", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id generated: %s", id)
		}
		seen[id] = true
	}
	if len(seen) != total {
		t.Fatalf("saved %d records, want %d", len(seen), total)
	}
}

func TestOpenAndCloseSessionRecordsLifecycle(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	opened, err := store.OpenSession(context.Background(), "session-123", "claude", "/tmp/project", "wrapper_owned", "backend-123")
	if err != nil {
		t.Fatal(err)
	}
	if opened.ID != "session-123" ||
		opened.Agent != "claude" ||
		opened.CWD != "/tmp/project" ||
		opened.Source != "wrapper_owned" ||
		opened.Status != "open" ||
		opened.ExternalID != "backend-123" ||
		opened.ClosedAt != nil {
		t.Fatalf("opened session = %+v", opened)
	}

	if err := store.CloseSession(context.Background(), "session-123"); err != nil {
		t.Fatal(err)
	}
	closed, err := store.Session(context.Background(), "session-123")
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != "closed" || closed.ClosedAt == nil {
		t.Fatalf("closed session = %+v, want closed with closed_at", closed)
	}
}

func TestCloseSessionNormalizesEmptySessionID(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.OpenSession(context.Background(), "", "claude", "/tmp/project", "daemon_observed", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseSession(context.Background(), ""); err != nil {
		t.Fatal(err)
	}

	closed, err := store.Session(context.Background(), "local")
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != "closed" || closed.ClosedAt == nil {
		t.Fatalf("closed session = %+v, want normalized local session closed", closed)
	}
}

func TestOpenSessionDoesNotDowngradeWrapperOwnedSource(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.OpenSession(context.Background(), "session-123", "claude", "/tmp/project", "wrapper_owned", "backend-123"); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.OpenSession(context.Background(), "session-123", "", "", "daemon_observed", "")
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Source != "wrapper_owned" || reopened.ExternalID != "backend-123" {
		t.Fatalf("reopened session = %+v, want wrapper-owned source preserved", reopened)
	}
}

func TestEnsureObservedSessionPreservesExistingLifecycle(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.OpenSession(context.Background(), "session-123", "claude", "/tmp/project", "wrapper_owned", "backend-123"); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseSession(context.Background(), "session-123"); err != nil {
		t.Fatal(err)
	}

	observed, err := store.EnsureObservedSession(context.Background(), "session-123", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if observed.Source != "wrapper_owned" ||
		observed.Status != "closed" ||
		observed.ExternalID != "backend-123" ||
		observed.ClosedAt == nil {
		t.Fatalf("observed session = %+v, want existing wrapper-owned closed session", observed)
	}
}

func TestSessionsRejectsInvalidStoredTimestamp(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.db.ExecContext(context.Background(), `
insert into risk_decisions(
  id, session_id, hook_event_name, decision, reason_code, reason, risk_event_json, created_at
) values(?, ?, ?, ?, ?, ?, ?, ?)
`, "evt_bad", "s1", "PreToolUse", risk.DecisionAllow, "normal_tool_call", "normal", `{}`, "not-a-time"); err != nil {
		t.Fatal(err)
	}

	_, err = store.Sessions(context.Background())
	if err == nil || !strings.Contains(err.Error(), "parse session latest_at") {
		t.Fatalf("err = %v, want invalid latest_at parse error", err)
	}
}

func TestEventsRejectsInvalidStoredTimestamp(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.db.ExecContext(context.Background(), `
insert into risk_decisions(
  id, session_id, hook_event_name, decision, reason_code, reason, risk_event_json, created_at
) values(?, ?, ?, ?, ?, ?, ?, ?)
`, "evt_bad", "s1", "PreToolUse", risk.DecisionAllow, "normal_tool_call", "normal", `{}`, "not-a-time"); err != nil {
		t.Fatal(err)
	}

	_, err = store.Events(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "parse decision created_at") {
		t.Fatalf("err = %v, want invalid created_at parse error", err)
	}
}
