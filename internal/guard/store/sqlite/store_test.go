package sqlite

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

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
