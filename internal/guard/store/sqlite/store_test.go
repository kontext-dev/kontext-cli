package sqlite

import (
	"context"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

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
