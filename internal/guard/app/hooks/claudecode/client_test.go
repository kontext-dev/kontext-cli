package claudecode

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestProcessPostsHookEventAndMapsResult(t *testing.T) {
	t.Parallel()

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/hooks/evaluate" {
			t.Fatalf("path = %q, want /api/hooks/evaluate", r.URL.Path)
		}
		var event risk.HookEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if event.HookEventName != "PreToolUse" || event.ToolName != "Read" || event.SessionID != "session-123" {
			t.Fatalf("event = %+v, want hook fields preserved", event)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(server.ProcessResponse{
			Decision:   risk.DecisionAsk,
			Reason:     "credential access requires approval",
			ReasonCode: "credential_access_without_intent",
			EventID:    "evt-123",
		}); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	t.Cleanup(httpServer.Close)

	result, err := NewClient(httpServer.URL).Process(context.Background(), hook.Event{
		SessionID: "session-123",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Read",
		ToolInput: map[string]any{"file_path": ".env"},
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionAsk {
		t.Fatalf("decision = %q, want ask", result.Decision)
	}
	if result.ReasonCode != "credential_access_without_intent" || result.EventID != "evt-123" {
		t.Fatalf("result = %+v, want metadata preserved", result)
	}
}

func TestProcessPostsTelemetryEventsToIngest(t *testing.T) {
	t.Parallel()

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/hooks/ingest" {
			t.Fatalf("path = %q, want /api/hooks/ingest", r.URL.Path)
		}
		var event risk.HookEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if event.HookEventName != "PostToolUse" || event.ToolName != "Bash" {
			t.Fatalf("event = %+v, want telemetry hook fields preserved", event)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(server.ProcessResponse{
			Decision:   risk.DecisionAllow,
			Reason:     "async telemetry event recorded",
			ReasonCode: "async_telemetry",
			EventID:    "evt-telemetry",
		}); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	t.Cleanup(httpServer.Close)

	result, err := NewClient(httpServer.URL).Process(context.Background(), hook.Event{
		SessionID: "session-123",
		HookName:  hook.HookPostToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "git status"},
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow || result.ReasonCode != "async_telemetry" || result.EventID != "evt-telemetry" {
		t.Fatalf("result = %+v, want telemetry result preserved", result)
	}
}
