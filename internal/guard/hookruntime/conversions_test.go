package hookruntime

import (
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestHookResultFromProcessResponsePreservesMetadata(t *testing.T) {
	t.Parallel()

	result := HookResultFromProcessResponse(server.ProcessResponse{
		Decision:   risk.DecisionAsk,
		Reason:     "needs review",
		ReasonCode: "sensitive_file",
		EventID:    "evt-123",
	})

	if result.Decision != hook.DecisionAsk {
		t.Fatalf("Decision = %q, want ask", result.Decision)
	}
	if result.Reason != "needs review" ||
		result.ReasonCode != "sensitive_file" ||
		result.EventID != "evt-123" {
		t.Fatalf("result = %+v, want metadata preserved", result)
	}
}
