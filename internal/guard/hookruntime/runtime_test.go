package hookruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

func TestRunObserveModeAllowsUnavailableBlockingHook(t *testing.T) {
	t.Parallel()

	adapter := &stubAdapter{
		event: Event{
			HookName:  "PreToolUse",
			CanBlock:  true,
			RiskEvent: risk.HookEvent{HookEventName: "PreToolUse"},
		},
	}
	err := Run(context.Background(), adapter, stubProcessor{err: errors.New("offline")}, ModeObserve, bytes.NewReader(nil), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.result.Decision != risk.DecisionAllow {
		t.Fatalf("decision = %s, want allow", adapter.result.Decision)
	}
	if adapter.result.Reason != "telemetry allowed" {
		t.Fatalf("reason = %q", adapter.result.Reason)
	}
}

func TestRunEnforceModeDeniesUnavailableBlockingHook(t *testing.T) {
	t.Parallel()

	adapter := &stubAdapter{
		event: Event{
			HookName:  "PreToolUse",
			CanBlock:  true,
			RiskEvent: risk.HookEvent{HookEventName: "PreToolUse"},
		},
	}
	err := Run(context.Background(), adapter, stubProcessor{err: errors.New("offline")}, ModeEnforce, bytes.NewReader(nil), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.result.Decision != risk.DecisionDeny {
		t.Fatalf("decision = %s, want deny", adapter.result.Decision)
	}
	if adapter.result.Reason != "Kontext daemon unavailable" {
		t.Fatalf("reason = %q", adapter.result.Reason)
	}
}

func TestRunNonBlockingHookCannotBlock(t *testing.T) {
	t.Parallel()

	adapter := &stubAdapter{
		event: Event{
			HookName:  "PostToolUse",
			CanBlock:  false,
			RiskEvent: risk.HookEvent{HookEventName: "PostToolUse"},
		},
	}
	err := Run(context.Background(), adapter, stubProcessor{resp: server.ProcessResponse{Decision: risk.DecisionDeny, Reason: "blocked"}}, ModeEnforce, bytes.NewReader(nil), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.result.Decision != risk.DecisionAllow {
		t.Fatalf("decision = %s, want allow", adapter.result.Decision)
	}
}

func TestRunUnknownDecisionFailsClosedForBlockingHook(t *testing.T) {
	t.Parallel()

	adapter := &stubAdapter{
		event: Event{
			HookName:  "PreToolUse",
			CanBlock:  true,
			RiskEvent: risk.HookEvent{HookEventName: "PreToolUse"},
		},
	}
	err := Run(context.Background(), adapter, stubProcessor{resp: server.ProcessResponse{Decision: "unexpected"}}, ModeObserve, bytes.NewReader(nil), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.result.Decision != risk.DecisionDeny {
		t.Fatalf("decision = %s, want deny", adapter.result.Decision)
	}
}

type stubProcessor struct {
	resp server.ProcessResponse
	err  error
}

func (p stubProcessor) Process(context.Context, risk.HookEvent) (server.ProcessResponse, error) {
	return p.resp, p.err
}

type stubAdapter struct {
	event     Event
	decodeErr error
	result    Result
}

func (a *stubAdapter) Decode(io.Reader) (Event, error) {
	return a.event, a.decodeErr
}

func (a *stubAdapter) Encode(_ io.Writer, result Result) error {
	a.result = result
	return nil
}

func (a *stubAdapter) MalformedHookName() string {
	return "PreToolUse"
}
