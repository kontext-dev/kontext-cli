package runtimecore

import (
	"context"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestEvaluateHookRejectsTelemetryHooks(t *testing.T) {
	core, err := New(&recordingRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.EvaluateHook(context.Background(), hook.Event{HookName: hook.HookPostToolUse})
	if err == nil {
		t.Fatal("EvaluateHook() error = nil, want non-blocking hook rejection")
	}
}

func TestIngestEventRejectsBlockingHooks(t *testing.T) {
	core, err := New(&recordingRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.IngestEvent(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if err == nil {
		t.Fatal("IngestEvent() error = nil, want blocking hook rejection")
	}
}

func TestProcessHookRoutesByBlockingCapability(t *testing.T) {
	runtime := &recordingRuntime{
		evaluateResult: hook.Result{Decision: hook.DecisionAsk, Reason: "review"},
		ingestResult:   hook.Result{Decision: hook.DecisionAllow, Reason: "recorded"},
	}
	core, err := New(runtime)
	if err != nil {
		t.Fatal(err)
	}
	evaluate, err := core.ProcessHook(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if err != nil {
		t.Fatal(err)
	}
	ingest, err := core.ProcessHook(context.Background(), hook.Event{HookName: hook.HookPostToolUse})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.evaluateCalls != 1 || runtime.ingestCalls != 1 {
		t.Fatalf("calls evaluate=%d ingest=%d", runtime.evaluateCalls, runtime.ingestCalls)
	}
	if evaluate.Decision != hook.DecisionAsk || ingest.Reason != "recorded" {
		t.Fatalf("evaluate=%+v ingest=%+v", evaluate, ingest)
	}
}

func TestNewRejectsMissingRuntime(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) error = nil, want error")
	}
}

type recordingRuntime struct {
	evaluateCalls  int
	ingestCalls    int
	evaluateResult hook.Result
	ingestResult   hook.Result
	err            error
}

func (r *recordingRuntime) EvaluateHook(context.Context, hook.Event) (hook.Result, error) {
	r.evaluateCalls++
	if r.err != nil {
		return hook.Result{}, r.err
	}
	if r.evaluateResult.Decision == "" {
		return hook.Result{Decision: hook.DecisionAllow}, nil
	}
	return r.evaluateResult, nil
}

func (r *recordingRuntime) IngestEvent(context.Context, hook.Event) (hook.Result, error) {
	r.ingestCalls++
	if r.err != nil {
		return hook.Result{}, r.err
	}
	if r.ingestResult.Decision == "" {
		return hook.Result{Decision: hook.DecisionAllow}, nil
	}
	return r.ingestResult, nil
}

var _ HookRuntime = (*recordingRuntime)(nil)
