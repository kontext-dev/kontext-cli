package hookruntime

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

type Mode string

const (
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
)

type Adapter interface {
	Decode(io.Reader) (Event, error)
	Encode(io.Writer, Result) error
	MalformedHookName() string
}

type Processor interface {
	Process(ctx context.Context, event risk.HookEvent) (server.ProcessResponse, error)
}

type Event struct {
	HookName  string
	CanBlock  bool
	RiskEvent risk.HookEvent
}

type Result struct {
	HookName string
	CanBlock bool
	Decision risk.Decision
	Reason   string
	Mode     Mode
}

func Run(ctx context.Context, adapter Adapter, processor Processor, mode Mode, stdin io.Reader, stdout, stderr io.Writer) error {
	event, err := adapter.Decode(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: malformed hook input: %v\n", err)
		return adapter.Encode(stdout, Result{
			HookName: adapter.MalformedHookName(),
			CanBlock: true,
			Decision: risk.DecisionDeny,
			Reason:   "malformed hook input",
			Mode:     mode,
		})
	}

	result, err := processor.Process(ctx, event.RiskEvent)
	if err != nil {
		if event.CanBlock && mode == ModeEnforce {
			return adapter.Encode(stdout, Result{
				HookName: event.outputHookName(),
				CanBlock: event.CanBlock,
				Decision: risk.DecisionDeny,
				Reason:   "Kontext daemon unavailable",
				Mode:     mode,
			})
		}
		fmt.Fprintf(stderr, "kontext: async hook ingestion failed: %v\n", err)
		return adapter.Encode(stdout, Result{
			HookName: event.outputHookName(),
			CanBlock: event.CanBlock,
			Decision: risk.DecisionAllow,
			Reason:   "telemetry allowed",
			Mode:     mode,
		})
	}

	decision := normalizeDecision(result.Decision)
	if !event.CanBlock {
		decision = risk.DecisionAllow
	}
	return adapter.Encode(stdout, Result{
		HookName: event.outputHookName(),
		CanBlock: event.CanBlock,
		Decision: decision,
		Reason:   result.Reason,
		Mode:     mode,
	})
}

func ParseMode(value string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(value))) {
	case "", ModeObserve:
		return ModeObserve, nil
	case ModeEnforce:
		return ModeEnforce, nil
	default:
		return "", fmt.Errorf("unknown hook mode %q; use observe or enforce", value)
	}
}

func (e Event) outputHookName() string {
	if e.HookName != "" {
		return e.HookName
	}
	return e.RiskEvent.HookEventName
}

func normalizeDecision(decision risk.Decision) risk.Decision {
	switch decision {
	case risk.DecisionAllow, risk.DecisionAsk, risk.DecisionDeny:
		return decision
	default:
		return risk.DecisionDeny
	}
}
