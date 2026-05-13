package cli

import (
	"context"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

type hookProcessor interface {
	Process(context.Context, hook.Event) (hook.Result, error)
}

type guardHookProcessor struct {
	socket     hookProcessor
	fallback   hookProcessor
	diagnostic diagnostic.Logger
}

func (p guardHookProcessor) Process(ctx context.Context, event hook.Event) (hook.Result, error) {
	result, err := p.socket.Process(ctx, event)
	if err == nil {
		return result, nil
	}
	p.diagnostic.Printf("guard hook socket unavailable; falling back to HTTP daemon: %v\n", err)
	return p.fallback.Process(ctx, event)
}
