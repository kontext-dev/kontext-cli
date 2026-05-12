package runtimecore

import (
	"context"
	"errors"
	"fmt"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

type HookRuntime interface {
	EvaluateHook(context.Context, hook.Event) (hook.Result, error)
	IngestEvent(context.Context, hook.Event) (hook.Result, error)
}

type Core struct {
	runtime HookRuntime
}

func New(runtime HookRuntime) (*Core, error) {
	if runtime == nil {
		return nil, errors.New("runtime core requires hook runtime")
	}
	return &Core{runtime: runtime}, nil
}

func (c *Core) EvaluateHook(ctx context.Context, event hook.Event) (hook.Result, error) {
	if event.HookName == "" {
		return hook.Result{}, errors.New("hook event name is required")
	}
	if !event.HookName.CanBlock() {
		return hook.Result{}, fmt.Errorf("hook event %q cannot be evaluated for enforcement", event.HookName)
	}
	return c.runtime.EvaluateHook(ctx, event)
}

func (c *Core) IngestEvent(ctx context.Context, event hook.Event) (hook.Result, error) {
	if event.HookName == "" {
		return hook.Result{}, errors.New("hook event name is required")
	}
	if event.HookName.CanBlock() {
		return hook.Result{}, fmt.Errorf("hook event %q must be evaluated for enforcement", event.HookName)
	}
	return c.runtime.IngestEvent(ctx, event)
}

func (c *Core) ProcessHook(ctx context.Context, event hook.Event) (hook.Result, error) {
	if event.HookName.CanBlock() {
		return c.EvaluateHook(ctx, event)
	}
	return c.IngestEvent(ctx, event)
}
