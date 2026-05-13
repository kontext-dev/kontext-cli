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
	if err := ValidateEvaluateHook(event); err != nil {
		return hook.Result{}, err
	}
	return c.runtime.EvaluateHook(ctx, event)
}

func ValidateEvaluateHook(event hook.Event) error {
	if event.HookName == "" {
		return errors.New("hook event name is required")
	}
	if !event.HookName.CanBlock() {
		return fmt.Errorf("hook event %q cannot be evaluated for enforcement", event.HookName)
	}
	return nil
}

func (c *Core) IngestEvent(ctx context.Context, event hook.Event) (hook.Result, error) {
	if err := ValidateIngestEvent(event); err != nil {
		return hook.Result{}, err
	}
	if event.HookName.CanBlock() {
		return hook.Result{}, fmt.Errorf("hook event %q must be evaluated for enforcement", event.HookName)
	}
	return c.runtime.IngestEvent(ctx, event)
}

func ValidateIngestEvent(event hook.Event) error {
	if event.HookName == "" {
		return errors.New("hook event name is required")
	}
	if event.HookName.CanBlock() {
		return fmt.Errorf("hook event %q must be evaluated for enforcement", event.HookName)
	}
	return nil
}

func (c *Core) ProcessHook(ctx context.Context, event hook.Event) (hook.Result, error) {
	if event.HookName.CanBlock() {
		return c.EvaluateHook(ctx, event)
	}
	return c.IngestEvent(ctx, event)
}
