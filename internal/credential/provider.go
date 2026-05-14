package credential

import (
	"context"
	"errors"
)

type Provider interface {
	ResolveCredential(context.Context, Entry) (Resolved, error)
}

type ProviderFunc func(context.Context, Entry) (Resolved, error)

func (f ProviderFunc) ResolveCredential(ctx context.Context, entry Entry) (Resolved, error) {
	return f(ctx, entry)
}

var ErrNoopProvider = errors.New("credential provider is not configured")

type NoopProvider struct{}

func (NoopProvider) ResolveCredential(context.Context, Entry) (Resolved, error) {
	return Resolved{}, ErrNoopProvider
}
