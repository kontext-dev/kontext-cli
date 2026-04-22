// Package providers is a registry of Kontext-governed provider actions
// exposed as MCP tools to host agents (e.g. Hermes).
package providers

import "context"

// Action is a single invocable operation on a provider.
type Action struct {
	Name        string
	Description string
	Params      []Param
	Handler     Handler
}

// Param describes a single parameter for an Action.
type Param struct {
	Name        string
	Type        string // "string", "number", "boolean", "object"
	Description string
	Required    bool
}

// Handler executes an action with the given arguments and returns a
// JSON-serializable result or an error.
type Handler func(ctx context.Context, args map[string]any) (any, error)

// Provider is a named group of Actions (e.g. "github", "linear").
type Provider struct {
	Name    string
	Actions []Action
}

// Registry holds all registered providers. Not safe for concurrent mutation
// after initialization.
type Registry struct {
	providers map[string]*Provider
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{providers: map[string]*Provider{}}
}

// Register adds a provider to the registry. If a provider with the same name
// is already present it is replaced.
func (r *Registry) Register(p *Provider) {
	r.providers[p.Name] = p
}

// Get returns a provider by name.
func (r *Registry) Get(name string) (*Provider, bool) {
	p, ok := r.providers[name]
	return p, ok
}

// All returns every registered provider. Order is not stable.
func (r *Registry) All() []*Provider {
	out := make([]*Provider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p)
	}
	return out
}

// Action returns a single action by provider + action name.
func (r *Registry) Action(provider, action string) (Action, bool) {
	p, ok := r.providers[provider]
	if !ok {
		return Action{}, false
	}
	for _, a := range p.Actions {
		if a.Name == action {
			return a, true
		}
	}
	return Action{}, false
}
