package providers

import (
	"context"
	"testing"
)

func TestRegistryRegisterAndAll(t *testing.T) {
	r := NewRegistry()
	p := &Provider{
		Name: "example",
		Actions: []Action{
			{
				Name:        "ping",
				Description: "Returns pong",
				Params:      nil,
				Handler: func(ctx context.Context, args map[string]any) (any, error) {
					return map[string]string{"status": "pong"}, nil
				},
			},
		},
	}
	r.Register(p)

	got, ok := r.Get("example")
	if !ok {
		t.Fatal("example provider not found")
	}
	if got.Name != "example" {
		t.Errorf("name: got %q", got.Name)
	}
	if len(got.Actions) != 1 || got.Actions[0].Name != "ping" {
		t.Errorf("actions: %+v", got.Actions)
	}

	all := r.All()
	if len(all) != 1 {
		t.Errorf("All(): expected 1, got %d", len(all))
	}
}

func TestRegistryActionLookup(t *testing.T) {
	r := NewRegistry()
	r.Register(&Provider{
		Name: "foo",
		Actions: []Action{
			{Name: "bar", Handler: func(ctx context.Context, args map[string]any) (any, error) { return nil, nil }},
		},
	})
	action, ok := r.Action("foo", "bar")
	if !ok {
		t.Fatal("foo.bar not found")
	}
	if action.Name != "bar" {
		t.Errorf("action name: %q", action.Name)
	}
	if _, ok := r.Action("foo", "missing"); ok {
		t.Error("missing action should not be found")
	}
	if _, ok := r.Action("missing", "bar"); ok {
		t.Error("missing provider should not be found")
	}
}
