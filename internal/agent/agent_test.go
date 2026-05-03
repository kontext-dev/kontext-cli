package agent

import "testing"

type registryTestAgent struct{}

func (registryTestAgent) Name() string { return "registry-test" }

func (registryTestAgent) Aliases() []string { return []string{"registry-test-alias"} }

func (registryTestAgent) DecodeHookInput([]byte) (*HookEvent, error) { return &HookEvent{}, nil }

func (registryTestAgent) EncodeAllow(*HookEvent, string, map[string]any) ([]byte, error) {
	return nil, nil
}

func (registryTestAgent) EncodeDeny(*HookEvent, string) ([]byte, error) { return nil, nil }

func TestRegistryResolvesAliasesWithoutListingThemAsPrimaryNames(t *testing.T) {
	Register(registryTestAgent{})

	if _, ok := Get("registry-test"); !ok {
		t.Fatal("primary agent was not registered")
	}
	if _, ok := Get("registry-test-alias"); !ok {
		t.Fatal("agent alias was not registered")
	}

	for _, name := range Names() {
		if name == "registry-test-alias" {
			t.Fatalf("Names() included alias %q, want primary names only", name)
		}
	}
}
