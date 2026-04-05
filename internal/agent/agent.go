// Package agent defines the interface for AI agent adapters.
// Each supported agent (Claude Code, Cursor, Codex) implements this interface
// to translate between the agent's native hook format and Kontext's protocol.
package agent

// Agent is the interface that each supported AI agent must implement.
// It handles the translation between the agent's native hook I/O format
// and Kontext's internal representation.
type Agent interface {
	// Name returns the agent identifier (e.g., "claude", "cursor", "codex").
	Name() string

	// DecodeHookInput parses the agent's native hook stdin JSON into a HookEvent.
	DecodeHookInput(input []byte) (*HookEvent, error)

	// EncodeAllow encodes an allow decision in the agent's native output format.
	EncodeAllow(event *HookEvent, reason string) ([]byte, error)

	// EncodeDeny encodes a deny decision in the agent's native output format.
	// The returned bytes are written to stdout, and the process exits with code 2.
	EncodeDeny(event *HookEvent, reason string) ([]byte, error)
}

// HookEvent is the normalized representation of a hook event across all agents.
type HookEvent struct {
	SessionID     string
	HookEventName string // "PreToolUse", "PostToolUse", "UserPromptSubmit"
	ToolName      string
	ToolInput     map[string]any
	ToolResponse  map[string]any // PostToolUse only
	ToolUseID     string
	CWD           string
}

// Registry holds the registered agent adapters.
var registry = map[string]Agent{}

// Register adds an agent adapter to the registry.
func Register(a Agent) {
	registry[a.Name()] = a
}

// Get returns the agent adapter for the given name.
func Get(name string) (Agent, bool) {
	a, ok := registry[name]
	return a, ok
}

// Names returns all registered agent names.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
