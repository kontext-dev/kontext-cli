// Package agent defines the interface for AI agent adapters.
// Each supported agent (Claude Code, Codex, ...) implements this interface
// to translate between the agent's native hook format and Kontext's protocol,
// and to own the per-session config generation required to launch the agent
// with Kontext hooks registered.
package agent

// Agent is the interface that each supported AI agent must implement.
type Agent interface {
	// Name returns the agent identifier (e.g., "claude", "codex").
	Name() string

	// Binary returns the name of the agent executable to look up in PATH.
	Binary() string

	// Prepare writes any per-session config the agent needs (hook settings,
	// feature flags, etc.) under sessionDir and returns the argv/env to pass
	// to the child process at launch. kontextBin is the absolute path of
	// the currently-running kontext binary, used inside generated hook
	// commands.
	Prepare(sessionDir, kontextBin string) (*PrepareResult, error)

	// Cleanup removes or restores any state that Prepare mutated outside
	// sessionDir. For agents whose config lives entirely under sessionDir,
	// this is a no-op.
	Cleanup() error

	// DecodeHookInput parses the agent's native hook stdin JSON into a HookEvent.
	DecodeHookInput(input []byte) (*HookEvent, error)

	// EncodeAllow encodes an allow decision in the agent's native output format.
	EncodeAllow(event *HookEvent, reason string) ([]byte, error)

	// EncodeDeny encodes a deny decision in the agent's native output format.
	// The returned bytes are written to stdout, and the process exits with code 2.
	EncodeDeny(event *HookEvent, reason string) ([]byte, error)

	// FilterUserArgs strips agent-specific flags from pass-through user args
	// that would otherwise conflict with Kontext's governance posture
	// (e.g. Claude's --settings, Codex's --sandbox danger-full-access).
	FilterUserArgs(args []string) []string
}

// PrepareResult is returned by Agent.Prepare with the argv/env the caller
// should apply when launching the child process.
type PrepareResult struct {
	// Args is prepended to the filtered user args at launch.
	Args []string

	// Env is appended to the base env the caller already assembled.
	// Entries are in "KEY=VALUE" form.
	Env []string
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
