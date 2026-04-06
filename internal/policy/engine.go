package policy

// Rule is a policy rule fetched from the backend.
type Rule struct {
	Action   string // "allow" or "deny"
	Scope    string // "server" or "tool"
	Level    string // "org", "user", or "agent"
	ToolName string // only set when Scope == "tool"
}

// Engine evaluates hook events against cached policy rules.
type Engine struct {
	enabled bool
	rules   []Rule
}

// NewEngine creates a policy engine with the given settings and rules.
func NewEngine(enabled bool, rules []Rule) *Engine {
	return &Engine{enabled: enabled, rules: rules}
}

// Evaluate checks whether a tool call is allowed.
// Returns (allowed, reason).
func (e *Engine) Evaluate(toolName string, toolUseID string) (bool, string) {
	if !e.enabled {
		return true, "policy disabled"
	}

	type match struct {
		rule     Rule
		priority int
	}

	levelPriority := map[string]int{"org": 0, "user": 1, "agent": 2}

	// Specificity tiers (higher = more specific):
	//   3 — tool-scope match on the exact tool name
	//   2 — server-scope match (applies to all tools)
	// Within each tier, level specificity: agent (2) > user (1) > org (0).
	// Combined priority = tier*10 + level. Most specific matching rule wins.
	var best *match
	for _, r := range e.rules {
		var tier int
		switch {
		case r.Scope == "tool" && r.ToolName == toolName:
			tier = 3
		case r.Scope == "server":
			tier = 2
		default:
			continue
		}

		p := tier*10 + levelPriority[r.Level]
		if best == nil || p > best.priority {
			best = &match{rule: r, priority: p}
		}
	}

	if best == nil {
		return false, "no matching rule (default deny)"
	}

	allowed := best.rule.Action == "allow"
	scope := best.rule.Scope
	if scope == "tool" {
		scope = "tool:" + best.rule.ToolName
	}
	reason := best.rule.Action + " by " + best.rule.Level + "-level " + scope + " rule"
	return allowed, reason
}
