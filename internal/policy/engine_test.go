package policy

import (
	"testing"
)

func TestEvaluateDisabledPolicy(t *testing.T) {
	e := &Engine{enabled: false}
	allowed, reason := e.Evaluate("Bash", "")
	if !allowed {
		t.Fatal("disabled policy should allow everything")
	}
	if reason == "" {
		t.Fatal("expected a reason")
	}
}

func TestEvaluateDefaultDeny(t *testing.T) {
	e := &Engine{enabled: true, rules: nil}
	allowed, _ := e.Evaluate("Bash", "")
	if allowed {
		t.Fatal("enabled policy with no rules should deny")
	}
}

func TestEvaluateOrgToolAllow(t *testing.T) {
	e := &Engine{
		enabled: true,
		rules: []Rule{
			{Action: "allow", Scope: "tool", Level: "org", ToolName: "Bash"},
		},
	}
	allowed, _ := e.Evaluate("Bash", "")
	if !allowed {
		t.Fatal("org-level tool allow should match")
	}
}

func TestEvaluateOrgToolDeny(t *testing.T) {
	e := &Engine{
		enabled: true,
		rules: []Rule{
			{Action: "deny", Scope: "tool", Level: "org", ToolName: "Bash"},
		},
	}
	allowed, _ := e.Evaluate("Bash", "")
	if allowed {
		t.Fatal("org-level tool deny should block")
	}
}

func TestEvaluateServerScopeMatchesAllTools(t *testing.T) {
	e := &Engine{
		enabled: true,
		rules: []Rule{
			{Action: "allow", Scope: "server", Level: "org"},
		},
	}
	allowed, _ := e.Evaluate("Bash", "")
	if !allowed {
		t.Fatal("server-scope allow should match any tool")
	}
}

func TestEvaluateSpecificRuleWins(t *testing.T) {
	e := &Engine{
		enabled: true,
		rules: []Rule{
			{Action: "allow", Scope: "server", Level: "org"},
			{Action: "deny", Scope: "tool", Level: "org", ToolName: "Bash"},
		},
	}
	allowed, _ := e.Evaluate("Bash", "")
	if allowed {
		t.Fatal("tool-scope deny should override server-scope allow")
	}
}

func TestEvaluateUnmatchedToolDenied(t *testing.T) {
	e := &Engine{
		enabled: true,
		rules: []Rule{
			{Action: "allow", Scope: "tool", Level: "org", ToolName: "Read"},
		},
	}
	allowed, _ := e.Evaluate("Bash", "")
	if allowed {
		t.Fatal("unmatched tool should be denied under default-deny")
	}
}
