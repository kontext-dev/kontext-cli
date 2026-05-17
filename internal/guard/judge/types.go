package judge

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

type RiskLevel string

const (
	RiskLevelLow    RiskLevel = "low"
	RiskLevelMedium RiskLevel = "medium"
	RiskLevelHigh   RiskLevel = "high"
)

type Input struct {
	Agent               string               `json:"agent,omitempty"`
	HookEvent           string               `json:"hook_event"`
	ToolName            string               `json:"tool_name,omitempty"`
	CWDClass            string               `json:"cwd_class,omitempty"`
	ToolInput           ToolInput            `json:"tool_input"`
	NormalizedEvent     NormalizedEvent      `json:"normalized_event"`
	DeterministicPolicy DeterministicContext `json:"deterministic_policy"`
}

type ToolInput struct {
	CommandRedacted string `json:"command_redacted,omitempty"`
	PathRedacted    string `json:"path_redacted,omitempty"`
	RequestSummary  string `json:"request_summary,omitempty"`
}

type NormalizedEvent struct {
	Type               string   `json:"type"`
	Provider           string   `json:"provider,omitempty"`
	ProviderCategory   string   `json:"provider_category,omitempty"`
	Operation          string   `json:"operation,omitempty"`
	OperationClass     string   `json:"operation_class,omitempty"`
	ResourceClass      string   `json:"resource_class,omitempty"`
	Environment        string   `json:"environment,omitempty"`
	CredentialObserved bool     `json:"credential_observed"`
	DirectAPICall      bool     `json:"direct_api_call"`
	ExplicitUserIntent bool     `json:"explicit_user_intent"`
	PathClass          string   `json:"path_class,omitempty"`
	CommandSummary     string   `json:"command_summary,omitempty"`
	RequestSummary     string   `json:"request_summary,omitempty"`
	Signals            []string `json:"signals,omitempty"`
}

type DeterministicContext struct {
	Decision      string   `json:"decision"`
	MatchedRules  []string `json:"matched_rules,omitempty"`
	PolicyVersion string   `json:"policy_version"`
}

type Output struct {
	Decision   Decision  `json:"decision"`
	RiskLevel  RiskLevel `json:"risk_level"`
	Categories []string  `json:"categories"`
	Reason     string    `json:"reason"`
}

type Metadata struct {
	Runtime     string
	Model       string
	DurationMs  int64
	FailureKind string
}

type Result struct {
	Output   Output
	Metadata Metadata
}

type Judge interface {
	Decide(context.Context, Input) (Result, error)
}

type MetadataProvider interface {
	Metadata() Metadata
}

const (
	FailureUnavailable   = "unavailable"
	FailureTimeout       = "timeout"
	FailureInvalidOutput = "invalid_output"
)

type Error struct {
	Kind string
	Err  error
}

func (e Error) Error() string {
	if e.Err == nil {
		return e.Kind
	}
	return fmt.Sprintf("%s: %v", e.Kind, e.Err)
}

func (e Error) Unwrap() error {
	return e.Err
}

func FailureKind(err error) string {
	if err == nil {
		return ""
	}
	var judgeErr Error
	if errors.As(err, &judgeErr) && judgeErr.Kind != "" {
		return judgeErr.Kind
	}
	return FailureUnavailable
}

func ValidateOutput(output Output) error {
	switch output.Decision {
	case DecisionAllow, DecisionDeny:
	default:
		return fmt.Errorf("invalid decision %q", output.Decision)
	}
	switch output.RiskLevel {
	case RiskLevelLow, RiskLevelMedium, RiskLevelHigh:
	default:
		return fmt.Errorf("invalid risk_level %q", output.RiskLevel)
	}
	if strings.TrimSpace(output.Reason) == "" {
		return errors.New("reason is required")
	}
	if len(output.Categories) > 12 {
		return errors.New("too many categories")
	}
	for _, category := range output.Categories {
		if strings.TrimSpace(category) == "" {
			return errors.New("empty category")
		}
	}
	return nil
}
