package server

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

type PolicyProvider interface {
	DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error)
}

type RiskPolicyProvider struct {
	scorer risk.Scorer
	judge  judge.Judge
}

func NewRiskPolicyProvider(scorer risk.Scorer) RiskPolicyProvider {
	return NewRiskPolicyProviderWithJudge(scorer, nil)
}

func NewRiskPolicyProviderWithJudge(scorer risk.Scorer, localJudge judge.Judge) RiskPolicyProvider {
	if scorer == nil {
		scorer = risk.NoopScorer{}
	}
	return RiskPolicyProvider{scorer: scorer, judge: localJudge}
}

func (p RiskPolicyProvider) DecideHook(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	if p.judge != nil && event.HookEventName == "PreToolUse" {
		return p.decideWithJudge(ctx, event)
	}
	return risk.DecideRisk(event, p.scorer)
}

func (p RiskPolicyProvider) decideWithJudge(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	riskEvent := risk.NormalizeHookEvent(event)
	riskEvent.PolicyVersion = risk.PolicyVersionLaunchV0

	if decision := risk.DeterministicDecision(riskEvent); decision.Decision != "" {
		decision.RiskEvent = riskEvent
		decision.RiskEvent.Decision = decision.Decision
		decision.RiskEvent.ReasonCode = decision.ReasonCode
		decision.RiskEvent.GuardID = decision.GuardID
		decision.RiskEvent.DecisionStage = "deterministic"
		decision.RiskEvent.PolicyVersion = risk.PolicyVersionLaunchV0
		return decision, nil
	}

	result, err := p.judge.Decide(ctx, judgeInputFromRiskEvent(event, riskEvent))
	if err != nil {
		failureKind := judge.FailureKind(err)
		metadata := judgeMetadata(p.judge)
		riskEvent.Decision = risk.DecisionAllow
		riskEvent.ReasonCode = "judge_unavailable_allow"
		riskEvent.DecisionStage = "judge_fail_open"
		riskEvent.JudgeRuntime = metadata.Runtime
		riskEvent.JudgeModel = metadata.Model
		riskEvent.JudgeFailureKind = failureKind
		return risk.RiskDecision{
			Decision:   risk.DecisionAllow,
			Reason:     "local judge unavailable; allowing by fail-open policy",
			ReasonCode: "judge_unavailable_allow",
			RiskEvent:  riskEvent,
		}, nil
	}

	decision := risk.DecisionAllow
	reasonCode := "judge_allow"
	if result.Output.Decision == judge.DecisionDeny {
		decision = risk.DecisionDeny
		reasonCode = "judge_deny"
	}
	duration := result.Metadata.DurationMs
	riskEvent.Decision = decision
	riskEvent.ReasonCode = reasonCode
	riskEvent.DecisionStage = string(reasonCode)
	riskEvent.GuardID = "local_llm_judge"
	riskEvent.JudgeRuntime = result.Metadata.Runtime
	riskEvent.JudgeModel = result.Metadata.Model
	riskEvent.JudgeDurationMs = &duration
	riskEvent.JudgeRiskLevel = string(result.Output.RiskLevel)
	riskEvent.JudgeCategories = result.Output.Categories

	return risk.RiskDecision{
		Decision:   decision,
		Reason:     result.Output.Reason,
		ReasonCode: reasonCode,
		GuardID:    "local_llm_judge",
		RiskEvent:  riskEvent,
	}, nil
}

func judgeInputFromRiskEvent(event risk.HookEvent, riskEvent risk.RiskEvent) judge.Input {
	return judge.Input{
		Agent:     event.Agent,
		HookEvent: event.HookEventName,
		ToolName:  event.ToolName,
		CWDClass:  cwdClass(event.CWD),
		ToolInput: judge.ToolInput{
			CommandRedacted: riskEvent.CommandSummary,
			PathRedacted:    riskEvent.PathClass,
			RequestSummary:  riskEvent.RequestSummary,
		},
		NormalizedEvent: judge.NormalizedEvent{
			Type:               string(riskEvent.Type),
			Provider:           riskEvent.Provider,
			ProviderCategory:   riskEvent.ProviderCategory,
			Operation:          riskEvent.Operation,
			OperationClass:     riskEvent.OperationClass,
			ResourceClass:      riskEvent.ResourceClass,
			Environment:        riskEvent.Environment,
			CredentialObserved: riskEvent.CredentialObserved,
			DirectAPICall:      riskEvent.DirectAPICall,
			ExplicitUserIntent: riskEvent.ExplicitUserIntent,
			PathClass:          riskEvent.PathClass,
			CommandSummary:     riskEvent.CommandSummary,
			RequestSummary:     riskEvent.RequestSummary,
			Signals:            riskEvent.Signals,
		},
		DeterministicPolicy: judge.DeterministicContext{
			Decision:      "allow",
			PolicyVersion: risk.PolicyVersionLaunchV0,
		},
	}
}

func cwdClass(cwd string) string {
	cwd = strings.TrimSpace(cwd)
	if cwd == "" {
		return "unknown"
	}
	base := strings.ToLower(filepath.Base(cwd))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "unknown"
	}
	return "project"
}

func judgeMetadata(localJudge judge.Judge) judge.Metadata {
	if provider, ok := localJudge.(judge.MetadataProvider); ok {
		return provider.Metadata()
	}
	return judge.Metadata{}
}
