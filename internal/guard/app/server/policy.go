package server

import (
	"context"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

type PolicyProvider interface {
	DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error)
}

type RiskPolicyProvider struct {
	scorer risk.Scorer
}

func NewRiskPolicyProvider(scorer risk.Scorer) RiskPolicyProvider {
	if scorer == nil {
		scorer = risk.NoopScorer{}
	}
	return RiskPolicyProvider{scorer: scorer}
}

func (p RiskPolicyProvider) DecideHook(_ context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	return risk.DecideRisk(event, p.scorer)
}
