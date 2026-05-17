package risk

const PolicyVersionLaunchV0 = "guard-launch-v0"

func DecideRisk(event HookEvent, scorer Scorer) (RiskDecision, error) {
	if scorer == nil {
		scorer = NoopScorer{}
	}
	riskEvent := NormalizeHookEvent(event)
	riskEvent.PolicyVersion = PolicyVersionLaunchV0
	score, err := scorer.Score(riskEvent)
	if err != nil {
		return RiskDecision{}, err
	}
	riskEvent.RiskScore = score.RiskScore
	riskEvent.ModelVersion = score.ModelVersion
	if event.HookEventName != "PreToolUse" {
		riskEvent.Decision = DecisionAllow
		riskEvent.ReasonCode = "async_telemetry"
		riskEvent.DecisionStage = "async_telemetry"
		return RiskDecision{
			Decision:     DecisionAllow,
			Reason:       "async telemetry event recorded",
			ReasonCode:   "async_telemetry",
			RiskScore:    score.RiskScore,
			Threshold:    score.Threshold,
			ModelVersion: score.ModelVersion,
			RiskEvent:    riskEvent,
		}, nil
	}

	decision := guardDecision(riskEvent)
	if decision.Decision == "" {
		decision = RiskDecision{
			Decision:   DecisionAllow,
			Reason:     "normal tool call",
			ReasonCode: "normal_tool_call",
		}
		if score.Known && score.RiskScore != nil && score.Threshold != nil && *score.RiskScore >= *score.Threshold && modelCanEscalate(riskEvent) {
			decision = RiskDecision{
				Decision:   DecisionAsk,
				Reason:     "model risk exceeded threshold",
				ReasonCode: "model_risk_threshold",
				GuardID:    "markov_threshold",
			}
		}
	}
	decision.RiskScore = score.RiskScore
	decision.Threshold = score.Threshold
	decision.ModelVersion = score.ModelVersion
	decision.RiskEvent = riskEvent
	decision.RiskEvent.Decision = decision.Decision
	decision.RiskEvent.ReasonCode = decision.ReasonCode
	decision.RiskEvent.GuardID = decision.GuardID
	decision.RiskEvent.RiskScore = decision.RiskScore
	decision.RiskEvent.ModelVersion = decision.ModelVersion
	decision.RiskEvent.PolicyVersion = PolicyVersionLaunchV0
	if decision.RiskEvent.DecisionStage == "" {
		switch {
		case decision.ReasonCode == "model_risk_threshold":
			decision.RiskEvent.DecisionStage = "model"
		case decision.GuardID != "":
			decision.RiskEvent.DecisionStage = "deterministic"
		default:
			decision.RiskEvent.DecisionStage = "policy_allow"
		}
	}
	return decision, nil
}

func DeterministicDecision(event RiskEvent) RiskDecision {
	return guardDecision(event)
}

func modelCanEscalate(event RiskEvent) bool {
	return event.Type == EventUnknown ||
		event.Type == EventCredentialAccess ||
		event.Type == EventDirectProviderAPICall ||
		event.Type == EventDestructiveProviderOperation
}

func guardDecision(event RiskEvent) RiskDecision {
	if event.Type == EventDestructiveProviderOperation && isPersistentResource(event.ResourceClass) && !event.ExplicitUserIntent {
		return RiskDecision{
			Decision:   DecisionDeny,
			Reason:     "destructive persistent-resource operation requires explicit user intent",
			ReasonCode: "destructive_operation_without_intent",
			GuardID:    "guard_destructive_persistent_resource",
		}
	}
	if event.Type == EventDirectProviderAPICall && event.ProviderCategory == "infrastructure" && event.CredentialObserved {
		return RiskDecision{
			Decision:   DecisionDeny,
			Reason:     "direct infrastructure API call included credential material",
			ReasonCode: "direct_infra_api_with_credential",
			GuardID:    "guard_direct_infra_api_credential",
		}
	}
	if event.Environment == "production" && event.OperationClass != "unknown" && event.OperationClass != "read" {
		return RiskDecision{
			Decision:   DecisionAsk,
			Reason:     "production mutation requires approval",
			ReasonCode: "production_mutation",
			GuardID:    "guard_production_mutation",
		}
	}
	if event.Type == EventCredentialAccess && !event.ExplicitUserIntent {
		return RiskDecision{
			Decision:   DecisionAsk,
			Reason:     "credential access requires approval",
			ReasonCode: "credential_access_without_intent",
			GuardID:    "guard_credential_access",
		}
	}
	if event.Type == EventUnknown {
		return RiskDecision{
			Decision:   DecisionAsk,
			Reason:     "unknown high-risk command requires review",
			ReasonCode: "unknown_high_risk_command",
			GuardID:    "guard_unknown_high_risk",
		}
	}
	return RiskDecision{}
}
