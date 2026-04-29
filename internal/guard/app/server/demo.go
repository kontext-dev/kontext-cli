package server

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
)

const (
	demoModelVersion = "demo-policy-v0"
	demoThreshold    = 0.5
)

type demoPolicy struct {
	mu              sync.Mutex
	intentBySession map[string]string
	allowOnce       map[string]bool
	allowSession    map[string]bool
	pending         map[string]chan risk.Decision
}

func newDemoPolicy() *demoPolicy {
	return &demoPolicy{
		intentBySession: map[string]string{},
		allowOnce:       map[string]bool{},
		allowSession:    map[string]bool{},
		pending:         map[string]chan risk.Decision{},
	}
}

func (p *demoPolicy) Decide(_ context.Context, event risk.HookEvent, scorer risk.Scorer) (risk.RiskDecision, error) {
	if strings.EqualFold(event.HookEventName, "UserPromptSubmit") && strings.TrimSpace(event.UserPrompt) != "" {
		p.mu.Lock()
		p.intentBySession[sessionID(event)] = event.UserPrompt
		p.mu.Unlock()
	}

	decision, err := risk.DecideRisk(event, scorer)
	if err != nil {
		return risk.RiskDecision{}, err
	}
	if event.HookEventName != "PreToolUse" {
		return decision, nil
	}

	sessionIntent := p.intent(sessionID(event))
	decision.RiskEvent.SessionIntent = summarizeIntent(sessionIntent)

	key := approvalKey(decision.RiskEvent)
	if p.consumeApproval(key, sessionID(event)) {
		return p.demoDecision(decision.RiskEvent, risk.DecisionAllow, 0.08, "approved by user for this action", "user_approved_action", "user_approval", "matches approved intent"), nil
	}

	if isHardBlock(decision.RiskEvent) {
		return p.demoDecision(decision.RiskEvent, risk.DecisionDeny, 0.97, "blocked destructive action before execution", "demo_block_destructive_action", "deterministic_block", "violates safety policy"), nil
	}

	if requiresSourceControlApproval(decision.RiskEvent) {
		return p.demoDecision(decision.RiskEvent, risk.DecisionAsk, 0.18, "source-control write requires approval", "demo_source_control_write_approval", "deterministic_source_control_policy", "policy requires approval"), nil
	}

	if decision.Decision == risk.DecisionAsk || decision.Decision == risk.DecisionDeny {
		decision.RiskEvent.IntentAlignment = "requires policy review"
		return decision, nil
	}

	return p.demoDecision(decision.RiskEvent, risk.DecisionAllow, 0.04, "no policy trigger", "demo_normal_action", "normal_flow", "allowed by policy"), nil
}

func (p *demoPolicy) Approve(ctx context.Context, store *sqlite.Store, eventID, scope string) error {
	record, err := store.Decision(ctx, strings.TrimSpace(eventID))
	if err != nil {
		return fmt.Errorf("find event: %w", err)
	}
	key := approvalKey(record.RiskEvent)
	p.mu.Lock()
	defer p.mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "once":
		p.allowOnce[key] = true
		p.resolvePendingLocked(record.ID, risk.DecisionAllow)
	case "session":
		p.allowSession[record.SessionID+"|"+key] = true
		p.resolvePendingLocked(record.ID, risk.DecisionAllow)
	case "reject":
		delete(p.allowOnce, key)
		delete(p.allowSession, record.SessionID+"|"+key)
		p.resolvePendingLocked(record.ID, risk.DecisionDeny)
	default:
		return fmt.Errorf("unknown approval scope %q", scope)
	}
	return nil
}

func (p *demoPolicy) RegisterPending(eventID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.pending[eventID]; !ok {
		p.pending[eventID] = make(chan risk.Decision, 1)
	}
}

func (p *demoPolicy) WaitApproval(ctx context.Context, eventID string) (risk.Decision, error) {
	p.mu.Lock()
	ch, ok := p.pending[eventID]
	if !ok {
		ch = make(chan risk.Decision, 1)
		p.pending[eventID] = ch
	}
	p.mu.Unlock()

	select {
	case decision := <-ch:
		p.mu.Lock()
		delete(p.pending, eventID)
		p.mu.Unlock()
		return decision, nil
	case <-ctx.Done():
		return risk.DecisionDeny, ctx.Err()
	}
}

func (p *demoPolicy) intent(sessionID string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.intentBySession[sessionID]
}

func (p *demoPolicy) consumeApproval(key, sessionID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.allowSession[sessionID+"|"+key] {
		return true
	}
	if p.allowOnce[key] {
		delete(p.allowOnce, key)
		return true
	}
	return false
}

func (p *demoPolicy) resolvePendingLocked(eventID string, decision risk.Decision) {
	ch, ok := p.pending[eventID]
	if !ok {
		return
	}
	select {
	case ch <- decision:
	default:
	}
}

func (p *demoPolicy) demoDecision(event risk.RiskEvent, decision risk.Decision, score float64, reason, reasonCode, guardID, alignment string) risk.RiskDecision {
	threshold := demoThreshold
	event.Decision = decision
	event.ReasonCode = reasonCode
	event.GuardID = guardID
	event.RiskScore = &score
	event.ModelVersion = demoModelVersion
	event.IntentAlignment = alignment
	event.Signals = appendUnique(event.Signals, signalFor(reasonCode))
	return risk.RiskDecision{
		Decision:     decision,
		Reason:       reason,
		ReasonCode:   reasonCode,
		RiskScore:    &score,
		Threshold:    &threshold,
		ModelVersion: demoModelVersion,
		GuardID:      guardID,
		RiskEvent:    event,
	}
}

func sessionID(event risk.HookEvent) string {
	if event.SessionID != "" {
		return event.SessionID
	}
	return "local"
}

func summarizeIntent(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 180 {
		return value[:180] + "..."
	}
	return value
}

func requiresSourceControlApproval(event risk.RiskEvent) bool {
	if event.ProviderCategory == "source_control" && event.OperationClass == "write" {
		return true
	}
	return false
}

func isHardBlock(event risk.RiskEvent) bool {
	text := strings.ToLower(event.CommandSummary + " " + event.RequestSummary)
	return strings.Contains(text, "git push --force") ||
		strings.Contains(text, "gcloud sql databases delete") ||
		strings.Contains(text, "rm -rf /") ||
		strings.Contains(text, "rm -rf ~") ||
		strings.Contains(text, ".ssh/id_rsa") ||
		event.ReasonCode == "direct_infra_api_with_credential" ||
		event.ReasonCode == "destructive_operation_without_intent"
}

func approvalKey(event risk.RiskEvent) string {
	key := event.Provider + "|" + event.Operation + "|" + event.CommandSummary + "|" + event.RequestSummary
	return strings.ToLower(strings.TrimSpace(key))
}

func signalFor(reasonCode string) string {
	switch reasonCode {
	case "demo_source_control_write_approval":
		return "source_control_write"
	case "demo_block_destructive_action":
		return "hard_block"
	case "user_approved_action":
		return "user_approved"
	default:
		return "demo_policy"
	}
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
