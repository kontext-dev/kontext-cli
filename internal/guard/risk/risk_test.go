package risk

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/markov"
	"github.com/kontext-security/kontext-cli/internal/guard/trace"
)

func TestNormalizeCredentialFileRead(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Read", ToolInput: map[string]any{"file_path": ".env"}})
	if event.Type != EventCredentialAccess {
		t.Fatalf("type = %s, want %s", event.Type, EventCredentialAccess)
	}
	if event.PathClass != "env_file" {
		t.Fatalf("path class = %s", event.PathClass)
	}
}

func TestNormalizeShellCredentialAccess(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "cat .env"}})
	if event.Type != EventCredentialAccess {
		t.Fatalf("type = %s", event.Type)
	}
	if event.CredentialSource != "command_output" {
		t.Fatalf("credential source = %s", event.CredentialSource)
	}
}

func TestNormalizeDirectProviderAPI(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "curl https://api.railway.app/graphql -H 'Authorization: Bearer secret'"}})
	if event.Type != EventDirectProviderAPICall {
		t.Fatalf("type = %s", event.Type)
	}
	if !event.CredentialObserved {
		t.Fatal("credential was not observed")
	}
}

func TestNormalizeDestructiveOperation(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "railway volume delete production"}})
	if event.Type != EventDestructiveProviderOperation {
		t.Fatalf("type = %s", event.Type)
	}
	if event.OperationClass != "delete" {
		t.Fatalf("operation class = %s", event.OperationClass)
	}
}

func TestNormalizeDestructiveSourceControlOperation(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "gh repo delete kontext-security/guard"}})
	if event.Type != EventDestructiveProviderOperation {
		t.Fatalf("type = %s", event.Type)
	}
	if event.ProviderCategory != "source_control" {
		t.Fatalf("provider category = %s", event.ProviderCategory)
	}
	if event.ResourceClass != "repo" {
		t.Fatalf("resource class = %s", event.ResourceClass)
	}
}

func TestNormalizeGitCommitIgnoresCommitMessageBody(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `git commit -m "$(cat <<'EOF'
feat: improve dashboard

Mentions production database delete only as copied text.
EOF
)"`}})
	if event.Type != EventNormalToolCall {
		t.Fatalf("type = %s", event.Type)
	}
	if event.OperationClass != "write" {
		t.Fatalf("operation class = %s", event.OperationClass)
	}
	if event.Environment == "production" {
		t.Fatal("environment should not be inferred from commit body")
	}
	if event.CredentialObserved {
		t.Fatal("credential material should not be inferred from commit body")
	}
	for _, signal := range event.Signals {
		if signal == "destructive_verb" || signal == "persistent_resource" {
			t.Fatalf("unexpected signal %s", signal)
		}
	}
}

func TestNormalizeGitHubPRDoesNotTreatBodyAsCredential(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `gh pr create --title "feat: dashboard" --body "$(cat <<'EOF'
This mentions token handling in documentation but does not pass a token.
EOF
)"`}})
	if event.ProviderCategory != "source_control" {
		t.Fatalf("provider category = %s", event.ProviderCategory)
	}
	if event.CredentialObserved {
		t.Fatal("credential material should not be inferred from PR body text")
	}
}

func TestNormalizeDirectProviderAPIStillSeesAuthorizationHeader(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `curl https://api.cloudflare.com/client/v4/zones -H "Authorization: Bearer abc123"`}})
	if event.Type != EventDirectProviderAPICall {
		t.Fatalf("type = %s", event.Type)
	}
	if !event.CredentialObserved {
		t.Fatal("credential material was not observed")
	}
}

func TestNormalizeRedactsCredentialValuesFromSummaries(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `API_TOKEN=real-secret-123 curl https://api.cloudflare.com -H "Authorization: Bearer abc123"`}})
	for _, value := range []string{event.CommandSummary, event.RequestSummary} {
		if strings.Contains(value, "real-secret-123") || strings.Contains(value, "abc123") {
			t.Fatalf("summary leaked credential value: %q", value)
		}
		if !strings.Contains(value, "[redacted-credential]") {
			t.Fatalf("summary did not include redaction marker: %q", value)
		}
	}
}

func TestGuardDecisionBeatsScorer(t *testing.T) {
	decision, err := DecideRisk(HookEvent{HookEventName: "PreToolUse", ToolName: "Bash", ToolInput: map[string]any{"command": "drop database"}}, fixedScorer(0))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionDeny {
		t.Fatalf("decision = %s", decision.Decision)
	}
}

func TestModelRiskDoesNotBlockNormalToolCalls(t *testing.T) {
	decision, err := DecideRisk(HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"file_path": "README.md"}}, fixedScorer(0.99))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionAllow {
		t.Fatalf("decision = %s", decision.Decision)
	}
	if decision.RiskScore == nil || *decision.RiskScore != 0.99 {
		t.Fatalf("risk score was not recorded: %+v", decision.RiskScore)
	}
}

func TestAsyncTelemetryStillGetsScore(t *testing.T) {
	decision, err := DecideRisk(HookEvent{HookEventName: "UserPromptSubmit", ToolName: "Read"}, fixedScorer(0.42))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionAllow {
		t.Fatalf("decision = %s", decision.Decision)
	}
	if decision.RiskScore == nil || *decision.RiskScore != 0.42 {
		t.Fatalf("risk score = %+v", decision.RiskScore)
	}
}

func TestNoopScorerReturnsNumericScore(t *testing.T) {
	decision, err := DecideRisk(HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"file_path": "README.md"}}, NoopScorer{})
	if err != nil {
		t.Fatal(err)
	}
	if decision.RiskScore == nil || *decision.RiskScore != 0 {
		t.Fatalf("risk score = %+v", decision.RiskScore)
	}
	if decision.Threshold == nil || *decision.Threshold != 0.5 {
		t.Fatalf("threshold = %+v", decision.Threshold)
	}
}

func TestDecideRiskReturnsScorerErrors(t *testing.T) {
	want := errors.New("model state is invalid")
	_, err := DecideRisk(HookEvent{HookEventName: "PreToolUse", ToolName: "Read"}, errorScorer{err: want})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestMarkovScorerUsesRiskAbstractionMetadata(t *testing.T) {
	model := &markov.Model{
		States: []string{
			"001000000000000000000000",
			"001001000000000000000000",
			"001110011000000000000000",
		},
		StateIndex: map[string]int{
			"001000000000000000000000": 0,
			"001001000000000000000000": 1,
			"001110011000000000000000": 2,
		},
		TransitionProbs: map[int]map[int]float64{
			0: {0: 1},
			1: {1: 1},
			2: {2: 1},
		},
		Metadata: map[string]json.RawMessage{
			"abstraction_version": json.RawMessage(`"coding-risk-v2"`),
		},
	}
	scorer := &MarkovScorer{
		Model:        model,
		Threshold:    0.5,
		Horizon:      5,
		ModelVersion: "test",
		Abstraction:  trace.RiskCodingAbstraction{},
		Unsafe:       trace.IsRiskUnsafeState,
	}

	cases := []RiskEvent{
		{Type: EventNormalToolCall},
		{Type: EventCredentialAccess, CredentialObserved: true},
		{
			Type:               EventDirectProviderAPICall,
			CredentialObserved: true,
			DirectAPICall:      true,
			ProviderCategory:   "infrastructure",
			CommandSummary:     "curl https://api.cloudflare.com -H 'Authorization: Bearer token'",
		},
	}
	for _, item := range cases {
		score, err := scorer.Score(item)
		if err != nil {
			t.Fatal(err)
		}
		if !score.Known {
			t.Fatalf("event %+v mapped to unknown state", item)
		}
	}
}

func TestLoadMarkovScorerRejectsMissingAbstractionMetadata(t *testing.T) {
	model := &markov.Model{
		States:          []string{"000000000000000000000000"},
		StateIndex:      map[string]int{"000000000000000000000000": 0},
		TransitionProbs: map[int]map[int]float64{0: {0: 1}},
	}
	_, _, err := abstractionFromModel(model)
	if err == nil {
		t.Fatal("expected missing abstraction metadata error")
	}
}

func TestMarkovScorerUsesBaselineScoreForUnknownState(t *testing.T) {
	model := &markov.Model{
		States:          []string{"000000000000000000000000"},
		StateIndex:      map[string]int{"000000000000000000000000": 0},
		TransitionProbs: map[int]map[int]float64{0: {0: 1}},
		Metadata: map[string]json.RawMessage{
			"abstraction_version": json.RawMessage(`"coding-risk-v2"`),
		},
	}
	scorer := &MarkovScorer{
		Model:        model,
		Threshold:    0.5,
		Horizon:      5,
		ModelVersion: "test",
		Abstraction:  trace.RiskCodingAbstraction{},
		Unsafe:       trace.IsRiskUnsafeState,
	}
	score, err := scorer.Score(RiskEvent{Type: EventNormalToolCall})
	if err != nil {
		t.Fatal(err)
	}
	if score.Known {
		t.Fatal("unknown model state should not be marked known")
	}
	if score.RiskScore == nil || *score.RiskScore != 0.05 {
		t.Fatalf("baseline risk score = %+v", score.RiskScore)
	}
}

type fixedScorer float64

func (s fixedScorer) Score(RiskEvent) (ScoreResult, error) {
	score := float64(s)
	threshold := 0.5
	return ScoreResult{RiskScore: &score, Threshold: &threshold, ModelVersion: "test", Known: true}, nil
}

type errorScorer struct {
	err error
}

func (s errorScorer) Score(RiskEvent) (ScoreResult, error) {
	return ScoreResult{}, s.err
}
