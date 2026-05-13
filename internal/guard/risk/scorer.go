package risk

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/guard/markov"
	"github.com/kontext-security/kontext-cli/internal/guard/markov/abstraction"
	"github.com/kontext-security/kontext-cli/internal/guard/trace"
)

type MarkovScorer struct {
	Model        *markov.Model
	Threshold    float64
	Horizon      int
	ModelVersion string
	Abstraction  abstraction.Interface[trace.Event]
	Unsafe       func(string) bool
}

func LoadMarkovScorer(path string, threshold float64, horizon int) (*MarkovScorer, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	model, err := markov.ReadModelJSON(file)
	if err != nil {
		return nil, err
	}
	abs, unsafe, err := abstractionFromModel(model)
	if err != nil {
		return nil, fmt.Errorf("select model abstraction: %w", err)
	}
	return &MarkovScorer{
		Model:        model,
		Threshold:    threshold,
		Horizon:      horizon,
		ModelVersion: path,
		Abstraction:  abs,
		Unsafe:       unsafe,
	}, nil
}

func ValidateMarkovModel(model *markov.Model) error {
	_, _, err := abstractionFromModel(model)
	return err
}

func (s *MarkovScorer) Score(event RiskEvent) (ScoreResult, error) {
	if s == nil || s.Model == nil {
		return ScoreResult{}, fmt.Errorf("markov scorer model is nil")
	}
	traceEvent := riskEventToTrace(event)
	abs := s.Abstraction
	if abs == nil {
		return ScoreResult{}, fmt.Errorf("markov scorer abstraction is nil")
	}
	unsafePredicate := s.Unsafe
	if unsafePredicate == nil {
		return ScoreResult{}, fmt.Errorf("markov scorer unsafe predicate is nil")
	}
	state, err := abs.Encode(traceEvent)
	if err != nil {
		return ScoreResult{}, err
	}
	index, ok := s.Model.IndexForState(state)
	threshold := s.Threshold
	result := ScoreResult{Threshold: &threshold, ModelVersion: s.ModelVersion}
	if !ok {
		score := baselineScore(event)
		result.RiskScore = &score
		return result, nil
	}
	unsafe := trace.UnsafeStates(s.Model.StateIndex, unsafePredicate)
	riskScore, err := markov.HorizonReachabilityProbability(s.Model, index, unsafe, s.Horizon)
	if err != nil {
		return ScoreResult{}, err
	}
	result.RiskScore = &riskScore
	result.Known = true
	return result, nil
}

func baselineScore(event RiskEvent) float64 {
	switch event.Type {
	case EventDestructiveProviderOperation:
		return 0.95
	case EventDirectProviderAPICall:
		return 0.85
	case EventCredentialAccess:
		return 0.72
	case EventUnknown:
		return 0.65
	default:
		return 0.05
	}
}

func abstractionFromModel(model *markov.Model) (abstraction.Interface[trace.Event], func(string) bool, error) {
	if model == nil {
		return nil, nil, fmt.Errorf("model is nil")
	}
	raw, ok := model.Metadata["abstraction_version"]
	if !ok {
		return nil, nil, fmt.Errorf("model metadata missing abstraction_version")
	}
	version := ""
	if err := json.Unmarshal(raw, &version); err != nil {
		var wrapped map[string]any
		if wrappedErr := json.Unmarshal(raw, &wrapped); wrappedErr != nil {
			return nil, nil, fmt.Errorf("decode abstraction_version: %w", err)
		}
		value, ok := wrapped["abstraction_version"].(string)
		if !ok {
			return nil, nil, fmt.Errorf("abstraction_version is not a string")
		}
		version = value
	}
	switch strings.TrimSpace(version) {
	case trace.CodingAbstractionVersion:
		return trace.CodingAbstraction{}, trace.IsFailureState, nil
	case trace.RiskAbstractionVersion:
		return trace.RiskCodingAbstraction{}, trace.IsRiskUnsafeState, nil
	default:
		return nil, nil, fmt.Errorf("unsupported abstraction_version %q", version)
	}
}

func riskEventToTrace(event RiskEvent) trace.Event {
	category := trace.ToolCategoryOther
	name := string(event.Type)
	switch event.Type {
	case EventCredentialAccess:
		category = trace.ToolCategoryRead
	case EventDirectProviderAPICall:
		category = trace.ToolCategoryBashNet
	case EventDestructiveProviderOperation:
		category = trace.ToolCategoryBash
	case EventManagedToolCall:
		category = trace.ToolCategoryMCP
	case EventNormalToolCall:
		category = trace.ToolCategoryOther
	}
	metadata := map[string]any{}
	addStringMetadata(metadata, "provider", event.Provider)
	addStringMetadata(metadata, "provider_category", event.ProviderCategory)
	addStringMetadata(metadata, "operation", event.Operation)
	addStringMetadata(metadata, "operation_class", event.OperationClass)
	addStringMetadata(metadata, "resource_class", event.ResourceClass)
	addStringMetadata(metadata, "environment", event.Environment)
	addStringMetadata(metadata, "command_summary", event.CommandSummary)
	addStringMetadata(metadata, "request_summary", event.RequestSummary)
	if event.Type == EventCredentialAccess {
		metadata["credential_access"] = true
	}
	if event.CredentialObserved {
		metadata["credential_observed"] = true
	}
	if event.DirectAPICall || event.Type == EventDirectProviderAPICall {
		metadata["direct_provider_api_call"] = true
	}
	if event.ExplicitUserIntent {
		metadata["explicit_user_intent"] = true
	}
	for _, signal := range event.Signals {
		metadata[signal] = true
	}
	return trace.Event{
		Actor:        trace.ActorTool,
		Kind:         trace.KindTool,
		ToolName:     name,
		ToolCategory: category,
		Metadata:     metadata,
	}
}

func addStringMetadata(metadata map[string]any, key, value string) {
	value = strings.TrimSpace(value)
	if value == "" || value == "unknown" {
		return
	}
	metadata[key] = value
}
