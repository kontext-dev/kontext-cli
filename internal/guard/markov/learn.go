package markov

import (
	"fmt"
	"sort"

	"github.com/kontext-security/kontext-cli/internal/guard/markov/abstraction"
)

// BuildOptions controls Markov-chain model learning.
type BuildOptions struct {
	// Alpha is the validity-aware Laplace smoothing amount.
	Alpha float64
}

// BuildModel learns a Markov-chain model from observation traces.
func BuildModel[O any](logs [][]O, abs abstraction.Interface[O], options BuildOptions) (*Model, error) {
	if abs == nil {
		return nil, fmt.Errorf("abstraction is nil")
	}
	alpha := options.Alpha
	if alpha < 0 {
		return nil, fmt.Errorf("alpha must be non-negative")
	}

	traceStates := make([][]string, 0, len(logs))
	stateSet := map[string]struct{}{}
	for traceIndex, log := range logs {
		encodedTrace := make([]string, 0, len(log))
		for observationIndex, observation := range log {
			state, err := abs.Encode(observation)
			if err != nil {
				return nil, fmt.Errorf("encode trace %d observation %d: %w", traceIndex, observationIndex, err)
			}
			encodedTrace = append(encodedTrace, state)
			stateSet[state] = struct{}{}
		}
		traceStates = append(traceStates, encodedTrace)
	}
	if len(stateSet) == 0 {
		return nil, fmt.Errorf("cannot build model from empty logs")
	}

	states := make([]string, 0, len(stateSet))
	for state := range stateSet {
		states = append(states, state)
	}

	stateIndex := buildStateIndex(states, abs)
	statesByIndex := make([]string, len(states))
	for state, index := range stateIndex {
		if index < 0 || index >= len(states) {
			return nil, fmt.Errorf("state index for %q is out of range: %d", state, index)
		}
		statesByIndex[index] = state
	}

	countMatrix := make([][]int, len(statesByIndex))
	for i := range countMatrix {
		countMatrix[i] = make([]int, len(statesByIndex))
	}
	stateCounts := make(map[int]int, len(statesByIndex))

	for _, trace := range traceStates {
		for _, state := range trace {
			index, ok := stateIndex[state]
			if !ok {
				return nil, fmt.Errorf("unknown observed state %q", state)
			}
			stateCounts[index]++
		}
		for i := 1; i < len(trace); i++ {
			from, ok := stateIndex[trace[i-1]]
			if !ok {
				return nil, fmt.Errorf("unknown source state %q", trace[i-1])
			}
			to, ok := stateIndex[trace[i]]
			if !ok {
				return nil, fmt.Errorf("unknown target state %q", trace[i])
			}
			countMatrix[from][to]++
		}
	}

	counts := make(map[int]map[int]int)
	probs := make(map[int]map[int]float64, len(statesByIndex))
	for from, fromState := range statesByIndex {
		denominator := 0.0
		weights := make([]float64, len(statesByIndex))
		for to, toState := range statesByIndex {
			weight := float64(countMatrix[from][to])
			if abs.ValidTransition(fromState, toState) {
				weight += alpha
			}
			if weight > 0 {
				weights[to] = weight
				denominator += weight
			}
			if countMatrix[from][to] > 0 {
				if counts[from] == nil {
					counts[from] = map[int]int{}
				}
				counts[from][to] = countMatrix[from][to]
			}
		}
		if denominator == 0 {
			probs[from] = map[int]float64{from: 1}
			continue
		}
		row := make(map[int]float64)
		for to, weight := range weights {
			if weight > 0 {
				row[to] = weight / denominator
			}
		}
		probs[from] = row
	}

	var interpretation map[string]map[string]bool
	if interpreter, ok := any(abs).(abstraction.StateInterpreter); ok {
		interpretation = interpreter.StateInterpretation(statesByIndex)
	}

	model := &Model{
		States:              statesByIndex,
		StateIndex:          stateIndex,
		StateInterpretation: interpretation,
		StateCounts:         stateCounts,
		TransitionCounts:    counts,
		TransitionProbs:     probs,
	}
	if err := model.Validate(); err != nil {
		return nil, err
	}
	return model, nil
}

func buildStateIndex[O any](states []string, abs abstraction.Interface[O]) map[string]int {
	if indexer, ok := any(abs).(abstraction.StateIndexer); ok {
		index := indexer.StateIndex(append([]string(nil), states...))
		if len(index) == len(states) {
			return index
		}
	}

	sorted := append([]string(nil), states...)
	sort.Strings(sorted)
	index := make(map[string]int, len(sorted))
	for i, state := range sorted {
		index[state] = i
	}
	return index
}
