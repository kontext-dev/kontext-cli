package markov

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Model is a learned Markov-chain model over integer-indexed symbolic states.
type Model struct {
	States              []string                   `json:"states"`
	StateIndex          map[string]int             `json:"state_index"`
	StateInterpretation map[string]map[string]bool `json:"state_interpret,omitempty"`
	StateCounts         map[int]int                `json:"state_counts,omitempty"`
	TransitionCounts    map[int]map[int]int        `json:"transition_counts,omitempty"`
	TransitionProbs     map[int]map[int]float64    `json:"transition_probs"`
	Metadata            map[string]json.RawMessage `json:"metadata,omitempty"`
}

// Validate checks basic Markov-chain model invariants.
func (m Model) Validate() error {
	if len(m.States) == 0 {
		return fmt.Errorf("model has no states")
	}
	if len(m.StateIndex) != len(m.States) {
		return fmt.Errorf("state index has %d entries for %d states", len(m.StateIndex), len(m.States))
	}
	seen := make(map[int]string, len(m.StateIndex))
	for state, index := range m.StateIndex {
		if index < 0 || index >= len(m.States) {
			return fmt.Errorf("state %q has out-of-range index %d", state, index)
		}
		if other, exists := seen[index]; exists {
			return fmt.Errorf("states %q and %q share index %d", other, state, index)
		}
		seen[index] = state
	}
	for index, state := range m.States {
		if m.StateIndex[state] != index {
			return fmt.Errorf("states[%d]=%q but state index maps it to %d", index, state, m.StateIndex[state])
		}
	}
	for from, row := range m.TransitionProbs {
		if from < 0 || from >= len(m.States) {
			return fmt.Errorf("transition source %d is out of range", from)
		}
		sum := 0.0
		for to, probability := range row {
			if to < 0 || to >= len(m.States) {
				return fmt.Errorf("transition target %d is out of range", to)
			}
			if probability < 0 {
				return fmt.Errorf("transition %d -> %d has negative probability %f", from, to, probability)
			}
			sum += probability
		}
		if len(row) == 0 {
			return fmt.Errorf("transition row %d is empty", from)
		}
		if sum < 0.999999 || sum > 1.000001 {
			return fmt.Errorf("transition row %d sums to %f", from, sum)
		}
	}
	return nil
}

// StateForIndex returns the symbolic state for an index.
func (m Model) StateForIndex(index int) (string, bool) {
	if index < 0 || index >= len(m.States) {
		return "", false
	}
	return m.States[index], true
}

// IndexForState returns the integer index for a symbolic state.
func (m Model) IndexForState(state string) (int, bool) {
	index, ok := m.StateIndex[state]
	return index, ok
}

// SortedStateIndexes returns all model indexes in ascending order.
func (m Model) SortedStateIndexes() []int {
	indexes := make([]int, 0, len(m.States))
	for i := range m.States {
		indexes = append(indexes, i)
	}
	sort.Ints(indexes)
	return indexes
}
