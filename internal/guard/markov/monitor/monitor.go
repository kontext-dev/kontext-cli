package monitor

import (
	"fmt"

	"github.com/kontext-security/kontext-cli/internal/guard/markov"
	"github.com/kontext-security/kontext-cli/internal/guard/markov/abstraction"
)

// Monitor evaluates runtime observations against a learned Markov-chain model.
type Monitor[O any] struct {
	Model       *markov.Model
	Abstraction abstraction.Interface[O]
	Unsafe      map[int]struct{}
	Threshold   float64
	Solver      markov.ReachabilityOptions
}

// Decision is one runtime monitoring result.
type Decision struct {
	State        string
	StateIndex   int
	Risk         float64
	Intervention bool
}

// Observe encodes an observation, computes probability of eventually reaching
// an unsafe state, and flags intervention if Risk > Threshold.
func (m Monitor[O]) Observe(observation O) (Decision, error) {
	if m.Model == nil {
		return Decision{}, fmt.Errorf("model is nil")
	}
	if m.Abstraction == nil {
		return Decision{}, fmt.Errorf("abstraction is nil")
	}
	state, err := m.Abstraction.Encode(observation)
	if err != nil {
		return Decision{}, err
	}
	index, ok := m.Model.IndexForState(state)
	if !ok {
		return Decision{}, fmt.Errorf("encoded state %q is not present in model", state)
	}
	risk, err := markov.ReachabilityProbability(m.Model, index, m.Unsafe, m.Solver)
	if err != nil {
		return Decision{}, err
	}
	return Decision{
		State:        state,
		StateIndex:   index,
		Risk:         risk,
		Intervention: risk > m.Threshold,
	}, nil
}
