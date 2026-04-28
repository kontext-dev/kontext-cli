package abstraction

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/guard/markov/predicate"
)

// Finish is the conventional terminal state label.
const Finish = "finish"

// Abstraction maps domain observations into finite symbolic states.
//
// Implementations own the domain-specific encoding, decoding, and transition
// validity rules. The Markov-chain model learner only requires Encode and ValidTransition;
// Decode is exposed for tooling and interpretation.
type Interface[O any] interface {
	Encode(observation O) (string, error)
	Decode(state string) (O, error)
	ValidTransition(from, to string) bool
}

// StateInterpreter is an optional extension for abstractions that can expose
// per-state proposition truth values for diagnostics and JSON output.
type StateInterpreter interface {
	StateInterpretation(states []string) map[string]map[string]bool
}

// StateIndexer is an optional extension for abstractions that need to control
// state index assignment. If absent, states are sorted lexicographically.
type StateIndexer interface {
	StateIndex(states []string) map[string]int
}

// PredicateAbstraction encodes one observation as a bitstring over predicates.
type PredicateAbstraction struct {
	Predicates []predicate.Predicate
}

// Encode returns one bit per predicate, in the configured order.
func (a PredicateAbstraction) Encode(observation predicate.Observation) (string, error) {
	var b strings.Builder
	b.Grow(len(a.Predicates))
	for _, predicate := range a.Predicates {
		ok, err := predicate.Evaluate(observation)
		if err != nil {
			return "", err
		}
		if ok {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	return b.String(), nil
}

// Decode returns a representative observation for the encoded predicate values.
// It is intentionally lossy: predicate abstractions generally cannot reconstruct
// the original domain observation.
func (a PredicateAbstraction) Decode(state string) (predicate.Observation, error) {
	if len(state) != len(a.Predicates) {
		return nil, fmt.Errorf("state length %d does not match predicate count %d", len(state), len(a.Predicates))
	}
	decoded := make(predicate.Observation, len(a.Predicates))
	for i, predicate := range a.Predicates {
		switch state[i] {
		case '0':
			decoded[predicate.String()] = false
		case '1':
			decoded[predicate.String()] = true
		default:
			return nil, fmt.Errorf("state contains non-bit byte %q at index %d", state[i], i)
		}
	}
	return decoded, nil
}

// ValidTransition allows every transition except transitions out of Finish.
func (a PredicateAbstraction) ValidTransition(from, to string) bool {
	return from != Finish
}

// StateInterpretation exposes predicate truth values for each state.
func (a PredicateAbstraction) StateInterpretation(states []string) map[string]map[string]bool {
	result := make(map[string]map[string]bool, len(states))
	for _, state := range states {
		interpretation := make(map[string]bool, len(a.Predicates))
		for i, predicate := range a.Predicates {
			if i < len(state) {
				interpretation[predicate.String()] = state[i] == '1'
			}
		}
		result[state] = interpretation
	}
	return result
}

// DefaultStateIndex returns a deterministic lexicographic state index.
func DefaultStateIndex(states []string) map[string]int {
	copied := append([]string(nil), states...)
	sort.Strings(copied)
	index := make(map[string]int, len(copied))
	for i, state := range copied {
		index[state] = i
	}
	return index
}
