package markov

import "fmt"

// ReachabilityOptions controls iterative probability solving.
type ReachabilityOptions struct {
	Tolerance     float64
	MaxIterations int
}

func (o ReachabilityOptions) withDefaults() ReachabilityOptions {
	if o.Tolerance <= 0 {
		o.Tolerance = 1e-12
	}
	if o.MaxIterations <= 0 {
		o.MaxIterations = 10000
	}
	return o
}

// ReachabilityProbability computes P_start(F target) for the Markov-chain model.
func ReachabilityProbability(model *Model, start int, targets map[int]struct{}, options ReachabilityOptions) (float64, error) {
	if model == nil {
		return 0, fmt.Errorf("model is nil")
	}
	if err := model.Validate(); err != nil {
		return 0, err
	}
	if start < 0 || start >= len(model.States) {
		return 0, fmt.Errorf("start state %d is out of range", start)
	}
	if _, ok := targets[start]; ok {
		return 1, nil
	}

	options = options.withDefaults()
	probs := make([]float64, len(model.States))
	next := make([]float64, len(model.States))
	for target := range targets {
		if target < 0 || target >= len(model.States) {
			return 0, fmt.Errorf("target state %d is out of range", target)
		}
		probs[target] = 1
		next[target] = 1
	}

	for iteration := 0; iteration < options.MaxIterations; iteration++ {
		delta := 0.0
		for state := range model.States {
			if _, target := targets[state]; target {
				next[state] = 1
				continue
			}
			value := 0.0
			for to, probability := range model.TransitionProbs[state] {
				value += probability * probs[to]
			}
			next[state] = value
			diff := value - probs[state]
			if diff < 0 {
				diff = -diff
			}
			if diff > delta {
				delta = diff
			}
		}
		copy(probs, next)
		if delta <= options.Tolerance {
			return probs[start], nil
		}
	}
	return probs[start], fmt.Errorf("reachability solver did not converge after %d iterations", options.MaxIterations)
}

// ReachabilityProbabilityByState computes P_start(F target) using symbolic
// state labels.
func ReachabilityProbabilityByState(model *Model, startState string, targetStates []string, options ReachabilityOptions) (float64, error) {
	start, ok := model.IndexForState(startState)
	if !ok {
		return 0, fmt.Errorf("unknown start state %q", startState)
	}
	targets := make(map[int]struct{}, len(targetStates))
	for _, state := range targetStates {
		index, ok := model.IndexForState(state)
		if !ok {
			return 0, fmt.Errorf("unknown target state %q", state)
		}
		targets[index] = struct{}{}
	}
	return ReachabilityProbability(model, start, targets, options)
}
