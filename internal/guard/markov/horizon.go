package markov

import "fmt"

// HorizonReachabilityProbability computes P_start(F<=steps target).
//
// Unlike ReachabilityProbability, this is a finite-session risk estimate. It is
// the probability of reaching a target state within the next steps transitions.
func HorizonReachabilityProbability(model *Model, start int, targets map[int]struct{}, steps int) (float64, error) {
	if model == nil {
		return 0, fmt.Errorf("model is nil")
	}
	if err := model.Validate(); err != nil {
		return 0, err
	}
	if start < 0 || start >= len(model.States) {
		return 0, fmt.Errorf("start state %d is out of range", start)
	}
	for target := range targets {
		if target < 0 || target >= len(model.States) {
			return 0, fmt.Errorf("target state %d is out of range", target)
		}
	}
	if _, ok := targets[start]; ok {
		return 1, nil
	}
	if steps <= 0 {
		return 0, nil
	}

	probs := make([]float64, len(model.States))
	next := make([]float64, len(model.States))
	for target := range targets {
		probs[target] = 1
		next[target] = 1
	}

	for step := 0; step < steps; step++ {
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
		}
		copy(probs, next)
	}
	return probs[start], nil
}

// HorizonReachabilityProbabilityByState computes finite-horizon reachability
// using symbolic state labels.
func HorizonReachabilityProbabilityByState(model *Model, startState string, targetStates []string, steps int) (float64, error) {
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
	return HorizonReachabilityProbability(model, start, targets, steps)
}
