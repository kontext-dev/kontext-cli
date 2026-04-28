package markov

import (
	"math"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/markov/abstraction"
)

type stringAbstraction struct{}

func (stringAbstraction) Encode(observation string) (string, error) {
	return observation, nil
}

func (stringAbstraction) Decode(state string) (string, error) {
	return state, nil
}

func (stringAbstraction) ValidTransition(from, to string) bool {
	return from != abstraction.Finish
}

func TestBuildModelWithoutSmoothing(t *testing.T) {
	t.Parallel()

	model, err := BuildModel([][]string{
		{"a", "b", "b", "c"},
		{"a", "c"},
	}, stringAbstraction{}, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildModel returned error: %v", err)
	}

	a := model.StateIndex["a"]
	b := model.StateIndex["b"]
	c := model.StateIndex["c"]

	assertNear(t, model.TransitionProbs[a][b], 0.5)
	assertNear(t, model.TransitionProbs[a][c], 0.5)
	assertNear(t, model.TransitionProbs[b][b], 0.5)
	assertNear(t, model.TransitionProbs[b][c], 0.5)
	assertNear(t, model.TransitionProbs[c][c], 1)
}

func TestBuildModelWithValidityAwareSmoothing(t *testing.T) {
	t.Parallel()

	model, err := BuildModel([][]string{
		{"a", "b"},
	}, stringAbstraction{}, BuildOptions{Alpha: 1})
	if err != nil {
		t.Fatalf("BuildModel returned error: %v", err)
	}

	a := model.StateIndex["a"]
	b := model.StateIndex["b"]

	assertNear(t, model.TransitionProbs[a][a], 1.0/3.0)
	assertNear(t, model.TransitionProbs[a][b], 2.0/3.0)
	assertNear(t, model.TransitionProbs[b][a], 0.5)
	assertNear(t, model.TransitionProbs[b][b], 0.5)
}

func TestReachabilityProbability(t *testing.T) {
	t.Parallel()

	model := &Model{
		States:     []string{"safe", "risky", "unsafe"},
		StateIndex: map[string]int{"safe": 0, "risky": 1, "unsafe": 2},
		TransitionProbs: map[int]map[int]float64{
			0: {1: 0.5, 2: 0.5},
			1: {1: 0.5, 2: 0.5},
			2: {2: 1},
		},
	}

	probability, err := ReachabilityProbability(model, 0, map[int]struct{}{2: {}}, ReachabilityOptions{})
	if err != nil {
		t.Fatalf("ReachabilityProbability returned error: %v", err)
	}
	assertNear(t, probability, 1)
}

func TestHorizonReachabilityProbability(t *testing.T) {
	t.Parallel()

	model := &Model{
		States:     []string{"safe", "middle", "unsafe"},
		StateIndex: map[string]int{"safe": 0, "middle": 1, "unsafe": 2},
		TransitionProbs: map[int]map[int]float64{
			0: {1: 1},
			1: {1: 0.75, 2: 0.25},
			2: {2: 1},
		},
	}
	targets := map[int]struct{}{2: {}}

	zero, err := HorizonReachabilityProbability(model, 0, targets, 0)
	if err != nil {
		t.Fatalf("HorizonReachabilityProbability returned error: %v", err)
	}
	assertNear(t, zero, 0)

	one, err := HorizonReachabilityProbability(model, 0, targets, 1)
	if err != nil {
		t.Fatalf("HorizonReachabilityProbability returned error: %v", err)
	}
	assertNear(t, one, 0)

	two, err := HorizonReachabilityProbability(model, 0, targets, 2)
	if err != nil {
		t.Fatalf("HorizonReachabilityProbability returned error: %v", err)
	}
	assertNear(t, two, 0.25)
}

func assertNear(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("got %f, want %f", got, want)
	}
}
