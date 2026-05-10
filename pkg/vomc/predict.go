package vomc

import (
	"fmt"
	"math/rand"

	"github.com/kontext-security/kontext-cli/pkg/vomc/internal/contextseq"
)

// Predict returns the highest-probability next symbol for context.
func (m *Model) Predict(context Sequence) Prediction {
	if m == nil {
		return Prediction{}
	}
	dist := m.Distribution(context)
	prediction := Prediction{
		Context:   Context(contextseq.Copy(dist.Context)),
		Depth:     dist.Depth,
		BackedOff: backedOffContext(context, dist.Context, m.maxDepth),
	}
	first := true
	for _, sym := range sortedDistributionSymbols(dist.Probs) {
		probability := dist.Probs[sym]
		if first || probability > prediction.Probability {
			prediction.Symbol = sym
			prediction.Probability = probability
			first = false
		}
	}
	return prediction
}

// Sample draws a next symbol from the model distribution using r.
func (m *Model) Sample(context Sequence, r *rand.Rand) (Symbol, error) {
	if r == nil {
		return 0, fmt.Errorf("rand is nil")
	}
	dist := m.Distribution(context)
	if len(dist.Probs) == 0 {
		return 0, fmt.Errorf("empty distribution")
	}
	sum := 0.0
	for _, probability := range dist.Probs {
		sum += probability
	}
	if sum <= 0 {
		return 0, fmt.Errorf("zero-probability distribution")
	}
	draw := r.Float64() * sum
	accumulated := 0.0
	for _, sym := range sortedDistributionSymbols(dist.Probs) {
		accumulated += dist.Probs[sym]
		if draw <= accumulated {
			return sym, nil
		}
	}
	for _, sym := range sortedDistributionSymbols(dist.Probs) {
		return sym, nil
	}
	return 0, fmt.Errorf("empty distribution")
}

func sortedDistributionSymbols(probs map[Symbol]float64) []Symbol {
	symbols := make([]Symbol, 0, len(probs))
	for sym := range probs {
		symbols = append(symbols, sym)
	}
	contextseq.SortSymbols(symbols)
	return symbols
}
