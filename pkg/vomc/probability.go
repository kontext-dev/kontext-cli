package vomc

import (
	"math"
	"sort"

	"github.com/kontext-security/kontext-cli/pkg/vomc/internal/contextseq"
)

// Distribution returns the next-symbol distribution for the longest retained
// suffix of context.
func (m *Model) Distribution(context Sequence) Distribution {
	info, _, ok := m.matchContext(context)
	if !ok {
		return Distribution{}
	}
	probs := m.probabilities(info)
	return Distribution{
		Context: Context(contextseq.Copy(info.Context)),
		Depth:   len(info.Context),
		Total:   info.Total,
		Probs:   probs,
	}
}

// Prob returns P(next | context).
func (m *Model) Prob(context Sequence, next Symbol) float64 {
	info, _, ok := m.matchContext(context)
	if !ok {
		return 0
	}
	return m.probability(info, next)
}

// LogProb returns log P(next | context), or -Inf for zero probability.
func (m *Model) LogProb(context Sequence, next Symbol) float64 {
	probability := m.Prob(context, next)
	if probability <= 0 {
		return math.Inf(-1)
	}
	return math.Log(probability)
}

func (m *Model) probabilities(info contextInfo) map[Symbol]float64 {
	probs := make(map[Symbol]float64)
	for _, sym := range m.alphabet {
		probability := m.probability(info, sym)
		if probability > 0 {
			probs[sym] = probability
		}
	}
	if len(m.alphabet) == 0 {
		for sym, count := range info.Next {
			probability := m.smoother.Probability(count, info.Total, uint64(len(info.Next)))
			if probability > 0 {
				probs[sym] = probability
			}
		}
	}
	return probs
}

func (m *Model) probability(info contextInfo, next Symbol) float64 {
	smoother := m.smoother
	if smoother == nil {
		smoother = mleSmoother{}
	}
	alphabetSize := len(m.alphabet)
	if alphabetSize > 0 && !containsSortedSymbol(m.alphabet, next) {
		return 0
	}
	if alphabetSize == 0 {
		alphabetSize = len(info.Next)
	}
	return smoother.Probability(info.Next[next], info.Total, uint64(alphabetSize))
}

func containsSortedSymbol(symbols []Symbol, target Symbol) bool {
	i := sort.Search(len(symbols), func(i int) bool {
		return symbols[i] >= target
	})
	return i < len(symbols) && symbols[i] == target
}
