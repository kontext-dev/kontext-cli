package vomc

import "math"

// Score computes average negative log probability for seq.
func (m *Model) Score(seq Sequence) Score {
	if m == nil || len(seq) == 0 {
		return Score{}
	}
	total := 0.0
	unknowns := 0
	hasZeroProbability := false
	for i, next := range seq {
		start := i - m.maxDepth
		if start < 0 {
			start = 0
		}
		logProbability := m.LogProb(seq[start:i], next)
		if math.IsInf(logProbability, -1) {
			unknowns++
			hasZeroProbability = true
			continue
		}
		total += -logProbability
	}
	if hasZeroProbability {
		return infiniteScore(len(seq), unknowns)
	}
	return Score{
		LogLoss:      total / float64(len(seq)),
		TokensScored: len(seq),
		Unknowns:     unknowns,
	}
}
