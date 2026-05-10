package vomc

// Smoother estimates P(next | context) from row counts.
type Smoother interface {
	Probability(count, total, alphabetSize uint64) float64
}

type mleSmoother struct{}

// Probability returns count / total.
func (mleSmoother) Probability(count, total, _ uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(count) / float64(total)
}

// LaplaceSmoother applies add-alpha smoothing over the model alphabet.
type LaplaceSmoother struct {
	Alpha float64
}

// Probability returns (count + alpha) / (total + alpha * alphabetSize).
func (s LaplaceSmoother) Probability(count, total, alphabetSize uint64) float64 {
	alpha := s.Alpha
	if alpha <= 0 {
		alpha = 1
	}
	denom := float64(total) + alpha*float64(alphabetSize)
	if denom == 0 {
		return 0
	}
	return (float64(count) + alpha) / denom
}
