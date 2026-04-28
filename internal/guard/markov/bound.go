package markov

import "math"

// ChenBound returns a sample-bound right-hand side for one source state.
func ChenBound(counts [][]int, source int, epsilon, delta float64) float64 {
	if len(counts) == 0 || source < 0 || source >= len(counts) || epsilon <= 0 || delta <= 0 {
		return 0
	}

	total := 0
	for _, count := range counts[source] {
		total += count
	}
	if total == 0 {
		return 0
	}

	deltaPrime := delta / float64(len(counts))
	coeff := (2.0 / (epsilon * epsilon)) * math.Log(2.0/deltaPrime)

	maximum := 0.0
	for _, count := range counts[source] {
		p := float64(count) / float64(total)
		inner := math.Abs(0.5-p) - (2.0/3.0)*epsilon
		term := 0.25 - inner*inner
		if term <= 0 {
			continue
		}
		if h := coeff * term; h > maximum {
			maximum = h
		}
	}
	return maximum
}
