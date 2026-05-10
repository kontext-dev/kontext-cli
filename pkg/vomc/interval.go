package vomc

import "math"

type interval struct {
	lo float64
	hi float64
}

func (i interval) overlaps(other interval) bool {
	return i.lo <= other.hi && other.lo <= i.hi
}

type wilsonEstimator struct {
	confidence float64
}

func (e wilsonEstimator) interval(row rowView, next Symbol) interval {
	lo, hi := wilsonInterval(row.Count(next), row.Total, e.confidence)
	return interval{lo: lo, hi: hi}
}

func wilsonInterval(successes, total uint64, confidence float64) (float64, float64) {
	if total == 0 {
		return 0, 1
	}
	z := zForConfidence(confidence)
	n := float64(total)
	phat := float64(successes) / n
	z2 := z * z
	denom := 1 + z2/n
	center := phat + z2/(2*n)
	margin := z * math.Sqrt((phat*(1-phat)+z2/(4*n))/n)
	lo := (center - margin) / denom
	hi := (center + margin) / denom
	if lo < 0 {
		lo = 0
	}
	if hi > 1 {
		hi = 1
	}
	return lo, hi
}

func zForConfidence(confidence float64) float64 {
	switch {
	case confidence >= 0.999:
		return 3.2905267314919255
	case confidence >= 0.99:
		return 2.5758293035489004
	case confidence >= 0.98:
		return 2.3263478740408408
	case confidence >= 0.95 || confidence <= 0:
		return 1.959963984540054
	case confidence >= 0.90:
		return 1.6448536269514722
	case confidence >= 0.80:
		return 1.2815515655446004
	default:
		return 1.959963984540054
	}
}
