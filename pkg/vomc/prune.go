package vomc

import "github.com/kontext-security/kontext-cli/pkg/vomc/internal/contextseq"

type rowIntervalEstimator interface {
	interval(row rowView, next Symbol) interval
}

type intervalPrune struct {
	intervals rowIntervalEstimator
}

func (p intervalPrune) collapsible(child, parent rowView, alphabet []Symbol) bool {
	if child.Total == 0 || parent.Total == 0 {
		return true
	}
	intervals := p.intervals
	if intervals == nil {
		intervals = wilsonEstimator{confidence: 0.95}
	}
	for _, next := range comparisonAlphabet(child, parent, alphabet) {
		childInterval := intervals.interval(child, next)
		parentInterval := intervals.interval(parent, next)
		if !childInterval.overlaps(parentInterval) {
			return false
		}
	}
	return true
}

func comparisonAlphabet(child, parent rowView, alphabet []Symbol) []Symbol {
	if len(alphabet) > 0 {
		return contextseq.Unique(alphabet)
	}
	seen := map[Symbol]struct{}{}
	for _, sym := range child.NextSymbols() {
		seen[sym] = struct{}{}
	}
	for _, sym := range parent.NextSymbols() {
		seen[sym] = struct{}{}
	}
	out := make([]Symbol, 0, len(seen))
	for sym := range seen {
		out = append(out, sym)
	}
	contextseq.SortSymbols(out)
	return out
}
