package vomc

import (
	"math"

	"github.com/kontext-security/kontext-cli/pkg/vomc/internal/contextseq"
)

// Symbol identifies one item in a sequence.
//
// The package treats symbols as opaque integers. Applications should keep the
// mapping between domain objects and symbols outside this package.
type Symbol uint32

// Sequence is an ordered list of symbols.
type Sequence []Symbol

// Context is the ordered suffix history used to predict the next symbol.
//
// Contexts are represented oldest-to-newest. For example, if the recent
// history is A, B, C, the context is []Symbol{A, B, C}.
type Context []Symbol

// Distribution is the estimated next-symbol distribution for a matched context.
type Distribution struct {
	Context Context
	Depth   int
	Total   uint64
	Probs   map[Symbol]float64
}

// Probability returns the estimated probability for sym.
func (d Distribution) Probability(sym Symbol) float64 {
	if d.Probs == nil {
		return 0
	}
	return d.Probs[sym]
}

// Prediction is the highest-probability next symbol for a context.
type Prediction struct {
	Symbol      Symbol
	Probability float64
	Context     Context
	Depth       int
	BackedOff   bool
}

// Score summarizes the log scoring of a sequence under a model.
//
// LogLoss is average negative log probability. It is +Inf if any scored symbol
// has zero probability.
type Score struct {
	LogLoss      float64
	TokensScored int
	Unknowns     int
}

func infiniteScore(tokens, unknowns int) Score {
	return Score{
		LogLoss:      math.Inf(1),
		TokensScored: tokens,
		Unknowns:     unknowns,
	}
}

type rowView struct {
	Context Context
	Total   uint64
	Next    map[Symbol]uint64
}

func (r rowView) Count(sym Symbol) uint64 {
	if r.Next == nil {
		return 0
	}
	return r.Next[sym]
}

func (r rowView) NextSymbols() []Symbol {
	symbols := make([]Symbol, 0, len(r.Next))
	for sym := range r.Next {
		symbols = append(symbols, sym)
	}
	contextseq.SortSymbols(symbols)
	return symbols
}
