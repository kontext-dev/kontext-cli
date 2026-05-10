package vomc

import (
	"fmt"

	"github.com/kontext-security/kontext-cli/pkg/vomc/internal/contextseq"
)

type contextInfo struct {
	Context  Context
	Total    uint64
	Next     map[Symbol]uint64
	Fallback Context
}

// Model is a variable-order Markov chain.
type Model struct {
	maxDepth int
	alphabet []Symbol
	smoother Smoother
	contexts map[string]contextInfo
}

func build(counts counts, options Options) (*Model, error) {
	options, err := options.normalize()
	if err != nil {
		return nil, err
	}
	if counts.total(nil) == 0 {
		return nil, fmt.Errorf("cannot fit model from empty counts")
	}

	model := &Model{
		maxDepth: options.MaxDepth,
		alphabet: mergeAlphabet(options.Alphabet, counts.alphabet()),
		smoother: options.Smoother,
		contexts: map[string]contextInfo{
			"": contextInfoFromRow(counts.row(nil), nil),
		},
	}

	candidates := counts.contexts()
	for _, ctx := range candidates {
		if len(ctx) == 0 || len(ctx) > options.MaxDepth {
			continue
		}
		total := counts.total(ctx)
		if total < options.MinCount {
			continue
		}
		fallback := model.longestRetainedSuffix(ctx)
		child := counts.row(ctx)
		parent := counts.row(fallback)
		if (intervalPrune{}).collapsible(child, parent, model.alphabet) {
			continue
		}
		model.contexts[contextseq.Key(ctx)] = contextInfoFromRow(child, fallback)
	}
	return model, nil
}

func contextInfoFromRow(row rowView, fallback []Symbol) contextInfo {
	info := contextInfo{
		Context:  Context(contextseq.Copy(row.Context)),
		Total:    row.Total,
		Next:     make(map[Symbol]uint64, len(row.Next)),
		Fallback: Context(contextseq.Copy(fallback)),
	}
	for sym, count := range row.Next {
		info.Next[sym] = count
	}
	return info
}

// MaxDepth returns the maximum context depth used by the model.
func (m *Model) MaxDepth() int {
	if m == nil {
		return 0
	}
	return m.maxDepth
}

// Alphabet returns the model alphabet in ascending order.
func (m *Model) Alphabet() []Symbol {
	if m == nil {
		return nil
	}
	return contextseq.Copy(m.alphabet)
}

func (m *Model) contextInfos() []contextInfo {
	if m == nil {
		return nil
	}
	contexts := make([]Context, 0, len(m.contexts))
	for _, info := range m.contexts {
		contexts = append(contexts, info.Context)
	}
	contextseq.SortContexts[Symbol, Context](contexts)
	result := make([]contextInfo, 0, len(contexts))
	for _, ctx := range contexts {
		info := m.contexts[contextseq.Key(ctx)]
		result = append(result, contextInfo{
			Context:  Context(contextseq.Copy(info.Context)),
			Total:    info.Total,
			Next:     copyNextCounts(info.Next),
			Fallback: Context(contextseq.Copy(info.Fallback)),
		})
	}
	return result
}

func (m *Model) matchContext(context []Symbol) (contextInfo, bool, bool) {
	if m == nil {
		return contextInfo{}, false, false
	}
	ctx := context
	if len(ctx) > m.maxDepth {
		ctx = ctx[len(ctx)-m.maxDepth:]
	}
	matched := m.longestRetainedSuffix(ctx)
	info, ok := m.contexts[contextseq.Key(matched)]
	if !ok {
		return contextInfo{}, false, false
	}
	return info, backedOffContext(context, info.Context, m.maxDepth), true
}

func (m *Model) longestRetainedSuffix(history []Symbol) []Symbol {
	limit := len(history)
	if limit > m.maxDepth {
		limit = m.maxDepth
	}
	for order := limit; order > 0; order-- {
		ctx := contextseq.Suffix(history, order)
		if _, ok := m.contexts[contextseq.Key(ctx)]; ok {
			return ctx
		}
	}
	return nil
}

func copyNextCounts(next map[Symbol]uint64) map[Symbol]uint64 {
	out := make(map[Symbol]uint64, len(next))
	for sym, count := range next {
		out[sym] = count
	}
	return out
}

func mergeAlphabet(configured, observed []Symbol) []Symbol {
	seen := map[Symbol]struct{}{}
	for _, sym := range configured {
		seen[sym] = struct{}{}
	}
	for _, sym := range observed {
		seen[sym] = struct{}{}
	}
	alphabet := make([]Symbol, 0, len(seen))
	for sym := range seen {
		alphabet = append(alphabet, sym)
	}
	contextseq.SortSymbols(alphabet)
	return alphabet
}

func backedOffContext(query, matched []Symbol, maxDepth int) bool {
	limit := len(query)
	if limit > maxDepth {
		limit = maxDepth
	}
	return len(matched) < limit
}
