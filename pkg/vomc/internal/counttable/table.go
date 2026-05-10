package counttable

import (
	"fmt"

	"github.com/kontext-security/kontext-cli/pkg/vomc/internal/contextseq"
)

// Row stores next-symbol counts for one context.
type Row[S ~uint32] struct {
	Context []S
	Total   uint64
	Next    map[S]uint64
}

// Table stores context-to-next-symbol counts up to MaxDepth.
type Table[S ~uint32] struct {
	MaxDepth int

	rows     map[string]*Row[S]
	alphabet map[S]struct{}
}

// New creates an empty count table.
func New[S ~uint32](maxDepth int) (*Table[S], error) {
	if maxDepth < 0 {
		return nil, fmt.Errorf("max depth must be non-negative")
	}
	return newTable[S](maxDepth), nil
}

func newTable[S ~uint32](maxDepth int) *Table[S] {
	return &Table[S]{
		MaxDepth: maxDepth,
		rows: map[string]*Row[S]{
			"": {Next: map[S]uint64{}},
		},
		alphabet: map[S]struct{}{},
	}
}

// AddAlphabet records symbols that should belong to the table alphabet even if
// they have not yet been observed.
func (t *Table[S]) AddAlphabet(symbols []S) {
	if t == nil {
		return
	}
	if t.alphabet == nil {
		t.alphabet = map[S]struct{}{}
	}
	for _, sym := range symbols {
		t.alphabet[sym] = struct{}{}
	}
}

// ObserveSequence records all transitions in seq.
func (t *Table[S]) ObserveSequence(seq []S) error {
	if t == nil {
		return fmt.Errorf("count table is nil")
	}
	for i, next := range seq {
		start := i - t.MaxDepth
		if start < 0 {
			start = 0
		}
		if err := t.observeTransition(seq[start:i], next); err != nil {
			return err
		}
	}
	return nil
}

func (t *Table[S]) observeTransition(history []S, next S) error {
	if t == nil {
		return fmt.Errorf("count table is nil")
	}
	t.alphabet[next] = struct{}{}
	limit := len(history)
	if limit > t.MaxDepth {
		limit = t.MaxDepth
	}
	for order := 0; order <= limit; order++ {
		ctx := contextseq.Suffix(history, order)
		t.observeContext(ctx, next)
	}
	return nil
}

func (t *Table[S]) observeContext(ctx []S, next S) {
	key := contextseq.Key(ctx)
	row := t.rows[key]
	if row == nil {
		row = &Row[S]{
			Context: contextseq.Copy(ctx),
			Next:    map[S]uint64{},
		}
		t.rows[key] = row
	}
	row.Total++
	row.Next[next]++
}

// Total returns the number of observations for ctx.
func (t *Table[S]) Total(ctx []S) uint64 {
	if t == nil {
		return 0
	}
	row := t.rows[contextseq.Key(ctx)]
	if row == nil {
		return 0
	}
	return row.Total
}

// Contexts returns all observed contexts.
func (t *Table[S]) Contexts() [][]S {
	if t == nil {
		return nil
	}
	contexts := make([][]S, 0, len(t.rows))
	for _, row := range t.rows {
		contexts = append(contexts, contextseq.Copy(row.Context))
	}
	contextseq.SortContexts[S, []S](contexts)
	return contexts
}

// Row returns a copy of the row for ctx.
func (t *Table[S]) Row(ctx []S) Row[S] {
	if t == nil {
		return Row[S]{Context: contextseq.Copy(ctx)}
	}
	row := t.rows[contextseq.Key(ctx)]
	if row == nil {
		return Row[S]{Context: contextseq.Copy(ctx)}
	}
	return Row[S]{
		Context: contextseq.Copy(row.Context),
		Total:   row.Total,
		Next:    copyNext(row.Next),
	}
}

// Alphabet returns observed symbols.
func (t *Table[S]) Alphabet() []S {
	if t == nil {
		return nil
	}
	symbols := make([]S, 0, len(t.alphabet))
	for sym := range t.alphabet {
		symbols = append(symbols, sym)
	}
	contextseq.SortSymbols(symbols)
	return symbols
}

// Clone returns a deep copy.
func (t *Table[S]) Clone() *Table[S] {
	if t == nil {
		return nil
	}
	out := &Table[S]{
		MaxDepth: t.MaxDepth,
		rows:     make(map[string]*Row[S], len(t.rows)),
		alphabet: make(map[S]struct{}, len(t.alphabet)),
	}
	for key, row := range t.rows {
		out.rows[key] = &Row[S]{
			Context: contextseq.Copy(row.Context),
			Total:   row.Total,
			Next:    copyNext(row.Next),
		}
	}
	for sym := range t.alphabet {
		out.alphabet[sym] = struct{}{}
	}
	return out
}

func copyNext[S ~uint32](next map[S]uint64) map[S]uint64 {
	out := make(map[S]uint64, len(next))
	for sym, count := range next {
		out[sym] = count
	}
	return out
}
