package vomc

import (
	"fmt"

	"github.com/kontext-security/kontext-cli/pkg/vomc/internal/contextseq"
	"github.com/kontext-security/kontext-cli/pkg/vomc/internal/counttable"
)

type counts struct {
	table *counttable.Table[Symbol]
}

func newCounts(maxDepth int) (*counts, error) {
	table, err := counttable.New[Symbol](maxDepth)
	if err != nil {
		return nil, err
	}
	return &counts{table: table}, nil
}

func (c *counts) observeSequence(seq Sequence) error {
	if c == nil || c.table == nil {
		return fmt.Errorf("counts is nil")
	}
	return c.table.ObserveSequence(seq)
}

func (c counts) total(ctx []Symbol) uint64 {
	if c.table == nil {
		return 0
	}
	return c.table.Total(ctx)
}

func (c counts) contexts() []Context {
	if c.table == nil {
		return nil
	}
	raw := c.table.Contexts()
	contexts := make([]Context, 0, len(raw))
	for _, ctx := range raw {
		contexts = append(contexts, Context(contextseq.Copy(ctx)))
	}
	return contexts
}

func (c counts) alphabet() []Symbol {
	if c.table == nil {
		return nil
	}
	return c.table.Alphabet()
}

func (c counts) row(ctx []Symbol) rowView {
	if c.table == nil {
		return rowView{Context: Context(contextseq.Copy(ctx))}
	}
	row := c.table.Row(ctx)
	return rowView{
		Context: Context(contextseq.Copy(row.Context)),
		Total:   row.Total,
		Next:    copyNextCounts(row.Next),
	}
}

func (c counts) clone() counts {
	if c.table == nil {
		return counts{}
	}
	return counts{table: c.table.Clone()}
}
