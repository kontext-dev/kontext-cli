package vomc

import "fmt"

// Builder incrementally observes sequences and fits immutable models.
//
// Builder is not safe for concurrent mutation.
type Builder struct {
	options Options
	counts  *counts
}

// NewBuilder creates an empty builder.
func NewBuilder(options Options) (*Builder, error) {
	options, err := options.normalize()
	if err != nil {
		return nil, err
	}
	counts, err := newCounts(options.MaxDepth)
	if err != nil {
		return nil, err
	}
	counts.table.AddAlphabet(options.Alphabet)
	return &Builder{options: options, counts: counts}, nil
}

// Observe records one sequence. Context does not cross sequence boundaries.
func (b *Builder) Observe(seq Sequence) error {
	if b == nil || b.counts == nil {
		return fmt.Errorf("builder is nil")
	}
	return b.counts.observeSequence(seq)
}

// ObserveBatch records several independent sequences.
func (b *Builder) ObserveBatch(seqs []Sequence) error {
	for i, seq := range seqs {
		if err := b.Observe(seq); err != nil {
			return fmt.Errorf("observe sequence %d: %w", i, err)
		}
	}
	return nil
}

// Fit prunes the observed counts into an immutable model.
func (b *Builder) Fit() (*Model, error) {
	if b == nil || b.counts == nil {
		return nil, fmt.Errorf("builder is nil")
	}
	return build(b.counts.clone(), b.options)
}
