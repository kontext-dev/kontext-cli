package vomc

import (
	"fmt"

	"github.com/kontext-security/kontext-cli/pkg/vomc/internal/contextseq"
)

// Options controls counting and prediction behavior.
type Options struct {
	// MaxDepth is the maximum suffix-context length observed during training.
	// MaxDepth=0 trains an order-0 model.
	MaxDepth int

	// MinCount is the minimum row count required for a non-root context to be
	// considered during pruning.
	MinCount uint64

	// Alphabet optionally fixes the model alphabet. Observed symbols are always
	// added even when this is set.
	Alphabet []Symbol

	// Smoother estimates probabilities from row counts. Defaults to MLE.
	Smoother Smoother
}

func (o Options) normalize() (Options, error) {
	if o.MaxDepth < 0 {
		return Options{}, fmt.Errorf("max depth must be non-negative")
	}
	if o.Smoother == nil {
		o.Smoother = mleSmoother{}
	}
	o.Alphabet = contextseq.Unique(o.Alphabet)
	return o, nil
}
