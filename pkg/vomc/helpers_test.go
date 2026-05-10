package vomc_test

import (
	"testing"

	"github.com/kontext-security/kontext-cli/pkg/vomc"
)

func newTestBuilder(t *testing.T, options vomc.Options) *vomc.Builder {
	t.Helper()
	builder, err := vomc.NewBuilder(options)
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func observe(t *testing.T, builder *vomc.Builder, seq vomc.Sequence) {
	t.Helper()
	if err := builder.Observe(seq); err != nil {
		t.Fatal(err)
	}
}

func observeBatch(t *testing.T, builder *vomc.Builder, seqs []vomc.Sequence) {
	t.Helper()
	if err := builder.ObserveBatch(seqs); err != nil {
		t.Fatal(err)
	}
}

func fit(t *testing.T, builder *vomc.Builder) *vomc.Model {
	t.Helper()
	model, err := builder.Fit()
	if err != nil {
		t.Fatal(err)
	}
	return model
}
