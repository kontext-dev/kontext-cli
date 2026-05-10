package vomc_test

import (
	"testing"

	"github.com/kontext-security/kontext-cli/pkg/vomc"
)

func BenchmarkBuilderFit(b *testing.B) {
	seqs := make([]vomc.Sequence, 1024)
	for i := range seqs {
		seq := make(vomc.Sequence, 128)
		for j := range seq {
			seq[j] = vomc.Symbol((i + j) % 32)
		}
		seqs[i] = seq
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder, err := vomc.NewBuilder(vomc.Options{MaxDepth: 4, MinCount: 2})
		if err != nil {
			b.Fatal(err)
		}
		if err := builder.ObserveBatch(seqs); err != nil {
			b.Fatal(err)
		}
		if _, err := builder.Fit(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkModelProb(b *testing.B) {
	builder, err := vomc.NewBuilder(vomc.Options{MaxDepth: 4})
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 1024; i++ {
		seq := make(vomc.Sequence, 64)
		for j := range seq {
			seq[j] = vomc.Symbol((i + j) % 64)
		}
		if err := builder.Observe(seq); err != nil {
			b.Fatal(err)
		}
	}
	model, err := builder.Fit()
	if err != nil {
		b.Fatal(err)
	}
	ctx := vomc.Sequence{1, 2, 3, 4}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.Prob(ctx, vomc.Symbol(i%64))
	}
}
