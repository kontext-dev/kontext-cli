package vomc_test

import (
	"math"
	"math/rand"
	"reflect"
	"testing"

	"github.com/kontext-security/kontext-cli/pkg/vomc"
)

func TestBuilderCountsAndOptions(t *testing.T) {
	builder, err := vomc.NewBuilder(vomc.Options{MaxDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		observe(t, builder, vomc.Sequence{1, 2})
		observe(t, builder, vomc.Sequence{3, 4})
	}
	model, err := builder.Fit()
	if err != nil {
		t.Fatal(err)
	}
	if got := model.Prob(vomc.Sequence{1}, 2); got != 1 {
		t.Fatalf("P(2 | [1]) = %f, want 1", got)
	}
}

func TestNewBuilderRejectsInvalidOptions(t *testing.T) {
	if _, err := vomc.NewBuilder(vomc.Options{MaxDepth: -1}); err == nil {
		t.Fatal("expected negative-depth error")
	}
}

func TestEncoderRoundTrip(t *testing.T) {
	encoder := vomc.NewEncoder[string]()
	seq := encoder.EncodeSequence([]string{"auth", "accounts", "auth"})
	if !reflect.DeepEqual(seq, vomc.Sequence{0, 1, 0}) {
		t.Fatalf("sequence = %#v, want [0 1 0]", seq)
	}

	value, ok := encoder.Decode(1)
	if !ok || value != "accounts" {
		t.Fatalf("decode = %q, %v; want accounts, true", value, ok)
	}
}

func TestModelContextSelectionAndPrediction(t *testing.T) {
	t.Run("retains distinct context", func(t *testing.T) {
		builder := newTestBuilder(t, vomc.Options{MaxDepth: 2})
		for i := 0; i < 100; i++ {
			observe(t, builder, vomc.Sequence{1, 2, 3})
			observe(t, builder, vomc.Sequence{4, 2, 5})
		}

		model := fit(t, builder)
		dist := model.Distribution(vomc.Sequence{1, 2})
		if got := dist.Context; !reflect.DeepEqual(got, vomc.Context{1, 2}) {
			t.Fatalf("context = %#v, want [1 2]", got)
		}
		if got := dist.Probability(3); got != 1 {
			t.Fatalf("P(3 | [1 2]) = %f, want 1", got)
		}
		if got := model.Prob(vomc.Sequence{4, 2}, 5); got != 1 {
			t.Fatalf("P(5 | [4 2]) = %f, want 1", got)
		}
	})

	t.Run("collapses redundant context", func(t *testing.T) {
		builder := newTestBuilder(t, vomc.Options{MaxDepth: 2})
		for i := 0; i < 100; i++ {
			observe(t, builder, vomc.Sequence{1, 2, 3})
			observe(t, builder, vomc.Sequence{4, 2, 3})
		}

		model := fit(t, builder)
		dist := model.Distribution(vomc.Sequence{1, 2})
		if got := dist.Context; !reflect.DeepEqual(got, vomc.Context{2}) {
			t.Fatalf("context = %#v, want collapsed [2]", got)
		}
	})

	t.Run("backs off and scores", func(t *testing.T) {
		builder := newTestBuilder(t, vomc.Options{MaxDepth: 2})
		for i := 0; i < 100; i++ {
			observe(t, builder, vomc.Sequence{1, 2, 3})
			observe(t, builder, vomc.Sequence{4, 2, 3})
			observe(t, builder, vomc.Sequence{2, 3})
		}

		model := fit(t, builder)
		prediction := model.Predict(vomc.Sequence{9, 2})
		if prediction.Symbol != 3 {
			t.Fatalf("predicted symbol = %d, want 3", prediction.Symbol)
		}
		if !prediction.BackedOff {
			t.Fatal("expected backoff for unseen [9 2]")
		}

		score := model.Score(vomc.Sequence{2, 3})
		if math.IsInf(score.LogLoss, 0) || score.TokensScored != 2 {
			t.Fatalf("score = %#v, want finite two-token score", score)
		}
	})
}

func TestSampleUsesCallerRand(t *testing.T) {
	builder := newTestBuilder(t, vomc.Options{MaxDepth: 1})
	observeBatch(t, builder, []vomc.Sequence{
		{1, 2},
		{1, 2},
		{1, 3},
	})

	model := fit(t, builder)
	sym, err := model.Sample(vomc.Sequence{1}, rand.New(rand.NewSource(1)))
	if err != nil {
		t.Fatal(err)
	}
	if sym != 2 && sym != 3 {
		t.Fatalf("sample = %d, want 2 or 3", sym)
	}
}

func TestLaplaceSmootherRespectsModelAlphabet(t *testing.T) {
	builder := newTestBuilder(t, vomc.Options{
		MaxDepth: 1,
		Alphabet: []vomc.Symbol{
			1,
			2,
			3,
		},
		Smoother: vomc.LaplaceSmoother{Alpha: 1},
	})
	observe(t, builder, vomc.Sequence{1, 2})
	model := fit(t, builder)

	if got := model.Prob(vomc.Sequence{1}, 99); got != 0 {
		t.Fatalf("P(99 | [1]) = %f, want 0 for out-of-alphabet symbol", got)
	}
	dist := model.Distribution(vomc.Sequence{1})
	if got := dist.Probability(3); got <= 0 {
		t.Fatalf("P(3 | [1]) = %f, want positive probability for configured symbol", got)
	}
	score := model.Score(vomc.Sequence{1, 99})
	if !math.IsInf(score.LogLoss, 1) || score.Unknowns != 1 {
		t.Fatalf("score = %#v, want one unknown and infinite log loss", score)
	}
}

func TestMinCountPrunesLowSupportContexts(t *testing.T) {
	builder := newTestBuilder(t, vomc.Options{MaxDepth: 2, MinCount: 2})
	observe(t, builder, vomc.Sequence{1, 2, 3})
	model := fit(t, builder)

	dist := model.Distribution(vomc.Sequence{1, 2})
	if len(dist.Context) != 0 {
		t.Fatalf("context = %#v, want root context because non-root rows are below min count", dist.Context)
	}
}

func TestScoreCountsAllUnknowns(t *testing.T) {
	builder := newTestBuilder(t, vomc.Options{MaxDepth: 1})
	observe(t, builder, vomc.Sequence{1, 2})
	model := fit(t, builder)

	score := model.Score(vomc.Sequence{1, 99, 2, 100})
	if !math.IsInf(score.LogLoss, 1) {
		t.Fatalf("log loss = %f, want +Inf", score.LogLoss)
	}
	if score.TokensScored != 4 {
		t.Fatalf("tokens scored = %d, want 4", score.TokensScored)
	}
	if score.Unknowns != 2 {
		t.Fatalf("unknowns = %d, want 2", score.Unknowns)
	}
}
