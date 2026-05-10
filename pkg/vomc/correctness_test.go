package vomc

import (
	"math"
	"testing"

	"github.com/kontext-security/kontext-cli/pkg/vomc/internal/contextseq"
)

func TestCountsABABC(t *testing.T) {
	A, B, C := Symbol(1), Symbol(2), Symbol(3)
	counts := mustCounts(t, 2)
	mustObserveSequence(t, counts, Sequence{A, B, A, B, C})

	assertNextCount(t, counts, nil, A, 2)
	assertNextCount(t, counts, nil, B, 2)
	assertNextCount(t, counts, nil, C, 1)

	assertNextCount(t, counts, Sequence{A}, B, 2)
	assertNextCount(t, counts, Sequence{B}, A, 1)
	assertNextCount(t, counts, Sequence{B}, C, 1)

	assertNextCount(t, counts, Sequence{A, B}, A, 1)
	assertNextCount(t, counts, Sequence{A, B}, C, 1)
	assertNextCount(t, counts, Sequence{B, A}, B, 1)
}

func TestCountsDoNotCrossSequenceBoundaries(t *testing.T) {
	A, B, C, D := Symbol(1), Symbol(2), Symbol(3), Symbol(4)
	counts := mustCounts(t, 2)
	mustObserveSequence(t, counts, Sequence{A, B})
	mustObserveSequence(t, counts, Sequence{C, D})

	assertNextCount(t, counts, Sequence{B}, C, 0)
	assertNextCount(t, counts, Sequence{A, B}, C, 0)
	assertNextCount(t, counts, Sequence{C}, D, 1)
}

func TestDistributionUsesRowProbabilities(t *testing.T) {
	A, B, C := Symbol(1), Symbol(2), Symbol(3)
	counts := mustCounts(t, 2)
	mustObserveSequence(t, counts, Sequence{A, B, A, B, C})

	model := modelWithContexts(2, []Symbol{A, B, C},
		contextInfoFromRow(counts.row(nil), nil),
		contextInfoFromRow(counts.row(Sequence{B}), nil),
	)

	dist := model.Distribution(Sequence{B})
	assertContext(t, dist.Context, Sequence{B})
	assertProbability(t, dist.Probability(A), 0.5)
	assertProbability(t, dist.Probability(C), 0.5)
	assertDistributionSum(t, dist)
}

func TestDistributionUsesLongestRetainedSuffix(t *testing.T) {
	A, B, C, X, Y := Symbol(1), Symbol(2), Symbol(3), Symbol(99), Symbol(100)

	model := modelWithContexts(3, []Symbol{A, B, C},
		testContext(nil, map[Symbol]uint64{C: 1}, nil),
		testContext(Sequence{B}, map[Symbol]uint64{C: 1}, nil),
		testContext(Sequence{A, B}, map[Symbol]uint64{C: 1}, Sequence{B}),
	)
	dist := model.Distribution(Sequence{X, A, B})
	assertContext(t, dist.Context, Sequence{A, B})
	if dist.Depth != 2 {
		t.Fatalf("depth = %d, want 2", dist.Depth)
	}

	model = modelWithContexts(3, []Symbol{A, B, C},
		testContext(nil, map[Symbol]uint64{C: 1}, nil),
		testContext(Sequence{B}, map[Symbol]uint64{C: 1}, nil),
	)
	dist = model.Distribution(Sequence{X, A, B})
	assertContext(t, dist.Context, Sequence{B})
	if dist.Depth != 1 {
		t.Fatalf("depth = %d, want 1", dist.Depth)
	}

	model = modelWithContexts(3, []Symbol{A, B, C},
		testContext(nil, map[Symbol]uint64{C: 1}, nil),
	)
	dist = model.Distribution(Sequence{X, Y, B})
	assertContext(t, dist.Context, nil)
	if dist.Depth != 0 {
		t.Fatalf("depth = %d, want 0", dist.Depth)
	}
}

func TestIntervalPruneCollapsesWhenAllIntervalsOverlap(t *testing.T) {
	A, B, C, X := Symbol(1), Symbol(2), Symbol(3), Symbol(4)
	parent := rowView{
		Context: Context{A},
		Total:   100,
		Next:    map[Symbol]uint64{B: 80, C: 20},
	}
	child := rowView{
		Context: Context{X, A},
		Total:   100,
		Next:    map[Symbol]uint64{B: 80, C: 20},
	}
	prune := intervalPrune{intervals: fakeIntervals{
		intervalKeyString(Sequence{A}, B):    {lo: 0.70, hi: 0.90},
		intervalKeyString(Sequence{A}, C):    {lo: 0.10, hi: 0.30},
		intervalKeyString(Sequence{X, A}, B): {lo: 0.75, hi: 0.85},
		intervalKeyString(Sequence{X, A}, C): {lo: 0.15, hi: 0.25},
	}}

	if !prune.collapsible(child, parent, []Symbol{B, C}) {
		t.Fatal("expected child context to collapse into parent")
	}
}

func TestIntervalPruneRetainsWhenAnyIntervalDoesNotOverlap(t *testing.T) {
	A, B, C, X := Symbol(1), Symbol(2), Symbol(3), Symbol(4)
	parent := rowView{
		Context: Context{A},
		Total:   100,
		Next:    map[Symbol]uint64{B: 50, C: 50},
	}
	child := rowView{
		Context: Context{X, A},
		Total:   100,
		Next:    map[Symbol]uint64{B: 95, C: 5},
	}
	prune := intervalPrune{intervals: fakeIntervals{
		intervalKeyString(Sequence{A}, B):    {lo: 0.40, hi: 0.60},
		intervalKeyString(Sequence{A}, C):    {lo: 0.40, hi: 0.60},
		intervalKeyString(Sequence{X, A}, B): {lo: 0.90, hi: 0.98},
		intervalKeyString(Sequence{X, A}, C): {lo: 0.02, hi: 0.10},
	}}

	if prune.collapsible(child, parent, []Symbol{B, C}) {
		t.Fatal("expected child context to be retained")
	}
}

func TestRetainedContextsHaveValidFallbacks(t *testing.T) {
	builder, err := NewBuilder(Options{MaxDepth: 3})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := builder.Observe(Sequence{1, 2, 3, 4}); err != nil {
			t.Fatal(err)
		}
		if err := builder.Observe(Sequence{5, 2, 3, 6}); err != nil {
			t.Fatal(err)
		}
	}
	model, err := builder.Fit()
	if err != nil {
		t.Fatal(err)
	}

	for _, info := range model.contextInfos() {
		if len(info.Context) == 0 {
			continue
		}
		if len(info.Fallback) >= len(info.Context) {
			t.Fatalf("fallback %v is not shorter than context %v", info.Fallback, info.Context)
		}
		if !isSuffix(Sequence(info.Context), Sequence(info.Fallback)) {
			t.Fatalf("fallback %v is not a suffix of context %v", info.Fallback, info.Context)
		}
		if _, ok := model.contexts[contextseq.Key(info.Fallback)]; !ok {
			t.Fatalf("fallback %v for context %v is not retained", info.Fallback, info.Context)
		}
	}
}

func TestPredictionAfterPruningUsesExpectedContextAndProbabilities(t *testing.T) {
	A, B, C, D, X := Symbol(1), Symbol(2), Symbol(3), Symbol(4), Symbol(99)
	builder, err := NewBuilder(Options{MaxDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := builder.Observe(Sequence{A, B, C}); err != nil {
			t.Fatal(err)
		}
		if err := builder.Observe(Sequence{X, B, D}); err != nil {
			t.Fatal(err)
		}
	}
	model, err := builder.Fit()
	if err != nil {
		t.Fatal(err)
	}

	dist := model.Distribution(Sequence{42, A, B})
	assertContext(t, dist.Context, Sequence{A, B})
	assertProbability(t, dist.Probability(C), 1)
	assertDistributionSum(t, dist)

	dist = model.Distribution(Sequence{42, B})
	assertContext(t, dist.Context, Sequence{B})
	assertProbability(t, dist.Probability(C), 0.5)
	assertProbability(t, dist.Probability(D), 0.5)
	assertDistributionSum(t, dist)
}

func TestOrderZeroModelUsesRootDistribution(t *testing.T) {
	builder, err := NewBuilder(Options{MaxDepth: 0})
	if err != nil {
		t.Fatal(err)
	}
	for _, seq := range []Sequence{{1}, {2}, {2}} {
		if err := builder.Observe(seq); err != nil {
			t.Fatal(err)
		}
	}
	model, err := builder.Fit()
	if err != nil {
		t.Fatal(err)
	}

	dist := model.Distribution(Sequence{99, 100})
	assertContext(t, dist.Context, nil)
	assertProbability(t, dist.Probability(1), 1.0/3.0)
	assertProbability(t, dist.Probability(2), 2.0/3.0)
	assertDistributionSum(t, dist)
}

type fakeIntervals map[string]interval

func (f fakeIntervals) interval(row rowView, next Symbol) interval {
	value, ok := f[intervalKeyString(Sequence(row.Context), next)]
	if !ok {
		return interval{lo: math.NaN(), hi: math.NaN()}
	}
	return value
}

func intervalKeyString(ctx Sequence, next Symbol) string {
	return contextseq.Key(ctx) + "|" + contextseq.Key(Sequence{next})
}

func mustCounts(t *testing.T, maxDepth int) *counts {
	t.Helper()
	counts, err := newCounts(maxDepth)
	if err != nil {
		t.Fatal(err)
	}
	return counts
}

func mustObserveSequence(t *testing.T, counts *counts, seq Sequence) {
	t.Helper()
	if err := counts.observeSequence(seq); err != nil {
		t.Fatal(err)
	}
}

func assertNextCount(t *testing.T, counts *counts, ctx Sequence, next Symbol, want uint64) {
	t.Helper()
	if got := counts.row(ctx).Count(next); got != want {
		t.Fatalf("count(%v -> %d) = %d, want %d", ctx, next, got, want)
	}
}

func modelWithContexts(maxDepth int, alphabet []Symbol, infos ...contextInfo) *Model {
	contexts := make(map[string]contextInfo, len(infos))
	for _, info := range infos {
		contexts[contextseq.Key(info.Context)] = info
	}
	return &Model{
		maxDepth: maxDepth,
		alphabet: contextseq.Unique(alphabet),
		smoother: mleSmoother{},
		contexts: contexts,
	}
}

func testContext(ctx Sequence, next map[Symbol]uint64, fallback Sequence) contextInfo {
	total := uint64(0)
	copied := make(map[Symbol]uint64, len(next))
	for sym, count := range next {
		total += count
		copied[sym] = count
	}
	return contextInfo{
		Context:  Context(contextseq.Copy(ctx)),
		Total:    total,
		Next:     copied,
		Fallback: Context(contextseq.Copy(fallback)),
	}
}

func assertContext(t *testing.T, got Context, want Sequence) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("context = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("context = %v, want %v", got, want)
		}
	}
}

func assertProbability(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-12 {
		t.Fatalf("probability = %.16f, want %.16f", got, want)
	}
}

func assertDistributionSum(t *testing.T, dist Distribution) {
	t.Helper()
	sum := 0.0
	for sym, probability := range dist.Probs {
		if math.IsNaN(probability) || math.IsInf(probability, 0) || probability < 0 {
			t.Fatalf("invalid probability for %d: %f", sym, probability)
		}
		sum += probability
	}
	assertProbability(t, sum, 1)
}

func isSuffix(seq, suffix Sequence) bool {
	if len(suffix) > len(seq) {
		return false
	}
	offset := len(seq) - len(suffix)
	for i := range suffix {
		if seq[offset+i] != suffix[i] {
			return false
		}
	}
	return true
}
