package vomcbench

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/pkg/vomc"
)

type RunOptions struct {
	Corpus     string
	MaxDepth   int
	MinCount   uint64
	Confidence float64
	TrainRatio float64
	Seed       int64
	Out        string
	ModelOut   string
}

func runBenchmark(args []string, stdout io.Writer) error {
	fs := newFlagSet("run")
	opts := RunOptions{}
	fs.StringVar(&opts.Corpus, "corpus", "", "input corpus JSONL path")
	fs.IntVar(&opts.MaxDepth, "max-depth", 4, "maximum context depth")
	fs.Uint64Var(&opts.MinCount, "min-count", 2, "minimum retained context count")
	fs.Float64Var(&opts.Confidence, "confidence", 0.95, "pruning confidence; currently only 0.95 is supported")
	fs.Float64Var(&opts.TrainRatio, "train-ratio", 0.8, "fraction of sessions used for training")
	fs.Int64Var(&opts.Seed, "seed", 42, "split seed")
	fs.StringVar(&opts.Out, "out", "", "output result JSON path")
	fs.StringVar(&opts.ModelOut, "model-out", "", "optional output model JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	result, modelJSON, err := runBenchmarkWithModel(opts)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if opts.Out == "" {
		if _, err := stdout.Write(append(data, '\n')); err != nil {
			return err
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(opts.Out), 0o755); err != nil && filepath.Dir(opts.Out) != "." {
			return err
		}
		if err := os.WriteFile(opts.Out, append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	if opts.ModelOut != "" {
		if err := os.MkdirAll(filepath.Dir(opts.ModelOut), 0o755); err != nil && filepath.Dir(opts.ModelOut) != "." {
			return err
		}
		if err := os.WriteFile(opts.ModelOut, append(modelJSON, '\n'), 0o644); err != nil {
			return err
		}
	}
	if opts.Out != "" {
		fmt.Fprintf(stdout, "wrote %s\n", opts.Out)
	}
	return nil
}

func RunBenchmark(opts RunOptions) (BenchResult, error) {
	result, _, err := runBenchmarkWithModel(opts)
	return result, err
}

func runBenchmarkWithModel(opts RunOptions) (BenchResult, []byte, error) {
	if opts.Corpus == "" {
		return BenchResult{}, nil, fmt.Errorf("run requires -corpus")
	}
	if opts.MaxDepth < 0 {
		return BenchResult{}, nil, fmt.Errorf("max depth must be non-negative")
	}
	if opts.TrainRatio <= 0 || opts.TrainRatio >= 1 {
		return BenchResult{}, nil, fmt.Errorf("train ratio must be > 0 and < 1")
	}
	if opts.Confidence != 0 && math.Abs(opts.Confidence-0.95) > 1e-12 {
		return BenchResult{}, nil, fmt.Errorf("custom confidence is not wired into pkg/vomc yet; use 0.95")
	}
	if opts.Confidence == 0 {
		opts.Confidence = 0.95
	}

	meta, sessions, err := ReadCorpus(opts.Corpus)
	if err != nil {
		return BenchResult{}, nil, err
	}
	if len(sessions) < 2 {
		return BenchResult{}, nil, fmt.Errorf("corpus must contain at least two sessions")
	}
	train, test := splitSessions(sessions, opts.TrainRatio, opts.Seed)
	if len(train) == 0 || len(test) == 0 {
		return BenchResult{}, nil, fmt.Errorf("split produced empty train or test set")
	}

	candidates := collectCounts(train, opts.MaxDepth)
	builder, err := vomc.NewBuilder(vomc.Options{
		MaxDepth: opts.MaxDepth,
		MinCount: opts.MinCount,
	})
	if err != nil {
		return BenchResult{}, nil, err
	}
	trainSequences := toSequences(train)
	trainSymbols := countSymbols(train)
	testSymbols := countSymbols(test)

	observeStart := time.Now()
	if err := builder.ObserveBatch(trainSequences); err != nil {
		return BenchResult{}, nil, err
	}
	observeElapsed := time.Since(observeStart)

	fitStart := time.Now()
	model, err := builder.Fit()
	if err != nil {
		return BenchResult{}, nil, err
	}
	fitElapsed := time.Since(fitStart)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	modelJSON, err := json.Marshal(model)
	if err != nil {
		return BenchResult{}, nil, err
	}
	var wire modelWire
	if err := json.Unmarshal(modelJSON, &wire); err != nil {
		return BenchResult{}, nil, err
	}

	scoreStart := time.Now()
	prediction := evaluatePrediction(model, test, opts.MaxDepth)
	scoreElapsed := time.Since(scoreStart)

	structure := structureMetrics(candidates, wire)
	discovery := discoveryMetrics(candidates, structure)
	performance := PerformanceMetrics{
		ObserveSymbolsPerSec:     ratePerSecond(trainSymbols, observeElapsed),
		FitMS:                    float64(fitElapsed.Microseconds()) / 1000,
		ScoreSymbolsPerSec:       ratePerSecond(testSymbols, scoreElapsed),
		ModelJSONBytes:           len(modelJSON),
		PeakHeapBytes:            after.HeapAlloc,
		BytesPerCandidateContext: ratioFloat(float64(len(modelJSON)), float64(structure.CandidateContexts)),
		BytesPerRetainedContext:  ratioFloat(float64(len(modelJSON)), float64(structure.RetainedContexts)),
	}

	result := BenchResult{
		Config: ConfigMetrics{
			MaxDepth:      opts.MaxDepth,
			MinCount:      opts.MinCount,
			Confidence:    opts.Confidence,
			PruneStrategy: "credible_interval_overlap",
			Smoother:      "mle",
			Seed:          opts.Seed,
		},
		Corpus: CorpusMetrics{
			Name:          strings.TrimSuffix(filepath.Base(opts.Corpus), filepath.Ext(opts.Corpus)),
			Kind:          meta.Kind,
			Sessions:      len(sessions),
			Symbols:       countSymbols(sessions),
			AlphabetSize:  meta.AlphabetSize,
			TrainSymbols:  trainSymbols,
			TestSymbols:   testSymbols,
			TrainSessions: len(train),
			TestSessions:  len(test),
		},
		Structure:   structure,
		Prediction:  prediction,
		Discovery:   discovery,
		Performance: performance,
	}
	return result, modelJSON, nil
}

func splitSessions(sessions []CorpusSession, ratio float64, seed int64) ([]CorpusSession, []CorpusSession) {
	indices := make([]int, len(sessions))
	for i := range indices {
		indices[i] = i
	}
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(indices), func(i, j int) {
		indices[i], indices[j] = indices[j], indices[i]
	})
	trainN := int(math.Round(float64(len(indices)) * ratio))
	if trainN <= 0 {
		trainN = 1
	}
	if trainN >= len(indices) {
		trainN = len(indices) - 1
	}
	train := make([]CorpusSession, 0, trainN)
	test := make([]CorpusSession, 0, len(indices)-trainN)
	for i, idx := range indices {
		if i < trainN {
			train = append(train, sessions[idx])
		} else {
			test = append(test, sessions[idx])
		}
	}
	return train, test
}

func toSequences(sessions []CorpusSession) []vomc.Sequence {
	sequences := make([]vomc.Sequence, 0, len(sessions))
	for _, session := range sessions {
		seq := make(vomc.Sequence, 0, len(session.Symbols))
		for _, sym := range session.Symbols {
			seq = append(seq, vomc.Symbol(sym))
		}
		sequences = append(sequences, seq)
	}
	return sequences
}

func countSymbols(sessions []CorpusSession) int {
	total := 0
	for _, session := range sessions {
		total += len(session.Symbols)
	}
	return total
}

type countIndex struct {
	contexts map[string][]uint32
	rows     map[string]map[uint32]uint64
	ngrams   map[string]ngramCount
	unigrams map[uint32]uint64
}

type ngramCount struct {
	seq   []uint32
	count uint64
}

func collectCounts(sessions []CorpusSession, maxDepth int) countIndex {
	idx := countIndex{
		contexts: map[string][]uint32{"": nil},
		rows:     map[string]map[uint32]uint64{"": {}},
		ngrams:   map[string]ngramCount{},
		unigrams: map[uint32]uint64{},
	}
	for _, session := range sessions {
		symbols := session.Symbols
		for i, next := range symbols {
			idx.unigrams[next]++
			start := i - maxDepth
			if start < 0 {
				start = 0
			}
			history := symbols[start:i]
			limit := len(history)
			if limit > maxDepth {
				limit = maxDepth
			}
			for order := 0; order <= limit; order++ {
				ctx := suffix(history, order)
				key := contextKey(ctx)
				if _, ok := idx.contexts[key]; !ok {
					idx.contexts[key] = append([]uint32(nil), ctx...)
				}
				row := idx.rows[key]
				if row == nil {
					row = map[uint32]uint64{}
					idx.rows[key] = row
				}
				row[next]++
				ngram := append(append([]uint32(nil), ctx...), next)
				ngramKey := contextKey(ngram)
				entry := idx.ngrams[ngramKey]
				if entry.seq == nil {
					entry.seq = ngram
				}
				entry.count++
				idx.ngrams[ngramKey] = entry
			}
		}
	}
	return idx
}

func structureMetrics(candidates countIndex, wire modelWire) StructureMetrics {
	candidateByDepth := map[int]int{}
	for _, ctx := range candidates.contexts {
		candidateByDepth[len(ctx)]++
	}
	retainedByDepth := map[int]int{}
	retained := map[string]contextWire{}
	maxDepth := 0
	for _, ctx := range wire.Contexts {
		depth := len(ctx.Context)
		retainedByDepth[depth]++
		if depth > maxDepth {
			maxDepth = depth
		}
		retained[contextKey(ctx.Context)] = ctx
	}
	collapsedByDepth := map[string]int{}
	for depth, count := range candidateByDepth {
		collapsed := count - retainedByDepth[depth]
		if collapsed > 0 {
			collapsedByDepth[itoa(depth)] = collapsed
		}
	}
	retainedContexts := len(wire.Contexts)
	candidateContexts := len(candidates.contexts)
	collapsedContexts := candidateContexts - retainedContexts
	if collapsedContexts < 0 {
		collapsedContexts = 0
	}
	return StructureMetrics{
		CandidateContexts:       candidateContexts,
		RetainedContexts:        retainedContexts,
		CollapsedContexts:       collapsedContexts,
		RetentionRatio:          ratioFloat(float64(retainedContexts), float64(candidateContexts)),
		MaxRetainedDepth:        maxDepth,
		ContextsByDepth:         stringifyDepthMap(retainedByDepth),
		CollapsedByDepth:        collapsedByDepth,
		SuffixClosureViolations: suffixClosureViolations(retained),
	}
}

func suffixClosureViolations(retained map[string]contextWire) int {
	violations := 0
	for _, ctx := range retained {
		if len(ctx.Context) == 0 {
			continue
		}
		if len(ctx.Fallback) >= len(ctx.Context) || !isSuffix(ctx.Context, ctx.Fallback) {
			violations++
			continue
		}
		if _, ok := retained[contextKey(ctx.Fallback)]; !ok {
			violations++
		}
	}
	return violations
}

func evaluatePrediction(model *vomc.Model, sessions []CorpusSession, maxDepth int) PredictionMetrics {
	const floor = 1e-12
	histogram := map[string]int{}
	tokens := 0
	unknowns := 0
	top1 := 0
	top3 := 0
	backoff := 0
	empty := 0
	nll := 0.0
	for _, session := range sessions {
		seq := session.Symbols
		for i, actualRaw := range seq {
			start := i - maxDepth
			if start < 0 {
				start = 0
			}
			context := make(vomc.Sequence, 0, i-start)
			for _, sym := range seq[start:i] {
				context = append(context, vomc.Symbol(sym))
			}
			actual := vomc.Symbol(actualRaw)
			dist := model.Distribution(context)
			tokens++
			histogram[itoa(dist.Depth)]++
			if dist.Depth == 0 {
				empty++
			}
			if dist.Depth < min(len(context), maxDepth) {
				backoff++
			}
			prob := dist.Probability(actual)
			if prob <= 0 {
				unknowns++
				prob = floor
			}
			nll += -math.Log(prob)
			ranked := rankedDistribution(dist.Probs)
			if len(ranked) > 0 && ranked[0] == actual {
				top1++
			}
			for j := 0; j < len(ranked) && j < 3; j++ {
				if ranked[j] == actual {
					top3++
					break
				}
			}
		}
	}
	avg := ratioFloat(nll, float64(tokens))
	return PredictionMetrics{
		TokensScored:          tokens,
		NegativeLogLikelihood: nll,
		AvgLogLoss:            avg,
		Perplexity:            math.Exp(avg),
		Top1Accuracy:          ratioFloat(float64(top1), float64(tokens)),
		Top3Accuracy:          ratioFloat(float64(top3), float64(tokens)),
		BackoffRate:           ratioFloat(float64(backoff), float64(tokens)),
		EmptyContextRate:      ratioFloat(float64(empty), float64(tokens)),
		UnknownSymbolRate:     ratioFloat(float64(unknowns), float64(tokens)),
		MatchedDepthHistogram: histogram,
	}
}

func discoveryMetrics(counts countIndex, structure StructureMetrics) DiscoveryMetrics {
	entries := precedenceEntries(counts)
	top := entries
	if len(top) > 20 {
		top = top[:20]
	}
	return DiscoveryMetrics{
		ImportantSequences:        structure.RetainedContexts,
		CredibleSeparationCount:   max(0, structure.RetainedContexts-1),
		RedundantContextCount:     structure.CollapsedContexts,
		TopPrecedence:             top,
		MeanPrecedenceTop10:       meanPrecedence(entries, 10),
		MeanPrecedenceTop100:      meanPrecedence(entries, 100),
		MeanSupportWeightedTop100: meanWeightedPrecedence(entries, 100),
	}
}

func precedenceEntries(counts countIndex) []PrecedenceEntry {
	entries := make([]PrecedenceEntry, 0, len(counts.ngrams))
	for _, entry := range counts.ngrams {
		if len(entry.seq) < 2 {
			continue
		}
		last := entry.seq[len(entry.seq)-1]
		lastCount := counts.unigrams[last]
		if lastCount == 0 {
			continue
		}
		precedence := float64(entry.count) / float64(lastCount)
		entries = append(entries, PrecedenceEntry{
			Sequence:                  append([]uint32(nil), entry.seq...),
			Count:                     entry.count,
			LastSymbolCount:           lastCount,
			Precedence:                precedence,
			SupportWeightedPrecedence: precedence * math.Log1p(float64(entry.count)),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Precedence != b.Precedence {
			return a.Precedence > b.Precedence
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if len(a.Sequence) != len(b.Sequence) {
			return len(a.Sequence) > len(b.Sequence)
		}
		return lexLess(a.Sequence, b.Sequence)
	})
	return entries
}

func rankedDistribution(probs map[vomc.Symbol]float64) []vomc.Symbol {
	symbols := make([]vomc.Symbol, 0, len(probs))
	for sym := range probs {
		symbols = append(symbols, sym)
	}
	sort.Slice(symbols, func(i, j int) bool {
		pi, pj := probs[symbols[i]], probs[symbols[j]]
		if pi != pj {
			return pi > pj
		}
		return symbols[i] < symbols[j]
	})
	return symbols
}

func meanPrecedence(entries []PrecedenceEntry, n int) float64 {
	if len(entries) == 0 {
		return 0
	}
	if n > len(entries) {
		n = len(entries)
	}
	sum := 0.0
	for i := 0; i < n; i++ {
		sum += entries[i].Precedence
	}
	return sum / float64(n)
}

func meanWeightedPrecedence(entries []PrecedenceEntry, n int) float64 {
	if len(entries) == 0 {
		return 0
	}
	if n > len(entries) {
		n = len(entries)
	}
	sum := 0.0
	for i := 0; i < n; i++ {
		sum += entries[i].SupportWeightedPrecedence
	}
	return sum / float64(n)
}

func ratePerSecond(count int, elapsed time.Duration) float64 {
	seconds := elapsedSeconds(elapsed)
	if seconds == 0 {
		return 0
	}
	return float64(count) / seconds
}

func stringifyDepthMap(input map[int]int) map[string]int {
	out := make(map[string]int, len(input))
	for depth, count := range input {
		out[itoa(depth)] = count
	}
	return out
}

func ratioFloat(num, denom float64) float64 {
	if denom == 0 {
		return 0
	}
	return num / denom
}

func suffix(seq []uint32, n int) []uint32 {
	if n <= 0 {
		return nil
	}
	if n >= len(seq) {
		return seq
	}
	return seq[len(seq)-n:]
}

func contextKey(seq []uint32) string {
	if len(seq) == 0 {
		return ""
	}
	var b strings.Builder
	for i, sym := range seq {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", sym)
	}
	return b.String()
}

func isSuffix(seq, suffix []uint32) bool {
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

func lexLess(a, b []uint32) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func itoa(v int) string {
	return fmt.Sprintf("%d", v)
}
