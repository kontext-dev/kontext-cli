package vomcbench

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ReportOptions struct {
	Dir        string
	Kind       string
	Seed       int64
	Alphabet   int
	Sessions   int
	MinLen     int
	MaxLen     int
	MaxDepth   int
	MinCount   uint64
	Confidence float64
	TrainRatio float64
	ReportOut  string
	ResultOut  string
	ModelOut   string
	CorpusOut  string
	Top        int
}

func runReport(args []string, stdout io.Writer) error {
	fs := newFlagSet("report")
	opts := ReportOptions{}
	fs.StringVar(&opts.Dir, "dir", "bench-results", "output directory")
	fs.StringVar(&opts.Kind, "kind", "variable-order", "corpus kind")
	fs.Int64Var(&opts.Seed, "seed", 42, "generation and split seed")
	fs.IntVar(&opts.Alphabet, "alphabet", 64, "alphabet size")
	fs.IntVar(&opts.Sessions, "sessions", 10000, "number of sessions")
	fs.IntVar(&opts.MinLen, "min-len", 5, "minimum session length")
	fs.IntVar(&opts.MaxLen, "max-len", 50, "maximum session length")
	fs.IntVar(&opts.MaxDepth, "max-depth", 4, "maximum VOMC context depth")
	fs.Uint64Var(&opts.MinCount, "min-count", 2, "minimum retained context count")
	fs.Float64Var(&opts.Confidence, "confidence", 0.95, "pruning confidence; currently only 0.95 is supported")
	fs.Float64Var(&opts.TrainRatio, "train-ratio", 0.8, "fraction of sessions used for training")
	fs.StringVar(&opts.ReportOut, "out", "", "report markdown path")
	fs.StringVar(&opts.ResultOut, "result-out", "", "result JSON path")
	fs.StringVar(&opts.ModelOut, "model-out", "", "model JSON path")
	fs.StringVar(&opts.CorpusOut, "corpus-out", "", "corpus JSONL path")
	fs.IntVar(&opts.Top, "top", 10, "top precedence sequences to include")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths := opts.withDefaults()
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		return err
	}
	if err := Generate(GenerateOptions{
		Kind:     paths.Kind,
		Seed:     paths.Seed,
		Alphabet: paths.Alphabet,
		Sessions: paths.Sessions,
		MinLen:   paths.MinLen,
		MaxLen:   paths.MaxLen,
		Out:      paths.CorpusOut,
	}); err != nil {
		return fmt.Errorf("generate corpus: %w", err)
	}
	result, modelJSON, err := runBenchmarkWithModel(RunOptions{
		Corpus:     paths.CorpusOut,
		MaxDepth:   paths.MaxDepth,
		MinCount:   paths.MinCount,
		Confidence: paths.Confidence,
		TrainRatio: paths.TrainRatio,
		Seed:       paths.Seed,
	})
	if err != nil {
		return fmt.Errorf("run benchmark: %w", err)
	}
	resultJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(paths.ResultOut, append(resultJSON, '\n')); err != nil {
		return err
	}
	if err := writeFile(paths.ModelOut, append(modelJSON, '\n')); err != nil {
		return err
	}
	report := renderReport(result, paths, validateResult(result))
	if err := writeFile(paths.ReportOut, []byte(report)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s\n", paths.ReportOut)
	return nil
}

func (opts ReportOptions) withDefaults() ReportOptions {
	if opts.Dir == "" {
		opts.Dir = "bench-results"
	}
	if opts.Kind == "" {
		opts.Kind = "variable-order"
	}
	if opts.ReportOut == "" {
		opts.ReportOut = filepath.Join(opts.Dir, fmt.Sprintf("%s_depth%d_report.md", opts.Kind, opts.MaxDepth))
	}
	if opts.ResultOut == "" {
		opts.ResultOut = filepath.Join(opts.Dir, fmt.Sprintf("%s_depth%d.json", opts.Kind, opts.MaxDepth))
	}
	if opts.ModelOut == "" {
		opts.ModelOut = filepath.Join(opts.Dir, fmt.Sprintf("%s_depth%d_model.json", opts.Kind, opts.MaxDepth))
	}
	if opts.CorpusOut == "" {
		opts.CorpusOut = filepath.Join(opts.Dir, fmt.Sprintf("%s.jsonl", opts.Kind))
	}
	if opts.Top <= 0 {
		opts.Top = 10
	}
	return opts
}

func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o644)
}

func renderReport(result BenchResult, opts ReportOptions, validationErrors []string) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# VOMC Evaluation Report")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## What This Evaluates")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "This evaluates the standalone `pkg/vomc` sequence model. It does not evaluate authorization policy, hook blocking behavior, credential handling, hosted runtime behavior, or product security decisions.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "The useful questions are:")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "- Does the model retain a compact set of variable-length contexts instead of degenerating into a fixed high-order model?")
	fmt.Fprintln(&b, "- What held-out next-symbol prediction quality does the retained context tree produce?")
	fmt.Fprintln(&b, "- Does it surface high-precedence sequences worth inspecting?")
	fmt.Fprintln(&b, "- Is training, fitting, scoring, and serialized model size acceptable for the corpus size?")
	fmt.Fprintln(&b, "- Do structural invariants hold, especially suffix-closure and valid probability metrics?")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Corpus And Options")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Corpus: `%s` (`%s`)\n", result.Corpus.Name, result.Corpus.Kind)
	fmt.Fprintf(&b, "- Sessions: %d total, %d train, %d test\n", result.Corpus.Sessions, result.Corpus.TrainSessions, result.Corpus.TestSessions)
	fmt.Fprintf(&b, "- Symbols: %d total, %d train, %d test\n", result.Corpus.Symbols, result.Corpus.TrainSymbols, result.Corpus.TestSymbols)
	fmt.Fprintf(&b, "- Alphabet size: %d\n", result.Corpus.AlphabetSize)
	fmt.Fprintf(&b, "- Max depth: %d\n", result.Config.MaxDepth)
	fmt.Fprintf(&b, "- Min count: %d\n", result.Config.MinCount)
	fmt.Fprintf(&b, "- Pruning: `%s` at %.2f confidence\n", result.Config.PruneStrategy, result.Config.Confidence)
	fmt.Fprintf(&b, "- Smoother: `%s`\n", result.Config.Smoother)
	fmt.Fprintf(&b, "- Seed: %d\n", result.Config.Seed)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Structure")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Candidate contexts: %d\n", result.Structure.CandidateContexts)
	fmt.Fprintf(&b, "- Retained contexts: %d\n", result.Structure.RetainedContexts)
	fmt.Fprintf(&b, "- Collapsed contexts: %d\n", result.Structure.CollapsedContexts)
	fmt.Fprintf(&b, "- Retention ratio: %.4f\n", result.Structure.RetentionRatio)
	fmt.Fprintf(&b, "- Max retained depth: %d\n", result.Structure.MaxRetainedDepth)
	fmt.Fprintf(&b, "- Contexts by depth: %v\n", result.Structure.ContextsByDepth)
	fmt.Fprintf(&b, "- Collapsed by depth: %v\n", result.Structure.CollapsedByDepth)
	fmt.Fprintf(&b, "- Suffix-closure violations: %d\n", result.Structure.SuffixClosureViolations)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Prediction")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Tokens scored: %d\n", result.Prediction.TokensScored)
	fmt.Fprintf(&b, "- Average log loss: %.6f\n", result.Prediction.AvgLogLoss)
	fmt.Fprintf(&b, "- Perplexity: %.6f\n", result.Prediction.Perplexity)
	fmt.Fprintf(&b, "- Top-1 accuracy: %.4f\n", result.Prediction.Top1Accuracy)
	fmt.Fprintf(&b, "- Top-3 accuracy: %.4f\n", result.Prediction.Top3Accuracy)
	fmt.Fprintf(&b, "- Backoff rate: %.4f\n", result.Prediction.BackoffRate)
	fmt.Fprintf(&b, "- Empty-context rate: %.4f\n", result.Prediction.EmptyContextRate)
	fmt.Fprintf(&b, "- Unknown-symbol rate: %.4f\n", result.Prediction.UnknownSymbolRate)
	fmt.Fprintf(&b, "- Matched depth histogram: %v\n", result.Prediction.MatchedDepthHistogram)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Sequence Discovery")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Important sequences: %d\n", result.Discovery.ImportantSequences)
	fmt.Fprintf(&b, "- Credible separation count: %d\n", result.Discovery.CredibleSeparationCount)
	fmt.Fprintf(&b, "- Redundant context count: %d\n", result.Discovery.RedundantContextCount)
	fmt.Fprintf(&b, "- Mean precedence top 10: %.6f\n", result.Discovery.MeanPrecedenceTop10)
	fmt.Fprintf(&b, "- Mean precedence top 100: %.6f\n", result.Discovery.MeanPrecedenceTop100)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Sequence | Count | Last Symbol Count | Precedence | Support Weighted |")
	fmt.Fprintln(&b, "| --- | ---: | ---: | ---: | ---: |")
	limit := opts.Top
	if limit > len(result.Discovery.TopPrecedence) {
		limit = len(result.Discovery.TopPrecedence)
	}
	for i := 0; i < limit; i++ {
		entry := result.Discovery.TopPrecedence[i]
		fmt.Fprintf(&b, "| `%v` | %d | %d | %.6f | %.6f |\n",
			entry.Sequence,
			entry.Count,
			entry.LastSymbolCount,
			entry.Precedence,
			entry.SupportWeightedPrecedence,
		)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Performance")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Observe symbols/sec: %.2f\n", result.Performance.ObserveSymbolsPerSec)
	fmt.Fprintf(&b, "- Fit ms: %.3f\n", result.Performance.FitMS)
	fmt.Fprintf(&b, "- Score symbols/sec: %.2f\n", result.Performance.ScoreSymbolsPerSec)
	fmt.Fprintf(&b, "- Model JSON bytes: %d\n", result.Performance.ModelJSONBytes)
	fmt.Fprintf(&b, "- Peak heap bytes: %d\n", result.Performance.PeakHeapBytes)
	fmt.Fprintf(&b, "- Bytes per candidate context: %.2f\n", result.Performance.BytesPerCandidateContext)
	fmt.Fprintf(&b, "- Bytes per retained context: %.2f\n", result.Performance.BytesPerRetainedContext)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Validation")
	fmt.Fprintln(&b)
	if len(validationErrors) == 0 {
		fmt.Fprintln(&b, "- OK")
	} else {
		for _, msg := range validationErrors {
			fmt.Fprintf(&b, "- FAIL: %s\n", msg)
		}
	}
	return b.String()
}
