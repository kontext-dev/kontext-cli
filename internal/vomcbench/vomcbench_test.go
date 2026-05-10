package vomcbench

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.jsonl")
	b := filepath.Join(dir, "b.jsonl")
	opts := GenerateOptions{
		Kind:     "variable-order",
		Seed:     42,
		Alphabet: 16,
		Sessions: 8,
		MinLen:   5,
		MaxLen:   12,
	}
	opts.Out = a
	if err := Generate(opts); err != nil {
		t.Fatal(err)
	}
	opts.Out = b
	if err := Generate(opts); err != nil {
		t.Fatal(err)
	}
	adata, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	bdata, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(adata, bdata) {
		t.Fatalf("generated corpus is not deterministic\n%s\n%s", adata, bdata)
	}
}

func TestGenerateRejectsUnsupportedKindWithoutOverwriting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corpus.jsonl")
	if err := os.WriteFile(path, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Generate(GenerateOptions{
		Kind:     "typo",
		Seed:     42,
		Alphabet: 8,
		Sessions: 2,
		MinLen:   4,
		MaxLen:   6,
		Out:      path,
	})
	if err == nil {
		t.Fatal("expected unsupported corpus kind error")
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "keep" {
		t.Fatalf("file was overwritten: %q", data)
	}
}

func TestRunBenchmarkProducesCoreMetrics(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "corpus.jsonl")
	if err := Generate(GenerateOptions{
		Kind:     "variable-order",
		Seed:     7,
		Alphabet: 16,
		Sessions: 40,
		MinLen:   8,
		MaxLen:   16,
		Out:      corpus,
	}); err != nil {
		t.Fatal(err)
	}

	result, err := RunBenchmark(RunOptions{
		Corpus:     corpus,
		MaxDepth:   3,
		MinCount:   2,
		Confidence: 0.95,
		TrainRatio: 0.75,
		Seed:       11,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Structure.CandidateContexts == 0 {
		t.Fatal("candidate contexts should be positive")
	}
	if result.Structure.RetainedContexts == 0 {
		t.Fatal("retained contexts should be positive")
	}
	if result.Structure.CandidateContexts < result.Structure.RetainedContexts {
		t.Fatalf("candidate contexts %d < retained contexts %d", result.Structure.CandidateContexts, result.Structure.RetainedContexts)
	}
	if result.Structure.SuffixClosureViolations != 0 {
		t.Fatalf("suffix closure violations = %d, want 0", result.Structure.SuffixClosureViolations)
	}
	if result.Prediction.TokensScored != result.Corpus.TestSymbols {
		t.Fatalf("tokens scored = %d, want %d", result.Prediction.TokensScored, result.Corpus.TestSymbols)
	}
	if result.Prediction.AvgLogLoss <= 0 {
		t.Fatalf("avg log loss = %f, want positive", result.Prediction.AvgLogLoss)
	}
	if result.Performance.ModelJSONBytes == 0 {
		t.Fatal("model JSON bytes should be positive")
	}
	if len(result.Discovery.TopPrecedence) == 0 {
		t.Fatal("expected top precedence entries")
	}
}

func TestRunSubcommandWritesModelWhenResultGoesToStdout(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "corpus.jsonl")
	modelPath := filepath.Join(dir, "model.json")
	if err := Generate(GenerateOptions{
		Kind:     "order1",
		Seed:     9,
		Alphabet: 8,
		Sessions: 20,
		MinLen:   4,
		MaxLen:   8,
		Out:      corpus,
	}); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	err := Run([]string{
		"run",
		"-corpus", corpus,
		"-max-depth", "2",
		"-min-count", "1",
		"-train-ratio", "0.7",
		"-seed", "3",
		"-model-out", modelPath,
	}, &stdout, ioDiscard{})
	if err != nil {
		t.Fatal(err)
	}
	var result BenchResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout should contain only result JSON: %v\n%s", err, stdout.String())
	}
	if _, err := os.Stat(modelPath); err != nil {
		t.Fatalf("missing model artifact: %v", err)
	}
}

func TestCompareFailsOnContextGrowthWithoutQualityGain(t *testing.T) {
	base := BenchResult{
		Structure: StructureMetrics{RetainedContexts: 100, RetentionRatio: 0.10},
		Prediction: PredictionMetrics{
			AvgLogLoss:   2.0,
			Perplexity:   7.4,
			Top1Accuracy: 0.5,
		},
		Discovery:   DiscoveryMetrics{MeanPrecedenceTop100: 0.8},
		Performance: PerformanceMetrics{FitMS: 10, ModelJSONBytes: 1000},
	}
	head := base
	head.Structure.RetainedContexts = 140
	head.Structure.RetentionRatio = 0.14
	head.Prediction.AvgLogLoss = 1.99

	dir := t.TempDir()
	basePath := writeResult(t, dir, "base.json", base)
	headPath := writeResult(t, dir, "head.json", head)
	var out bytes.Buffer
	failed, err := Compare(CompareOptions{Base: basePath, Head: headPath}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !failed {
		t.Fatal("expected comparison failure")
	}
	if !strings.Contains(out.String(), "retained contexts increased materially") {
		t.Fatalf("missing rule failure output:\n%s", out.String())
	}
}

func TestRunSubcommandWritesResult(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "corpus.jsonl")
	resultPath := filepath.Join(dir, "result.json")
	modelPath := filepath.Join(dir, "model.json")
	if err := Generate(GenerateOptions{
		Kind:     "order1",
		Seed:     9,
		Alphabet: 8,
		Sessions: 20,
		MinLen:   4,
		MaxLen:   8,
		Out:      corpus,
	}); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	err := Run([]string{
		"run",
		"-corpus", corpus,
		"-max-depth", "2",
		"-min-count", "1",
		"-train-ratio", "0.7",
		"-seed", "3",
		"-out", resultPath,
		"-model-out", modelPath,
	}, &stdout, ioDiscard{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "wrote") {
		t.Fatalf("stdout = %q, want wrote message", stdout.String())
	}
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	var result BenchResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Config.MaxDepth != 2 {
		t.Fatalf("max depth = %d, want 2", result.Config.MaxDepth)
	}
	var validateOut bytes.Buffer
	if err := Validate(ValidateOptions{Result: resultPath}, &validateOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(validateOut.String(), "OK") {
		t.Fatalf("validate output = %q, want OK", validateOut.String())
	}
	var inspectOut bytes.Buffer
	if err := Inspect(InspectOptions{Model: modelPath, Top: 5, Sort: "precedence"}, &inspectOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inspectOut.String(), "sequence") {
		t.Fatalf("inspect output = %q, want table header", inspectOut.String())
	}
}

func TestReportSubcommandWritesMarkdownAndArtifacts(t *testing.T) {
	dir := t.TempDir()
	var stdout bytes.Buffer
	err := Run([]string{
		"report",
		"-dir", dir,
		"-kind", "redundant-contexts",
		"-seed", "5",
		"-alphabet", "8",
		"-sessions", "20",
		"-min-len", "4",
		"-max-len", "8",
		"-max-depth", "2",
		"-min-count", "1",
		"-train-ratio", "0.7",
	}, &stdout, ioDiscard{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "wrote") {
		t.Fatalf("stdout = %q, want wrote message", stdout.String())
	}
	reportPath := filepath.Join(dir, "redundant-contexts_depth2_report.md")
	report, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(report)
	for _, want := range []string{
		"# VOMC Evaluation Report",
		"## What This Evaluates",
		"## Structure",
		"## Prediction",
		"## Sequence Discovery",
		"## Performance",
		"## Validation",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("report missing %q:\n%s", want, text)
		}
	}
	for _, name := range []string{
		"redundant-contexts.jsonl",
		"redundant-contexts_depth2.json",
		"redundant-contexts_depth2_model.json",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing artifact %s: %v", name, err)
		}
	}
}

func writeResult(t *testing.T, dir, name string, result BenchResult) string {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}
