package vomcbench

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type CompareOptions struct {
	Base             string
	Head             string
	FailOnRegression bool
}

func runCompare(args []string, stdout io.Writer) error {
	fs := newFlagSet("compare")
	opts := CompareOptions{}
	fs.StringVar(&opts.Base, "base", "", "baseline result JSON")
	fs.StringVar(&opts.Head, "head", "", "candidate result JSON")
	fs.BoolVar(&opts.FailOnRegression, "fail-on-regression", false, "return non-zero on material regressions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	failed, err := Compare(opts, stdout)
	if err != nil {
		return err
	}
	if failed && opts.FailOnRegression {
		return fmt.Errorf("benchmark regressions detected")
	}
	return nil
}

func Compare(opts CompareOptions, stdout io.Writer) (bool, error) {
	if opts.Base == "" || opts.Head == "" {
		return false, fmt.Errorf("compare requires -base and -head")
	}
	base, err := readResult(opts.Base)
	if err != nil {
		return false, fmt.Errorf("read base: %w", err)
	}
	head, err := readResult(opts.Head)
	if err != nil {
		return false, fmt.Errorf("read head: %w", err)
	}

	failed := false
	fmt.Fprintln(stdout, "STRUCTURE")
	failed = printMetric(stdout, "retained_contexts", float64(base.Structure.RetainedContexts), float64(head.Structure.RetainedContexts), higherIsWorse, 0.20) || failed
	failed = printMetric(stdout, "retention_ratio", base.Structure.RetentionRatio, head.Structure.RetentionRatio, higherIsWorse, 0.20) || failed
	failed = printMetric(stdout, "suffix_closure_errors", float64(base.Structure.SuffixClosureViolations), float64(head.Structure.SuffixClosureViolations), higherIsWorse, 0.0) || failed

	fmt.Fprintln(stdout, "\nPREDICTION")
	failed = printMetric(stdout, "avg_log_loss", base.Prediction.AvgLogLoss, head.Prediction.AvgLogLoss, higherIsWorse, 0.01) || failed
	failed = printMetric(stdout, "perplexity", base.Prediction.Perplexity, head.Prediction.Perplexity, higherIsWorse, 0.01) || failed
	failed = printMetric(stdout, "top1_accuracy", base.Prediction.Top1Accuracy, head.Prediction.Top1Accuracy, lowerIsWorse, 0.02) || failed

	fmt.Fprintln(stdout, "\nDISCOVERY")
	failed = printMetric(stdout, "mean_precedence_top100", base.Discovery.MeanPrecedenceTop100, head.Discovery.MeanPrecedenceTop100, lowerIsWorse, 0.05) || failed

	fmt.Fprintln(stdout, "\nPERFORMANCE")
	failed = printMetric(stdout, "fit_ms", base.Performance.FitMS, head.Performance.FitMS, higherIsWorse, 0.50) || failed
	failed = printMetric(stdout, "model_json_bytes", float64(base.Performance.ModelJSONBytes), float64(head.Performance.ModelJSONBytes), higherIsWorse, 0.50) || failed

	if retainedContextRegression(base, head) {
		fmt.Fprintln(stdout, "\nRULE")
		fmt.Fprintln(stdout, "  retained contexts increased materially without meaningful log-loss improvement   FAIL")
		failed = true
	}
	return failed, nil
}

func readResult(path string) (BenchResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return BenchResult{}, err
	}
	var result BenchResult
	if err := json.Unmarshal(data, &result); err != nil {
		return BenchResult{}, err
	}
	return result, nil
}

type metricDirection int

const (
	higherIsWorse metricDirection = iota
	lowerIsWorse
)

func printMetric(w io.Writer, name string, base, head float64, direction metricDirection, threshold float64) bool {
	change := relativeChange(base, head)
	fail := false
	switch direction {
	case higherIsWorse:
		fail = change > threshold
	case lowerIsWorse:
		fail = change < -threshold
	}
	status := "OK"
	if fail {
		status = "FAIL"
	}
	fmt.Fprintf(w, "  %-24s %.6g -> %.6g   %+6.1f%%   %s\n", name, base, head, change*100, status)
	return fail
}

func retainedContextRegression(base, head BenchResult) bool {
	contextIncrease := relativeChange(float64(base.Structure.RetainedContexts), float64(head.Structure.RetainedContexts))
	logLossChange := relativeChange(base.Prediction.AvgLogLoss, head.Prediction.AvgLogLoss)
	logLossImprovement := -logLossChange
	return contextIncrease > 0.20 && logLossImprovement < 0.01
}

func relativeChange(base, head float64) float64 {
	if base == 0 {
		if head == 0 {
			return 0
		}
		return 1
	}
	return (head - base) / base
}
