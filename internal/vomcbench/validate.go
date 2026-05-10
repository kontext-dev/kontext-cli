package vomcbench

import (
	"fmt"
	"io"
	"math"
	"strconv"
)

type ValidateOptions struct {
	Result string
}

func runValidate(args []string, stdout io.Writer) error {
	fs := newFlagSet("validate")
	opts := ValidateOptions{}
	fs.StringVar(&opts.Result, "result", "", "result JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return Validate(opts, stdout)
}

func Validate(opts ValidateOptions, stdout io.Writer) error {
	if opts.Result == "" {
		return fmt.Errorf("validate requires -result")
	}
	result, err := readResult(opts.Result)
	if err != nil {
		return err
	}
	errors := validateResult(result)
	if len(errors) > 0 {
		for _, msg := range errors {
			fmt.Fprintf(stdout, "FAIL %s\n", msg)
		}
		return fmt.Errorf("result failed validation")
	}
	fmt.Fprintln(stdout, "OK")
	return nil
}

func validateResult(result BenchResult) []string {
	var errors []string
	if result.Structure.CandidateContexts < result.Structure.RetainedContexts {
		errors = append(errors, "candidate_contexts < retained_contexts")
	}
	if result.Structure.CollapsedContexts < 0 {
		errors = append(errors, "collapsed_contexts is negative")
	}
	if result.Structure.SuffixClosureViolations != 0 {
		errors = append(errors, "suffix_closure_violations must be 0")
	}
	if result.Structure.RetentionRatio < 0 || result.Structure.RetentionRatio > 1 {
		errors = append(errors, "retention_ratio outside [0,1]")
	}
	if result.Prediction.TokensScored < 0 {
		errors = append(errors, "tokens_scored is negative")
	}
	if result.Prediction.AvgLogLoss < 0 || isBadFloat(result.Prediction.AvgLogLoss) {
		errors = append(errors, "avg_log_loss is invalid")
	}
	if result.Prediction.Perplexity < 0 || isBadFloat(result.Prediction.Perplexity) {
		errors = append(errors, "perplexity is invalid")
	}
	if result.Prediction.UnknownSymbolRate < 0 || result.Prediction.UnknownSymbolRate > 1 {
		errors = append(errors, "unknown_symbol_rate outside [0,1]")
	}
	for depth := range result.Prediction.MatchedDepthHistogram {
		parsed, err := strconv.Atoi(depth)
		if err != nil || parsed < 0 {
			errors = append(errors, "matched_depth_histogram contains invalid depth")
			break
		}
		if parsed > result.Config.MaxDepth {
			errors = append(errors, "matched_depth_histogram contains depth above max_depth")
			break
		}
	}
	for _, entry := range result.Discovery.TopPrecedence {
		if entry.Precedence < 0 || entry.Precedence > 1 || isBadFloat(entry.Precedence) {
			errors = append(errors, "precedence outside [0,1]")
			break
		}
	}
	return errors
}

func isBadFloat(v float64) bool {
	return math.IsNaN(v) || math.IsInf(v, 0)
}
