package vomcbench

import (
	"flag"
	"fmt"
	"io"
)

func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return fmt.Errorf("missing subcommand")
	}
	switch args[0] {
	case "generate":
		return runGenerate(args[1:], stdout)
	case "run":
		return runBenchmark(args[1:], stdout)
	case "report":
		return runReport(args[1:], stdout)
	case "compare":
		return runCompare(args[1:], stdout)
	case "inspect":
		return runInspect(args[1:], stdout)
	case "validate":
		return runValidate(args[1:], stdout)
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `vomcbench is a replayable evaluation harness for pkg/vomc.

Usage:
  vomcbench generate -kind variable-order -seed 42 -alphabet 64 -sessions 10000 -out corpus.jsonl
  vomcbench run -corpus corpus.jsonl -max-depth 4 -min-count 2 -train-ratio 0.8 -seed 42 -out result.json -model-out model.json
  vomcbench report -dir bench-results -kind variable-order -seed 42 -sessions 10000
  vomcbench compare -base main.json -head pr.json -fail-on-regression
  vomcbench inspect -model model.json -top 50 -sort precedence
  vomcbench validate -result result.json`)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}
