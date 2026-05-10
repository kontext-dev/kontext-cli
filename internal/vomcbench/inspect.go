package vomcbench

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

type InspectOptions struct {
	Model string
	Top   int
	Sort  string
}

func runInspect(args []string, stdout io.Writer) error {
	fs := newFlagSet("inspect")
	opts := InspectOptions{}
	fs.StringVar(&opts.Model, "model", "", "model JSON path")
	fs.IntVar(&opts.Top, "top", 50, "number of rows to print")
	fs.StringVar(&opts.Sort, "sort", "precedence", "sort key: precedence or count")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return Inspect(opts, stdout)
}

func Inspect(opts InspectOptions, stdout io.Writer) error {
	if opts.Model == "" {
		return fmt.Errorf("inspect requires -model")
	}
	if opts.Top <= 0 {
		return fmt.Errorf("top must be positive")
	}
	data, err := os.ReadFile(opts.Model)
	if err != nil {
		return err
	}
	var model modelWire
	if err := json.Unmarshal(data, &model); err != nil {
		return err
	}
	entries := retainedPrecedence(model)
	switch opts.Sort {
	case "precedence":
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Precedence != entries[j].Precedence {
				return entries[i].Precedence > entries[j].Precedence
			}
			return entries[i].Count > entries[j].Count
		})
	case "count":
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Count != entries[j].Count {
				return entries[i].Count > entries[j].Count
			}
			return entries[i].Precedence > entries[j].Precedence
		})
	default:
		return fmt.Errorf("unsupported sort key %q", opts.Sort)
	}
	if opts.Top > len(entries) {
		opts.Top = len(entries)
	}
	fmt.Fprintln(stdout, "sequence\tcount\tlast_count\tprecedence\tdepth\tp_next_given_ctx")
	for i := 0; i < opts.Top; i++ {
		entry := entries[i]
		fmt.Fprintf(stdout, "%v\t%d\t%d\t%.6f\t%d\t%.6f\n",
			entry.Sequence,
			entry.Count,
			entry.LastSymbolCount,
			entry.Precedence,
			len(entry.Sequence)-1,
			entry.ConditionalProbability,
		)
	}
	return nil
}

type inspectEntry struct {
	Sequence               []uint32
	Count                  uint64
	LastSymbolCount        uint64
	Precedence             float64
	ConditionalProbability float64
}

func retainedPrecedence(model modelWire) []inspectEntry {
	rootCounts := map[uint32]uint64{}
	for _, ctx := range model.Contexts {
		if len(ctx.Context) != 0 {
			continue
		}
		for _, next := range ctx.Next {
			rootCounts[next.Symbol] = next.Count
		}
		break
	}
	entries := make([]inspectEntry, 0)
	for _, ctx := range model.Contexts {
		for _, next := range ctx.Next {
			if len(ctx.Context) == 0 {
				continue
			}
			lastCount := rootCounts[next.Symbol]
			if lastCount == 0 || ctx.Total == 0 {
				continue
			}
			sequence := append(append([]uint32(nil), ctx.Context...), next.Symbol)
			entries = append(entries, inspectEntry{
				Sequence:               sequence,
				Count:                  next.Count,
				LastSymbolCount:        lastCount,
				Precedence:             float64(next.Count) / float64(lastCount),
				ConditionalProbability: float64(next.Count) / float64(ctx.Total),
			})
		}
	}
	return entries
}
