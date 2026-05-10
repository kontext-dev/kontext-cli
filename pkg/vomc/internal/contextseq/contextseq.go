package contextseq

import (
	"sort"
	"strconv"
	"strings"
)

// Key encodes a symbol sequence as a deterministic map key.
func Key[S ~uint32](seq []S) string {
	if len(seq) == 0 {
		return ""
	}
	var b strings.Builder
	for i, sym := range seq {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(sym), 10))
	}
	return b.String()
}

// Copy returns a shallow copy of seq.
func Copy[S ~uint32](seq []S) []S {
	if len(seq) == 0 {
		return nil
	}
	return append([]S(nil), seq...)
}

// Suffix returns the last n symbols of seq.
func Suffix[S ~uint32](seq []S, n int) []S {
	if n <= 0 {
		return nil
	}
	if n >= len(seq) {
		return seq
	}
	return seq[len(seq)-n:]
}

// SortSymbols sorts symbols ascending.
func SortSymbols[S ~uint32](symbols []S) {
	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i] < symbols[j]
	})
}

// SortContexts sorts contexts by length and lexicographic value.
func SortContexts[S ~uint32, C ~[]S](contexts []C) {
	sort.Slice(contexts, func(i, j int) bool {
		a, b := contexts[i], contexts[j]
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		for k := range a {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return false
	})
}

// Unique returns sorted unique symbols.
func Unique[S ~uint32](symbols []S) []S {
	if len(symbols) == 0 {
		return nil
	}
	seen := make(map[S]struct{}, len(symbols))
	out := make([]S, 0, len(symbols))
	for _, sym := range symbols {
		if _, ok := seen[sym]; ok {
			continue
		}
		seen[sym] = struct{}{}
		out = append(out, sym)
	}
	SortSymbols(out)
	return out
}
