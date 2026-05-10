package vomc

import (
	"encoding/json"
	"fmt"

	"github.com/kontext-security/kontext-cli/pkg/vomc/internal/contextseq"
	"github.com/kontext-security/kontext-cli/pkg/vomc/internal/wire"
)

// MarshalJSON serializes an immutable model.
func (m *Model) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	smoother, err := encodeSmoother(m.smoother)
	if err != nil {
		return nil, err
	}
	contexts := m.contextInfos()
	rows := make([]wire.Context, 0, len(contexts))
	for _, info := range contexts {
		rows = append(rows, wire.Context{
			Context:  toWireSymbols(info.Context),
			Total:    info.Total,
			Next:     sortedSymbolCounts(info.Next),
			Fallback: toWireSymbols(info.Fallback),
		})
	}
	return json.Marshal(wire.Model{
		MaxDepth: m.maxDepth,
		Alphabet: toWireSymbols(m.alphabet),
		Smoother: smoother,
		Contexts: rows,
	})
}

// UnmarshalJSON restores a model.
func (m *Model) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*m = Model{}
		return nil
	}
	var payload wire.Model
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	if payload.MaxDepth < 0 {
		return fmt.Errorf("max depth must be non-negative")
	}
	smoother, err := decodeSmoother(payload.Smoother)
	if err != nil {
		return err
	}
	contexts := make(map[string]contextInfo, len(payload.Contexts))
	observedAlphabet := make([]Symbol, 0)
	for _, row := range payload.Contexts {
		next := make(map[Symbol]uint64, len(row.Next))
		seenNext := make(map[Symbol]struct{}, len(row.Next))
		total := uint64(0)
		for _, entry := range row.Next {
			sym := Symbol(entry.Symbol)
			if _, exists := seenNext[sym]; exists {
				return fmt.Errorf("context %v has duplicate next symbol %d", row.Context, entry.Symbol)
			}
			if entry.Count == 0 {
				return fmt.Errorf("context %v has zero count for next symbol %d", row.Context, entry.Symbol)
			}
			seenNext[sym] = struct{}{}
			next[sym] = entry.Count
			total += entry.Count
			observedAlphabet = append(observedAlphabet, sym)
		}
		if row.Total != total {
			return fmt.Errorf("context %v total %d does not match next-count total %d", row.Context, row.Total, total)
		}
		if row.Total == 0 {
			return fmt.Errorf("context %v has zero total", row.Context)
		}
		context := fromWireSymbols(row.Context)
		if len(context) > payload.MaxDepth {
			return fmt.Errorf("context %v exceeds max depth %d", row.Context, payload.MaxDepth)
		}
		key := contextseq.Key(context)
		if _, exists := contexts[key]; exists {
			return fmt.Errorf("duplicate context %v", row.Context)
		}
		fallback := fromWireSymbols(row.Fallback)
		contexts[key] = contextInfo{
			Context:  Context(contextseq.Copy(context)),
			Total:    row.Total,
			Next:     next,
			Fallback: Context(contextseq.Copy(fallback)),
		}
	}
	root, ok := contexts[""]
	if !ok || root.Next == nil {
		return fmt.Errorf("model missing root context")
	}
	for _, info := range contexts {
		if len(info.Context) == 0 {
			if len(info.Fallback) != 0 {
				return fmt.Errorf("root context has fallback %v", info.Fallback)
			}
			continue
		}
		if len(info.Fallback) >= len(info.Context) || !isSuffixContext(info.Context, info.Fallback) {
			return fmt.Errorf("fallback %v is not a shorter suffix of context %v", info.Fallback, info.Context)
		}
		if _, ok := contexts[contextseq.Key(info.Fallback)]; !ok {
			return fmt.Errorf("fallback %v for context %v is not retained", info.Fallback, info.Context)
		}
	}
	m.maxDepth = payload.MaxDepth
	m.alphabet = mergeAlphabet(fromWireSymbols(payload.Alphabet), observedAlphabet)
	m.smoother = smoother
	m.contexts = contexts
	return nil
}

func isSuffixContext(seq, suffix []Symbol) bool {
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

func sortedSymbolCounts(next map[Symbol]uint64) []wire.SymbolCount {
	symbols := make([]Symbol, 0, len(next))
	for sym := range next {
		symbols = append(symbols, sym)
	}
	contextseq.SortSymbols(symbols)
	counts := make([]wire.SymbolCount, 0, len(symbols))
	for _, sym := range symbols {
		counts = append(counts, wire.SymbolCount{Symbol: uint32(sym), Count: next[sym]})
	}
	return counts
}

func encodeSmoother(s Smoother) (wire.Smoother, error) {
	switch value := s.(type) {
	case nil:
		return wire.Smoother{Type: "mle"}, nil
	case mleSmoother:
		return wire.Smoother{Type: "mle"}, nil
	case LaplaceSmoother:
		alpha := value.Alpha
		if alpha <= 0 {
			alpha = 1
		}
		return wire.Smoother{Type: "laplace", Alpha: alpha}, nil
	default:
		return wire.Smoother{}, fmt.Errorf("cannot serialize smoother %T", s)
	}
}

func decodeSmoother(s wire.Smoother) (Smoother, error) {
	switch s.Type {
	case "", "mle":
		return mleSmoother{}, nil
	case "laplace":
		return LaplaceSmoother{Alpha: s.Alpha}, nil
	default:
		return nil, fmt.Errorf("unsupported smoother type %q", s.Type)
	}
}

func toWireSymbols(symbols []Symbol) []uint32 {
	if len(symbols) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(symbols))
	for _, sym := range symbols {
		out = append(out, uint32(sym))
	}
	return out
}

func fromWireSymbols(symbols []uint32) []Symbol {
	if len(symbols) == 0 {
		return nil
	}
	out := make([]Symbol, 0, len(symbols))
	for _, sym := range symbols {
		out = append(out, Symbol(sym))
	}
	return out
}
