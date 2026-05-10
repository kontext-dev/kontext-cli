package vomcbench

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
)

type GenerateOptions struct {
	Kind     string
	Seed     int64
	Alphabet int
	Sessions int
	MinLen   int
	MaxLen   int
	Out      string
}

func runGenerate(args []string, stdout io.Writer) error {
	fs := newFlagSet("generate")
	opts := GenerateOptions{}
	fs.StringVar(&opts.Kind, "kind", "variable-order", "corpus kind")
	fs.Int64Var(&opts.Seed, "seed", 42, "random seed")
	fs.IntVar(&opts.Alphabet, "alphabet", 64, "alphabet size")
	fs.IntVar(&opts.Sessions, "sessions", 10000, "number of sessions")
	fs.IntVar(&opts.MinLen, "min-len", 5, "minimum session length")
	fs.IntVar(&opts.MaxLen, "max-len", 50, "maximum session length")
	fs.StringVar(&opts.Out, "out", "", "output JSONL path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.Out == "" {
		return fmt.Errorf("generate requires -out")
	}
	if err := Generate(opts); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s\n", opts.Out)
	return nil
}

func Generate(opts GenerateOptions) error {
	if opts.Alphabet <= 0 {
		return fmt.Errorf("alphabet must be positive")
	}
	if opts.Sessions <= 0 {
		return fmt.Errorf("sessions must be positive")
	}
	if opts.MinLen <= 0 || opts.MaxLen < opts.MinLen {
		return fmt.Errorf("invalid length range")
	}
	if !supportedCorpusKind(opts.Kind) {
		return fmt.Errorf("unsupported corpus kind %q", opts.Kind)
	}
	if err := os.MkdirAll(filepath.Dir(opts.Out), 0o755); err != nil && filepath.Dir(opts.Out) != "." {
		return err
	}
	file, err := os.Create(opts.Out)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()
	enc := json.NewEncoder(writer)
	header := CorpusHeader{Meta: CorpusMeta{
		Kind:             opts.Kind,
		Seed:             opts.Seed,
		AlphabetSize:     opts.Alphabet,
		Sessions:         opts.Sessions,
		MinLen:           opts.MinLen,
		MaxLen:           opts.MaxLen,
		GeneratorVersion: generatorVersion,
	}}
	if err := enc.Encode(header); err != nil {
		return err
	}

	rng := rand.New(rand.NewSource(opts.Seed))
	for i := 0; i < opts.Sessions; i++ {
		length := opts.MinLen
		if opts.MaxLen > opts.MinLen {
			length += rng.Intn(opts.MaxLen - opts.MinLen + 1)
		}
		session, err := generateSession(opts.Kind, opts.Alphabet, length, i, rng)
		if err != nil {
			return err
		}
		if err := enc.Encode(CorpusSession{
			SessionID: fmt.Sprintf("s%d", i+1),
			Symbols:   session,
		}); err != nil {
			return err
		}
	}
	return nil
}

func ReadCorpus(path string) (CorpusMeta, []CorpusSession, error) {
	file, err := os.Open(path)
	if err != nil {
		return CorpusMeta{}, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	line := 0
	var meta CorpusMeta
	sessions := make([]CorpusSession, 0)
	for scanner.Scan() {
		line++
		data := scanner.Bytes()
		if line == 1 {
			var header CorpusHeader
			if err := json.Unmarshal(data, &header); err != nil {
				return CorpusMeta{}, nil, fmt.Errorf("decode header: %w", err)
			}
			meta = header.Meta
			continue
		}
		var session CorpusSession
		if err := json.Unmarshal(data, &session); err != nil {
			return CorpusMeta{}, nil, fmt.Errorf("decode session line %d: %w", line, err)
		}
		sessions = append(sessions, session)
	}
	if err := scanner.Err(); err != nil {
		return CorpusMeta{}, nil, err
	}
	if meta.Kind == "" {
		return CorpusMeta{}, nil, fmt.Errorf("missing corpus metadata")
	}
	return meta, sessions, nil
}

func supportedCorpusKind(kind string) bool {
	switch kind {
	case "order0", "order1", "fixed-order", "variable-order", "redundant-contexts", "precedence-heavy", "zipf", "drift":
		return true
	default:
		return false
	}
}

func generateSession(kind string, alphabet, length, index int, rng *rand.Rand) ([]uint32, error) {
	switch kind {
	case "order0":
		return generateOrder0(alphabet, length, rng), nil
	case "order1":
		return generateOrder1(alphabet, length, rng), nil
	case "fixed-order":
		return generateFixedOrder(alphabet, length, rng), nil
	case "variable-order":
		return generateVariableOrder(alphabet, length, rng), nil
	case "redundant-contexts":
		return generateRedundantContexts(alphabet, length, rng), nil
	case "precedence-heavy":
		return generatePrecedenceHeavy(alphabet, length, rng), nil
	case "zipf":
		return generateZipf(alphabet, length, rng), nil
	case "drift":
		return generateDrift(alphabet, length, index, rng), nil
	default:
		return nil, fmt.Errorf("unsupported corpus kind %q", kind)
	}
}

func generateOrder0(alphabet, length int, rng *rand.Rand) []uint32 {
	out := make([]uint32, length)
	for i := range out {
		out[i] = uint32(rng.Intn(alphabet))
	}
	return out
}

func generateOrder1(alphabet, length int, rng *rand.Rand) []uint32 {
	out := make([]uint32, length)
	out[0] = uint32(rng.Intn(alphabet))
	for i := 1; i < length; i++ {
		if rng.Float64() < 0.85 {
			out[i] = uint32((int(out[i-1]) + 1) % alphabet)
		} else {
			out[i] = uint32(rng.Intn(alphabet))
		}
	}
	return out
}

func generateFixedOrder(alphabet, length int, rng *rand.Rand) []uint32 {
	out := generateOrder0(alphabet, length, rng)
	for i := 2; i < length; i++ {
		if out[i-2] == sym(1, alphabet) && out[i-1] == sym(2, alphabet) {
			out[i] = sym(3, alphabet)
		}
	}
	if length >= 3 && rng.Float64() < 0.7 {
		pos := rng.Intn(length - 2)
		out[pos], out[pos+1], out[pos+2] = sym(1, alphabet), sym(2, alphabet), sym(3, alphabet)
	}
	return out
}

func generateVariableOrder(alphabet, length int, rng *rand.Rand) []uint32 {
	out := make([]uint32, 0, length)
	for len(out) < length {
		switch {
		case len(out) <= length-3 && rng.Float64() < 0.25:
			out = append(out, sym(1, alphabet), sym(7, alphabet), sym(9, alphabet))
		case len(out) <= length-2 && rng.Float64() < 0.35:
			out = append(out, sym(4, alphabet), sym(2, alphabet))
		default:
			out = append(out, uint32(rng.Intn(alphabet)))
		}
	}
	return out[:length]
}

func generateRedundantContexts(alphabet, length int, rng *rand.Rand) []uint32 {
	out := make([]uint32, 0, length)
	A, B, C := sym(1, alphabet), sym(2, alphabet), sym(3, alphabet)
	for len(out) < length {
		prefix := uint32(rng.Intn(alphabet))
		next := B
		if rng.Float64() < 0.2 {
			next = C
		}
		out = append(out, prefix, A, next)
	}
	return out[:length]
}

func generatePrecedenceHeavy(alphabet, length int, rng *rand.Rand) []uint32 {
	out := make([]uint32, 0, length)
	for len(out) < length {
		if len(out) <= length-3 && rng.Float64() < 0.30 {
			out = append(out, sym(1, alphabet), sym(7, alphabet), sym(9, alphabet))
			continue
		}
		if rng.Float64() < 0.02 {
			out = append(out, sym(9, alphabet))
			continue
		}
		v := uint32(rng.Intn(alphabet))
		if v == sym(9, alphabet) {
			v = sym(8, alphabet)
		}
		out = append(out, v)
	}
	return out[:length]
}

func generateZipf(alphabet, length int, rng *rand.Rand) []uint32 {
	out := make([]uint32, length)
	zipf := rand.NewZipf(rng, 1.2, 1, uint64(alphabet-1))
	for i := range out {
		out[i] = uint32(zipf.Uint64())
	}
	return out
}

func generateDrift(alphabet, length, index int, rng *rand.Rand) []uint32 {
	out := make([]uint32, length)
	lowMax := max(1, alphabet/3)
	highMin := max(0, alphabet-lowMax)
	for i := range out {
		if index%2 == 0 {
			out[i] = uint32(rng.Intn(lowMax))
		} else {
			out[i] = uint32(highMin + rng.Intn(alphabet-highMin))
		}
	}
	return out
}

func sym(value, alphabet int) uint32 {
	return uint32(value % alphabet)
}
