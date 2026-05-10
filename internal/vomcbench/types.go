package vomcbench

import "time"

const generatorVersion = 1

type CorpusMeta struct {
	Kind             string `json:"kind"`
	Seed             int64  `json:"seed"`
	AlphabetSize     int    `json:"alphabet_size"`
	Sessions         int    `json:"sessions"`
	MinLen           int    `json:"min_len"`
	MaxLen           int    `json:"max_len"`
	GeneratorVersion int    `json:"generator_version"`
	GeneratedAt      string `json:"generated_at,omitempty"`
}

type CorpusHeader struct {
	Meta CorpusMeta `json:"meta"`
}

type CorpusSession struct {
	SessionID string   `json:"session_id"`
	Symbols   []uint32 `json:"symbols"`
}

type BenchResult struct {
	Config      ConfigMetrics      `json:"config"`
	Corpus      CorpusMetrics      `json:"corpus"`
	Structure   StructureMetrics   `json:"structure"`
	Prediction  PredictionMetrics  `json:"prediction"`
	Discovery   DiscoveryMetrics   `json:"discovery"`
	Performance PerformanceMetrics `json:"performance"`
}

type ConfigMetrics struct {
	MaxDepth      int     `json:"max_depth"`
	MinCount      uint64  `json:"min_count"`
	Confidence    float64 `json:"confidence"`
	PruneStrategy string  `json:"prune_strategy"`
	Smoother      string  `json:"smoother"`
	Seed          int64   `json:"seed"`
}

type CorpusMetrics struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Sessions      int    `json:"sessions"`
	Symbols       int    `json:"symbols"`
	AlphabetSize  int    `json:"alphabet_size"`
	TrainSymbols  int    `json:"train_symbols"`
	TestSymbols   int    `json:"test_symbols"`
	TrainSessions int    `json:"train_sessions"`
	TestSessions  int    `json:"test_sessions"`
}

type StructureMetrics struct {
	CandidateContexts       int            `json:"candidate_contexts"`
	RetainedContexts        int            `json:"retained_contexts"`
	CollapsedContexts       int            `json:"collapsed_contexts"`
	RetentionRatio          float64        `json:"retention_ratio"`
	MaxRetainedDepth        int            `json:"max_retained_depth"`
	ContextsByDepth         map[string]int `json:"contexts_by_depth"`
	CollapsedByDepth        map[string]int `json:"collapsed_by_depth"`
	SuffixClosureViolations int            `json:"suffix_closure_violations"`
}

type PredictionMetrics struct {
	TokensScored          int            `json:"tokens_scored"`
	NegativeLogLikelihood float64        `json:"negative_log_likelihood"`
	AvgLogLoss            float64        `json:"avg_log_loss"`
	Perplexity            float64        `json:"perplexity"`
	Top1Accuracy          float64        `json:"top1_accuracy"`
	Top3Accuracy          float64        `json:"top3_accuracy"`
	BackoffRate           float64        `json:"backoff_rate"`
	EmptyContextRate      float64        `json:"empty_context_rate"`
	UnknownSymbolRate     float64        `json:"unknown_symbol_rate"`
	MatchedDepthHistogram map[string]int `json:"matched_depth_histogram"`
}

type DiscoveryMetrics struct {
	ImportantSequences        int               `json:"important_sequences"`
	CredibleSeparationCount   int               `json:"credible_separation_count"`
	RedundantContextCount     int               `json:"redundant_context_count"`
	TopPrecedence             []PrecedenceEntry `json:"top_precedence"`
	MeanPrecedenceTop10       float64           `json:"mean_precedence_top10"`
	MeanPrecedenceTop100      float64           `json:"mean_precedence_top100"`
	MeanSupportWeightedTop100 float64           `json:"mean_support_weighted_precedence_top100"`
}

type PrecedenceEntry struct {
	Sequence                  []uint32 `json:"sequence"`
	Count                     uint64   `json:"count"`
	LastSymbolCount           uint64   `json:"last_symbol_count"`
	Precedence                float64  `json:"precedence"`
	SupportWeightedPrecedence float64  `json:"support_weighted_precedence"`
}

type PerformanceMetrics struct {
	ObserveSymbolsPerSec     float64 `json:"observe_symbols_per_sec"`
	FitMS                    float64 `json:"fit_ms"`
	ScoreSymbolsPerSec       float64 `json:"score_symbols_per_sec"`
	ModelJSONBytes           int     `json:"model_json_bytes"`
	PeakHeapBytes            uint64  `json:"peak_heap_bytes"`
	BytesPerCandidateContext float64 `json:"bytes_per_candidate_context"`
	BytesPerRetainedContext  float64 `json:"bytes_per_retained_context"`
}

type modelWire struct {
	MaxDepth int           `json:"max_depth"`
	Alphabet []uint32      `json:"alphabet,omitempty"`
	Smoother smootherWire  `json:"smoother"`
	Contexts []contextWire `json:"contexts"`
}

type smootherWire struct {
	Type  string  `json:"type"`
	Alpha float64 `json:"alpha,omitempty"`
}

type contextWire struct {
	Context  []uint32          `json:"context,omitempty"`
	Total    uint64            `json:"total"`
	Next     []symbolCountWire `json:"next,omitempty"`
	Fallback []uint32          `json:"fallback,omitempty"`
}

type symbolCountWire struct {
	Symbol uint32 `json:"symbol"`
	Count  uint64 `json:"count"`
}

func elapsedSeconds(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return d.Seconds()
}
