package wire

// SymbolCount is the JSON form of a next-symbol count.
type SymbolCount struct {
	Symbol uint32 `json:"symbol"`
	Count  uint64 `json:"count"`
}

// Smoother is the JSON form of a smoother configuration.
type Smoother struct {
	Type  string  `json:"type"`
	Alpha float64 `json:"alpha,omitempty"`
}

// Context is the JSON form of one retained model context.
type Context struct {
	Context  []uint32      `json:"context,omitempty"`
	Total    uint64        `json:"total"`
	Next     []SymbolCount `json:"next,omitempty"`
	Fallback []uint32      `json:"fallback,omitempty"`
}

// Model is the JSON form of a VOMC model.
type Model struct {
	MaxDepth int       `json:"max_depth"`
	Alphabet []uint32  `json:"alphabet,omitempty"`
	Smoother Smoother  `json:"smoother"`
	Contexts []Context `json:"contexts"`
}
