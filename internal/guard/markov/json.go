package markov

import (
	"encoding/json"
	"io"
)

// WriteModelJSON writes a learned model as JSON.
func WriteModelJSON(w io.Writer, model *Model) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(model)
}

// ReadModelJSON reads a learned model from JSON.
func ReadModelJSON(r io.Reader) (*Model, error) {
	var model Model
	if err := json.NewDecoder(r).Decode(&model); err != nil {
		return nil, err
	}
	if err := model.Validate(); err != nil {
		return nil, err
	}
	return &model, nil
}
