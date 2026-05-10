package vomc

import (
	"encoding/json"
	"fmt"
)

// Encoder maps comparable caller values to compact symbols.
type Encoder[T comparable] struct {
	values []T
	index  map[T]Symbol
}

// NewEncoder creates an empty encoder.
func NewEncoder[T comparable]() *Encoder[T] {
	return &Encoder[T]{index: map[T]Symbol{}}
}

// Encode returns the stable symbol for value, creating one if necessary.
func (e *Encoder[T]) Encode(value T) Symbol {
	if e.index == nil {
		e.index = map[T]Symbol{}
	}
	if sym, ok := e.index[value]; ok {
		return sym
	}
	sym := Symbol(len(e.values))
	e.values = append(e.values, value)
	e.index[value] = sym
	return sym
}

// Decode returns the value mapped to sym.
func (e *Encoder[T]) Decode(sym Symbol) (T, bool) {
	var zero T
	if e == nil || uint64(sym) >= uint64(len(e.values)) {
		return zero, false
	}
	return e.values[sym], true
}

// EncodeSequence maps values to a sequence of symbols.
func (e *Encoder[T]) EncodeSequence(values []T) Sequence {
	seq := make(Sequence, 0, len(values))
	for _, value := range values {
		seq = append(seq, e.Encode(value))
	}
	return seq
}

// Values returns values in symbol order.
func (e *Encoder[T]) Values() []T {
	if e == nil {
		return nil
	}
	return append([]T(nil), e.values...)
}

// Len returns the number of encoded values.
func (e *Encoder[T]) Len() int {
	if e == nil {
		return 0
	}
	return len(e.values)
}

// MarshalJSON stores values in symbol order.
func (e *Encoder[T]) MarshalJSON() ([]byte, error) {
	if e == nil {
		return json.Marshal([]T(nil))
	}
	return json.Marshal(e.values)
}

// UnmarshalJSON restores values in symbol order.
func (e *Encoder[T]) UnmarshalJSON(data []byte) error {
	var values []T
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	index := make(map[T]Symbol, len(values))
	for i, value := range values {
		if _, exists := index[value]; exists {
			return fmt.Errorf("duplicate encoded value at index %d", i)
		}
		index[value] = Symbol(i)
	}
	e.values = values
	e.index = index
	return nil
}
