package predicate

import (
	"fmt"
	"reflect"
)

// Observation is the default map shape used by predicates.
type Observation map[string]any

// Predicate evaluates a boolean property over one observation.
type Predicate interface {
	Evaluate(observation Observation) (bool, error)
	String() string
}

// ComparisonOp is a supported atomic predicate comparison.
type ComparisonOp string

const (
	OpEQ  ComparisonOp = "=="
	OpNEQ ComparisonOp = "!="
	OpGT  ComparisonOp = ">"
	OpLT  ComparisonOp = "<"
	OpGTE ComparisonOp = ">="
	OpLTE ComparisonOp = "<="
)

// AtomicPredicate compares one observation field with a right-hand value.
type AtomicPredicate struct {
	Negated bool         `json:"negated,omitempty"`
	LHS     string       `json:"lhs"`
	Op      ComparisonOp `json:"op"`
	RHS     any          `json:"rhs"`
}

func (p AtomicPredicate) String() string {
	prefix := ""
	if p.Negated {
		prefix = "!"
	}
	return fmt.Sprintf("%s(%s %s %v)", prefix, p.LHS, p.Op, p.RHS)
}

func (p AtomicPredicate) Evaluate(observation Observation) (bool, error) {
	left, ok := observation[p.LHS]
	if !ok {
		return false, fmt.Errorf("observation missing field %q", p.LHS)
	}
	result, err := compareValues(left, p.Op, p.RHS)
	if err != nil {
		return false, fmt.Errorf("%s: %w", p.String(), err)
	}
	if p.Negated {
		return !result, nil
	}
	return result, nil
}

// BinaryOp combines two predicates.
type BinaryOp string

const (
	OpAnd BinaryOp = "and"
	OpOr  BinaryOp = "or"
)

// BinaryPredicate combines two predicates with boolean AND or OR.
type BinaryPredicate struct {
	LHS Predicate `json:"-"`
	Op  BinaryOp  `json:"op"`
	RHS Predicate `json:"-"`
}

func (p BinaryPredicate) String() string {
	return fmt.Sprintf("(%s) %s (%s)", p.LHS.String(), p.Op, p.RHS.String())
}

func (p BinaryPredicate) Evaluate(observation Observation) (bool, error) {
	left, err := p.LHS.Evaluate(observation)
	if err != nil {
		return false, err
	}
	switch p.Op {
	case OpAnd:
		if !left {
			return false, nil
		}
		return p.RHS.Evaluate(observation)
	case OpOr:
		if left {
			return true, nil
		}
		return p.RHS.Evaluate(observation)
	default:
		return false, fmt.Errorf("unsupported binary predicate operator %q", p.Op)
	}
}

// Quantifier determines how a predicate is evaluated over a slice of objects.
type Quantifier string

const (
	QuantifierExists Quantifier = "exist"
	QuantifierAll    Quantifier = "all"
)

// QuantifiedPredicate evaluates a predicate over multiple object observations.
type QuantifiedPredicate struct {
	Quantifier Quantifier
	Predicate  Predicate
}

func (p QuantifiedPredicate) String() string {
	return fmt.Sprintf("%s %s", p.Quantifier, p.Predicate.String())
}

func (p QuantifiedPredicate) Evaluate(observations []Observation) (bool, error) {
	switch p.Quantifier {
	case QuantifierExists:
		for _, observation := range observations {
			ok, err := p.Predicate.Evaluate(observation)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case QuantifierAll:
		for _, observation := range observations {
			ok, err := p.Predicate.Evaluate(observation)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported quantifier %q", p.Quantifier)
	}
}

func compareValues(left any, op ComparisonOp, right any) (bool, error) {
	if lf, ok := asFloat64(left); ok {
		rf, ok := asFloat64(right)
		if !ok {
			return false, fmt.Errorf("cannot compare numeric value with %T", right)
		}
		switch op {
		case OpEQ:
			return lf == rf, nil
		case OpNEQ:
			return lf != rf, nil
		case OpGT:
			return lf > rf, nil
		case OpLT:
			return lf < rf, nil
		case OpGTE:
			return lf >= rf, nil
		case OpLTE:
			return lf <= rf, nil
		default:
			return false, fmt.Errorf("unsupported comparison operator %q", op)
		}
	}

	switch op {
	case OpEQ:
		return reflect.DeepEqual(left, right), nil
	case OpNEQ:
		return !reflect.DeepEqual(left, right), nil
	default:
		return false, fmt.Errorf("operator %q requires numeric operands", op)
	}
}

func asFloat64(value any) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}
