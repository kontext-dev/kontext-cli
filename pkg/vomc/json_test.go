package vomc_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kontext-security/kontext-cli/pkg/vomc"
)

func TestModelJSONGoldenAndRoundTrip(t *testing.T) {
	model := goldenModel(t)

	data, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	assertGoldenJSON(t, "model_golden.json", data)

	before := model.Prob(vomc.Sequence{1, 2}, 3)
	var restored vomc.Model
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	after := restored.Prob(vomc.Sequence{1, 2}, 3)
	if before != after {
		t.Fatalf("probability changed after round trip: before %f after %f", before, after)
	}
}

func TestModelJSONRestoresObservedAlphabet(t *testing.T) {
	data := []byte(`{
		"max_depth": 0,
		"alphabet": [1],
		"smoother": {"type": "mle"},
		"contexts": [
			{"total": 1, "next": [{"symbol": 2, "count": 1}]}
		]
	}`)
	var restored vomc.Model
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if got, want := restored.Alphabet(), []vomc.Symbol{1, 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("alphabet = %#v, want %#v", got, want)
	}
	dist := restored.Distribution(nil)
	if got := dist.Probability(2); got != 1 {
		t.Fatalf("P(2 | root) = %f, want 1", got)
	}
}

func TestEncoderJSONRoundTrip(t *testing.T) {
	encoder := vomc.NewEncoder[string]()
	encoder.EncodeSequence([]string{"auth", "accounts", "auth"})

	data, err := json.Marshal(encoder)
	if err != nil {
		t.Fatal(err)
	}
	var restored vomc.Encoder[string]
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if got := restored.Encode("auth"); got != 0 {
		t.Fatalf("restored auth symbol = %d, want 0", got)
	}
	if got := restored.Encode("profile"); got != 2 {
		t.Fatalf("new profile symbol = %d, want 2", got)
	}
}

func TestJSONRejectsInvalidPayloads(t *testing.T) {
	tests := []struct {
		name   string
		target any
		data   string
	}{
		{
			name:   "model missing root",
			target: &vomc.Model{},
			data:   `{"max_depth":0,"smoother":{"type":"mle"},"contexts":[]}`,
		},
		{
			name:   "model context total",
			target: &vomc.Model{},
			data:   `{"max_depth":0,"smoother":{"type":"mle"},"contexts":[{"total":2,"next":[{"symbol":1,"count":1}]}]}`,
		},
		{
			name:   "model smoother",
			target: &vomc.Model{},
			data:   `{"max_depth":0,"smoother":{"type":"unknown"},"contexts":[{"total":1,"next":[{"symbol":1,"count":1}]}]}`,
		},
		{
			name:   "model zero total",
			target: &vomc.Model{},
			data:   `{"max_depth":0,"smoother":{"type":"mle"},"contexts":[{"total":0}]}`,
		},
		{
			name:   "model duplicate context",
			target: &vomc.Model{},
			data:   `{"max_depth":0,"smoother":{"type":"mle"},"contexts":[{"total":1,"next":[{"symbol":1,"count":1}]},{"total":1,"next":[{"symbol":2,"count":1}]}]}`,
		},
		{
			name:   "model duplicate next symbol",
			target: &vomc.Model{},
			data:   `{"max_depth":0,"smoother":{"type":"mle"},"contexts":[{"total":2,"next":[{"symbol":1,"count":1},{"symbol":1,"count":1}]}]}`,
		},
		{
			name:   "model zero next count",
			target: &vomc.Model{},
			data:   `{"max_depth":0,"smoother":{"type":"mle"},"contexts":[{"total":1,"next":[{"symbol":1,"count":1},{"symbol":2,"count":0}]}]}`,
		},
		{
			name:   "model context exceeds max depth",
			target: &vomc.Model{},
			data:   `{"max_depth":1,"smoother":{"type":"mle"},"contexts":[{"total":1,"next":[{"symbol":1,"count":1}]},{"context":[1,2],"total":1,"next":[{"symbol":3,"count":1}],"fallback":[2]}]}`,
		},
		{
			name:   "model fallback is not suffix",
			target: &vomc.Model{},
			data:   `{"max_depth":2,"smoother":{"type":"mle"},"contexts":[{"total":1,"next":[{"symbol":1,"count":1}]},{"context":[1],"total":1,"next":[{"symbol":2,"count":1}]},{"context":[1,2],"total":1,"next":[{"symbol":3,"count":1}],"fallback":[1]}]}`,
		},
		{
			name:   "model fallback is not retained",
			target: &vomc.Model{},
			data:   `{"max_depth":2,"smoother":{"type":"mle"},"contexts":[{"total":1,"next":[{"symbol":1,"count":1}]},{"context":[1,2],"total":1,"next":[{"symbol":3,"count":1}],"fallback":[2]}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(tt.data), tt.target); err == nil {
				t.Fatal("expected unmarshal error")
			}
		})
	}
}

func goldenModel(t *testing.T) *vomc.Model {
	t.Helper()
	builder := newTestBuilder(t, vomc.Options{
		MaxDepth: 2,
		Smoother: vomc.LaplaceSmoother{
			Alpha: 0.5,
		},
	})
	for i := 0; i < 20; i++ {
		observe(t, builder, vomc.Sequence{1, 2, 3})
		observe(t, builder, vomc.Sequence{4, 2, 5})
	}
	return fit(t, builder)
}

func assertGoldenJSON(t *testing.T, name string, actual []byte) {
	t.Helper()
	expected, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(expected, actual) {
		t.Fatalf("%s mismatch\nexpected:\n%s\nactual:\n%s", name, expected, actual)
	}
}

func jsonEqual(a, b []byte) bool {
	var av any
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	var bv any
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}
