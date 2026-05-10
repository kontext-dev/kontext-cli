package vomc_test

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/kontext-security/kontext-cli/pkg/vomc"
)

func FuzzModelJSONRoundTrip(f *testing.F) {
	f.Add([]byte{1, 2, 1, 3, 2, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		builder, err := vomc.NewBuilder(vomc.Options{MaxDepth: 3})
		if err != nil {
			t.Fatal(err)
		}
		seq := make(vomc.Sequence, 0, len(data))
		for _, b := range data {
			seq = append(seq, vomc.Symbol(b%16))
		}
		if len(seq) == 0 {
			return
		}
		if err := builder.Observe(seq); err != nil {
			t.Fatal(err)
		}
		model, err := builder.Fit()
		if err != nil {
			t.Fatal(err)
		}
		dist := model.Distribution(seq)
		sum := 0.0
		for _, probability := range dist.Probs {
			if probability < 0 || math.IsNaN(probability) || math.IsInf(probability, 0) {
				t.Fatalf("invalid probability %f", probability)
			}
			sum += probability
		}
		if sum > 0 && (sum < 0.999999 || sum > 1.000001) {
			t.Fatalf("probabilities sum to %f", sum)
		}

		encoded, err := json.Marshal(model)
		if err != nil {
			t.Fatal(err)
		}
		var restored vomc.Model
		if err := json.Unmarshal(encoded, &restored); err != nil {
			t.Fatal(err)
		}
		if got, want := restored.Prob(seq, seq[len(seq)-1]), model.Prob(seq, seq[len(seq)-1]); got != want {
			t.Fatalf("round-trip probability = %f, want %f", got, want)
		}
	})
}
