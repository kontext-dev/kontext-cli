package vomc_test

import (
	"fmt"

	"github.com/kontext-security/kontext-cli/pkg/vomc"
)

func Example() {
	encoder := vomc.NewEncoder[string]()
	sequences := make([]vomc.Sequence, 0, 101)
	for i := 0; i < 100; i++ {
		sequences = append(sequences, encoder.EncodeSequence([]string{"start", "browse", "checkout"}))
	}
	sequences = append(sequences, encoder.EncodeSequence([]string{"start", "browse", "details"}))

	builder, err := vomc.NewBuilder(vomc.Options{MaxDepth: 2})
	if err != nil {
		panic(err)
	}
	if err := builder.ObserveBatch(sequences); err != nil {
		panic(err)
	}
	model, err := builder.Fit()
	if err != nil {
		panic(err)
	}

	context := encoder.EncodeSequence([]string{"start", "browse"})
	prediction := model.Predict(context)
	label, _ := encoder.Decode(prediction.Symbol)
	fmt.Printf("%s %.2f\n", label, prediction.Probability)

	// Output:
	// checkout 0.99
}
