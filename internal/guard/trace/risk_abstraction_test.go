package trace

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type riskAbstractionSchema struct {
	AbstractionVersion string   `json:"abstraction_version"`
	Signals            []string `json:"signals"`
	UnsafeDefinition   []string `json:"unsafe_definition"`
}

func TestRiskAbstractionSchemaMatchesRuntime(t *testing.T) {
	raw, err := os.ReadFile("../../../models/guard/coding-risk-v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema riskAbstractionSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.AbstractionVersion != RiskAbstractionVersion {
		t.Fatalf("abstraction version = %q, want %q", schema.AbstractionVersion, RiskAbstractionVersion)
	}
	if !reflect.DeepEqual(schema.Signals, riskSignalNames) {
		t.Fatalf("signals = %#v, want %#v", schema.Signals, riskSignalNames)
	}
	if !reflect.DeepEqual(schema.UnsafeDefinition, RiskUnsafeDefinition) {
		t.Fatalf("unsafe definition = %#v, want %#v", schema.UnsafeDefinition, RiskUnsafeDefinition)
	}
	if len(riskSignalNames) != riskSignalIdentityOrDocsProvider+1 {
		t.Fatalf("risk signal indexes cover %d signals, want %d", riskSignalIdentityOrDocsProvider+1, len(riskSignalNames))
	}
}
