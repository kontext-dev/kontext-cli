package trace

import (
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/markov"
)

func TestGroupSessionsAndBuildModel(t *testing.T) {
	t.Parallel()

	events := []Event{
		{SessionID: "s2", Step: 2, Actor: ActorUser, Kind: KindPrompt, PushbackType: PushbackCorrection},
		{SessionID: "s1", CheckpointID: "c1", Repository: "entireio/cli", Step: 2, Actor: ActorTool, Kind: KindTool, ToolCategory: ToolCategoryBashBuild, ToolStatus: ToolStatusFailure},
		{SessionID: "s1", CheckpointID: "c1", Repository: "entireio/cli", Step: 1, Actor: ActorUser, Kind: KindPrompt, PromptIntent: PromptIntentDebug},
	}

	sessions := GroupSessions(events)
	if len(sessions) != 2 {
		t.Fatalf("session count = %d, want 2", len(sessions))
	}
	if sessions[0].ID != "s1" || sessions[0].Events[0].Step != 1 {
		t.Fatalf("sessions were not deterministically grouped and sorted: %#v", sessions)
	}
	if sessions[0].Repository != "entireio/cli" || len(sessions[0].CheckpointIDs) != 1 || sessions[0].CheckpointIDs[0] != "c1" {
		t.Fatalf("session metadata was not derived: %#v", sessions[0])
	}

	model, err := markov.BuildModel(Observations(sessions), CodingAbstraction{}, markov.BuildOptions{Alpha: 1})
	if err != nil {
		t.Fatalf("BuildModel returned error: %v", err)
	}
	unsafe := UnsafeStates(model.StateIndex, IsFailureState)
	if len(unsafe) == 0 {
		t.Fatal("expected at least one unsafe state")
	}
}

func TestJSONL(t *testing.T) {
	t.Parallel()

	input := `{"session_id":"s1","step":1,"actor":"user","kind":"prompt"}
{"session_id":"s1","step":2,"actor":"tool","kind":"tool","tool_status":"failure"}`

	events, err := ReadJSONL(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}

	var output strings.Builder
	if err := WriteJSONL(&output, events); err != nil {
		t.Fatalf("WriteJSONL returned error: %v", err)
	}
	if !strings.Contains(output.String(), `"tool_status":"failure"`) {
		t.Fatalf("output missing tool status: %s", output.String())
	}
}

func TestCodingAbstractionEncodesPaperSignals(t *testing.T) {
	t.Parallel()

	event := Event{
		Actor:        ActorTool,
		Kind:         KindCommit,
		ToolCategory: ToolCategoryGit,
		CommitOutcome: &CommitOutcome{
			AgentAuthoredRatio: 1,
			NewVulnerabilities: 2,
			CodingMode:         CodingModeVibe,
		},
	}

	state, err := (CodingAbstraction{}).Encode(event)
	if err != nil {
		t.Fatalf("Encode returned error: %v", err)
	}
	for _, index := range []int{2, 5, 8, 9, 10} {
		if state[index] != '1' {
			t.Fatalf("state[%d] = %q, want 1 in %s", index, state[index], state)
		}
	}
}
