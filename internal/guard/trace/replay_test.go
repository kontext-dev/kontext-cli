package trace

import (
	"os"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/markov"
	"github.com/kontext-security/kontext-cli/internal/guard/markov/monitor"
)

func TestEndToEndReplayFixture(t *testing.T) {
	t.Parallel()

	file, err := os.Open("testdata/coding_sessions.jsonl")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer file.Close()

	events, err := ReadJSONL(file)
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	sessions := GroupSessions(events)
	model, err := markov.BuildModel(Observations(sessions), CodingAbstraction{}, markov.BuildOptions{Alpha: 1})
	if err != nil {
		t.Fatalf("BuildModel returned error: %v", err)
	}

	unsafe := UnsafeStates(model.StateIndex, IsFailureState)
	if len(unsafe) == 0 {
		t.Fatal("expected fixture to produce unsafe states")
	}

	replayMonitor := monitor.Monitor[Event]{
		Model:       model,
		Abstraction: CodingAbstraction{},
		Unsafe:      unsafe,
		Threshold:   0.5,
	}

	riskyDecision, err := replayMonitor.Observe(Event{
		Actor:        ActorTool,
		Kind:         KindTool,
		ToolName:     "Bash npm test",
		ToolCategory: ToolCategoryBashBuild,
		ToolStatus:   ToolStatusFailure,
	})
	if err != nil {
		t.Fatalf("Observe risky event returned error: %v", err)
	}
	if !riskyDecision.Intervention {
		t.Fatalf("expected risky event to trigger intervention, got risk %.3f", riskyDecision.Risk)
	}

	benignDecision, err := replayMonitor.Observe(Event{
		Actor:        ActorTool,
		Kind:         KindTool,
		ToolName:     "Read",
		ToolCategory: ToolCategoryRead,
		ToolStatus:   ToolStatusSuccess,
	})
	if err != nil {
		t.Fatalf("Observe benign event returned error: %v", err)
	}
	if benignDecision.Risk >= riskyDecision.Risk {
		t.Fatalf("benign risk %.3f should be lower than risky risk %.3f", benignDecision.Risk, riskyDecision.Risk)
	}
}
