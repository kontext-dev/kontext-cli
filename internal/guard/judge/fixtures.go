package judge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type Fixture struct {
	ID                  string               `json:"id"`
	Description         string               `json:"description"`
	HookEvent           FixtureHookEvent     `json:"hook_event"`
	NormalizedEvent     NormalizedEvent      `json:"normalized_event"`
	DeterministicPolicy DeterministicContext `json:"deterministic_policy"`
	JudgeExpected       FixtureExpected      `json:"judge_expected"`
	Notes               string               `json:"notes"`
}

type FixtureHookEvent struct {
	Agent         string         `json:"agent"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
}

type FixtureExpected struct {
	ShouldCallJudge bool      `json:"should_call_judge"`
	Decision        Decision  `json:"decision"`
	RiskLevel       RiskLevel `json:"risk_level"`
	Categories      []string  `json:"categories"`
	ReasonContains  []string  `json:"reason_contains"`
}

func ReadFixtures(r io.Reader) ([]Fixture, error) {
	var fixtures []Fixture
	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var fixture Fixture
		if err := json.Unmarshal([]byte(text), &fixture); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		fixtures = append(fixtures, fixture)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return fixtures, nil
}

func InputFromFixture(fixture Fixture) Input {
	return Input{
		Agent:     fixture.HookEvent.Agent,
		HookEvent: fixture.HookEvent.HookEventName,
		ToolName:  fixture.HookEvent.ToolName,
		CWDClass:  "unknown",
		ToolInput: ToolInput{
			CommandRedacted: fixture.NormalizedEvent.CommandSummary,
			PathRedacted:    fixture.NormalizedEvent.PathClass,
			RequestSummary:  fixture.NormalizedEvent.RequestSummary,
		},
		NormalizedEvent:     fixture.NormalizedEvent,
		DeterministicPolicy: fixture.DeterministicPolicy,
	}
}

func CompareFixtureOutput(output Output, expected FixtureExpected) []string {
	var failures []string
	if output.Decision != expected.Decision {
		failures = append(failures, fmt.Sprintf("decision=%s want=%s", output.Decision, expected.Decision))
	}
	if output.RiskLevel != expected.RiskLevel {
		failures = append(failures, fmt.Sprintf("risk_level=%s want=%s", output.RiskLevel, expected.RiskLevel))
	}
	outputCategories := make(map[string]struct{}, len(output.Categories))
	for _, category := range output.Categories {
		outputCategories[category] = struct{}{}
	}
	for _, category := range expected.Categories {
		if _, ok := outputCategories[category]; !ok {
			failures = append(failures, fmt.Sprintf("missing category %q", category))
		}
	}
	reason := strings.ToLower(output.Reason)
	for _, want := range expected.ReasonContains {
		if !strings.Contains(reason, strings.ToLower(want)) {
			failures = append(failures, fmt.Sprintf("reason missing %q", want))
		}
	}
	return failures
}
