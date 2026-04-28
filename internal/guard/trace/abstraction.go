package trace

import (
	"strings"
)

const CodingAbstractionVersion = "coding-v1"

// CodingAbstraction maps coding-agent events into safety-relevant state bits.
//
// Bit layout:
// 0 user prompt
// 1 agent reply
// 2 tool call
// 3 write/edit operation
// 4 shell-like operation
// 5 git operation
// 6 failed tool
// 7 user pushback
// 8 commit
// 9 agent-authored/vibe-coded commit
// 10 vulnerability introduced
// 11 agent asked user for clarification
// 12 hard interruption
// 13 plan-mode boundary
type CodingAbstraction struct{}

func (CodingAbstraction) Encode(event Event) (string, error) {
	bits := []byte("00000000000000")
	if event.Actor == ActorUser || event.Kind == KindPrompt {
		bits[0] = '1'
	}
	if event.Actor == ActorAgent || event.Kind == KindReply {
		bits[1] = '1'
	}
	if event.Kind == KindTool || event.Actor == ActorTool {
		bits[2] = '1'
	}
	if event.Kind == KindEdit || event.ToolCategory == ToolCategoryWrite || event.ToolCategory == ToolCategoryEdit ||
		event.FilesChanged > 0 || event.LinesAdded > 0 || event.LinesDeleted > 0 {
		bits[3] = '1'
	}
	tool := strings.ToLower(event.ToolName)
	if event.ToolCategory == ToolCategoryBash || event.ToolCategory == ToolCategoryBashFile ||
		event.ToolCategory == ToolCategoryBashBuild || event.ToolCategory == ToolCategoryBashNet ||
		strings.Contains(tool, "bash") || strings.Contains(tool, "shell") || strings.Contains(tool, "terminal") {
		bits[4] = '1'
	}
	if event.ToolCategory == ToolCategoryGit || strings.Contains(tool, "git") || event.Kind == KindCommit {
		bits[5] = '1'
	}
	if event.ToolStatus == ToolStatusFailure {
		bits[6] = '1'
	}
	if event.PushbackType == PushbackCorrection || event.PushbackType == PushbackRejection || event.PushbackType == PushbackFailureReport ||
		(event.Annotations != nil && (event.Annotations.PushbackType == PushbackCorrection ||
			event.Annotations.PushbackType == PushbackRejection ||
			event.Annotations.PushbackType == PushbackFailureReport)) {
		bits[7] = '1'
	}
	if event.Kind == KindCommit {
		bits[8] = '1'
	}
	if event.CommitOutcome != nil && event.CommitOutcome.AgentAuthoredRatio >= 0.99 {
		bits[9] = '1'
	}
	if event.CommitOutcome != nil && event.CommitOutcome.NewVulnerabilities > 0 {
		bits[10] = '1'
	}
	if event.ToolCategory == ToolCategoryAskUser {
		bits[11] = '1'
	}
	if event.Kind == KindInterrupt || (event.Kind == KindUnknown && strings.Contains(strings.ToLower(event.ToolName), "interrupted")) {
		bits[12] = '1'
	}
	if event.ToolCategory == ToolCategoryEnterPlan || event.ToolCategory == ToolCategoryExitPlan {
		bits[13] = '1'
	}
	return string(bits), nil
}

func (CodingAbstraction) Decode(state string) (Event, error) {
	event := Event{}
	if len(state) > 0 && state[0] == '1' {
		event.Actor = ActorUser
		event.Kind = KindPrompt
	}
	if len(state) > 1 && state[1] == '1' {
		event.Actor = ActorAgent
		event.Kind = KindReply
	}
	if len(state) > 2 && state[2] == '1' {
		event.Actor = ActorTool
		event.Kind = KindTool
	}
	if len(state) > 6 && state[6] == '1' {
		event.ToolStatus = ToolStatusFailure
	}
	if len(state) > 7 && state[7] == '1' {
		event.PushbackType = PushbackCorrection
	}
	if len(state) > 8 && state[8] == '1' {
		event.Kind = KindCommit
	}
	if len(state) > 9 && state[9] == '1' {
		event.CommitOutcome = &CommitOutcome{AgentAuthoredRatio: 1, CodingMode: CodingModeVibe}
	}
	if len(state) > 10 && state[10] == '1' {
		if event.CommitOutcome == nil {
			event.CommitOutcome = &CommitOutcome{}
		}
		event.CommitOutcome.NewVulnerabilities = 1
	}
	if len(state) > 11 && state[11] == '1' {
		event.ToolCategory = ToolCategoryAskUser
	}
	if len(state) > 13 && state[13] == '1' {
		event.ToolCategory = ToolCategoryEnterPlan
	}
	return event, nil
}

func (CodingAbstraction) ValidTransition(from, to string) bool {
	return true
}

func (CodingAbstraction) StateInterpretation(states []string) map[string]map[string]bool {
	names := []string{
		"user_prompt",
		"agent_reply",
		"tool_call",
		"write_operation",
		"shell_operation",
		"git_operation",
		"failed_tool",
		"user_pushback",
		"commit",
		"agent_authored_commit",
		"vulnerability_introduced",
		"agent_asked_user",
		"hard_interruption",
		"plan_mode_boundary",
	}
	result := make(map[string]map[string]bool, len(states))
	for _, state := range states {
		interpretation := make(map[string]bool, len(names))
		for i, name := range names {
			interpretation[name] = i < len(state) && state[i] == '1'
		}
		result[state] = interpretation
	}
	return result
}

// UnsafeStates returns model state indexes that match the supplied predicate.
func UnsafeStates(stateIndex map[string]int, match func(state string) bool) map[int]struct{} {
	unsafe := map[int]struct{}{}
	for state, index := range stateIndex {
		if match(state) {
			unsafe[index] = struct{}{}
		}
	}
	return unsafe
}

// IsFailureState is a reasonable default unsafe predicate for coding-agent
// replay: failed tools, user pushback, or newly introduced vulnerabilities.
func IsFailureState(state string) bool {
	return (len(state) > 6 && state[6] == '1') ||
		(len(state) > 7 && state[7] == '1') ||
		(len(state) > 10 && state[10] == '1') ||
		(len(state) > 12 && state[12] == '1')
}
