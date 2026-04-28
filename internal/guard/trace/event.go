package trace

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// Event is the package's canonical historical trace unit.
//
// Source datasets should be adapted into this shape before learning a Markov-chain model.
// The fields intentionally capture behavior that matters for proactive
// evaluation rather than preserving every source-specific column.
type Event struct {
	SessionID     string         `json:"session_id"`
	CheckpointID  string         `json:"checkpoint_id,omitempty"`
	Repository    string         `json:"repository,omitempty"`
	Agent         string         `json:"agent,omitempty"`
	TurnID        string         `json:"turn_id,omitempty"`
	Step          int            `json:"step"`
	Timestamp     time.Time      `json:"timestamp,omitempty"`
	Actor         Actor          `json:"actor"`
	Kind          Kind           `json:"kind"`
	ToolName      string         `json:"tool_name,omitempty"`
	ToolCategory  ToolCategory   `json:"tool_category,omitempty"`
	ToolStatus    ToolStatus     `json:"tool_status,omitempty"`
	PromptIntent  PromptIntent   `json:"prompt_intent,omitempty"`
	PushbackType  PushbackType   `json:"pushback_type,omitempty"`
	FilesChanged  int            `json:"files_changed,omitempty"`
	LinesAdded    int            `json:"lines_added,omitempty"`
	LinesDeleted  int            `json:"lines_deleted,omitempty"`
	TokensInput   int            `json:"tokens_input,omitempty"`
	TokensOutput  int            `json:"tokens_output,omitempty"`
	TokensCache   int            `json:"tokens_cache,omitempty"`
	CostUSD       float64        `json:"cost_usd,omitempty"`
	DurationMS    int64          `json:"duration_ms,omitempty"`
	CommitOutcome *CommitOutcome `json:"commit_outcome,omitempty"`
	Annotations   *Annotations   `json:"annotations,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type Actor string

const (
	ActorUser  Actor = "user"
	ActorAgent Actor = "agent"
	ActorTool  Actor = "tool"
	ActorOther Actor = "other"
)

type Kind string

const (
	KindPrompt    Kind = "prompt"
	KindReply     Kind = "reply"
	KindTool      Kind = "tool"
	KindEdit      Kind = "edit"
	KindCommit    Kind = "commit"
	KindReview    Kind = "review"
	KindInterrupt Kind = "interrupt"
	KindUnknown   Kind = "unknown"
)

type ToolStatus string

const (
	ToolStatusUnset   ToolStatus = ""
	ToolStatusSuccess ToolStatus = "success"
	ToolStatusFailure ToolStatus = "failure"
)

type ToolCategory string

const (
	ToolCategoryRead         ToolCategory = "read"
	ToolCategoryGrep         ToolCategory = "grep"
	ToolCategoryGlob         ToolCategory = "glob"
	ToolCategoryBashFile     ToolCategory = "bash:file"
	ToolCategoryBashBuild    ToolCategory = "bash:build"
	ToolCategoryBashNet      ToolCategory = "bash:net"
	ToolCategoryBash         ToolCategory = "bash"
	ToolCategoryGit          ToolCategory = "git/gh"
	ToolCategoryWrite        ToolCategory = "write"
	ToolCategoryEdit         ToolCategory = "edit"
	ToolCategoryWeb          ToolCategory = "web"
	ToolCategoryAgent        ToolCategory = "agent"
	ToolCategoryMCP          ToolCategory = "mcp"
	ToolCategoryTodoWrite    ToolCategory = "TodoWrite"
	ToolCategoryToolSearch   ToolCategory = "ToolSearch"
	ToolCategoryAskUser      ToolCategory = "AskUserQuestion"
	ToolCategorySkill        ToolCategory = "Skill"
	ToolCategoryEnterPlan    ToolCategory = "EnterPlanMode"
	ToolCategoryExitPlan     ToolCategory = "ExitPlanMode"
	ToolCategoryOther        ToolCategory = "other"
	ToolCategoryUnclassified ToolCategory = ""
)

type PromptIntent string

const (
	PromptIntentCreate     PromptIntent = "create new code"
	PromptIntentRefactor   PromptIntent = "refactor"
	PromptIntentDebug      PromptIntent = "debug"
	PromptIntentUnderstand PromptIntent = "understand"
	PromptIntentConnect    PromptIntent = "connect"
	PromptIntentGit        PromptIntent = "git"
	PromptIntentTest       PromptIntent = "test"
	PromptIntentOther      PromptIntent = "other"
)

type PushbackType string

const (
	PushbackNone          PushbackType = ""
	PushbackCorrection    PushbackType = "correction"
	PushbackRejection     PushbackType = "rejection"
	PushbackFailureReport PushbackType = "failure_report"
	PushbackNonPushback   PushbackType = "non_pushback"
)

type Persona string

const (
	PersonaExpertNitpicker Persona = "Expert Nitpicker"
	PersonaVagueRequester  Persona = "Vague Requester"
	PersonaMindChanger     Persona = "Mind Changer"
	PersonaOther           Persona = "Other"
)

type CodingMode string

const (
	CodingModeHumanOnly     CodingMode = "human-only"
	CodingModeCollaborative CodingMode = "collaborative"
	CodingModeVibe          CodingMode = "vibe coding"
)

type CommitOutcome struct {
	CommitSHA                   string     `json:"commit_sha,omitempty"`
	CommittedLines              int        `json:"committed_lines,omitempty"`
	AgentAuthoredRatio          float64    `json:"agent_authored_ratio,omitempty"`
	AgentLinesProduced          int        `json:"agent_lines_produced,omitempty"`
	AgentLinesSurvived          int        `json:"agent_lines_survived,omitempty"`
	AgentLinesFinal             int        `json:"agent_lines_final,omitempty"`
	AgentSelfOverwriteLines     int        `json:"agent_self_overwrite_lines,omitempty"`
	HumanOverwriteLines         int        `json:"human_overwrite_lines,omitempty"`
	HumanDeletionLines          int        `json:"human_deletion_lines,omitempty"`
	NewVulnerabilities          int        `json:"new_vulnerabilities,omitempty"`
	FixedVulnerabilities        int        `json:"fixed_vulnerabilities,omitempty"`
	IntroducedVulnerabilityCWEs []string   `json:"introduced_vulnerability_cwes,omitempty"`
	CodingMode                  CodingMode `json:"coding_mode,omitempty"`
}

type Annotations struct {
	SessionSuccessScore int          `json:"session_success_score,omitempty"`
	Persona             Persona      `json:"persona,omitempty"`
	RepositoryDomain    string       `json:"repository_domain,omitempty"`
	RepositoryAudience  string       `json:"repository_audience,omitempty"`
	PushbackType        PushbackType `json:"pushback_type,omitempty"`
	PromptIntent        PromptIntent `json:"prompt_intent,omitempty"`
}

// Session is one ordered coding-agent interaction trace.
type Session struct {
	ID                 string         `json:"id"`
	Repository         string         `json:"repository,omitempty"`
	Agent              string         `json:"agent,omitempty"`
	CheckpointIDs      []string       `json:"checkpoint_ids,omitempty"`
	SuccessScore       int            `json:"success_score,omitempty"`
	Persona            Persona        `json:"persona,omitempty"`
	CodingMode         CodingMode     `json:"coding_mode,omitempty"`
	AgentAuthoredRatio float64        `json:"agent_authored_ratio,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	Events             []Event        `json:"events"`
}

// GroupSessions groups flat events by session and sorts each trace by Step.
func GroupSessions(events []Event) []Session {
	byID := map[string][]Event{}
	for _, event := range events {
		byID[event.SessionID] = append(byID[event.SessionID], event)
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	sessions := make([]Session, 0, len(ids))
	for _, id := range ids {
		trace := byID[id]
		sort.SliceStable(trace, func(i, j int) bool {
			if !trace[i].Timestamp.IsZero() && !trace[j].Timestamp.IsZero() && !trace[i].Timestamp.Equal(trace[j].Timestamp) {
				return trace[i].Timestamp.Before(trace[j].Timestamp)
			}
			return trace[i].Step < trace[j].Step
		})
		session := Session{ID: id, Events: trace}
		checkpoints := map[string]struct{}{}
		for _, event := range trace {
			if session.Repository == "" {
				session.Repository = event.Repository
			}
			if session.Agent == "" {
				session.Agent = event.Agent
			}
			if event.CheckpointID != "" {
				checkpoints[event.CheckpointID] = struct{}{}
			}
			if event.Annotations != nil {
				if session.SuccessScore == 0 {
					session.SuccessScore = event.Annotations.SessionSuccessScore
				}
				if session.Persona == "" {
					session.Persona = event.Annotations.Persona
				}
			}
			if event.CommitOutcome != nil {
				if session.CodingMode == "" {
					session.CodingMode = event.CommitOutcome.CodingMode
				}
				if session.AgentAuthoredRatio == 0 {
					session.AgentAuthoredRatio = event.CommitOutcome.AgentAuthoredRatio
				}
			}
		}
		for checkpoint := range checkpoints {
			session.CheckpointIDs = append(session.CheckpointIDs, checkpoint)
		}
		sort.Strings(session.CheckpointIDs)
		sessions = append(sessions, session)
	}
	return sessions
}

// Observations converts sessions into logs suitable for markov.BuildModel.
func Observations(sessions []Session) [][]Event {
	logs := make([][]Event, 0, len(sessions))
	for _, session := range sessions {
		if len(session.Events) == 0 {
			continue
		}
		logs = append(logs, append([]Event(nil), session.Events...))
	}
	return logs
}

// ReadJSONL reads one Event per line.
func ReadJSONL(r io.Reader) ([]Event, error) {
	scanner := bufio.NewScanner(r)
	var events []Event
	line := 0
	for scanner.Scan() {
		line++
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("decode JSONL line %d: %w", line, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// WriteJSONL writes one Event per line.
func WriteJSONL(w io.Writer, events []Event) error {
	encoder := json.NewEncoder(w)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return nil
}
