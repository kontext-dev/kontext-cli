package trace

import (
	"fmt"
	"strings"
)

const RiskAbstractionVersion = "coding-risk-v2"

var RiskUnsafeDefinition = []string{
	"policy_block",
	"failed_tool",
	"hard_interruption",
	"vulnerability_introduced",
	"direct_infrastructure_api_with_managed_credential",
	"unapproved_destructive_persistent_or_production_operation",
}

// RiskCodingAbstraction maps agent trace events into risk-oriented state bits.
//
// Bit layout:
// 0  user_prompt
// 1  agent_reply
// 2  tool_call
// 3  shell_operation
// 4  network_operation
// 5  credential_access
// 6  managed_credential_use
// 7  direct_provider_api_call
// 8  infrastructure_provider
// 9  destructive_operation
// 10 persistent_data_resource
// 11 production_environment
// 12 explicit_user_approval
// 13 policy_ask
// 14 policy_block
// 15 failed_tool
// 16 user_pushback
// 17 hard_interruption
// 18 vulnerability_introduced
// 19 unknown_or_low_confidence
// 20 managed_tool_call
// 21 write_operation
// 22 source_control_provider
// 23 identity_or_docs_provider
type RiskCodingAbstraction struct{}

func (RiskCodingAbstraction) Encode(event Event) (string, error) {
	bits := []byte(strings.Repeat("0", len(riskSignalNames)))
	tool := strings.ToLower(event.ToolName)
	meta := metadataText(event.Metadata)
	text := strings.ToLower(strings.Join([]string{tool, meta, string(event.ToolCategory), string(event.Kind)}, " "))

	set := func(index int) {
		bits[index] = '1'
	}

	if event.Actor == ActorUser || event.Kind == KindPrompt {
		set(riskSignalUserPrompt)
	}
	if event.Actor == ActorAgent || event.Kind == KindReply {
		set(riskSignalAgentReply)
	}
	if event.Kind == KindTool || event.Kind == KindEdit || event.Actor == ActorTool {
		set(riskSignalToolCall)
	}
	if isShellEvent(event, tool) {
		set(riskSignalShellOperation)
	}
	if isNetworkEvent(event, text) {
		set(riskSignalNetworkOperation)
	}
	if isCredentialAccess(event, text) {
		set(riskSignalCredentialAccess)
	}
	if isManagedCredentialUse(event, text) {
		set(riskSignalManagedCredentialUse)
	}
	if isDirectProviderAPICall(event, text) {
		set(riskSignalDirectProviderAPICall)
	}
	if isInfrastructureProvider(text) {
		set(riskSignalInfrastructureProvider)
	}
	if isDestructiveOperation(text) {
		set(riskSignalDestructiveOperation)
	}
	if isPersistentDataResource(text) {
		set(riskSignalPersistentDataResource)
	}
	if strings.Contains(text, "production") || strings.Contains(text, " prod ") {
		set(riskSignalProductionEnvironment)
	}
	if strings.Contains(text, "explicit_user_intent") || strings.Contains(text, "approved_by_user") || strings.Contains(text, "user_approved") {
		set(riskSignalExplicitUserApproval)
	}
	if metadataBool(event.Metadata, "kontext_warn") || strings.Contains(text, "policy_ask") || strings.Contains(text, "permissionDecision:ask") {
		set(riskSignalPolicyAsk)
	}
	if strings.Contains(text, "policy_block") || strings.Contains(text, "permissionDecision:deny") {
		set(riskSignalPolicyBlock)
	}
	if event.ToolStatus == ToolStatusFailure {
		set(riskSignalFailedTool)
	}
	if event.PushbackType == PushbackCorrection || event.PushbackType == PushbackRejection || event.PushbackType == PushbackFailureReport ||
		(event.Annotations != nil && (event.Annotations.PushbackType == PushbackCorrection ||
			event.Annotations.PushbackType == PushbackRejection ||
			event.Annotations.PushbackType == PushbackFailureReport)) {
		set(riskSignalUserPushback)
	}
	if event.Kind == KindInterrupt || (event.Kind == KindUnknown && strings.Contains(tool, "interrupted")) {
		set(riskSignalHardInterruption)
	}
	if event.CommitOutcome != nil && event.CommitOutcome.NewVulnerabilities > 0 {
		set(riskSignalVulnerabilityIntroduced)
	}
	if event.ToolCategory == ToolCategoryUnclassified || strings.Contains(text, "unknown") || event.ToolName == "" && event.Kind == KindTool {
		set(riskSignalUnknownOrLowConfidence)
	}
	if event.ToolCategory == ToolCategoryMCP || strings.Contains(text, "managed_tool_call") || strings.Contains(text, "execute_tool") || strings.Contains(text, "remote_execute_tool") {
		set(riskSignalManagedToolCall)
	}
	if event.Kind == KindEdit || event.ToolCategory == ToolCategoryWrite || event.ToolCategory == ToolCategoryEdit ||
		event.FilesChanged > 0 || event.LinesAdded > 0 || event.LinesDeleted > 0 {
		set(riskSignalWriteOperation)
	}
	if isSourceControlProvider(text) {
		set(riskSignalSourceControlProvider)
	}
	if isIdentityOrDocsProvider(text) {
		set(riskSignalIdentityOrDocsProvider)
	}
	return string(bits), nil
}

func (RiskCodingAbstraction) Decode(state string) (Event, error) {
	event := Event{}
	if bit(state, riskSignalUserPrompt) {
		event.Actor = ActorUser
		event.Kind = KindPrompt
	}
	if bit(state, riskSignalToolCall) {
		event.Actor = ActorTool
		event.Kind = KindTool
	}
	if bit(state, riskSignalFailedTool) {
		event.ToolStatus = ToolStatusFailure
	}
	if bit(state, riskSignalHardInterruption) {
		event.Kind = KindInterrupt
	}
	return event, nil
}

func (RiskCodingAbstraction) ValidTransition(from, to string) bool {
	return true
}

func (RiskCodingAbstraction) StateInterpretation(states []string) map[string]map[string]bool {
	result := make(map[string]map[string]bool, len(states))
	for _, state := range states {
		interpretation := make(map[string]bool, len(riskSignalNames))
		for i, name := range riskSignalNames {
			interpretation[name] = i < len(state) && state[i] == '1'
		}
		result[state] = interpretation
	}
	return result
}

func IsRiskUnsafeState(state string) bool {
	return bit(state, riskSignalPolicyBlock) || bit(state, riskSignalFailedTool) ||
		bit(state, riskSignalHardInterruption) || bit(state, riskSignalVulnerabilityIntroduced) ||
		(bit(state, riskSignalDirectProviderAPICall) && bit(state, riskSignalManagedCredentialUse) && bit(state, riskSignalInfrastructureProvider)) ||
		(bit(state, riskSignalDestructiveOperation) && (bit(state, riskSignalPersistentDataResource) || bit(state, riskSignalProductionEnvironment)) && !bit(state, riskSignalExplicitUserApproval))
}

const (
	riskSignalUserPrompt = iota
	riskSignalAgentReply
	riskSignalToolCall
	riskSignalShellOperation
	riskSignalNetworkOperation
	riskSignalCredentialAccess
	riskSignalManagedCredentialUse
	riskSignalDirectProviderAPICall
	riskSignalInfrastructureProvider
	riskSignalDestructiveOperation
	riskSignalPersistentDataResource
	riskSignalProductionEnvironment
	riskSignalExplicitUserApproval
	riskSignalPolicyAsk
	riskSignalPolicyBlock
	riskSignalFailedTool
	riskSignalUserPushback
	riskSignalHardInterruption
	riskSignalVulnerabilityIntroduced
	riskSignalUnknownOrLowConfidence
	riskSignalManagedToolCall
	riskSignalWriteOperation
	riskSignalSourceControlProvider
	riskSignalIdentityOrDocsProvider
)

var riskSignalNames = []string{
	"user_prompt",
	"agent_reply",
	"tool_call",
	"shell_operation",
	"network_operation",
	"credential_access",
	"managed_credential_use",
	"direct_provider_api_call",
	"infrastructure_provider",
	"destructive_operation",
	"persistent_data_resource",
	"production_environment",
	"explicit_user_approval",
	"policy_ask",
	"policy_block",
	"failed_tool",
	"user_pushback",
	"hard_interruption",
	"vulnerability_introduced",
	"unknown_or_low_confidence",
	"managed_tool_call",
	"write_operation",
	"source_control_provider",
	"identity_or_docs_provider",
}

func bit(state string, index int) bool {
	return len(state) > index && state[index] == '1'
}

func isShellEvent(event Event, tool string) bool {
	return event.ToolCategory == ToolCategoryBash || event.ToolCategory == ToolCategoryBashFile ||
		event.ToolCategory == ToolCategoryBashBuild || event.ToolCategory == ToolCategoryBashNet ||
		strings.Contains(tool, "bash") || strings.Contains(tool, "shell") || strings.Contains(tool, "terminal")
}

func isNetworkEvent(event Event, text string) bool {
	return event.ToolCategory == ToolCategoryBashNet || event.ToolCategory == ToolCategoryWeb ||
		strings.Contains(text, "curl") || strings.Contains(text, "wget") || strings.Contains(text, "http")
}

func isCredentialAccess(event Event, text string) bool {
	return strings.Contains(text, ".env") || strings.Contains(text, ".npmrc") || strings.Contains(text, ".pypirc") ||
		strings.Contains(text, ".netrc") || strings.Contains(text, ".aws") || strings.Contains(text, ".gcloud") ||
		strings.Contains(text, "credential_access")
}

func isManagedCredentialUse(event Event, text string) bool {
	return strings.Contains(text, "credentialkind") || strings.Contains(text, "credential_kind") ||
		strings.Contains(text, "credential_exchange") || strings.Contains(text, "broker_credential") ||
		strings.Contains(text, "authenticated_call") || strings.Contains(text, "provider_token_exchange")
}

func isDirectProviderAPICall(event Event, text string) bool {
	if strings.Contains(text, "direct_provider_api_call") {
		return true
	}
	return isShellEvent(event, strings.ToLower(event.ToolName)) && (strings.Contains(text, "curl") || strings.Contains(text, "authorization") || strings.Contains(text, "bearer"))
}

func isInfrastructureProvider(text string) bool {
	return strings.Contains(text, "railway") || strings.Contains(text, "vercel") || strings.Contains(text, "cloudflare") ||
		strings.Contains(text, "aws") || strings.Contains(text, "googleapis") || strings.Contains(text, "gcloud") ||
		strings.Contains(text, "digitalocean") || strings.Contains(text, "database") || strings.Contains(text, "bucket")
}

func isSourceControlProvider(text string) bool {
	return strings.Contains(text, "github") || strings.Contains(text, "gitlab") || strings.Contains(text, "pull_request") ||
		strings.Contains(text, "repository") || strings.Contains(text, "commit")
}

func isIdentityOrDocsProvider(text string) bool {
	return strings.Contains(text, "notion") || strings.Contains(text, "google") || strings.Contains(text, "slack") ||
		strings.Contains(text, "linear") || strings.Contains(text, "user") || strings.Contains(text, "team")
}

func isDestructiveOperation(text string) bool {
	return strings.Contains(text, "delete") || strings.Contains(text, "destroy") || strings.Contains(text, "drop") ||
		strings.Contains(text, "truncate") || strings.Contains(text, "wipe") || strings.Contains(text, "remove")
}

func isPersistentDataResource(text string) bool {
	return strings.Contains(text, "database") || strings.Contains(text, "volume") || strings.Contains(text, "backup") ||
		strings.Contains(text, "bucket") || strings.Contains(text, "project")
}

func metadataText(metadata map[string]any) string {
	if len(metadata) == 0 {
		return ""
	}
	var b strings.Builder
	for key, value := range metadata {
		fmt.Fprintf(&b, " %s:%v", key, value)
	}
	return b.String()
}

func metadataBool(metadata map[string]any, key string) bool {
	value, ok := metadata[key]
	if !ok {
		return false
	}
	typed, ok := value.(bool)
	return ok && typed
}
