package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/credential"
)

type credentialResolver func(context.Context, credential.Entry) (string, error)

type credentialInjector struct {
	sessionDir string
	entries    []credential.Entry
	resolve    credentialResolver
}

func newCredentialInjector(sessionDir string, entries []credential.Entry, resolve credentialResolver) *credentialInjector {
	if len(entries) == 0 || resolve == nil {
		return nil
	}
	return &credentialInjector{
		sessionDir: sessionDir,
		entries:    entries,
		resolve:    resolve,
	}
}

func (i *credentialInjector) updatedInputForAllowedHook(ctx context.Context, req *EvaluateRequest) (map[string]any, error) {
	if i == nil || req.HookEvent != "PreToolUse" || req.ToolName != "Bash" {
		return nil, nil
	}

	var input map[string]any
	if err := json.Unmarshal(req.ToolInput, &input); err != nil {
		return nil, nil
	}
	command, ok := input["command"].(string)
	if !ok {
		return nil, nil
	}

	entry, ok := i.entryForCommand(command)
	if !ok {
		return nil, nil
	}
	value, err := i.resolve(ctx, entry)
	if err != nil || strings.TrimSpace(value) == "" {
		return nil, err
	}
	credentialPath, err := i.writeCredentialFile(entry.EnvVar, value)
	if err != nil {
		return nil, err
	}

	updated := make(map[string]any, len(input))
	for key, value := range input {
		updated[key] = value
	}
	updated["command"] = prefixCommandWithCredential(command, entry.EnvVar, credentialPath)
	return updated, nil
}

func (i *credentialInjector) entryForCommand(command string) (credential.Entry, bool) {
	for _, entry := range i.entries {
		if entry.EnvVar != "" && looksLikeProviderCommand(command, entry.Provider) {
			return entry, true
		}
	}
	return credential.Entry{}, false
}

func (i *credentialInjector) writeCredentialFile(envVar, value string) (string, error) {
	dir := filepath.Join(i.sessionDir, "credentials")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create credential dir: %w", err)
	}
	path := filepath.Join(dir, envVar)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		return "", fmt.Errorf("write credential file: %w", err)
	}
	return path, nil
}

func prefixCommandWithCredential(command, envVar, credentialPath string) string {
	return fmt.Sprintf(
		"export %s=\"$(cat %s)\"; %s",
		shellQuoteAssignmentName(envVar),
		shellQuote(credentialPath),
		command,
	)
}

func shellQuoteAssignmentName(value string) string {
	if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(value) {
		return value
	}
	return "KONTEXT_MANAGED_TOKEN"
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func looksLikeGitHubCommand(command string) bool {
	lower := strings.ToLower(command)
	return strings.Contains(lower, "github.com") ||
		strings.Contains(lower, "api.github.com") ||
		regexp.MustCompile(`(^|[;&|()\s])gh(\s|$)`).MatchString(lower) ||
		regexp.MustCompile(`(^|[;&|()\s])git\s+(fetch|pull|push|clone|ls-remote|remote|submodule)\b`).MatchString(lower)
}

func looksLikeProviderCommand(command, provider string) bool {
	switch strings.ToLower(provider) {
	case "github":
		return looksLikeGitHubCommand(command)
	case "linear":
		return regexp.MustCompile(`(^|[;&|()\s])linear(\s|$)`).MatchString(strings.ToLower(command))
	case "slack":
		return regexp.MustCompile(`(^|[;&|()\s])slack(\s|$)`).MatchString(strings.ToLower(command))
	default:
		return strings.Contains(strings.ToLower(command), strings.ToLower(provider))
	}
}
