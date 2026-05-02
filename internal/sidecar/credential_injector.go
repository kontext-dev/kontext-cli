package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	entries := i.entriesForCommand(command)
	if len(entries) == 0 {
		return nil, nil
	}

	credentials := make([]commandCredential, 0, len(entries))
	for _, entry := range entries {
		value, err := i.resolve(ctx, entry)
		if err != nil || strings.TrimSpace(value) == "" {
			return nil, err
		}
		credentialPath, err := i.writeCredentialFile(entry.EnvVar, value)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, commandCredential{
			envVar: entry.EnvVar,
			path:   credentialPath,
		})
	}

	updated := make(map[string]any, len(input))
	for key, value := range input {
		updated[key] = value
	}
	updated["command"] = prefixCommandWithCredentials(command, credentials)
	return updated, nil
}

func (i *credentialInjector) entriesForCommand(command string) []credential.Entry {
	var matches []credential.Entry
	for _, entry := range i.entries {
		if entry.EnvVar != "" && looksLikeProviderCommand(command, entry.Provider) {
			matches = append(matches, entry)
		}
	}
	return matches
}

func (i *credentialInjector) writeCredentialFile(envVar, value string) (string, error) {
	dir := filepath.Join(i.sessionDir, "credentials")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create credential dir: %w", err)
	}
	path := filepath.Join(dir, safeCredentialFileName(envVar))
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		return "", fmt.Errorf("write credential file: %w", err)
	}
	return path, nil
}

type commandCredential struct {
	envVar string
	path   string
}

func prefixCommandWithCredentials(command string, credentials []commandCredential) string {
	prefixes := make([]string, 0, len(credentials))
	for _, item := range credentials {
		prefixes = append(prefixes, fmt.Sprintf(
			"export %s=\"$(cat %s)\"",
			shellQuoteAssignmentName(item.envVar),
			shellQuote(item.path),
		))
	}
	if len(prefixes) == 0 {
		return command
	}
	return strings.Join(prefixes, "; ") + "; " + command
}

func shellQuoteAssignmentName(value string) string {
	if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(value) {
		return value
	}
	sum := sha256.Sum256([]byte(value))
	return "KONTEXT_MANAGED_TOKEN_" + strings.ToUpper(hex.EncodeToString(sum[:6]))
}

func safeCredentialFileName(envVar string) string {
	return shellQuoteAssignmentName(envVar)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func looksLikeGitHubCommand(command string) bool {
	lower := strings.ToLower(command)
	return strings.Contains(lower, "github.com") ||
		strings.Contains(lower, "api.github.com") ||
		regexp.MustCompile(`(^|[;&|()\s])gh(\s|$)`).MatchString(lower)
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
		return false
	}
}
