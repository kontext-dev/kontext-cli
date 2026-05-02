package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

const gitContextTimeout = 500 * time.Millisecond

type localGitContext struct {
	WorktreeRoot string            `json:"worktree_root,omitempty"`
	Branch       string            `json:"branch,omitempty"`
	Remotes      map[string]string `json:"remotes,omitempty"`
}

func enrichToolInputWithLocalContext(ctx context.Context, req *EvaluateRequest) {
	if req.HookEvent != "PreToolUse" || req.ToolName != "Bash" || len(req.ToolInput) == 0 {
		return
	}

	var input map[string]any
	if err := json.Unmarshal(req.ToolInput, &input); err != nil {
		return
	}
	delete(input, "kontext")

	gitCtx, ok := collectLocalGitContext(ctx, req.CWD)
	if ok {
		input["kontext"] = map[string]any{"git": gitCtx}
	}

	data, err := json.Marshal(input)
	if err != nil {
		return
	}
	req.ToolInput = data
}

func collectLocalGitContext(ctx context.Context, cwd string) (localGitContext, bool) {
	ctx, cancel := context.WithTimeout(ctx, gitContextTimeout)
	defer cancel()

	root, ok := runGit(ctx, cwd, "rev-parse", "--show-toplevel")
	if !ok || root == "" {
		return localGitContext{}, false
	}

	branch, _ := runGit(ctx, cwd, "branch", "--show-current")
	remoteLines, _ := runGit(ctx, cwd, "remote", "-v")
	remotes := parseGitRemotes(remoteLines)

	return localGitContext{
		WorktreeRoot: root,
		Branch:       branch,
		Remotes:      remotes,
	}, true
}

func runGit(ctx context.Context, cwd string, args ...string) (string, bool) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", false
	}
	return strings.TrimSpace(stdout.String()), true
}

func parseGitRemotes(output string) map[string]string {
	remotes := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, exists := remotes[fields[0]]; exists {
			continue
		}
		if sanitized := sanitizeGitRemote(fields[1]); sanitized != "" {
			remotes[fields[0]] = sanitized
		}
	}
	if len(remotes) == 0 {
		return nil
	}
	return remotes
}

func sanitizeGitRemote(raw string) string {
	if strings.HasPrefix(raw, "git@github.com:") {
		return "https://github.com/" + strings.TrimPrefix(raw, "git@github.com:")
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if !strings.EqualFold(parsed.Hostname(), "github.com") {
		return ""
	}

	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
