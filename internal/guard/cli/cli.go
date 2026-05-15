package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cli/browser"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	"github.com/kontext-security/kontext-cli/internal/guard/markov"
	"github.com/kontext-security/kontext-cli/internal/guard/modelsnapshot"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/guard/trace"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

const (
	defaultBaseURL   = "http://" + server.DefaultAddr
	defaultModelPath = "models/guard/coding-agent-v0.json"

	hooksUsage  = "usage: kontext guard hooks install claude-code | kontext guard hooks uninstall claude-code"
	tracesUsage = "usage: kontext guard traces inspect"
	modelUsage  = "usage: kontext guard model info|train"
)

// Run executes the Kontext command line.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stdout)
		return nil
	}
	switch args[0] {
	case "start", "daemon":
		return runDaemon(args[1:], stdout)
	case "stop":
		fmt.Fprintln(stdout, "Stop the foreground `kontext guard start` process with Ctrl-C.")
		return nil
	case "status":
		return runStatus(ctx, args[1:], stdout)
	case "dashboard":
		return runDashboard(args[1:], stdout)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout)
	case "hooks":
		return runHooks(args[1:], stdout)
	case "traces":
		return runTraces(ctx, args[1:], stdout)
	case "model":
		return runModel(args[1:], stdout)
	case "smoke-test":
		return runSmokeTest(ctx, args[1:], stdout)
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "Kontext Guard")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "commands:")
	fmt.Fprintln(out, "  start                         Run the local daemon on 127.0.0.1:4765")
	fmt.Fprintln(out, "  stop                          Print stop instructions")
	fmt.Fprintln(out, "  status                        Print local dashboard counters")
	fmt.Fprintln(out, "  dashboard                     Print dashboard URL")
	fmt.Fprintln(out, "  doctor                        Check local daemon health")
	fmt.Fprintln(out, "  hooks install claude-code     Install Claude Code hooks")
	fmt.Fprintln(out, "  hooks uninstall claude-code   Remove Claude Code hooks")
	fmt.Fprintln(out, "  traces inspect                Inspect local trace summary")
	fmt.Fprintln(out, "  model info                    Print baseline model info")
	fmt.Fprintln(out, "  model train                   Train a local fixture model")
}

func runDaemon(args []string, out io.Writer) error {
	defaultThreshold, err := envFloat("KONTEXT_THRESHOLD", 0.5)
	if err != nil {
		return err
	}
	defaultHorizon, err := envInt("KONTEXT_HORIZON", 5)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", envString("KONTEXT_ADDR", server.DefaultAddr), "listen address")
	dbPath := fs.String("db", envString("KONTEXT_DB", defaultDBPath()), "SQLite database path")
	modelPath := fs.String("model", envString("KONTEXT_MODEL", defaultModelPath), "optional Markov-chain model path")
	threshold := fs.Float64("threshold", defaultThreshold, "Markov-chain risk threshold")
	horizon := fs.Int("horizon", defaultHorizon, "Markov-chain risk horizon")
	skipHookInstall := fs.Bool("skip-hook-install", false, "skip Claude Code hook install")
	noOpen := fs.Bool("no-open", false, "do not open the local dashboard")
	socketPath := fs.String("socket", defaultGuardSocketPath(), "Unix socket path for local hook runtime")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*skipHookInstall {
		if err := verifyClaudeCode(); err != nil {
			return err
		}
		if err := installClaudeHooks(out, *socketPath); err != nil {
			return err
		}
	}
	var scorer risk.Scorer = risk.NoopScorer{}
	activeModelPath := *modelPath
	if *modelPath != "" {
		snapshot, err := modelsnapshot.NewWithValidator(defaultModelSnapshotDir(*dbPath), risk.ValidateMarkovModel).ActivateFromFile(*modelPath)
		if err != nil {
			return err
		}
		activeModelPath = snapshot.Path
		loaded, err := risk.LoadMarkovScorer(activeModelPath, *threshold, *horizon)
		if err != nil {
			return err
		}
		scorer = loaded
	}
	localServer, closeStore, err := server.OpenDefaultServer(*dbPath, scorer)
	if err != nil {
		return err
	}
	defer func() {
		_ = closeStore()
	}()
	if err := ensureGuardSocketDir(*socketPath); err != nil {
		return err
	}
	runtimeService, err := localruntime.NewService(localruntime.Options{
		SocketPath:  *socketPath,
		Core:        localServer.RuntimeCore(),
		AgentName:   "claude",
		AsyncIngest: true,
		Diagnostic:  diagnostic.New(out, diagnostic.EnabledFromEnv()),
	})
	if err != nil {
		return err
	}
	if err := runtimeService.Start(context.Background()); err != nil {
		return fmt.Errorf("local runtime start: %w", err)
	}
	defer runtimeService.Stop()
	fmt.Fprintf(out, "Kontext Guard local daemon listening on http://%s\n", *addr)
	fmt.Fprintf(out, "Hook runtime: unix://%s\n", *socketPath)
	fmt.Fprintln(out, "Mode: observe (Claude Code runs normally; decisions are recorded as would allow / would ask / would deny).")
	fmt.Fprintf(out, "Dashboard: http://%s\n", *addr)
	fmt.Fprintf(out, "Risk model: %s\n", activeModelPath)
	if !*noOpen {
		_ = browser.OpenURL("http://" + *addr)
	}
	return localServer.ListenAndServe(*addr)
}

func verifyClaudeCode() error {
	if _, err := exec.LookPath("claude"); err != nil {
		return fmt.Errorf("Claude Code was not found on PATH; install Claude Code or run with --skip-hook-install")
	}
	return nil
}

func runStatus(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	baseURL := fs.String("daemon-url", envString("KONTEXT_DAEMON_URL", defaultBaseURL), "local daemon URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	summary, err := fetchSummary(ctx, *baseURL)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Kontext Guard active")
	fmt.Fprintf(out, "%d critical\n", summary.Critical)
	fmt.Fprintf(out, "%d warnings\n", summary.Warnings)
	fmt.Fprintf(out, "%d actions\n", summary.Actions)
	fmt.Fprintf(out, "Dashboard: %s\n", *baseURL)
	return nil
}

func runDashboard(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	baseURL := fs.String("daemon-url", envString("KONTEXT_DAEMON_URL", defaultBaseURL), "local daemon URL")
	noOpen := fs.Bool("no-open", false, "print URL without opening a browser")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s\n", *baseURL)
	if !*noOpen {
		_ = browser.OpenURL(*baseURL)
	}
	return nil
}

func fetchSummary(ctx context.Context, baseURL string) (sqlite.Summary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/summary", nil)
	if err != nil {
		return sqlite.Summary{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return sqlite.Summary{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sqlite.Summary{}, fmt.Errorf("daemon returned %s", resp.Status)
	}
	var summary sqlite.Summary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return sqlite.Summary{}, err
	}
	return summary, nil
}

func runDoctor(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	baseURL := fs.String("daemon-url", envString("KONTEXT_DAEMON_URL", defaultBaseURL), "local daemon URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	PrintHookStatus(out)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("local daemon is not reachable at %s: %w", *baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("local daemon health returned %s", resp.Status)
	}
	fmt.Fprintf(out, "Kontext Guard daemon healthy at %s\n", *baseURL)
	return nil
}

func PrintHookStatus(out io.Writer) {
	settingsPath, settings, err := readClaudeSettings()
	if err != nil {
		fmt.Fprintf(out, "Claude Code hooks: unavailable (%v)\n", err)
		return
	}
	fmt.Fprintf(out, "Claude Code settings: %s\n", settingsPath)
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok || len(hooks) == 0 {
		fmt.Fprintln(out, "Claude Code hooks: none installed")
		return
	}
	hosted := false
	guard := false
	for _, raw := range hooks {
		for _, command := range hookCommands(raw) {
			switch {
			case isGuardHookCommand(command):
				guard = true
				fmt.Fprintf(out, "Claude Code Guard hook: %s\n", command)
			case strings.Contains(command, "kontext hook"):
				hosted = true
				fmt.Fprintf(out, "Claude Code hosted hook: %s\n", command)
			}
		}
	}
	if guard && hosted {
		fmt.Fprintln(out, "Claude Code hook mode: conflict (hosted and Guard hooks are both installed)")
		return
	}
	if guard {
		fmt.Fprintln(out, "Claude Code hook mode: local Guard")
		return
	}
	if hosted {
		fmt.Fprintln(out, "Claude Code hook mode: hosted")
		return
	}
	fmt.Fprintln(out, "Claude Code hook mode: no Kontext hook detected")
}

func hookCommands(raw any) []string {
	groups, ok := raw.([]any)
	if !ok {
		return nil
	}
	var commands []string
	for _, group := range groups {
		groupMap, ok := group.(map[string]any)
		if !ok {
			continue
		}
		hooks, ok := groupMap["hooks"].([]any)
		if !ok {
			continue
		}
		for _, hook := range hooks {
			hookMap, ok := hook.(map[string]any)
			if !ok {
				continue
			}
			if command, ok := hookMap["command"].(string); ok {
				commands = append(commands, command)
			}
		}
	}
	return commands
}

func runHooks(args []string, out io.Writer) error {
	if len(args) < 2 || args[1] != "claude-code" {
		return fmt.Errorf(hooksUsage)
	}
	switch args[0] {
	case "install":
		fs := flag.NewFlagSet("hooks install claude-code", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		socketPath := fs.String("socket", defaultGuardSocketPath(), "Unix socket path for local hook runtime")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		return installClaudeHooks(out, *socketPath)
	case "uninstall":
		if len(args) != 2 {
			return fmt.Errorf(hooksUsage)
		}
		return uninstallClaudeHooks(out)
	default:
		return fmt.Errorf(hooksUsage)
	}
}

func installClaudeHooks(out io.Writer, socketPath string) error {
	settingsPath, settings, err := readClaudeSettings()
	if err != nil {
		return err
	}
	if err := backupFile(settingsPath, "kontext-guard"); err != nil {
		return err
	}
	hookCommand := installedHookCommand(socketPath)
	settings["hooks"] = mergeHooks(settings["hooks"], hookCommand)
	if err := writeJSONFile(settingsPath, settings); err != nil {
		return err
	}
	fmt.Fprintf(out, "Installed Kontext Guard Claude Code hooks into %s\n", settingsPath)
	fmt.Fprintf(out, "Hook command: %s\n", hookCommand)
	fmt.Fprintln(out, "Default mode is observe. Set KONTEXT_MODE=enforce later to block ask/deny decisions.")
	return nil
}

func uninstallClaudeHooks(out io.Writer) error {
	settingsPath, settings, err := readClaudeSettings()
	if err != nil {
		return err
	}
	if err := backupFile(settingsPath, "kontext-guard"); err != nil {
		return err
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		fmt.Fprintf(out, "No Claude Code hooks found in %s\n", settingsPath)
		return nil
	}
	for hookName, raw := range hooks {
		list, ok := raw.([]any)
		if !ok {
			continue
		}
		filtered := make([]any, 0, len(list))
		for _, entry := range list {
			if !isGuardHookEntry(entry) {
				filtered = append(filtered, entry)
			}
		}
		hooks[hookName] = filtered
	}
	if err := writeJSONFile(settingsPath, settings); err != nil {
		return err
	}
	fmt.Fprintf(out, "Removed Kontext Guard Claude Code hooks from %s\n", settingsPath)
	return nil
}

func readClaudeSettings() (string, map[string]any, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil, err
	}
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		return "", nil, err
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")
	settings := map[string]any{}
	raw, err := os.ReadFile(settingsPath)
	if err == nil {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return "", nil, fmt.Errorf("parse Claude settings: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return "", nil, err
	}
	return settingsPath, settings, nil
}

func backupFile(path, label string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	backupPath := fmt.Sprintf("%s.%s-backup-%s", path, label, time.Now().UTC().Format("20060102T150405Z"))
	input, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(backupPath, input, 0o644)
}

func writeJSONFile(path string, value any) error {
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')
	return os.WriteFile(path, bytes, 0o644)
}

func mergeHooks(raw any, hookCommand string) map[string]any {
	hooks, ok := raw.(map[string]any)
	if !ok {
		hooks = map[string]any{}
	}
	for _, hookName := range []string{"PreToolUse", "PostToolUse", "UserPromptSubmit"} {
		var list []any
		if existing, ok := hooks[hookName].([]any); ok {
			for _, entry := range existing {
				if !isGuardHookEntry(entry) {
					list = append(list, entry)
				}
			}
		}
		if len(list) == 0 {
			delete(hooks, hookName)
			continue
		}
		hooks[hookName] = list
	}
	for _, hookName := range []string{"PreToolUse", "PostToolUse"} {
		var list []any
		if existing, ok := hooks[hookName].([]any); ok {
			list = append(list, existing...)
		}
		list = append(list, map[string]any{
			"matcher": "*",
			"hooks": []any{
				map[string]any{
					"type":    "command",
					"command": hookCommand,
				},
			},
		})
		hooks[hookName] = list
	}
	return hooks
}

func isGuardHookEntry(entry any) bool {
	return isGuardHookCommand(fmt.Sprintf("%v", entry))
}

func isGuardHookCommand(command string) bool {
	normalized := strings.ReplaceAll(command, "'", "")
	return strings.Contains(normalized, "kontext guard hook claude-code") ||
		(strings.Contains(normalized, "kontext hook --agent claude") && strings.Contains(normalized, "--mode"))
}

func runSmokeTest(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("smoke-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "kontext-guard-smoke-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	store, err := sqlite.OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		return err
	}
	defer store.Close()
	localServer, err := server.NewServer(store, risk.NoopScorer{})
	if err != nil {
		return err
	}
	socketPath := filepath.Join(dir, "kontext.sock")
	runtimeService, err := localruntime.NewService(localruntime.Options{
		SocketPath:  socketPath,
		Core:        localServer.RuntimeCore(),
		AgentName:   "claude",
		AsyncIngest: true,
		Diagnostic:  diagnostic.New(io.Discard, false),
	})
	if err != nil {
		return err
	}
	if err := runtimeService.Start(ctx); err != nil {
		return err
	}
	defer runtimeService.Stop()
	client := localruntime.NewClient(socketPath)
	cases := []struct {
		name string
		ev   hook.Event
		want hook.Decision
	}{
		{"safe read", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Read", ToolInput: map[string]any{"file_path": "README.md"}}, hook.DecisionAllow},
		{"env read", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Read", ToolInput: map[string]any{"file_path": ".env"}}, hook.DecisionAsk},
		{"cat env", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": "cat .env"}}, hook.DecisionAsk},
		{"provider token", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": "curl https://api.railway.app/graphql -H 'Authorization: Bearer secret'"}}, hook.DecisionDeny},
		{"drop database", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": "drop database"}}, hook.DecisionDeny},
	}
	for _, item := range cases {
		result, err := client.Process(ctx, item.ev)
		if err != nil {
			return fmt.Errorf("%s: %w", item.name, err)
		}
		if result.Decision != item.want {
			return fmt.Errorf("%s: decision=%s want=%s", item.name, result.Decision, item.want)
		}
		fmt.Fprintf(out, "ok %-16s -> %s\n", item.name, result.Decision)
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return err
	}
	if summary.Actions != 5 || summary.Warnings != 2 || summary.Critical != 2 {
		return fmt.Errorf("summary=%+v, want actions=5 warnings=2 critical=2", summary)
	}
	fmt.Fprintf(out, "summary critical=%d warnings=%d actions=%d\n", summary.Critical, summary.Warnings, summary.Actions)
	return nil
}

func runTraces(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf(tracesUsage)
	}
	switch args[0] {
	case "inspect":
		return runStatus(ctx, args[1:], out)
	default:
		return fmt.Errorf(tracesUsage)
	}
}

func runModel(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf(modelUsage)
	}
	switch args[0] {
	case "info":
		info, err := modelInfo(defaultModelPath)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, info)
		return nil
	case "train":
		return runTrainFixtureModel(args[1:], out)
	default:
		return fmt.Errorf(modelUsage)
	}
}

func modelInfo(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	model, err := markov.ReadModelJSON(file)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s: %d states", path, len(model.States)), nil
}

func runTrainFixtureModel(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("model train", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	inputPath := fs.String("input", "internal/trace/testdata/coding_sessions.jsonl", "fixture JSONL path")
	outputPath := fs.String("out", "models/generated/local-model.json", "model output path")
	alpha := fs.Float64("alpha", 1, "Markov smoothing alpha")
	if err := fs.Parse(args); err != nil {
		return err
	}
	file, err := os.Open(*inputPath)
	if err != nil {
		return err
	}
	defer file.Close()
	events, err := trace.ReadJSONL(file)
	if err != nil {
		return err
	}
	sessions := trace.GroupSessions(events)
	model, err := markov.BuildModel(trace.Observations(sessions), trace.CodingAbstraction{}, markov.BuildOptions{Alpha: *alpha})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*outputPath), 0o755); err != nil {
		return err
	}
	outFile, err := os.Create(*outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()
	if err := markov.WriteModelJSON(outFile, model); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s from %d events, %d sessions, %d states\n", *outputPath, len(events), len(sessions), len(model.States))
	return nil
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer: %w", key, err)
		}
		return parsed, nil
	}
	return fallback, nil
}

func envFloat(key string, fallback float64) (float64, error) {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return 0, fmt.Errorf("%s must be a number: %w", key, err)
		}
		return parsed, nil
	}
	return fallback, nil
}

func defaultDBPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "kontext", "guard.db")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".kontext", "guard.db")
	}
	return "kontext-guard.db"
}

func defaultModelSnapshotDir(dbPath string) string {
	if dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "models")
	}
	return filepath.Join(".", "models")
}

func selfPath() string {
	if path, err := os.Executable(); err == nil {
		return path
	}
	return "kontext"
}

func installedHookCommand(socketPath string) string {
	if command := os.Getenv("KONTEXT_GUARD_HOOK_COMMAND"); strings.TrimSpace(command) != "" {
		return command
	}
	if strings.TrimSpace(socketPath) == "" {
		socketPath = defaultGuardSocketPath()
	}
	path := selfPath()
	if strings.Contains(path, "go-build") {
		if cwd, err := os.Getwd(); err == nil {
			if _, statErr := os.Stat(filepath.Join(cwd, "cmd", "kontext")); statErr == nil {
				return fmt.Sprintf("cd %s && %s", shellQuote(cwd), installedHookInvocation("go run ./cmd/kontext", socketPath))
			}
		}
	}
	return installedHookInvocation(shellQuote(path), socketPath)
}

func installedHookInvocation(launcher, socketPath string) string {
	return fmt.Sprintf("%s hook --agent claude --mode \"${KONTEXT_MODE:-observe}\" --socket %s", launcher, shellQuote(socketPath))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
