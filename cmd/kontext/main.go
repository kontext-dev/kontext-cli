package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/auth"
	"github.com/kontext-security/kontext-cli/internal/backend"
	guardcli "github.com/kontext-security/kontext-cli/internal/guard/cli"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/run"
	"github.com/kontext-security/kontext-cli/internal/sidecar"
	"github.com/kontext-security/kontext-cli/internal/update"

	_ "github.com/kontext-security/kontext-cli/internal/agent/claude"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:     "kontext",
		Short:   "Kontext CLI — governed agent sessions",
		Version: version,
	}

	root.AddCommand(startCmd())
	root.AddCommand(loginCmd())
	root.AddCommand(logoutCmd())
	root.AddCommand(hookCmd())
	root.AddCommand(doctorCmd())
	root.AddCommand(guardCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Inspect local Kontext CLI setup",
		RunE: func(cmd *cobra.Command, args []string) error {
			guardcli.PrintHookStatus(cmd.OutOrStdout())
			return nil
		},
	}
}

func guardCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "guard",
		Short:              "Run local-only Kontext Guard mode",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return guardcli.Run(context.Background(), args, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
}

func startCmd() *cobra.Command {
	var (
		agentName    string
		templateFile string
		verbose      bool
	)

	cmd := &cobra.Command{
		Use:   "start [flags] [-- extra-agent-args...]",
		Short: "Launch an agent with Kontext governance",
		RunE: func(cmd *cobra.Command, args []string) error {
			if isInteractivePrompt() {
				if latest := update.Available(version); latest != "" {
					upgraded, _ := update.PromptAndUpgrade(os.Stdin, os.Stderr, version, latest)
					if upgraded {
						return nil
					}
				}
			} else {
				update.CheckAsync(version)
			}
			ctx := context.Background()
			err := run.Start(ctx, run.Options{
				Agent:        agentName,
				TemplateFile: templateFile,
				IssuerURL:    backend.BaseURL(),
				ClientID:     auth.DefaultClientID,
				Verbose:      verbose,
				Args:         args,
			})
			if exitErr, ok := err.(*run.AgentExitError); ok {
				fmt.Fprintf(os.Stderr, "Error: %v\n", exitErr)
				os.Exit(exitErr.ExitCode())
			}
			return err
		},
	}

	cmd.Flags().StringVar(&agentName, "agent", "claude", "Agent to launch (currently: claude)")
	cmd.Flags().StringVar(&templateFile, "env-template", ".env.kontext", "Path to env template file")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show redacted diagnostic output")

	return cmd
}

func loginCmd() *cobra.Command {
	var issuerURL, clientID string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Kontext via browser",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			result, err := auth.Login(ctx, issuerURL, clientID)
			if err != nil {
				return fmt.Errorf("login failed: %w", err)
			}

			if err := auth.SaveSession(result.Session); err != nil {
				return fmt.Errorf("save session: %w", err)
			}

			if display := result.Session.DisplayIdentity(); display != "" {
				fmt.Fprintf(os.Stderr, "Logged in as %s\n", display)
			} else {
				fmt.Fprintln(os.Stderr, "Logged in.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&issuerURL, "issuer-url", auth.DefaultIssuerURL, "OIDC issuer URL")
	cmd.Flags().StringVar(&clientID, "client-id", auth.DefaultClientID, "OAuth client ID")

	return cmd
}

func logoutCmd() *cobra.Command {
	return newLogoutCmd(auth.ClearSession)
}

func newLogoutCmd(clearSession func() error) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out and clear stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := clearSession(); err != nil {
				if errors.Is(err, keyring.ErrNotFound) {
					return errors.New("already logged out")
				}
				return fmt.Errorf("logout failed: %w", err)
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Logged out successfully.")
			return nil
		},
	}
}

func hookCmd() *cobra.Command {
	var agentName string

	cmd := &cobra.Command{
		Use:    "hook",
		Short:  "Process a hook event (called by the agent, not by users)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, ok := agent.Get(agentName)
			if !ok {
				fmt.Fprintf(os.Stderr, "unknown agent: %s\n", agentName)
				os.Exit(2)
			}

			socketPath := os.Getenv("KONTEXT_SOCKET")
			if socketPath == "" {
				hook.Run(a, func(e *agent.HookEvent) (hookruntime.Result, error) {
					return hookruntime.Result{Decision: hookruntime.DecisionAllow, Reason: "no sidecar"}, nil
				})
				return nil
			}

			hook.Run(a, func(e *agent.HookEvent) (hookruntime.Result, error) {
				return evaluateViaSidecar(socketPath, hookruntime.EventFromAgent(agentName, e))
			})
			return nil
		},
	}

	cmd.Flags().StringVar(&agentName, "agent", "claude", "Agent type")

	return cmd
}

func evaluateViaSidecar(socketPath string, event hookruntime.Event) (hookruntime.Result, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return sidecarFailureResult(event, "sidecar unreachable"), nil
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return sidecarFailureResult(event, "sidecar deadline error"), nil
	}

	req := sidecar.EvaluateRequest{
		Type:           "evaluate",
		Agent:          event.Agent,
		HookEvent:      event.HookEventName,
		ToolName:       event.ToolName,
		ToolUseID:      event.ToolUseID,
		CWD:            event.CWD,
		PermissionMode: event.PermissionMode,
		DurationMs:     event.DurationMs,
		Error:          event.Error,
		IsInterrupt:    event.IsInterrupt,
	}

	if event.ToolInput != nil {
		data, err := hookruntime.MarshalMap(event.ToolInput)
		if err != nil {
			return sidecarFailureResult(event, "sidecar marshal error"), nil
		}
		req.ToolInput = data
	}
	if event.ToolResponse != nil {
		data, err := hookruntime.MarshalMap(event.ToolResponse)
		if err != nil {
			return sidecarFailureResult(event, "sidecar marshal error"), nil
		}
		req.ToolResponse = data
	}

	if err := sidecar.WriteMessage(conn, req); err != nil {
		return sidecarFailureResult(event, "sidecar write error"), nil
	}

	var result sidecar.EvaluateResult
	if err := sidecar.ReadMessage(conn, &result); err != nil {
		return sidecarFailureResult(event, "sidecar read error"), nil
	}

	decision := hookruntime.Decision(result.Decision)
	if decision == "" {
		decision = hookruntime.ResultFromBool(result.Allowed, result.Reason).Decision
	}
	return hookruntime.Result{
		Decision:     decision,
		Reason:       result.Reason,
		ReasonCode:   result.ReasonCode,
		RequestID:    result.RequestID,
		Mode:         result.Mode,
		Epoch:        result.Epoch,
		UpdatedInput: result.UpdatedInput,
	}, nil
}

func sidecarFailureResult(event hookruntime.Event, reason string) hookruntime.Result {
	if event.HookEventName == "PreToolUse" && currentHostedAccessMode() == "enforce" {
		return hookruntime.Result{Decision: hookruntime.DecisionDeny, Reason: reason, Mode: "enforce"}
	}
	return hookruntime.Result{Decision: hookruntime.DecisionAllow, Reason: reason}
}

func currentHostedAccessMode() string {
	if path := os.Getenv("KONTEXT_ACCESS_MODE_PATH"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return os.Getenv("KONTEXT_ACCESS_MODE")
}

// isInteractivePrompt reports whether both stdin (where the answer is read)
// and stderr (where the prompt is written) are terminals. If either is
// redirected, the user cannot meaningfully answer the prompt, so we fall
// back to the passive async notification.
func isInteractivePrompt() bool {
	return isCharDevice(os.Stdin) && isCharDevice(os.Stderr)
}

func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
