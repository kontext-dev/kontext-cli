package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext-cli/internal/mcpserve"
)

func mcpServeCmd() *cobra.Command {
	var agentName, socketPath string
	cmd := &cobra.Command{
		Use:    "mcp-serve",
		Short:  "Run Kontext as an MCP server (invoked by host agents)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := os.Getenv("KONTEXT_SESSION_ID")
			return mcpserve.Run(cmd.Context(), agentName, socketPath, sessionID)
		},
	}
	cmd.Flags().StringVar(&agentName, "agent", "hermes", "Agent label used for hook events")
	cmd.Flags().StringVar(&socketPath, "socket", "", "Path to Kontext sidecar Unix socket")
	return cmd
}
