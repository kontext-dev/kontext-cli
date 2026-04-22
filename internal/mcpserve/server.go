// Package mcpserve implements `kontext mcp-serve`: an MCP server that bridges
// tool calls to the Kontext sidecar for governance and tracing, and dispatches
// them to registered providers.
package mcpserve

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/kontext-security/kontext-cli/internal/mcpserve/providers"
	"github.com/kontext-security/kontext-cli/internal/sidecar"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type handler struct {
	agent     string
	socket    string
	sessionID string
}

func newHandler(agent, socket, sessionID string) *handler {
	return &handler{agent: agent, socket: socket, sessionID: sessionID}
}

// dispatch runs PreToolUse -> action.Handler -> PostToolUse. Returns the
// JSON-encoded result on allow, or an error containing the deny reason on deny.
func (h *handler) dispatch(ctx context.Context, toolName string, action providers.Action, args map[string]any) (string, error) {
	allowed, reason, err := h.sendHook(ctx, toolName, "PreToolUse", args, nil)
	if err != nil {
		return "", fmt.Errorf("sidecar pre: %w", err)
	}
	if !allowed {
		return "", fmt.Errorf("kontext denied: %s", reason)
	}

	result, err := action.Handler(ctx, args)
	if err != nil {
		// Emit PostToolUse with the error surface so traces still record the failure.
		errResp := map[string]any{"error": err.Error()}
		_, _, _ = h.sendHook(ctx, toolName, "PostToolUse", args, errResp)
		return "", err
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("marshal result: %w", err)
	}

	respMap, _ := result.(map[string]any)
	if respMap == nil {
		// Non-map results (arrays etc.) still need to reach PostToolUse.
		respMap = map[string]any{"result": result}
	}
	_, _, _ = h.sendHook(ctx, toolName, "PostToolUse", args, respMap)

	return string(resultBytes), nil
}

func (h *handler) sendHook(ctx context.Context, toolName, eventName string, toolInput, toolResponse map[string]any) (bool, string, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", h.socket)
	if err != nil {
		return false, "sidecar unreachable", nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	req := sidecar.EvaluateRequest{
		Type:      "evaluate",
		Agent:     h.agent,
		HookEvent: eventName,
		ToolName:  toolName,
	}
	if toolInput != nil {
		b, err := json.Marshal(toolInput)
		if err != nil {
			return false, "marshal input", err
		}
		req.ToolInput = b
	}
	if toolResponse != nil {
		b, err := json.Marshal(toolResponse)
		if err != nil {
			return false, "marshal response", err
		}
		req.ToolResponse = b
	}

	if err := sidecar.WriteMessage(conn, req); err != nil {
		return false, "write", err
	}
	var res sidecar.EvaluateResult
	if err := sidecar.ReadMessage(conn, &res); err != nil {
		return false, "read", err
	}
	return res.Allowed, res.Reason, nil
}

// Run starts an MCP server over stdio. Blocks until stdin is closed.
// Every action in the provider registry is registered as a separate MCP tool
// named kontext.<provider>.<action>.
func Run(ctx context.Context, agentName, socketPath, sessionID string) error {
	h := newHandler(agentName, socketPath, sessionID)
	reg := defaultRegistry()

	s := server.NewMCPServer("kontext", "0.2.0")

	for _, p := range reg.All() {
		for _, action := range p.Actions {
			toolName := fmt.Sprintf("kontext.%s.%s", p.Name, action.Name)
			opts := []mcp.ToolOption{mcp.WithDescription(action.Description)}
			for _, param := range action.Params {
				opts = append(opts, toolOption(param))
			}
			tool := mcp.NewTool(toolName, opts...)

			action := action // loop-var capture
			s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				args := req.GetArguments()
				out, err := h.dispatch(ctx, toolName, action, args)
				if err != nil {
					return mcp.NewToolResultError(err.Error()), nil
				}
				return mcp.NewToolResultText(out), nil
			})
		}
	}

	return server.ServeStdio(s)
}

func toolOption(p providers.Param) mcp.ToolOption {
	var paramOpts []mcp.PropertyOption
	if p.Required {
		paramOpts = append(paramOpts, mcp.Required())
	}
	if p.Description != "" {
		paramOpts = append(paramOpts, mcp.Description(p.Description))
	}
	switch p.Type {
	case "number":
		return mcp.WithNumber(p.Name, paramOpts...)
	case "boolean":
		return mcp.WithBoolean(p.Name, paramOpts...)
	case "object":
		return mcp.WithObject(p.Name, paramOpts...)
	default:
		return mcp.WithString(p.Name, paramOpts...)
	}
}

// defaultRegistry returns the registry populated with first-party providers.
func defaultRegistry() *providers.Registry {
	r := providers.NewRegistry()
	r.Register(providers.NewGitHubProvider())
	return r
}
