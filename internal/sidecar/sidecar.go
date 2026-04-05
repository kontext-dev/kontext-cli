// Package sidecar implements the local session server.
// Hook handlers (kontext hook) connect to the sidecar over a Unix socket.
// The sidecar relays events to the backend and returns policy decisions.
package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/kontext-dev/kontext-cli/internal/backend"
)

// Server is the local sidecar that hook handlers communicate with.
type Server struct {
	socketPath string
	listener   net.Listener
	sessionID  string
	traceID    string
	backend    backend.BackendService
	cancel     context.CancelFunc
}

// New creates a new sidecar server.
func New(sessionDir string, b backend.BackendService, sessionID, traceID string) (*Server, error) {
	socketPath := filepath.Join(sessionDir, "kontext.sock")
	return &Server{
		socketPath: socketPath,
		sessionID:  sessionID,
		traceID:    traceID,
		backend:    b,
	}, nil
}

// SocketPath returns the Unix socket path for hook handlers.
func (s *Server) SocketPath() string {
	return s.socketPath
}

// Start begins listening and processing hook events.
func (s *Server) Start(ctx context.Context) error {
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("sidecar listen: %w", err)
	}
	s.listener = ln

	ctx, s.cancel = context.WithCancel(ctx)

	go s.acceptLoop(ctx)
	go s.heartbeatLoop(ctx)

	return nil
}

// Stop shuts down the sidecar.
func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	var req EvaluateRequest
	if err := ReadMessage(conn, &req); err != nil {
		log.Printf("sidecar: read error: %v", err)
		return
	}

	// Always allow for now — policy evaluation is a future phase
	result := EvaluateResult{
		Type:    "result",
		Allowed: true,
		Reason:  "allowed",
	}

	// Write response immediately — don't block on event ingestion
	if err := WriteMessage(conn, result); err != nil {
		log.Printf("sidecar: write error: %v", err)
		return
	}

	// Ingest event asynchronously
	go s.ingestEvent(ctx, &req)
}

func (s *Server) ingestEvent(ctx context.Context, req *EvaluateRequest) {
	eventType := "hook." + normalizeHookEvent(req.HookEvent)
	status := "ok"

	var reqJSON, respJSON any
	if len(req.ToolInput) > 0 {
		json.Unmarshal(req.ToolInput, &reqJSON)
	}
	if len(req.ToolResponse) > 0 {
		json.Unmarshal(req.ToolResponse, &respJSON)
	}

	err := s.backend.IngestEvent(ctx, &backend.IngestEventParams{
		SessionID:    s.sessionID,
		EventType:    eventType,
		Status:       status,
		ToolName:     req.ToolName,
		DurationMs:   0,
		TraceID:      s.traceID,
		RequestJSON:  reqJSON,
		ResponseJSON: respJSON,
	})
	if err != nil {
		log.Printf("sidecar: ingest error: %v", err)
	}
}

func (s *Server) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.backend.Heartbeat(ctx, s.sessionID); err != nil {
				log.Printf("sidecar: heartbeat error: %v", err)
			}
		}
	}
}

func normalizeHookEvent(event string) string {
	switch event {
	case "PreToolUse":
		return "pre_tool_call"
	case "PostToolUse":
		return "post_tool_call"
	case "UserPromptSubmit":
		return "user_prompt"
	default:
		return event
	}
}
