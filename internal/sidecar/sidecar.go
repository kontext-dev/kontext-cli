package sidecar

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
)

// sidecarClient is the backend surface used by the sidecar.
type sidecarClient interface {
	Heartbeat(ctx context.Context, sessionID string) error
	ProcessHookEvent(ctx context.Context, req *agentv1.ProcessHookEventRequest) (*agentv1.ProcessHookEventResponse, error)
	IngestEvent(ctx context.Context, req *agentv1.ProcessHookEventRequest) error
}

const (
	heartbeatMinInterval = 30 * time.Second
	heartbeatMaxInterval = 5 * time.Minute
)

type heartbeatState struct {
	interval    time.Duration
	lastErr     string
	failedSince time.Time
}

func newHeartbeatState() heartbeatState {
	return heartbeatState{interval: heartbeatMinInterval}
}

func (h *heartbeatState) nextInterval() time.Duration {
	if h.interval == 0 {
		return heartbeatMinInterval
	}
	return h.interval
}

func (h *heartbeatState) record(now time.Time, err error, logf func(string, ...any)) {
	if err != nil {
		errStr := err.Error()
		if h.lastErr != errStr {
			logf("sidecar heartbeat: %v\n", err)
			h.lastErr = errStr
		}
		if h.failedSince.IsZero() {
			h.failedSince = now
		}
		h.interval *= 2
		if h.interval > heartbeatMaxInterval {
			h.interval = heartbeatMaxInterval
		}
		return
	}

	if !h.failedSince.IsZero() {
		elapsed := now.Sub(h.failedSince).Truncate(time.Second)
		logf("sidecar: heartbeat recovered after %s\n", elapsed)
		h.failedSince = time.Time{}
		h.lastErr = ""
	}
	h.interval = heartbeatMinInterval
}

type Server struct {
	socketPath string
	listener   net.Listener
	sessionID  string
	agentName  string
	client     sidecarClient
	diagnostic diagnostic.Logger
	cancel     context.CancelFunc
}

// New creates a new sidecar server.
func New(sessionDir string, client sidecarClient, sessionID, agentName string, diagnostics diagnostic.Logger) (*Server, error) {
	return &Server{
		socketPath: filepath.Join(sessionDir, "kontext.sock"),
		sessionID:  sessionID,
		agentName:  agentName,
		client:     client,
		diagnostic: diagnostics,
	}, nil
}

func (s *Server) SocketPath() string { return s.socketPath }

func (s *Server) Start(ctx context.Context) error {
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}
	s.listener = ln

	ctx, s.cancel = context.WithCancel(ctx)
	go s.acceptLoop(ctx)
	go s.heartbeatLoop(ctx)

	return nil
}

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
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					s.diagnostic.Printf("sidecar accept temporary error: %v\n", err)
					continue
				}
				s.diagnostic.Printf("sidecar accept: %v\n", err)
				return
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		s.diagnostic.Printf("sidecar deadline: %v\n", err)
		return
	}

	var req EvaluateRequest
	if err := ReadMessage(conn, &req); err != nil {
		s.diagnostic.Printf("sidecar read: %v\n", err)
		return
	}

	if req.HookEvent == "PreToolUse" {
		// Synchronous: call server, wait for authorization decision.
		protoReq := buildHookEventRequest(s.sessionID, s.agentName, &req)
		resp, err := s.client.ProcessHookEvent(ctx, protoReq)
		if err != nil {
			s.diagnostic.Printf("sidecar ProcessHookEvent: %v\n", err)
			result := EvaluateResult{
				Type:     "result",
				Allowed:  false,
				Decision: "deny",
				Reason:   "authorization service unreachable",
			}
			if writeErr := WriteMessage(conn, result); writeErr != nil {
				s.diagnostic.Printf("sidecar write: %v\n", writeErr)
			}
			return
		}
		result := mapServerResponse(resp)
		if err := WriteMessage(conn, result); err != nil {
			s.diagnostic.Printf("sidecar write: %v\n", err)
		}
	} else {
		// PostToolUse, UserPromptSubmit: allow immediately, telemetry async.
		result := EvaluateResult{Type: "result", Allowed: true, Decision: "allow"}
		if err := WriteMessage(conn, result); err != nil {
			s.diagnostic.Printf("sidecar write: %v\n", err)
			return
		}
		go s.ingestEvent(ctx, &req)
	}
}

func (s *Server) ingestEvent(ctx context.Context, req *EvaluateRequest) {
	hookEvent := buildHookEventRequest(s.sessionID, s.agentName, req)
	if err := s.client.IngestEvent(ctx, hookEvent); err != nil {
		s.diagnostic.Printf("sidecar ingest: %v\n", err)
	}
}

func (s *Server) heartbeatLoop(ctx context.Context) {
	state := newHeartbeatState()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		timer := time.NewTimer(state.nextInterval())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		state.record(time.Now(), s.client.Heartbeat(ctx, s.sessionID), s.diagnostic.Printf)
	}
}

func defaultAllowResult() EvaluateResult {
	return EvaluateResult{Type: "result", Allowed: true, Decision: "allow"}
}

// mapServerResponse converts a ProcessHookEventResponse into an EvaluateResult.
// ASK is encoded as deny because Claude Code only understands allow/deny;
// the reason message guides the developer to seek admin approval.
func mapServerResponse(resp *agentv1.ProcessHookEventResponse) EvaluateResult {
	switch resp.GetDecision() {
	case agentv1.Decision_DECISION_ALLOW:
		return EvaluateResult{
			Type:     "result",
			Allowed:  true,
			Decision: "allow",
			Reason:   resp.GetReason(),
		}
	case agentv1.Decision_DECISION_DENY:
		return EvaluateResult{
			Type:     "result",
			Allowed:  false,
			Decision: "deny",
			Reason:   resp.GetReason(),
		}
	case agentv1.Decision_DECISION_ASK:
		return EvaluateResult{
			Type:      "result",
			Allowed:   false,
			Decision:  "deny",
			Reason:    fmt.Sprintf("Access request created: %s. Ask your admin to approve at your organization's Access page.", resp.GetEventId()),
			RequestID: resp.GetEventId(),
		}
	default:
		// DECISION_UNSPECIFIED or unknown — fail closed.
		return EvaluateResult{
			Type:     "result",
			Allowed:  false,
			Decision: "deny",
			Reason:   "unknown authorization decision",
		}
	}
}

func buildHookEventRequest(sessionID, agentName string, req *EvaluateRequest) *agentv1.ProcessHookEventRequest {
	hookEvent := &agentv1.ProcessHookEventRequest{
		SessionId: sessionID,
		Agent:     agentName,
		HookEvent: req.HookEvent,
		ToolName:  req.ToolName,
		ToolUseId: req.ToolUseID,
		Cwd:       req.CWD,
	}
	if req.PermissionMode != "" {
		hookEvent.PermissionMode = &req.PermissionMode
	}
	if req.DurationMs != nil {
		hookEvent.DurationMs = req.DurationMs
	}
	if req.Error != "" {
		hookEvent.Error = &req.Error
	}
	if req.IsInterrupt != nil {
		hookEvent.IsInterrupt = req.IsInterrupt
	}

	if len(req.ToolInput) > 0 {
		hookEvent.ToolInput = req.ToolInput
	}
	if len(req.ToolResponse) > 0 {
		hookEvent.ToolResponse = req.ToolResponse
	}

	return hookEvent
}
