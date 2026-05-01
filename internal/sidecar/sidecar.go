package sidecar

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/credential"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/hookruntime"
)

// sidecarClient is the backend surface used by the sidecar.
type sidecarClient interface {
	Heartbeat(ctx context.Context, sessionID string) error
	ProcessHookEvent(context.Context, *agentv1.ProcessHookEventRequest) (*backend.ProcessHookEventResult, error)
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
	socketPath  string
	listener    net.Listener
	sessionID   string
	agentName   string
	mu          sync.RWMutex
	accessMode  backend.HostedAccessMode
	client      sidecarClient
	diagnostic  diagnostic.Logger
	cancel      context.CancelFunc
	credentials *credentialInjector
}

// New creates a new sidecar server.
func New(sessionDir string, client sidecarClient, sessionID, agentName string, accessMode backend.HostedAccessMode, diagnostics diagnostic.Logger) (*Server, error) {
	return &Server{
		socketPath: filepath.Join(sessionDir, "kontext.sock"),
		sessionID:  sessionID,
		agentName:  agentName,
		accessMode: accessMode,
		client:     client,
		diagnostic: diagnostics,
	}, nil
}

func NewWithCredentials(sessionDir string, client sidecarClient, sessionID, agentName string, accessMode backend.HostedAccessMode, diagnostics diagnostic.Logger, entries []credential.Entry, resolve credentialResolver) (*Server, error) {
	server, err := New(sessionDir, client, sessionID, agentName, accessMode, diagnostics)
	if err != nil {
		return nil, err
	}
	server.credentials = newCredentialInjector(sessionDir, entries, resolve)
	return server, nil
}

func (s *Server) SocketPath() string { return s.socketPath }

func (s *Server) currentAccessMode() backend.HostedAccessMode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accessMode
}

func (s *Server) refreshAccessMode(mode backend.HostedAccessMode) {
	if mode == "" {
		return
	}
	s.mu.Lock()
	s.accessMode = mode
	s.mu.Unlock()
}

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

	result := s.evaluate(ctx, &req)
	if err := WriteMessage(conn, result); err != nil {
		s.diagnostic.Printf("sidecar write: %v\n", err)
		return
	}

	if req.HookEvent != "PreToolUse" {
		go s.ingestEvent(ctx, &req)
	}
}

func (s *Server) ingestEvent(ctx context.Context, req *EvaluateRequest) {
	hookEvent := buildHookEventRequest(s.sessionID, s.agentName, req)
	if _, err := s.client.ProcessHookEvent(ctx, hookEvent); err != nil {
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

func (s *Server) evaluate(ctx context.Context, req *EvaluateRequest) EvaluateResult {
	if req.HookEvent != "PreToolUse" {
		return defaultAllowResult()
	}

	hookEvent := buildHookEventRequest(s.sessionID, s.agentName, req)
	result, err := s.client.ProcessHookEvent(ctx, hookEvent)
	if err != nil {
		s.diagnostic.Printf("sidecar enforce: %v\n", err)
		accessMode := s.currentAccessMode()
		if accessMode != backend.HostedAccessModeEnforce {
			return resultFromRuntime(hookruntime.Result{
				Decision: hookruntime.DecisionAllow,
				Reason:   "Kontext hosted access is not enforcing.",
				Mode:     string(accessMode),
			})
		}
		return EvaluateResult{
			Type:     "result",
			Decision: string(hookruntime.DecisionDeny),
			Allowed:  false,
			Reason:   "Kontext access policy could not be evaluated.",
		}
	}
	s.refreshAccessMode(result.AccessMode)

	resp := result.Response
	switch resp.GetDecision() {
	case agentv1.Decision_DECISION_ALLOW:
		runtimeResult := hookruntime.Result{
			Decision:   hookruntime.DecisionAllow,
			Reason:     resp.GetReason(),
			ReasonCode: result.ReasonCode,
			RequestID:  result.RequestID,
			Mode:       string(result.AccessMode),
			Epoch:      result.PolicySetEpoch,
		}
		updatedInput, err := s.credentials.updatedInputForAllowedHook(ctx, req)
		if err != nil {
			s.diagnostic.Printf("sidecar credential injection skipped: %v\n", err)
		}
		runtimeResult.UpdatedInput = updatedInput
		return resultFromRuntime(runtimeResult)
	case agentv1.Decision_DECISION_ASK:
		return resultFromRuntime(hookruntime.Result{
			Decision:   hookruntime.DecisionAsk,
			Reason:     resp.GetReason(),
			ReasonCode: result.ReasonCode,
			RequestID:  result.RequestID,
			Mode:       string(result.AccessMode),
			Epoch:      result.PolicySetEpoch,
		})
	case agentv1.Decision_DECISION_DENY:
		fallthrough
	default:
		return resultFromRuntime(hookruntime.Result{
			Decision:   hookruntime.DecisionDeny,
			Reason:     resp.GetReason(),
			ReasonCode: result.ReasonCode,
			RequestID:  result.RequestID,
			Mode:       string(result.AccessMode),
			Epoch:      result.PolicySetEpoch,
		})
	}
}

func defaultAllowResult() EvaluateResult {
	return resultFromRuntime(hookruntime.Result{Decision: hookruntime.DecisionAllow})
}

func resultFromRuntime(result hookruntime.Result) EvaluateResult {
	return EvaluateResult{
		Type:         "result",
		Decision:     string(result.Decision),
		Allowed:      result.Allowed(),
		Reason:       result.ClaudeReason(),
		ReasonCode:   result.ReasonCode,
		RequestID:    result.RequestID,
		Mode:         result.Mode,
		Epoch:        result.Epoch,
		UpdatedInput: result.UpdatedInput,
	}
}

func buildHookEventRequest(sessionID, agentName string, req *EvaluateRequest) *agentv1.ProcessHookEventRequest {
	enrichToolInputWithLocalContext(context.Background(), req)

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
