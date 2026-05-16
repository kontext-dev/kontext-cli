package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	dashboardassets "github.com/kontext-security/kontext-cli/internal/guard/web/assets"
	"github.com/kontext-security/kontext-cli/internal/runtimecore"
)

const (
	DefaultAddr = "127.0.0.1:4765"
)

type Server struct {
	store *sqlite.Store
	core  *runtimecore.Core
	mux   *http.ServeMux
}

type ProcessResponse struct {
	Decision   risk.Decision `json:"decision"`
	Reason     string        `json:"reason"`
	ReasonCode string        `json:"reason_code"`
	EventID    string        `json:"event_id"`
}

type Options struct {
	Scorer risk.Scorer
	Judge  judge.Judge
}

func NewServer(store *sqlite.Store, scorer risk.Scorer) (*Server, error) {
	return NewServerWithOptions(store, Options{Scorer: scorer})
}

func NewServerWithOptions(store *sqlite.Store, opts Options) (*Server, error) {
	return NewServerWithPolicy(store, NewRiskPolicyProviderWithJudge(opts.Scorer, opts.Judge))
}

// NewServerWithPolicy creates a Guard server with an injected policy provider.
// A nil interface uses the default local risk policy; callers must not pass a
// typed-nil provider because it still satisfies the PolicyProvider interface.
func NewServerWithPolicy(store *sqlite.Store, policy PolicyProvider) (*Server, error) {
	if policy == nil {
		policy = NewRiskPolicyProvider(nil)
	}
	runtime := newGuardHookRuntime(store, policy)
	core, err := runtimecore.New(runtime)
	if err != nil {
		return nil, fmt.Errorf("create runtime core: %w", err)
	}
	server := &Server{store: store, core: core, mux: http.NewServeMux()}
	server.routes()
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return withCORS(s.mux)
}

func (s *Server) RuntimeCore() *runtimecore.Core {
	return s.core
}

func (s *Server) ListenAndServe(addr string) error {
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return httpServer.ListenAndServe()
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("POST /api/hooks/evaluate", s.handleEvaluate)
	s.mux.HandleFunc("POST /api/hooks/ingest", s.handleIngest)
	s.mux.HandleFunc("POST /api/hooks/process", s.handleProcess)
	s.mux.HandleFunc("GET /api/summary", s.handleSummary)
	s.mux.HandleFunc("GET /api/sessions", s.handleSessions)
	s.mux.HandleFunc("GET /api/sessions/", s.handleSession)
	s.mux.HandleFunc("GET /", s.handleDashboard)
}

func (s *Server) EvaluateHook(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	result, err := s.core.EvaluateHook(ctx, hookEventFromRiskEvent(event))
	if err != nil {
		return risk.RiskDecision{}, err
	}
	return riskDecisionFromHookResult(result), nil
}

func (s *Server) IngestEvent(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	result, err := s.core.IngestEvent(ctx, hookEventFromRiskEvent(event))
	if err != nil {
		return risk.RiskDecision{}, err
	}
	return riskDecisionFromHookResult(result), nil
}

func (s *Server) ProcessHookEvent(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	result, err := s.core.ProcessHook(ctx, hookEventFromRiskEvent(event))
	if err != nil {
		return risk.RiskDecision{}, err
	}
	return riskDecisionFromHookResult(result), nil
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	s.handleHook(w, r, s.EvaluateHook)
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	s.handleHook(w, r, s.IngestEvent)
}

func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request) {
	s.handleHook(w, r, s.ProcessHookEvent)
}

func (s *Server) handleHook(w http.ResponseWriter, r *http.Request, process func(context.Context, risk.HookEvent) (risk.RiskDecision, error)) {
	var event risk.HookEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		writeError(w, http.StatusBadRequest, "invalid hook event")
		return
	}
	decision, err := process(r.Context(), event)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ProcessResponse{
		Decision:   decision.Decision,
		Reason:     decision.Reason,
		ReasonCode: decision.ReasonCode,
		EventID:    decision.EventID,
	})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.store.Summary(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.Sessions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sessionID := parts[0]
	switch parts[1] {
	case "summary":
		summary, err := s.store.SessionSummary(r.Context(), sessionID)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, summary)
	case "events":
		events, err := s.store.Events(r.Context(), sessionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, events)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	dist, err := fs.Sub(dashboardassets.FS, "dist")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard assets unavailable")
		return
	}
	http.FileServer(http.FS(dist)).ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:5173")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func OpenDefaultServer(dbPath string, scorer risk.Scorer) (*Server, func() error, error) {
	return OpenDefaultServerWithOptions(dbPath, Options{Scorer: scorer})
}

func OpenDefaultServerWithOptions(dbPath string, opts Options) (*Server, func() error, error) {
	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open store: %w", err)
	}
	server, err := NewServerWithOptions(store, opts)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	return server, store.Close, nil
}
