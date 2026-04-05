// Package backend provides the client interface for the Kontext API.
// The BackendService interface mirrors the proto AgentService RPCs.
// The REST bridge implementation routes calls to existing REST endpoints;
// when the gRPC server exists, swap NewRESTBridgeClient for NewConnectClient.
package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// BackendService is the interface the sidecar and orchestrator depend on.
type BackendService interface {
	CreateSession(ctx context.Context, userID, agent, hostname, cwd string) (sessionID, sessionName string, err error)
	Heartbeat(ctx context.Context, sessionID string) error
	EndSession(ctx context.Context, sessionID string) error
	IngestEvent(ctx context.Context, event *IngestEventParams) error
}

// IngestEventParams holds the fields for a telemetry event.
type IngestEventParams struct {
	SessionID string
	EventType string // session.begin, session.end, hook.pre_tool_call, hook.post_tool_call, hook.user_prompt
	Status    string // ok, denied
	ToolName  string
	DurationMs int
	TraceID   string
	RequestJSON  any
	ResponseJSON any
}

// Config holds backend connection parameters.
type Config struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
}

// LoadConfig reads backend configuration from environment variables.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		BaseURL:      envOr("KONTEXT_API_URL", "https://api.kontext.security"),
		ClientID:     os.Getenv("KONTEXT_CLIENT_ID"),
		ClientSecret: os.Getenv("KONTEXT_CLIENT_SECRET"),
	}

	// Try config file if env vars are missing
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		fileCfg, _ := loadConfigFile()
		if fileCfg != nil {
			if cfg.ClientID == "" {
				cfg.ClientID = fileCfg.ClientID
			}
			if cfg.ClientSecret == "" {
				cfg.ClientSecret = fileCfg.ClientSecret
			}
		}
	}

	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("KONTEXT_CLIENT_ID and KONTEXT_CLIENT_SECRET are required (set via env or ~/.kontext/config.json)")
	}

	return cfg, nil
}

func loadConfigFile() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(home, ".kontext", "config.json"))
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- REST Bridge Client ---

// RESTBridgeClient implements BackendService using existing REST endpoints.
type RESTBridgeClient struct {
	config     *Config
	httpClient *http.Client
	token      string
	tokenExp   time.Time
	mu         sync.Mutex
	userID     string // authenticatedUserId for events
}

// NewRESTBridgeClient creates a backend client that routes to REST endpoints.
func NewRESTBridgeClient(config *Config) *RESTBridgeClient {
	return &RESTBridgeClient{
		config:     config,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *RESTBridgeClient) CreateSession(ctx context.Context, userID, agent, hostname, cwd string) (string, string, error) {
	c.userID = userID

	token, err := c.getToken(ctx)
	if err != nil {
		return "", "", fmt.Errorf("auth: %w", err)
	}

	body := map[string]any{
		"tokenIdentifier":     fmt.Sprintf("cli:%s", uuid.New().String()),
		"authenticatedUserId": userID,
		"clientSessionId":     uuid.New().String(),
		"hostname":            hostname,
		"clientInfo":          map[string]string{"name": "kontext-cli", "agent": agent},
	}

	var resp struct {
		SessionID string `json:"sessionId"`
		Name      string `json:"name"`
	}
	if err := c.doJSON(ctx, "POST", "/api/v1/agent-sessions", token, body, &resp); err != nil {
		return "", "", fmt.Errorf("create session: %w", err)
	}

	return resp.SessionID, resp.Name, nil
}

func (c *RESTBridgeClient) Heartbeat(ctx context.Context, sessionID string) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, "POST", fmt.Sprintf("/api/v1/agent-sessions/%s/heartbeat", sessionID), token, nil, nil)
}

func (c *RESTBridgeClient) EndSession(ctx context.Context, sessionID string) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, "POST", fmt.Sprintf("/api/v1/agent-sessions/%s/disconnect", sessionID), token, nil, nil)
}

func (c *RESTBridgeClient) IngestEvent(ctx context.Context, event *IngestEventParams) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return err
	}

	body := map[string]any{
		"sessionId":           event.SessionID,
		"authenticatedUserId": c.userID,
		"clientId":            c.config.ClientID,
		"eventType":           event.EventType,
		"status":              event.Status,
		"durationMs":          event.DurationMs,
		"toolName":            event.ToolName,
		"traceId":             event.TraceID,
		"requestJson":         event.RequestJSON,
		"responseJson":        event.ResponseJSON,
	}

	return c.doJSON(ctx, "POST", "/api/v1/mcp-events", token, body, nil)
}

// --- Token management ---

func (c *RESTBridgeClient) getToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}

	// Discover token endpoint
	var meta struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := c.doGet(ctx, "/.well-known/oauth-authorization-server", &meta); err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}

	// Client credentials flow
	params := fmt.Sprintf("grant_type=client_credentials&scope=management:all+mcp:invoke")
	req, err := http.NewRequestWithContext(ctx, "POST", meta.TokenEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)
	req.Body = newStringBody(params)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token request failed: %s", resp.Status)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	c.token = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		c.tokenExp = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)
	} else {
		c.tokenExp = time.Now().Add(50 * time.Minute)
	}

	return c.token, nil
}

// --- HTTP helpers ---

func (c *RESTBridgeClient) doJSON(ctx context.Context, method, path, token string, body any, result any) error {
	var reqBody io.Reader
	if body != nil {
		reqBody = newJSONBody(body)
	}

	url := c.config.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errBody json.RawMessage
		json.NewDecoder(resp.Body).Decode(&errBody)
		return fmt.Errorf("API %s %s: %d %s", method, path, resp.StatusCode, string(errBody))
	}

	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

func (c *RESTBridgeClient) doGet(ctx context.Context, path string, result any) error {
	url := c.config.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(result)
}

func newJSONBody(v any) io.Reader {
	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(v)
	return buf
}

func newStringBody(s string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(s))
}
