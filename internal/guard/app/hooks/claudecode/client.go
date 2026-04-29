package claudecode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func NewClient(baseURL string) Client {
	return Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c Client) Process(ctx context.Context, event risk.HookEvent) (server.ProcessResponse, error) {
	body, err := json.Marshal(event)
	if err != nil {
		return server.ProcessResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/hooks/process", bytes.NewReader(body))
	if err != nil {
		return server.ProcessResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return server.ProcessResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var payload map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		if payload["error"] != "" {
			return server.ProcessResponse{}, fmt.Errorf("daemon rejected hook: %s", payload["error"])
		}
		return server.ProcessResponse{}, fmt.Errorf("daemon returned %s", resp.Status)
	}
	var result server.ProcessResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return server.ProcessResponse{}, err
	}
	return result, nil
}

func (c Client) WaitApproval(ctx context.Context, eventID string) (risk.Decision, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/demo/approvals/"+url.PathEscape(eventID)+"/wait", nil)
	if err != nil {
		return risk.DecisionDeny, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return risk.DecisionDeny, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var payload map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		if payload["error"] != "" {
			return risk.DecisionDeny, fmt.Errorf("approval wait failed: %s", payload["error"])
		}
		return risk.DecisionDeny, fmt.Errorf("approval wait returned %s", resp.Status)
	}
	var result struct {
		Decision risk.Decision `json:"decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return risk.DecisionDeny, err
	}
	return result.Decision, nil
}
