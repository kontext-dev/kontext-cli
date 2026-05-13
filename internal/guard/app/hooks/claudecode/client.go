package claudecode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	guardhook "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func NewClient(baseURL string) Client {
	return Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 5 * time.Second},
	}
}

func (c Client) Process(ctx context.Context, event hook.Event) (hook.Result, error) {
	body, err := json.Marshal(guardhook.RiskEventFromHookEvent(event, time.Now().UTC()))
	if err != nil {
		return hook.Result{}, err
	}
	endpoint := "/api/hooks/ingest"
	if event.HookName.CanBlock() {
		endpoint = "/api/hooks/evaluate"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+endpoint, bytes.NewReader(body))
	if err != nil {
		return hook.Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return hook.Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var payload map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		if payload["error"] != "" {
			return hook.Result{}, fmt.Errorf("daemon rejected hook: %s", payload["error"])
		}
		return hook.Result{}, fmt.Errorf("daemon returned %s", resp.Status)
	}
	var result server.ProcessResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return hook.Result{}, err
	}
	return guardhook.HookResultFromProcessResponse(result), nil
}
