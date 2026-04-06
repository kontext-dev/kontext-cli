package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ExchangeResult is the response from a successful token exchange.
type ExchangeResult struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// NotConnectedError indicates the user hasn't connected this provider yet.
type NotConnectedError struct {
	Provider string
	Message  string
}

func (e *NotConnectedError) Error() string {
	return fmt.Sprintf("provider %s not connected: %s", e.Provider, e.Message)
}

// IsNotConnected checks if an error is a NotConnectedError.
func IsNotConnected(err error) bool {
	_, ok := err.(*NotConnectedError)
	return ok
}

// Exchange performs an RFC 8693 token exchange to get a provider credential.
func Exchange(ctx context.Context, tokenURL string, clientID string, accessToken string, provider string) (*ExchangeResult, error) {
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {clientID},
		"subject_token":      {accessToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {provider},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)

		if strings.Contains(errResp.Description, "not connected") ||
			strings.Contains(errResp.Description, "provider not found") {
			return nil, &NotConnectedError{Provider: provider, Message: errResp.Description}
		}
		return nil, fmt.Errorf("token exchange failed: %s: %s", errResp.Error, errResp.Description)
	}

	var result ExchangeResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode token exchange response: %w", err)
	}
	return &result, nil
}
