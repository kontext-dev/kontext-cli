// Package auth handles OIDC browser-based authentication and keyring storage.
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	keyringService = "kontext-cli"
	keyringUser    = "default"
)

// Session holds the authenticated user's identity and tokens.
type Session struct {
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
	OrgID        string    `json:"organization_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// IsExpired returns true if the access token has expired or will expire within the buffer.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt.Add(-60 * time.Second))
}

// LoadSession reads the stored session from the system keyring.
func LoadSession() (*Session, error) {
	data, err := keyring.Get(keyringService, keyringUser)
	if err != nil {
		return nil, fmt.Errorf("no stored session (run `kontext login`): %w", err)
	}
	_ = data // TODO: unmarshal JSON
	return nil, fmt.Errorf("not implemented")
}

// SaveSession stores the session in the system keyring.
func SaveSession(session *Session) error {
	_ = session // TODO: marshal JSON
	return keyring.Set(keyringService, keyringUser, "TODO")
}

// ClearSession removes the stored session from the system keyring.
func ClearSession() error {
	return keyring.Delete(keyringService, keyringUser)
}

// Login performs the browser-based OIDC PKCE login flow.
func Login(ctx context.Context, issuerURL string) (*Session, error) {
	_ = ctx
	_ = issuerURL
	// TODO:
	// 1. Start localhost callback server
	// 2. Open browser to issuer authorize endpoint with PKCE
	// 3. Wait for callback with auth code
	// 4. Exchange code for tokens
	// 5. Decode ID token for user info
	// 6. Return Session
	return nil, fmt.Errorf("not implemented")
}
