package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestResolveLoginScopesDefaults(t *testing.T) {
	t.Parallel()

	got := resolveLoginScopes(nil)
	want := []string{
		"openid",
		"email",
		"profile",
		"offline_access",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveLoginScopes(nil) = %#v, want %#v", got, want)
	}

	got[0] = "mutated"
	if reflect.DeepEqual(got, resolveLoginScopes(nil)) {
		t.Fatal("resolveLoginScopes(nil) returned a shared slice")
	}
}

func TestResolveLoginScopesCustom(t *testing.T) {
	t.Parallel()

	input := []string{"gateway:access"}
	got := resolveLoginScopes(input)
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("resolveLoginScopes(%#v) = %#v", input, got)
	}

	got[0] = "mutated"
	if reflect.DeepEqual(got, resolveLoginScopes(input)) {
		t.Fatal("resolveLoginScopes(custom) returned a shared slice")
	}
}

// fakeIssuer is a minimal OAuth authorization server for RefreshSession tests.
// It serves /.well-known/oauth-authorization-server and a configurable token
// endpoint handler.
type fakeIssuer struct {
	server      *httptest.Server
	tokenHandle http.HandlerFunc
}

func newFakeIssuer(t *testing.T, tokenHandle http.HandlerFunc) *fakeIssuer {
	t.Helper()
	fi := &fakeIssuer{tokenHandle: tokenHandle}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OAuthMetadata{
			Issuer:                fi.server.URL,
			AuthorizationEndpoint: fi.server.URL + "/oauth2/auth",
			TokenEndpoint:         fi.server.URL + "/oauth2/token",
			JwksURI:               fi.server.URL + "/jwks.json",
		})
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		fi.tokenHandle(w, r)
	})
	fi.server = httptest.NewServer(mux)
	t.Cleanup(fi.server.Close)
	return fi
}

func TestRefreshSession_InvalidGrantIsPermanent(t *testing.T) {
	t.Parallel()

	fi := newFakeIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token expired"}`))
	})

	session := &Session{
		IssuerURL:    fi.server.URL,
		AccessToken:  "old-access",
		RefreshToken: "dead-refresh",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}

	_, err := RefreshSession(context.Background(), session)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("errors.Is(err, ErrInvalidGrant) = false; err = %v", err)
	}
}

func TestRefreshSession_ServerErrorIsNotPermanent(t *testing.T) {
	t.Parallel()

	fi := newFakeIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	session := &Session{
		IssuerURL:    fi.server.URL,
		RefreshToken: "still-valid",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}

	_, err := RefreshSession(context.Background(), session)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("errors.Is(err, ErrInvalidGrant) = true; want false for 500 response; err = %v", err)
	}
}

func TestRefreshSession_NoRefreshTokenIsNotInvalidGrant(t *testing.T) {
	t.Parallel()

	session := &Session{
		IssuerURL:    "http://127.0.0.1:1", // never contacted
		RefreshToken: "",
	}

	_, err := RefreshSession(context.Background(), session)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("missing refresh token should not classify as ErrInvalidGrant; err = %v", err)
	}
}

func TestRefreshSession_Success(t *testing.T) {
	t.Parallel()

	fi := newFakeIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token":"new-access",
			"refresh_token":"new-refresh",
			"token_type":"Bearer",
			"expires_in":3600
		}`))
	})

	session := &Session{
		IssuerURL:    fi.server.URL,
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}

	updated, err := RefreshSession(context.Background(), session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.AccessToken != "new-access" {
		t.Errorf("AccessToken = %q, want %q", updated.AccessToken, "new-access")
	}
	if updated.RefreshToken != "new-refresh" {
		t.Errorf("RefreshToken = %q, want %q", updated.RefreshToken, "new-refresh")
	}
	if !updated.ExpiresAt.After(time.Now()) {
		t.Errorf("ExpiresAt = %v, want future", updated.ExpiresAt)
	}
}
