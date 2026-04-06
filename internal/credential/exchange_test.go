package credential

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
			t.Errorf("unexpected grant_type: %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("subject_token") != "my-access-token" {
			t.Errorf("unexpected subject_token: %s", r.Form.Get("subject_token"))
		}
		if r.Form.Get("resource") != "github" {
			t.Errorf("unexpected resource: %s", r.Form.Get("resource"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"gho_xxxx","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	result, err := Exchange(context.Background(), srv.URL+"/oauth2/token", "my-access-token", "github")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if result.AccessToken != "gho_xxxx" {
		t.Errorf("got access_token %q, want %q", result.AccessToken, "gho_xxxx")
	}
}

func TestExchangeNotConnected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"provider not connected"}`))
	}))
	defer srv.Close()

	_, err := Exchange(context.Background(), srv.URL+"/oauth2/token", "my-access-token", "github")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsNotConnected(err) {
		t.Errorf("expected not-connected error, got: %v", err)
	}
}
