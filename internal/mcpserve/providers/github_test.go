package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func withBaseURL(t *testing.T, url string) {
	t.Helper()
	prev := githubBaseURL
	githubBaseURL = url
	t.Cleanup(func() { githubBaseURL = prev })
}

func withToken(t *testing.T, token string) {
	t.Helper()
	t.Setenv("GITHUB_TOKEN", token)
}

func TestGitHubGetUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("auth header: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"octocat","id":1}`))
	}))
	defer srv.Close()
	withBaseURL(t, srv.URL)
	withToken(t, "test-token")

	p := NewGitHubProvider()
	action, ok := findAction(p, "get_user")
	if !ok {
		t.Fatal("get_user not found")
	}
	result, err := action.Handler(context.Background(), nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("result type: %T", result)
	}
	if m["login"] != "octocat" {
		t.Errorf("login: %v", m["login"])
	}
}

func TestGitHubListRepos(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/repos" {
			t.Errorf("path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("visibility") != "private" {
			t.Errorf("visibility: %s", q.Get("visibility"))
		}
		if q.Get("per_page") != "5" {
			t.Errorf("per_page: %s", q.Get("per_page"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name":"repo1"}]`))
	}))
	defer srv.Close()
	withBaseURL(t, srv.URL)
	withToken(t, "test-token")

	p := NewGitHubProvider()
	action, _ := findAction(p, "list_repos")
	result, err := action.Handler(context.Background(), map[string]any{
		"visibility": "private",
		"per_page":   float64(5), // json numbers decode to float64
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	arr, ok := result.([]any)
	if !ok {
		t.Fatalf("type: %T", result)
	}
	if len(arr) != 1 {
		t.Errorf("len: %d", len(arr))
	}
}

func TestGitHubCreateIssue(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method: %s", r.Method)
		}
		if r.URL.Path != "/repos/octo/hello/issues" {
			t.Errorf("path: %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"number":42}`))
	}))
	defer srv.Close()
	withBaseURL(t, srv.URL)
	withToken(t, "test-token")

	p := NewGitHubProvider()
	action, _ := findAction(p, "create_issue")
	result, err := action.Handler(context.Background(), map[string]any{
		"owner": "octo",
		"repo":  "hello",
		"title": "bug",
		"body":  "details",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if got["title"] != "bug" || got["body"] != "details" {
		t.Errorf("body sent: %v", got)
	}
	m := result.(map[string]any)
	if m["number"] != float64(42) {
		t.Errorf("number: %v", m["number"])
	}
}

func TestGitHubMissingToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	p := NewGitHubProvider()
	action, _ := findAction(p, "get_user")
	_, err := action.Handler(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Errorf("expected missing token error, got %v", err)
	}
}

func TestGitHubNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()
	withBaseURL(t, srv.URL)
	withToken(t, "bad")

	p := NewGitHubProvider()
	action, _ := findAction(p, "get_user")
	_, err := action.Handler(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 error, got %v", err)
	}
}

func findAction(p *Provider, name string) (Action, bool) {
	for _, a := range p.Actions {
		if a.Name == name {
			return a, true
		}
	}
	return Action{}, false
}
