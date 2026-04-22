package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

var githubBaseURL = "https://api.github.com"

var githubClient = &http.Client{Timeout: 15 * time.Second}

// githubCall performs a GitHub REST API call. body may be nil for GET requests.
func githubCall(ctx context.Context, method, path string, body any) (any, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, errors.New("GITHUB_TOKEN not set")
	}

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("github marshal body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, githubBaseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("github new request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := githubClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, fmt.Errorf("github read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview := respBody
		if len(preview) > 512 {
			preview = preview[:512]
		}
		return nil, fmt.Errorf("github %s %s: %d: %s", method, path, resp.StatusCode, preview)
	}

	var result any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("github decode response: %w", err)
	}
	return result, nil
}

// NewGitHubProvider returns a Provider with all four GitHub actions.
func NewGitHubProvider() *Provider {
	return &Provider{
		Name: "github",
		Actions: []Action{
			{
				Name:        "get_user",
				Description: "Get the authenticated user",
				Params:      nil,
				Handler: func(ctx context.Context, args map[string]any) (any, error) {
					return githubCall(ctx, http.MethodGet, "/user", nil)
				},
			},
			{
				Name:        "list_repos",
				Description: "List repositories for the authenticated user",
				Params: []Param{
					{Name: "visibility", Type: "string", Description: "all/owner/public/private", Required: false},
					{Name: "per_page", Type: "number", Description: "Number of results per page (default 30)", Required: false},
				},
				Handler: func(ctx context.Context, args map[string]any) (any, error) {
					path := "/user/repos"
					sep := "?"
					if v, ok := args["visibility"]; ok {
						if s, ok := v.(string); ok && s != "" {
							path += sep + "visibility=" + s
							sep = "&"
						}
					}
					if v, ok := args["per_page"]; ok {
						if f, ok := v.(float64); ok {
							path += sep + "per_page=" + strconv.Itoa(int(f))
						}
					}
					return githubCall(ctx, http.MethodGet, path, nil)
				},
			},
			{
				Name:        "list_issues",
				Description: "List issues for a repository",
				Params: []Param{
					{Name: "owner", Type: "string", Description: "Repository owner", Required: true},
					{Name: "repo", Type: "string", Description: "Repository name", Required: true},
					{Name: "state", Type: "string", Description: "open/closed/all (default open)", Required: false},
				},
				Handler: func(ctx context.Context, args map[string]any) (any, error) {
					owner, ok := stringParam(args, "owner")
					if !ok {
						return nil, fmt.Errorf("missing required param: owner")
					}
					repo, ok := stringParam(args, "repo")
					if !ok {
						return nil, fmt.Errorf("missing required param: repo")
					}
					path := "/repos/" + owner + "/" + repo + "/issues"
					if v, ok := args["state"]; ok {
						if s, ok := v.(string); ok && s != "" {
							path += "?state=" + s
						}
					}
					return githubCall(ctx, http.MethodGet, path, nil)
				},
			},
			{
				Name:        "create_issue",
				Description: "Create an issue in a repository",
				Params: []Param{
					{Name: "owner", Type: "string", Description: "Repository owner", Required: true},
					{Name: "repo", Type: "string", Description: "Repository name", Required: true},
					{Name: "title", Type: "string", Description: "Issue title", Required: true},
					{Name: "body", Type: "string", Description: "Issue body", Required: false},
				},
				Handler: func(ctx context.Context, args map[string]any) (any, error) {
					owner, ok := stringParam(args, "owner")
					if !ok {
						return nil, fmt.Errorf("missing required param: owner")
					}
					repo, ok := stringParam(args, "repo")
					if !ok {
						return nil, fmt.Errorf("missing required param: repo")
					}
					title, ok := stringParam(args, "title")
					if !ok {
						return nil, fmt.Errorf("missing required param: title")
					}
					issueBody := map[string]any{"title": title}
					if b, ok := args["body"]; ok {
						issueBody["body"] = b
					}
					path := "/repos/" + owner + "/" + repo + "/issues"
					return githubCall(ctx, http.MethodPost, path, issueBody)
				},
			},
		},
	}
}

// stringParam extracts a non-empty string from an args map.
func stringParam(args map[string]any, key string) (string, bool) {
	v, ok := args[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok && s != ""
}
