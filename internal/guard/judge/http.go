package judge

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultTimeout = 2 * time.Second
	DefaultRuntime = "openai-compatible"
)

//go:embed prompts/launch-v0.md
var defaultPrompt string

type HTTPOptions struct {
	BaseURL    string
	Model      string
	Timeout    time.Duration
	HTTPClient *http.Client
	Prompt     string
}

type OpenAICompatibleJudge struct {
	endpoint   string
	model      string
	timeout    time.Duration
	httpClient *http.Client
	prompt     string
}

func NewOpenAICompatibleJudge(opts HTTPOptions) (*OpenAICompatibleJudge, error) {
	baseURL := strings.TrimSpace(opts.BaseURL)
	if baseURL == "" {
		return nil, errors.New("judge base URL is required")
	}
	endpoint, err := chatCompletionsEndpoint(baseURL)
	if err != nil {
		return nil, err
	}
	model := strings.TrimSpace(opts.Model)
	if model == "" {
		return nil, errors.New("judge model is required")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	prompt := opts.Prompt
	if strings.TrimSpace(prompt) == "" {
		prompt = defaultPrompt
	}
	return &OpenAICompatibleJudge{
		endpoint:   endpoint,
		model:      model,
		timeout:    timeout,
		httpClient: client,
		prompt:     prompt,
	}, nil
}

func (j *OpenAICompatibleJudge) Decide(ctx context.Context, input Input) (Result, error) {
	if j == nil {
		return Result{}, Error{Kind: FailureUnavailable, Err: errors.New("judge is nil")}
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, j.timeout)
	defer cancel()

	payload, err := j.requestBody(input)
	if err != nil {
		return Result{}, Error{Kind: FailureUnavailable, Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.endpoint, bytes.NewReader(payload))
	if err != nil {
		return Result{}, Error{Kind: FailureUnavailable, Err: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := j.httpClient.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Result{}, Error{Kind: FailureTimeout, Err: err}
		}
		return Result{}, Error{Kind: FailureUnavailable, Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Result{}, Error{Kind: FailureUnavailable, Err: fmt.Errorf("judge returned %s", resp.Status)}
	}

	var decoded openAIChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return Result{}, Error{Kind: FailureInvalidOutput, Err: err}
	}
	content := strings.TrimSpace(decoded.firstContent())
	output, err := ParseOutput(content)
	if err != nil {
		return Result{}, Error{Kind: FailureInvalidOutput, Err: err}
	}
	return Result{
		Output:   output,
		Metadata: j.metadata(time.Since(start).Milliseconds()),
	}, nil
}

func (j *OpenAICompatibleJudge) Metadata() Metadata {
	if j == nil {
		return Metadata{}
	}
	return j.metadata(0)
}

func (j *OpenAICompatibleJudge) metadata(durationMs int64) Metadata {
	return Metadata{
		Runtime:    DefaultRuntime,
		Model:      j.model,
		DurationMs: durationMs,
	}
}

func (j *OpenAICompatibleJudge) requestBody(input Input) ([]byte, error) {
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal judge input: %w", err)
	}
	request := openAIChatRequest{
		Model: j.model,
		Messages: []openAIMessage{
			{Role: "system", Content: j.prompt},
			{Role: "user", Content: string(inputJSON)},
		},
		Temperature:    0,
		MaxTokens:      256,
		ResponseFormat: map[string]string{"type": "json_object"},
	}
	return json.Marshal(request)
}

func ParseOutput(content string) (Output, error) {
	if strings.TrimSpace(content) == "" {
		return Output{}, errors.New("empty judge output")
	}
	var output Output
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		return Output{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Output{}, errors.New("trailing data after judge output")
	}
	if err := ValidateOutput(output); err != nil {
		return Output{}, err
	}
	return output, nil
}

func chatCompletionsEndpoint(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse judge URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("judge URL must include scheme and host")
	}
	path := strings.TrimRight(parsed.Path, "/")
	switch {
	case strings.HasSuffix(path, "/chat/completions"):
		return parsed.String(), nil
	case strings.HasSuffix(path, "/v1"):
		parsed.Path = path + "/chat/completions"
	default:
		parsed.Path = path + "/v1/chat/completions"
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

type openAIChatRequest struct {
	Model          string            `json:"model"`
	Messages       []openAIMessage   `json:"messages"`
	Temperature    float64           `json:"temperature"`
	MaxTokens      int               `json:"max_tokens"`
	ResponseFormat map[string]string `json:"response_format,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
}

func (r openAIChatResponse) firstContent() string {
	if len(r.Choices) == 0 {
		return ""
	}
	return r.Choices[0].Message.Content
}
