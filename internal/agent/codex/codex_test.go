package codex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

func TestCodexPrepareWritesConfig(t *testing.T) {
	t.Parallel()

	c := &Codex{}
	dir := t.TempDir()
	prep, err := c.Prepare(dir, "/usr/local/bin/kontext")
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	if len(prep.Args) != 0 {
		t.Fatalf("prep.Args = %#v, want empty", prep.Args)
	}
	wantEnv := "CODEX_HOME=" + filepath.Join(dir, ".codex")
	if !slices.Contains(prep.Env, wantEnv) {
		t.Fatalf("prep.Env missing %q; got %#v", wantEnv, prep.Env)
	}

	// config.toml has the feature flag
	tomlBytes, err := os.ReadFile(filepath.Join(dir, ".codex", "config.toml"))
	if err != nil {
		t.Fatalf("read config.toml: %v", err)
	}
	tomlText := string(tomlBytes)
	if !strings.Contains(tomlText, "[features]") {
		t.Fatalf("config.toml missing [features] section: %q", tomlText)
	}
	if !strings.Contains(tomlText, "codex_hooks = true") {
		t.Fatalf("config.toml missing codex_hooks = true: %q", tomlText)
	}

	// hooks.json has the three events, matcher "*" on tool events, and the
	// right command in each.
	hooksBytes, err := os.ReadFile(filepath.Join(dir, ".codex", "hooks.json"))
	if err != nil {
		t.Fatalf("read hooks.json: %v", err)
	}
	var parsed struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(hooksBytes, &parsed); err != nil {
		t.Fatalf("unmarshal hooks.json: %v", err)
	}
	for _, event := range []string{"PreToolUse", "PostToolUse", "UserPromptSubmit"} {
		groups, ok := parsed.Hooks[event]
		if !ok || len(groups) == 0 || len(groups[0].Hooks) == 0 {
			t.Fatalf("no hooks registered for %q", event)
		}
		cmd := groups[0].Hooks[0].Command
		if !strings.Contains(cmd, "/usr/local/bin/kontext") {
			t.Fatalf("%s: command %q missing binary path", event, cmd)
		}
		if !strings.Contains(cmd, "--agent codex") {
			t.Fatalf("%s: command %q missing --agent codex", event, cmd)
		}
		if groups[0].Hooks[0].Type != "command" {
			t.Fatalf("%s: type = %q, want command", event, groups[0].Hooks[0].Type)
		}
	}
	if m := parsed.Hooks["PreToolUse"][0].Matcher; m != "*" {
		t.Fatalf("PreToolUse matcher = %q, want *", m)
	}
	if m := parsed.Hooks["PostToolUse"][0].Matcher; m != "*" {
		t.Fatalf("PostToolUse matcher = %q, want *", m)
	}
}

func TestCodexDecodeHookInput(t *testing.T) {
	t.Parallel()

	c := &Codex{}
	cases := []struct {
		name  string
		input string
		check func(t *testing.T, got map[string]any)
	}{
		{
			name:  "pre_tool_use_shell",
			input: `{"session_id":"sess-1","hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"ls"},"cwd":"/tmp"}`,
			check: func(t *testing.T, got map[string]any) {
				if got["ToolName"] != "shell" {
					t.Fatalf("ToolName = %v, want shell", got["ToolName"])
				}
				input := got["ToolInput"].(map[string]any)
				if input["command"] != "ls" {
					t.Fatalf("tool_input.command = %v, want ls", input["command"])
				}
			},
		},
		{
			name:  "pre_tool_use_apply_patch",
			input: `{"session_id":"sess-2","hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"patch":"*** Begin Patch"},"cwd":"/repo"}`,
			check: func(t *testing.T, got map[string]any) {
				if got["ToolName"] != "apply_patch" {
					t.Fatalf("ToolName = %v, want apply_patch", got["ToolName"])
				}
			},
		},
		{
			name:  "post_tool_use_string_response",
			input: `{"session_id":"sess-4","hook_event_name":"PostToolUse","tool_name":"shell","tool_input":{"command":"ls"},"tool_response":"file1\nfile2\n","cwd":"/tmp"}`,
			check: func(t *testing.T, got map[string]any) {
				if got["ToolName"] != "shell" {
					t.Fatalf("ToolName = %v, want shell", got["ToolName"])
				}
				resp, ok := got["ToolResponse"].(map[string]any)
				if !ok {
					t.Fatalf("ToolResponse not a map: %T %v", got["ToolResponse"], got["ToolResponse"])
				}
				if resp["value"] != "file1\nfile2\n" {
					t.Fatalf("ToolResponse.value = %v, want file1\\nfile2\\n", resp["value"])
				}
			},
		},
		{
			name:  "user_prompt_submit",
			input: `{"session_id":"sess-3","hook_event_name":"UserPromptSubmit","cwd":"/repo"}`,
			check: func(t *testing.T, got map[string]any) {
				if got["HookEventName"] != "UserPromptSubmit" {
					t.Fatalf("HookEventName = %v, want UserPromptSubmit", got["HookEventName"])
				}
				if got["SessionID"] != "sess-3" {
					t.Fatalf("SessionID = %v, want sess-3", got["SessionID"])
				}
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evt, err := c.DecodeHookInput([]byte(tc.input))
			if err != nil {
				t.Fatalf("DecodeHookInput() error = %v", err)
			}
			raw, _ := json.Marshal(evt)
			var asMap map[string]any
			_ = json.Unmarshal(raw, &asMap)
			tc.check(t, asMap)
		})
	}
}

func TestCodexDecodeHookInputSynthesizesToolUseID(t *testing.T) {
	t.Parallel()
	c := &Codex{}

	pre := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"ls"},"cwd":"/tmp"}`
	post := `{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"shell","tool_input":{"command":"ls"},"tool_response":"ok","cwd":"/tmp"}`

	preEvt, err := c.DecodeHookInput([]byte(pre))
	if err != nil {
		t.Fatalf("decode pre: %v", err)
	}
	postEvt, err := c.DecodeHookInput([]byte(post))
	if err != nil {
		t.Fatalf("decode post: %v", err)
	}
	if preEvt.ToolUseID == "" {
		t.Fatalf("PreToolUse ToolUseID empty, want synthesized")
	}
	if preEvt.ToolUseID != postEvt.ToolUseID {
		t.Fatalf("Pre/Post ToolUseIDs differ: %q vs %q", preEvt.ToolUseID, postEvt.ToolUseID)
	}

	// Different session → different ID
	pre2 := `{"session_id":"s2","hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"ls"},"cwd":"/tmp"}`
	evt2, _ := c.DecodeHookInput([]byte(pre2))
	if evt2.ToolUseID == preEvt.ToolUseID {
		t.Fatalf("different sessions produced same ToolUseID: %q", evt2.ToolUseID)
	}

	// Explicit tool_use_id wins over synthesis
	withID := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"ls"},"tool_use_id":"explicit-123","cwd":"/tmp"}`
	evt3, _ := c.DecodeHookInput([]byte(withID))
	if evt3.ToolUseID != "explicit-123" {
		t.Fatalf("explicit tool_use_id overridden: got %q", evt3.ToolUseID)
	}

	// UserPromptSubmit does not synthesize
	ups := `{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/repo"}`
	evt4, _ := c.DecodeHookInput([]byte(ups))
	if evt4.ToolUseID != "" {
		t.Fatalf("UserPromptSubmit got ToolUseID %q, want empty", evt4.ToolUseID)
	}
}

func TestCodexEncodeAllowEncodeDenyToolEvent(t *testing.T) {
	t.Parallel()

	c := &Codex{}
	evt := &agent.HookEvent{HookEventName: "PreToolUse", ToolName: "shell"}

	allowBytes, err := c.EncodeAllow(evt, "ok")
	if err != nil {
		t.Fatalf("EncodeAllow: %v", err)
	}
	if len(allowBytes) != 0 {
		t.Fatalf("EncodeAllow(PreToolUse) = %q, want empty output", allowBytes)
	}

	denyBytes, err := c.EncodeDeny(evt, "blocked")
	if err != nil {
		t.Fatalf("EncodeDeny: %v", err)
	}
	var deny map[string]any
	if err := json.Unmarshal(denyBytes, &deny); err != nil {
		t.Fatalf("unmarshal deny: %v", err)
	}
	if deny["decision"] != "deny" {
		t.Fatalf("deny decision = %v, want deny", deny["decision"])
	}
	if deny["reason"] != "blocked" {
		t.Fatalf("deny reason = %v, want blocked", deny["reason"])
	}
}

func TestCodexEncodeAllowEncodeDenyUserPromptSubmit(t *testing.T) {
	t.Parallel()

	c := &Codex{}
	evt := &agent.HookEvent{HookEventName: "UserPromptSubmit"}

	allowBytes, err := c.EncodeAllow(evt, "ok")
	if err != nil {
		t.Fatalf("EncodeAllow: %v", err)
	}
	if len(allowBytes) != 0 {
		t.Fatalf("EncodeAllow(UserPromptSubmit) = %q, want empty output", allowBytes)
	}

	denyBytes, err := c.EncodeDeny(evt, "not allowed")
	if err != nil {
		t.Fatalf("EncodeDeny: %v", err)
	}
	var deny map[string]any
	if err := json.Unmarshal(denyBytes, &deny); err != nil {
		t.Fatalf("unmarshal deny: %v", err)
	}
	if deny["decision"] != "block" {
		t.Fatalf("UserPromptSubmit deny decision = %v, want block", deny["decision"])
	}
	if deny["reason"] != "not allowed" {
		t.Fatalf("UserPromptSubmit deny reason = %v, want 'not allowed'", deny["reason"])
	}
}

func TestCodexFilterUserArgs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "passes through safe args",
			in:   []string{"--model", "gpt-5", "resume", "--sandbox", "workspace-write"},
			want: []string{"--model", "gpt-5", "resume", "--sandbox", "workspace-write"},
		},
		{
			name: "strips --sandbox danger-full-access pair",
			in:   []string{"--sandbox", "danger-full-access", "prompt"},
			want: []string{"prompt"},
		},
		{
			name: "strips --sandbox=danger-full-access inline",
			in:   []string{"--sandbox=danger-full-access", "prompt"},
			want: []string{"prompt"},
		},
		{
			name: "strips -a never pair",
			in:   []string{"-a", "never", "prompt"},
			want: []string{"prompt"},
		},
		{
			name: "strips --ask-for-approval=never inline",
			in:   []string{"--ask-for-approval=never"},
			want: nil,
		},
		{
			name: "passes through -a untrusted",
			in:   []string{"-a", "untrusted"},
			want: []string{"-a", "untrusted"},
		},
	}
	c := &Codex{}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := c.FilterUserArgs(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("FilterUserArgs(%#v) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCodexCleanupIsNoOp(t *testing.T) {
	t.Parallel()
	if err := (&Codex{}).Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
}
