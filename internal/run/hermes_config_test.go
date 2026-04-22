package run

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/credential"
)

func TestWriteHermesEnv(t *testing.T) {
	dir := t.TempDir()
	resolved := []credential.Resolved{
		{Entry: credential.Entry{EnvVar: "GITHUB_TOKEN"}, Value: "ghs_abc"},
		{Entry: credential.Entry{EnvVar: "LINEAR_API_KEY"}, Value: "lin_xyz"},
	}
	if err := writeHermesEnv(dir, resolved); err != nil {
		t.Fatalf("writeHermesEnv: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	got := string(b)
	if !containsLine(got, `GITHUB_TOKEN=ghs_abc`) {
		t.Errorf(".env missing GITHUB_TOKEN line: %q", got)
	}
	if !containsLine(got, `LINEAR_API_KEY=lin_xyz`) {
		t.Errorf(".env missing LINEAR_API_KEY line: %q", got)
	}
}

func containsLine(haystack, needle string) bool {
	for _, line := range splitLines(haystack) {
		if line == needle {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
