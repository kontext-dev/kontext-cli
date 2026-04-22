package run

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/credential"
)

// writeHermesEnv writes resolved credentials into <dir>/.env in KEY=VALUE form,
// sorted by env var name for deterministic output. Values that contain
// whitespace, '#', or quotes are wrapped in double quotes with escaping.
func writeHermesEnv(dir string, resolved []credential.Resolved) error {
	entries := make([]credential.Resolved, len(resolved))
	copy(entries, resolved)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].EnvVar < entries[j].EnvVar
	})

	var b strings.Builder
	for _, r := range entries {
		fmt.Fprintf(&b, "%s=%s\n", r.EnvVar, dotenvQuote(r.Value))
	}

	path := filepath.Join(dir, ".env")
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func dotenvQuote(value string) string {
	if !strings.ContainsAny(value, " \t\"#'\\\n") {
		return value
	}
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}
