package run

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/credential"
)

func TestBuildHermesLaunch(t *testing.T) {
	dir := t.TempDir()
	kontextBin := "/bin/kontext"
	sessionID := "sess-launch"
	socket := filepath.Join(dir, "s.sock")
	resolved := []credential.Resolved{
		{Entry: credential.Entry{EnvVar: "GITHUB_TOKEN"}, Value: "x"},
	}
	home, args, extraEnv, err := buildHermesLaunch(dir, kontextBin, socket, sessionID, resolved)
	if err != nil {
		t.Fatalf("buildHermesLaunch: %v", err)
	}
	if home == "" || !strings.HasPrefix(home, dir) {
		t.Errorf("unexpected home: %q", home)
	}
	if len(args) != 0 {
		t.Errorf("expected no extra args for hermes, got %v", args)
	}
	found := false
	for _, e := range extraEnv {
		if e == "HERMES_HOME="+home {
			found = true
		}
	}
	if !found {
		t.Errorf("HERMES_HOME not in extraEnv: %v", extraEnv)
	}
}
