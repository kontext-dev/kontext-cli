package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

func defaultGuardSocketPath() string {
	if path := os.Getenv("KONTEXT_GUARD_SOCKET"); path != "" {
		return path
	}
	return filepath.Join("/tmp", fmt.Sprintf("kontext-guard-%d", os.Getuid()), "kontext.sock")
}

func ensureGuardSocketDir(socketPath string) error {
	return os.MkdirAll(filepath.Dir(socketPath), 0o700)
}
