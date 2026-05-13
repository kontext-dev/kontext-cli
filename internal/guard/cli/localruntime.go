package cli

import (
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

func defaultGuardSocketPath() string {
	return localruntime.DefaultSocketPath()
}

func ensureGuardSocketDir(socketPath string) error {
	return localruntime.EnsureSocketDir(socketPath)
}
