package guard_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuardRuntimeDoesNotImportHostedRuntime(t *testing.T) {
	disallowed := []string{
		"github.com/kontext-security/kontext-cli/gen/",
		"github.com/kontext-security/kontext-cli/internal/auth",
		"github.com/kontext-security/kontext-cli/internal/backend",
		"github.com/kontext-security/kontext-cli/internal/run",
		"github.com/kontext-security/kontext-cli/internal/sidecar",
	}
	root := "."
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			value := strings.Trim(imported.Path.Value, `"`)
			for _, blocked := range disallowed {
				if value == blocked || strings.HasPrefix(value, blocked+"/") {
					t.Fatalf("Guard local mode must not import hosted runtime package %q from %s", value, path)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
