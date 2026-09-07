package contracts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportGraphRejectsTransitiveCgoBinding(t *testing.T) {
	dir := t.TempDir()
	// Use approved shared package names so an unrelated allowlist violation
	// cannot disguise failure to inspect a transitive package's cgo sources.
	for name, content := range map[string]string{
		"go.mod":                        "module corp.example/overseas-access-gateway\n\ngo 1.27.0\n",
		"internal/localapi/root.go":     "package localapi\nimport _ \"corp.example/overseas-access-gateway/internal/lineprobe\"\n",
		"internal/lineprobe/middle.go":  "package lineprobe\nimport _ \"corp.example/overseas-access-gateway/internal/traceevent\"\n",
		"internal/traceevent/shared.go": "package traceevent\n",
		"internal/traceevent/native.go": "package traceevent\n/* typedef int native_handle; */\nimport \"C\"\n",
	} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []struct{ os, arch string }{{"linux", "amd64"}, {"darwin", "arm64"}} {
		t.Run(target.os, func(t *testing.T) {
			if violations := importGraphViolations(t, dir, target.os, target.arch, "0", "./internal/localapi"); len(violations) != 0 {
				t.Fatalf("portable fixture unexpectedly rejected: %v", violations)
			}
			violations := importGraphViolations(t, dir, target.os, target.arch, "1", "./internal/localapi")
			if !strings.Contains(strings.Join(violations, "\n"), "internal/traceevent contains cgo sources") {
				t.Fatalf("transitive cgo binding escaped guard: %v", violations)
			}
		})
	}
}
