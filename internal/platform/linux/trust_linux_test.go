//go:build linux

package linux

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedFileRejectsSymlinksAndWritableComponents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership fixture")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte("core")))
	for _, kind := range []string{"valid", "file-symlink", "parent-symlink", "writable-file", "writable-parent", "wrong-hash"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			os.Mkdir(filepath.Join(root, "payload"), 0700)
			path := filepath.Join(root, "payload", "core")
			os.WriteFile(path, []byte("core"), 0600)
			relative := "payload/core"
			expected := digest
			switch kind {
			case "file-symlink":
				os.Symlink("core", filepath.Join(root, "payload", "alias"))
				relative = "payload/alias"
			case "parent-symlink":
				os.Symlink("payload", filepath.Join(root, "alias"))
				relative = "alias/core"
			case "writable-file":
				os.Chmod(path, 0666)
			case "writable-parent":
				os.Chmod(filepath.Dir(path), 0777)
			case "wrong-hash":
				expected = fmt.Sprintf("%064x", 0)
			}
			f, err := openTrustedAt(root, relative, expected)
			if f != nil {
				f.Close()
			}
			if (err == nil) != (kind == "valid") {
				t.Fatalf("open %s error=%v", kind, err)
			}
		})
	}
}
