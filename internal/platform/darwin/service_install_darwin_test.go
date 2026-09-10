//go:build darwin

package darwin

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedCoreDigestRejectsChangedBinary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root owned fixture")
	}
	path := filepath.Join(t.TempDir(), "core")
	data := []byte("fixed test core")
	digest := sha256.Sum256(data)
	if err := os.WriteFile(path, data, 0755); err != nil {
		t.Fatal(err)
	}
	if err := verifyCoreFile(path, hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := verifyCoreFile(path, hex.EncodeToString(digest[:])); err == nil {
		t.Fatal("accepted changed core hash")
	}
}

func TestProtectedServiceFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership fixture")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := protectedPath(path, false, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := protectedPath(path, false, 0600); err == nil {
		t.Fatal("accepted writable file")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := protectedPath(link, false, 0600); err == nil {
		t.Fatal("accepted symlink")
	}
	os.Chmod(path, 0600)
	os.Chown(path, 501, 20)
	if err := protectedPath(path, false, 0600); err == nil {
		t.Fatal("accepted user owned file")
	}
}

func TestDaemonLockExcludesAnotherInstance(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership fixture")
	}
	path := filepath.Join(t.TempDir(), "daemon.lock")
	first, err := lockDaemon(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := lockDaemon(path); err == nil {
		second.Close()
		t.Fatal("second daemon acquired lock")
	}
}

func TestServiceRejectsCallerSelectedPaths(t *testing.T) {
	if err := VerifyInstalledCore("/tmp/core"); err == nil {
		t.Fatal("accepted caller executable")
	}
	if err := VerifyInstalledLaunch(CorePath, "/tmp/config"); err == nil {
		t.Fatal("accepted caller config")
	}
	if err := WriteInstalledConfig("/tmp/config", []byte("{}")); err == nil {
		t.Fatal("wrote arbitrary config path")
	}
}
