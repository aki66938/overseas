//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedAncestorRejectsSymlinkAndWritablePaths(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root fixture required")
	}
	d, e := os.MkdirTemp("/Library/Application Support", ".regenbio-installer-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(d) // Exact generated fixture only; never an installation path.
	if e = protect(d, false); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(d, "real")
	os.Mkdir(p, 0755)
	l := filepath.Join(d, "link")
	os.Symlink(p, l)
	if protect(l, false) == nil {
		t.Fatal("symlink accepted")
	}
	os.Chmod(p, 0777)
	if protect(p, false) == nil {
		t.Fatal("writable path accepted")
	}
}

func TestCopyStageDoesNotFollowEscapingLink(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, appName, "Contents"), 0755)
	os.Symlink("/etc/passwd", filepath.Join(d, appName, "Contents", "evil"))
	if _, e := makeManifest(d); e == nil {
		t.Fatal("escaping link accepted")
	}
}
