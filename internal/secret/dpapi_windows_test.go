//go:build windows

package secret

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestMachineStoreRoundTripAndZeroesPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.bin")
	plaintext := []byte("test-only-secret")

	if err := StoreMachine(path, plaintext); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, make([]byte, len(plaintext))) {
		t.Fatal("StoreMachine did not zero the caller's plaintext buffer")
	}

	got, err := LoadMachine(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { zero(got) })
	if string(got) != "test-only-secret" {
		t.Fatalf("round trip mismatch: got %d bytes", len(got))
	}
}

func TestMachineStoreRejectsCorruptCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.bin")
	if err := os.WriteFile(path, []byte("not dpapi ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadMachine(path)
	if err == nil {
		zero(got)
		t.Fatal("LoadMachine accepted corrupt ciphertext")
	}
	if strings.Contains(err.Error(), "not dpapi ciphertext") {
		t.Fatal("error leaked secret content")
	}
}

func TestMachineLoadPreservesMissingFileIdentity(t *testing.T) {
	_, err := LoadMachine(filepath.Join(t.TempDir(), "missing.bin"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadMachine error = %v, want os.ErrNotExist", err)
	}
}

func TestMachineStoreAtomicallyReplacesExistingSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.bin")
	first := []byte("first-secret")
	second := []byte("second-secret")
	if err := StoreMachine(path, first); err != nil {
		t.Fatal(err)
	}
	if err := StoreMachine(path, second); err != nil {
		t.Fatal(err)
	}

	got, err := LoadMachine(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { zero(got) })
	if string(got) != "second-secret" {
		t.Fatalf("replacement mismatch: got %d bytes", len(got))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "credential.bin" {
		t.Fatalf("temporary file leaked after replacement: %v", entryNames(entries))
	}
}

func TestMachineStoreRestrictsFileACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.bin")
	plaintext := []byte("acl-secret")
	if err := StoreMachine(path, plaintext); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("stored path mode = %v, want regular file", info.Mode())
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("inspect ACL: %v", err)
	}
	sddl := sd.String()
	for _, allowed := range []string{";;;SY)", ";;;BA)"} {
		if !strings.Contains(sddl, allowed) {
			t.Fatalf("ACL %q does not grant expected principal %q", sddl, allowed)
		}
	}
	for _, forbidden := range []string{";;;BU)", ";;;AU)", ";;;WD)"} {
		if strings.Contains(sddl, forbidden) {
			t.Fatalf("ACL %q grants forbidden principal %q", sddl, forbidden)
		}
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
