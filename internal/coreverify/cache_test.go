//go:build windows

package coreverify

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCachedVerifierReusesOnlyIdenticalSuccessfulEvidence(t *testing.T) {
	identity := FileIdentity{VolumeSerialNumber: 1, FileIndex: 2, Size: 3, LastWriteTime: 4, ChangeTime: 5}
	identityCalls := 0
	fullCalls := 0
	verifier, err := newCachedVerifier(strings.Repeat("a", 64), []string{"BB"},
		func(string) (FileIdentity, error) { identityCalls++; return identity, nil },
		func(string, string, []string) (Evidence, error) {
			fullCalls++
			return Evidence{Identity: identity, SHA256: strings.Repeat("a", 64), AuthenticodeStatus: "Valid", AuthenticodeThumbprint: "BB"}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(`C:\Program Files\RegenBio\OverseasAccess\sing-box.exe`); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(`c:\program files\regenbio\overseasaccess\sing-box.exe`); err != nil {
		t.Fatal(err)
	}
	if identityCalls != 2 || fullCalls != 1 {
		t.Fatalf("identity calls=%d full calls=%d", identityCalls, fullCalls)
	}
	identity.ChangeTime++
	if err := verifier.Verify(`C:\Program Files\RegenBio\OverseasAccess\sing-box.exe`); err != nil {
		t.Fatal(err)
	}
	if fullCalls != 2 {
		t.Fatalf("full calls after identity change=%d", fullCalls)
	}
}

func TestCachedVerifierDoesNotCacheFailures(t *testing.T) {
	identity := FileIdentity{VolumeSerialNumber: 1, FileIndex: 2, Size: 3, LastWriteTime: 4, ChangeTime: 5}
	fullCalls := 0
	verifier, err := newCachedVerifier(strings.Repeat("a", 64), nil,
		func(string) (FileIdentity, error) { return identity, nil },
		func(string, string, []string) (Evidence, error) {
			fullCalls++
			return Evidence{}, errors.New("bad signature")
		})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := verifier.Verify(`C:\sing-box.exe`); err == nil {
			t.Fatal("verification succeeded")
		}
	}
	if fullCalls != 2 {
		t.Fatalf("failed verification calls=%d", fullCalls)
	}
}

func TestCachedVerifierRejectsEvidenceThatDoesNotMatchTrustPolicy(t *testing.T) {
	identity := FileIdentity{VolumeSerialNumber: 1, FileIndex: 2, Size: 3, LastWriteTime: 4, ChangeTime: 5}
	verifier, err := newCachedVerifier(strings.Repeat("a", 64), []string{"BB"},
		func(string) (FileIdentity, error) { return identity, nil },
		func(string, string, []string) (Evidence, error) {
			return Evidence{Identity: identity, SHA256: strings.Repeat("c", 64), AuthenticodeStatus: "Valid", AuthenticodeThumbprint: "CC"}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(`C:\sing-box.exe`); err == nil {
		t.Fatal("mismatched evidence was cached")
	}
}

func TestFileIdentityChangesWhenFileIsReplaced(t *testing.T) {
	path, _ := writeTestPE(t)
	first, err := readFileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement, _ := writeTestPE(t)
	data, err := os.ReadFile(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, 0), 0o755); err != nil {
		t.Fatal(err)
	}
	second, err := readFileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("file identity did not change: %+v", first)
	}
}
