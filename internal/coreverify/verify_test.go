//go:build windows

package coreverify

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerify(t *testing.T) {
	executablePath, executableHash := writeTestPE(t)

	tests := []struct {
		name            string
		path            string
		expectedSHA256  string
		signerAllowlist []string
		security        securityMetadata
		signature       signatureMetadata
		wantErr         string
	}{
		{
			name:           "accepts pinned unsigned executable when hash matches",
			path:           executablePath,
			expectedSHA256: executableHash,
			security: securityMetadata{
				OwnerSID: "S-1-5-32-544",
			},
			signature: signatureMetadata{
				Status: "NotSigned",
			},
		},
		{
			name:           "rejects mismatched hash",
			path:           executablePath,
			expectedSHA256: strings.Repeat("b", 64),
			security: securityMetadata{
				OwnerSID: "S-1-5-32-544",
			},
			signature: signatureMetadata{
				Status: "NotSigned",
			},
			wantErr: "sha256 mismatch",
		},
		{
			name:           "rejects writable by standard users",
			path:           executablePath,
			expectedSHA256: executableHash,
			security: securityMetadata{
				OwnerSID:         "S-1-5-32-544",
				UnsafeWriteSIDs:  []string{"S-1-5-32-545"},
				UnsafeWriteNames: []string{"BUILTIN\\Users"},
			},
			signature: signatureMetadata{
				Status: "NotSigned",
			},
			wantErr: "standard users",
		},
		{
			name:           "rejects invalid authenticode status",
			path:           executablePath,
			expectedSHA256: executableHash,
			security: securityMetadata{
				OwnerSID: "S-1-5-32-544",
			},
			signature: signatureMetadata{
				Status: "UnknownError",
			},
			wantErr: "Authenticode",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			restore := installTestSeams(
				func(string) (securityMetadata, error) { return test.security, nil },
				func(string) (signatureMetadata, error) { return test.signature, nil },
			)
			t.Cleanup(restore)

			err := Verify(test.path, test.expectedSHA256, test.signerAllowlist)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("Verify() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Verify() error = nil, want substring %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Verify() error = %q, want substring %q", err.Error(), test.wantErr)
			}
		})
	}
}

func TestVerifyRejectsDirectory(t *testing.T) {
	restore := installTestSeams(
		func(string) (securityMetadata, error) { return securityMetadata{OwnerSID: "S-1-5-32-544"}, nil },
		func(string) (signatureMetadata, error) { return signatureMetadata{Status: "NotSigned"}, nil },
	)
	t.Cleanup(restore)

	err := Verify(t.TempDir(), strings.Repeat("a", 64), nil)
	if err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("Verify() error = %v, want directory rejection", err)
	}
}

func TestVerifyRejectsReparsePoint(t *testing.T) {
	targetPath, targetHash := writeTestPE(t)
	linkPath := filepath.Join(t.TempDir(), "sing-box-link.exe")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	restore := installTestSeams(
		func(string) (securityMetadata, error) { return securityMetadata{OwnerSID: "S-1-5-32-544"}, nil },
		func(string) (signatureMetadata, error) { return signatureMetadata{Status: "NotSigned"}, nil },
	)
	t.Cleanup(restore)

	err := Verify(linkPath, targetHash, nil)
	if err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("Verify() error = %v, want reparse-point rejection", err)
	}
}

func installTestSeams(
	security func(string) (securityMetadata, error),
	signature func(string) (signatureMetadata, error),
) func() {
	previousSecurity := inspectSecurity
	previousSignature := inspectAuthenticode
	inspectSecurity = security
	inspectAuthenticode = signature
	return func() {
		inspectSecurity = previousSecurity
		inspectAuthenticode = previousSignature
	}
}

func writeTestPE(t *testing.T) (string, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "sing-box.exe")
	bytes := make([]byte, 128)
	bytes[0] = 0x4d
	bytes[1] = 0x5a
	bytes[0x3c] = 0x40
	bytes[0x40] = 0x50
	bytes[0x41] = 0x45
	if err := os.WriteFile(path, bytes, 0o755); err != nil {
		t.Fatalf("write test executable: %v", err)
	}

	sum := sha256.Sum256(bytes)
	return path, hex.EncodeToString(sum[:])
}
