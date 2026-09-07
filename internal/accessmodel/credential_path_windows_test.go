//go:build windows

package accessmodel

import (
	"path/filepath"
	"testing"
)

func TestCredentialPathMatchesWindowsFilepath(t *testing.T) {
	check := func(path string) {
		t.Helper()
		if got, want := windowsCredentialPathIsAbs(path), filepath.IsAbs(path); got != want {
			t.Fatalf("absolute(%q) = %v, Windows filepath.IsAbs = %v", path, got, want)
		}
	}
	for _, test := range credentialPathCases {
		check(test.path)
	}
	// Exercise short/incomplete/device/UNC volume edge cases against the pinned
	// native implementation, including mixed separators and dot components.
	for _, prefix := range []string{"", `C:`, `1:`, `\`, `/`, `\\`, `//`, `\/`, `\\.`, `\\?`, `\??`, `\\?\UNC`, `\\.\UNC`, `\??\UNC`} {
		for _, middle := range []string{"", `\`, `/`, `C:`, `C:\`, `server`, `server\`, `server/share`, `.`, `..`, `..\share`, `server\..`, `server\.`, `UNC`, `UNC\`} {
			for _, suffix := range []string{"", `\`, `/`, `\credential.bin`, `/credential.bin`, `\..\credential.bin`} {
				check(prefix + middle + suffix)
			}
		}
	}
}
