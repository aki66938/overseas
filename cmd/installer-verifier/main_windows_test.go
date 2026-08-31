//go:build windows

package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestVerifyBundleScriptContainsCompletePreInstallTrustGate(t *testing.T) {
	for _, required := range []string{
		"Get-AuthenticodeSignature", "SignedCms", "CheckSignature", "Get-FileHash",
		"schema_version", "product_version", "source_commit", "mode", "release",
		"signer_thumbprints", "authenticode_required", "authenticode_thumbprints",
		"artifact-manifest.json", "fixture-manifest", "expected commit", "exact payload allowlist",
		"fixture artifact hash mismatch", "Get-SHA256 ([string]$artifact.path)",
		"FileMode]::CreateNew", "installer-verifier.json",
	} {
		if !strings.Contains(verifyBundleScript, required) {
			t.Fatalf("verifyBundleScript lacks %q", required)
		}
	}
	for _, forbidden := range []string{"msiexec", "Start-Process", "Invoke-Expression"} {
		if strings.Contains(strings.ToLower(verifyBundleScript), strings.ToLower(forbidden)) {
			t.Fatalf("verifyBundleScript contains mutation primitive %q", forbidden)
		}
	}
}

func TestVerifyBundleScriptParsesWithoutExecution(t *testing.T) {
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$null=[ScriptBlock]::Create([Console]::In.ReadToEnd())")
	command.Stdin = bytes.NewBufferString(verifyBundleScript)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("verifyBundleScript parse failed: %v: %s", err, output)
	}
}
