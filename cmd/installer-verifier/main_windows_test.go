//go:build windows

package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRunPowerShellReceivesExactArguments(t *testing.T) {
	err := runPowerShell(`if($args.Count-ne 2-or$args[0]-cne'path with spaces'-or$args[1]-cne'ABC123'){exit 19}`, "path with spaces", "ABC123")
	if err != nil {
		t.Fatalf("runPowerShell() error: %v", err)
	}
}

func TestRunPowerShellLoadsNetSecurityModule(t *testing.T) {
	err := runPowerShell(`$command=Get-Command Get-NetFirewallRule -ErrorAction Stop;if($command.Source-cne'NetSecurity'){exit 18}`)
	if err != nil {
		t.Fatalf("runPowerShell() NetSecurity error: %v", err)
	}
}

func TestRunPowerShellVerifiesConfiguredMSI(t *testing.T) {
	msi := os.Getenv("INSTALLER_VERIFIER_TEST_MSI")
	thumbprint := os.Getenv("INSTALLER_VERIFIER_TEST_THUMBPRINT")
	if msi == "" || thumbprint == "" {
		t.Skip("signed MSI integration inputs are absent")
	}
	err := runPowerShell(`if($args.Count-ne 2){exit 41};if(-not(Test-Path -LiteralPath $args[0] -PathType Leaf)){exit 42};$signature=Get-AuthenticodeSignature -LiteralPath $args[0];if($null-eq$signature){exit 43};if($null-eq$signature.Status){exit 44};if($signature.Status.ToString() -ne 'Valid'){exit (30+[int]$signature.Status)};if($null-eq$signature.SignerCertificate){exit 45};if($signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $args[1].ToUpperInvariant()){exit 11}`, msi, thumbprint)
	if err != nil {
		t.Fatalf("runPowerShell() error: %v", err)
	}
}

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
