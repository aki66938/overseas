//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
)

type windowsTrustVerifier struct{}

func main() { os.Exit(run(os.Args[1:], windowsTrustVerifier{}, os.Stderr)) }

func runPowerShell(script string, args ...string) error {
	commandArgs := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "AllSigned", "-Command", script}
	commandArgs = append(commandArgs, args...)
	command := exec.Command(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, commandArgs...)
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Run(); err != nil {
		return errors.New("PowerShell trust verification failed")
	}
	return nil
}

func (windowsTrustVerifier) verifyPackage(msi, thumbprint string) error {
	const script = `$ErrorActionPreference='Stop'; $signature=Get-AuthenticodeSignature -LiteralPath $args[0]; if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) { exit 10 }; if ($signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $args[1].ToUpperInvariant()) { exit 11 }`
	return runPowerShell(script, msi, thumbprint)
}

func (windowsTrustVerifier) verifyPayload(input payloadInput) error {
	const script = `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; $manifestBytes=[IO.File]::ReadAllBytes($args[2]); $content=New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList @(,$manifestBytes); $cms=New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList @($content,$true); $cms.Decode([Convert]::FromBase64String([IO.File]::ReadAllText($args[3]).Trim())); $cms.CheckSignature($true); if ($cms.SignerInfos.Count -ne 1 -or $null -eq $cms.SignerInfos[0].Certificate -or $cms.SignerInfos[0].Certificate.Thumbprint.ToUpperInvariant() -ne $args[4].ToUpperInvariant()) { exit 20 }; $manifest=[Text.Encoding]::UTF8.GetString($manifestBytes)|ConvertFrom-Json; if ($manifest.schema_version -ne 1 -or @($manifest.files).Count -eq 0) { exit 21 }; foreach($entry in @($manifest.files)){ $name=[string]$entry.name; if($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or $name.Contains('..')){exit 22}; $root=switch([string]$entry.destination){'program-files'{$args[0]}'program-data'{$args[1]}default{exit 23}}; $path=Join-Path $root $name; if(-not(Test-Path -LiteralPath $path -PathType Leaf)){exit 24}; if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant() -ne ([string]$entry.sha256).ToUpperInvariant()){exit 25}; if($entry.authenticode_required -eq $true){$signature=Get-AuthenticodeSignature -LiteralPath $path; if($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or @($entry.authenticode_thumbprints|ForEach-Object{$_.ToUpperInvariant()}) -notcontains $signature.SignerCertificate.Thumbprint.ToUpperInvariant()){exit 26}} }`
	return runPowerShell(script, input.ProgramFiles, input.ProgramData, input.Manifest, input.Signature, input.Thumbprint)
}
