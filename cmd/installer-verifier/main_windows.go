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

func (windowsTrustVerifier) installFirewall() error {
	const script = `$ErrorActionPreference='Stop'; $g='RegenBioOverseasAccess.Installer'; $r=@(@('RegenBioOverseasAccess-AllowAgent-Out','C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe','TCP'),@('RegenBioOverseasAccess-AllowCoreTCP-Out','C:\Program Files\RegenBio\OverseasAccess\sing-box.exe','TCP'),@('RegenBioOverseasAccess-AllowCoreUDP-Out','C:\Program Files\RegenBio\OverseasAccess\sing-box.exe','UDP')); foreach($x in $r){if(Get-NetFirewallRule -Name $x[0] -ErrorAction SilentlyContinue){exit 31};New-NetFirewallRule -Name $x[0] -DisplayName $x[0] -Group $g -Direction Outbound -Action Allow -Program $x[1] -Protocol $x[2] -Profile Any -PolicyStore PersistentStore|Out-Null}`
	return runPowerShell(script)
}
func (windowsTrustVerifier) removeFirewall() error {
	const script = `$ErrorActionPreference='Stop'; foreach($n in @('RegenBioOverseasAccess-AllowAgent-Out','RegenBioOverseasAccess-AllowCoreTCP-Out','RegenBioOverseasAccess-AllowCoreUDP-Out')){$r=@(Get-NetFirewallRule -Name $n -PolicyStore PersistentStore -ErrorAction SilentlyContinue);foreach($x in $r){if($x.Group -ne 'RegenBioOverseasAccess.Installer'){exit 32};Remove-NetFirewallRule -Name $n -PolicyStore PersistentStore}}`
	return runPowerShell(script)
}
func (windowsTrustVerifier) cleanupRuntime() error {
	const script = `$ErrorActionPreference='Stop';$d='C:\ProgramData\RegenBio\OverseasAccess';$l=Join-Path $d 'runtime-owned.json';if(!(Test-Path -LiteralPath $l)){exit 40};$o=Get-Content -Raw -LiteralPath $l|ConvertFrom-Json;$owned=@($o.files);foreach($n in @('credential.bin','sing-box.json')){$p=Join-Path $d $n;if((Test-Path -LiteralPath $p)-and $owned -notcontains $n){exit 41}};foreach($n in $owned){if($n -notin @('credential.bin','sing-box.json')){exit 41};$p=Join-Path $d $n;if(Test-Path -LiteralPath $p){$z=New-Object byte[] ((Get-Item -LiteralPath $p).Length);[IO.File]::WriteAllBytes($p,$z);Remove-Item -LiteralPath $p -Force};if(Test-Path -LiteralPath $p){exit 42}}}`
	return runPowerShell(script)
}
