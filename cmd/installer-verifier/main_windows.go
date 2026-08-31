//go:build windows

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"unicode/utf16"
)

type windowsTrustVerifier struct{}

func main() { os.Exit(run(os.Args[1:], windowsTrustVerifier{}, os.Stderr)) }

func runPowerShell(script string, args ...string) error {
	preamble := `$payload=[Console]::In.ReadToEnd()|ConvertFrom-Json;$args=@($payload.arguments);Import-Module 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1' -ErrorAction Stop;`
	encoded := encodePowerShellCommand(preamble + script)
	var stdin bytes.Buffer
	if err := json.NewEncoder(&stdin).Encode(map[string][]string{"arguments": args}); err != nil {
		return errors.New("PowerShell trust input encoding failed")
	}
	command := exec.Command(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-EncodedCommand", encoded)
	command.Stdin = &stdin
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("PowerShell trust verification failed with exit code %d", exitError.ExitCode())
		}
		return errors.New("PowerShell trust verification failed")
	}
	return nil
}

func encodePowerShellCommand(script string) string {
	codeUnits := utf16.Encode([]rune(script))
	encoded := make([]byte, len(codeUnits)*2)
	for index, codeUnit := range codeUnits {
		binary.LittleEndian.PutUint16(encoded[index*2:], codeUnit)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func (windowsTrustVerifier) verifyPackage(msi, thumbprint string) error {
	const script = `$ErrorActionPreference='Stop'; $signature=Get-AuthenticodeSignature -LiteralPath $args[0]; if ($signature.Status.ToString() -ne 'Valid' -or $null -eq $signature.SignerCertificate) { exit 10 }; if ($signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $args[1].ToUpperInvariant()) { exit 11 }`
	return runPowerShell(script, msi, thumbprint)
}

const verifyBundleScript = `$ErrorActionPreference='Stop'
function Assert-OrdinaryFile([string]$Path) {
  if(-not [IO.Path]::IsPathRooted($Path) -or -not(Test-Path -LiteralPath $Path -PathType Leaf)){throw 'required file is absent'}
  $item=Get-Item -LiteralPath $Path -Force
  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'reparse file refused'}
}
function Assert-OrdinaryDirectory([string]$Path) {
  if(-not [IO.Path]::IsPathRooted($Path) -or -not(Test-Path -LiteralPath $Path -PathType Container)){throw 'required directory is absent'}
  $item=Get-Item -LiteralPath $Path -Force
  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'reparse directory refused'}
}
function Get-SHA256([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Assert-ExactProperties($Object,[string[]]$Names,[string]$Label) {
  $actual=@($Object.PSObject.Properties.Name|Sort-Object)
  $expected=@($Names|Sort-Object)
  if($actual.Count-ne$expected.Count-or (Compare-Object -ReferenceObject $expected -DifferenceObject $actual)){throw "$Label schema mismatch"}
}
function Assert-Detached([byte[]]$Bytes,[string]$SignaturePath,[string]$Signer) {
  Assert-OrdinaryFile $SignaturePath
  Add-Type -AssemblyName System.Security
  $content=New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList @(,$Bytes)
  $cms=New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList @($content,$true)
  $cms.Decode([Convert]::FromBase64String([IO.File]::ReadAllText($SignaturePath).Trim()))
  $cms.CheckSignature($true)
  if($cms.SignerInfos.Count-ne 1-or$null-eq$cms.SignerInfos[0].Certificate-or$cms.SignerInfos[0].Certificate.Thumbprint.ToUpperInvariant()-cne$Signer.ToUpperInvariant()){throw 'detached signer mismatch'}
}
function Assert-Authenticode([string]$Path,[string[]]$Signers) {
  $signature=Get-AuthenticodeSignature -LiteralPath $Path
  if($signature.Status.ToString() -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $Signers -notcontains $signature.SignerCertificate.Thumbprint.ToUpperInvariant()){throw 'Authenticode signer mismatch'}
}
$bundle=$args[0];$msi=$args[1];$fixturePath=$args[2];$fixtureSignature=$args[3];$releasePath=$args[4];$releaseSignature=$args[5]
$expectedCommit=$args[6];$expectedMSI=$args[7];$expectedFixture=$args[8];$expectedRelease=$args[9]
$fixtureSigner=$args[10].ToUpperInvariant();$releaseSigner=$args[11].ToUpperInvariant();$msiSigner=$args[12].ToUpperInvariant();$evidence=$args[13]
Assert-OrdinaryDirectory $bundle
foreach($path in @($msi,$fixturePath,$fixtureSignature,$releasePath,$releaseSignature)){Assert-OrdinaryFile $path}
if((Get-SHA256 $msi)-cne$expectedMSI-or(Get-SHA256 $fixturePath)-cne$expectedFixture-or(Get-SHA256 $releasePath)-cne$expectedRelease){throw 'externally pinned hash mismatch'}
Assert-Authenticode $msi @($msiSigner)
$fixtureBytes=[IO.File]::ReadAllBytes($fixturePath);Assert-Detached $fixtureBytes $fixtureSignature $fixtureSigner
$fixture=[Text.Encoding]::UTF8.GetString($fixtureBytes)|ConvertFrom-Json
Assert-ExactProperties $fixture @('schema_version','corporate_cidrs','corporate_dns','internal_suffixes','artifacts') 'fixture-manifest'
if($fixture.schema_version-ne 1-or@($fixture.corporate_cidrs).Count-eq 0-or@($fixture.corporate_dns).Count-eq 0-or@($fixture.internal_suffixes).Count-eq 0){throw 'fixture-manifest values invalid'}
$artifactRoles=@('action-helper','agent','capture-script','core','driver','installer','powershell','sentinel','server-service','ui')
Assert-ExactProperties $fixture.artifacts $artifactRoles 'fixture-manifest artifacts'
foreach($role in $artifactRoles){
  $artifact=$fixture.artifacts.$role;$allowed=@('path','sha256');if($role-in@('agent','core','server-service','ui')){$allowed+=,'installed_path'}
  Assert-ExactProperties $artifact $allowed "fixture artifact $role"
  if([string]$artifact.path-eq''-or[string]$artifact.sha256-cnotmatch'^[a-f0-9]{64}$'){throw 'fixture artifact invalid'}
  Assert-OrdinaryFile ([string]$artifact.path)
  if((Get-SHA256 ([string]$artifact.path))-cne[string]$artifact.sha256){throw 'fixture artifact hash mismatch'}
}
$releaseBytes=[IO.File]::ReadAllBytes($releasePath);Assert-Detached $releaseBytes $releaseSignature $releaseSigner
$release=[Text.Encoding]::UTF8.GetString($releaseBytes)|ConvertFrom-Json
Assert-ExactProperties $release @('schema_version','product_version','source_commit','mode','signer_thumbprints','files') 'release manifest'
if($release.schema_version-ne 1-or[string]$release.product_version-cne'0.1.0'-or[string]$release.source_commit-cne$expectedCommit-or[string]$release.mode-cne'release'){throw 'release expected commit/schema mismatch'}
$manifestSigners=@($release.signer_thumbprints|ForEach-Object{([string]$_).ToUpperInvariant()})
if($manifestSigners.Count-eq 0-or@($manifestSigners|Sort-Object -Unique).Count-ne$manifestSigners.Count-or$manifestSigners-notcontains$releaseSigner-or@($manifestSigners|Where-Object{$_-cnotmatch'^[A-F0-9]{40}$'}).Count-ne 0){throw 'release signer_thumbprints invalid'}
$expectedPayloadNames=@('SHA256SUMS','agent.yaml','agent.yaml.p7s','client-sbom.json','install-client.ps1','installer-verifier.exe','libcronet.dll','overseas-agent.exe','overseas-client.exe','sing-box-LICENSE.txt','sing-box.exe','sing-box.manifest.json','wintun-LICENSE.txt','wintun.dll')
$names=@($release.files|ForEach-Object{[string]$_.name})
if($names.Count-ne$expectedPayloadNames.Count-or@($names|Sort-Object -Unique).Count-ne$expectedPayloadNames.Count-or(Compare-Object -ReferenceObject ($expectedPayloadNames|Sort-Object) -DifferenceObject ($names|Sort-Object))){throw 'release manifest exact payload allowlist mismatch'}
$programDataNames=@('SHA256SUMS','agent.yaml','agent.yaml.p7s','client-sbom.json')
$authenticodeNames=@('installer-verifier.exe','overseas-agent.exe','overseas-client.exe','wintun.dll')
foreach($entry in @($release.files)){
  Assert-ExactProperties $entry @('name','destination','sha256','authenticode_required','authenticode_thumbprints') 'release payload entry'
  $name=[string]$entry.name;if($name-cnotmatch'^[A-Za-z0-9][A-Za-z0-9._-]*$'-or$name.Contains('..')-or[string]$entry.sha256-cnotmatch'^[a-f0-9]{64}$'){throw 'release payload entry invalid'}
  $expectedDestination=if($programDataNames-contains$name){'program-data'}else{'program-files'}
  if([string]$entry.destination-cne$expectedDestination-or[bool]$entry.authenticode_required-ne($authenticodeNames-contains$name)){throw 'release payload policy mismatch'}
  $path=Join-Path $bundle $name;Assert-OrdinaryFile $path
  if((Get-SHA256 $path)-cne[string]$entry.sha256){throw 'release payload hash mismatch'}
  $allowed=@($entry.authenticode_thumbprints|ForEach-Object{([string]$_).ToUpperInvariant()})
  if([bool]$entry.authenticode_required){if($allowed.Count-eq 0-or@($allowed|Where-Object{$manifestSigners-notcontains$_}).Count-ne 0){throw 'payload signer allowlist mismatch'};Assert-Authenticode $path $allowed}elseif($allowed.Count-ne 0){throw 'unsigned payload declares signers'}
}
$bundleNames=@(Get-ChildItem -LiteralPath $bundle -File -Force|ForEach-Object{$_.Name})
$expectedBundleNames=@($expectedPayloadNames)+@('artifact-manifest.json','artifact-manifest.json.p7s')
if($bundleNames.Count-ne$expectedBundleNames.Count-or(Compare-Object -ReferenceObject ($expectedBundleNames|Sort-Object) -DifferenceObject ($bundleNames|Sort-Object))){throw 'bundle contains unmanifested files'}
if([IO.Path]::GetFullPath($releasePath)-cne[IO.Path]::GetFullPath((Join-Path $bundle 'artifact-manifest.json'))-or[IO.Path]::GetFullPath($releaseSignature)-cne[IO.Path]::GetFullPath((Join-Path $bundle 'artifact-manifest.json.p7s'))){throw 'release trust roots are outside bundle'}
$evidenceDirectory=Split-Path -Parent $evidence;Assert-OrdinaryDirectory $evidenceDirectory
$record=[ordered]@{schema_version=1;kind='installer-verifier.json';verified=$true;source_commit=$expectedCommit;msi_sha256=$expectedMSI;fixture_manifest_sha256=$expectedFixture;release_manifest_sha256=$expectedRelease;fixture_signer=$fixtureSigner;release_signer=$releaseSigner;msi_signer=$msiSigner;verified_utc=[datetime]::UtcNow.ToString('o')}
$stream=[IO.File]::Open($evidence,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$writer=New-Object IO.StreamWriter($stream,(New-Object Text.UTF8Encoding($false)));$writer.Write(($record|ConvertTo-Json -Compress));$writer.Flush()}finally{if($null-ne$writer){$writer.Dispose()}else{$stream.Dispose()}}
`

func (windowsTrustVerifier) verifyBundle(input bundleInput) error {
	return runPowerShell(verifyBundleScript, input.Bundle, input.MSI, input.FixtureManifest, input.FixtureSignature, input.ReleaseManifest, input.ReleaseSignature, input.ExpectedCommit, input.ExpectedMSISHA256, input.ExpectedFixtureSHA256, input.ExpectedReleaseSHA256, input.FixtureSigner, input.ReleaseSigner, input.MSISigner, input.Evidence)
}

func (windowsTrustVerifier) verifyPayload(input payloadInput) error {
	const script = `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; $manifestBytes=[IO.File]::ReadAllBytes($args[2]); $content=New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList @(,$manifestBytes); $cms=New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList @($content,$true); $cms.Decode([Convert]::FromBase64String([IO.File]::ReadAllText($args[3]).Trim())); $cms.CheckSignature($true); if ($cms.SignerInfos.Count -ne 1 -or $null -eq $cms.SignerInfos[0].Certificate -or $cms.SignerInfos[0].Certificate.Thumbprint.ToUpperInvariant() -ne $args[4].ToUpperInvariant()) { exit 20 }; $manifest=[Text.Encoding]::UTF8.GetString($manifestBytes)|ConvertFrom-Json; if ($manifest.schema_version -ne 1 -or @($manifest.files).Count -eq 0) { exit 21 }; foreach($entry in @($manifest.files)){ $name=[string]$entry.name; if($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or $name.Contains('..')){exit 22}; $root=switch([string]$entry.destination){'program-files'{$args[0]}'program-data'{$args[1]}default{exit 23}}; $path=Join-Path $root $name; if(-not(Test-Path -LiteralPath $path -PathType Leaf)){exit 24}; if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant() -ne ([string]$entry.sha256).ToUpperInvariant()){exit 25}; if($entry.authenticode_required -eq $true){$signature=Get-AuthenticodeSignature -LiteralPath $path; if($signature.Status.ToString() -ne 'Valid' -or $null -eq $signature.SignerCertificate -or @($entry.authenticode_thumbprints|ForEach-Object{$_.ToUpperInvariant()}) -notcontains $signature.SignerCertificate.Thumbprint.ToUpperInvariant()){exit 26}} }`
	return runPowerShell(script, input.ProgramFiles, input.ProgramData, input.Manifest, input.Signature, input.Thumbprint)
}

const firewallLifecycleScript = `$ErrorActionPreference='Stop'
$mode=$args[0]
$data='C:\ProgramData\RegenBio\OverseasAccess'
$journal=Join-Path $data 'msi-firewall-owned.json'
$group='RegenBioOverseasAccess.Installer'
$definitions=@(
  [ordered]@{name='RegenBioOverseasAccess-AllowAgent-Out';display_name='RegenBioOverseasAccess-AllowAgent-Out';program='C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe';protocol='TCP';local_port='Any';remote_port='Any';local_address='Any';remote_address='Any';service='Any';interface_type='Any';authentication='NotRequired';encryption='NotRequired';local_user='Any';remote_user='Any';remote_machine='Any';override_block_rules='False'},
  [ordered]@{name='RegenBioOverseasAccess-AllowCoreTCP-Out';display_name='RegenBioOverseasAccess-AllowCoreTCP-Out';program='C:\Program Files\RegenBio\OverseasAccess\sing-box.exe';protocol='TCP';local_port='Any';remote_port='Any';local_address='Any';remote_address='Any';service='Any';interface_type='Any';authentication='NotRequired';encryption='NotRequired';local_user='Any';remote_user='Any';remote_machine='Any';override_block_rules='False'},
  [ordered]@{name='RegenBioOverseasAccess-AllowCoreUDP-Out';display_name='RegenBioOverseasAccess-AllowCoreUDP-Out';program='C:\Program Files\RegenBio\OverseasAccess\sing-box.exe';protocol='UDP';local_port='Any';remote_port='Any';local_address='Any';remote_address='Any';service='Any';interface_type='Any';authentication='NotRequired';encryption='NotRequired';local_user='Any';remote_user='Any';remote_machine='Any';override_block_rules='False'}
)
function Test-SameDefinition($left,$right){
  return [string]::Equals([string]$left.name,[string]$right.name,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.display_name,[string]$right.display_name,[StringComparison]::Ordinal) -and
    [string]::Equals([string]$left.program,[string]$right.program,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.protocol,[string]$right.protocol,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.local_port,[string]$right.local_port,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.remote_port,[string]$right.remote_port,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.local_address,[string]$right.local_address,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.remote_address,[string]$right.remote_address,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.service,[string]$right.service,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.interface_type,[string]$right.interface_type,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.authentication,[string]$right.authentication,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.encryption,[string]$right.encryption,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.local_user,[string]$right.local_user,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.remote_user,[string]$right.remote_user,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.remote_machine,[string]$right.remote_machine,[StringComparison]::OrdinalIgnoreCase) -and
    [string]::Equals([string]$left.override_block_rules,[string]$right.override_block_rules,[StringComparison]::OrdinalIgnoreCase)
}
function Get-Definition([string]$name){
  $matches=@($definitions|Where-Object{$_.name -eq $name})
  if($matches.Count -ne 1){throw 'Unknown firewall definition.'}
  return $matches[0]
}
function Read-FirewallJournal{
  if(!(Test-Path -LiteralPath $journal -PathType Leaf)){return $null}
  $value=Get-Content -LiteralPath $journal -Raw|ConvertFrom-Json
  if($value.schema_version -ne 2 -or $value.product_id -ne 'RegenBioOverseasAccess' -or $null -eq $value.owned_rules){throw 'Invalid firewall ownership journal.'}
  foreach($owned in @($value.owned_rules)){if(-not(Test-SameDefinition $owned (Get-Definition ([string]$owned.name)))){throw 'Invalid owned firewall definition.'}}
  if($null -ne $value.current_operation){
    if([string]$value.current_operation.id -notmatch '^[0-9a-fA-F-]{36}$' -or [string]$value.current_operation.state -notin @('applying','committed')){throw 'Invalid firewall operation journal.'}
    foreach($entry in @($value.current_operation.rules)){
      if([string]$entry.disposition -notin @('intended','created','preexisting') -or -not(Test-SameDefinition $entry (Get-Definition ([string]$entry.name)))){throw 'Invalid firewall operation entry.'}
      if($entry.PSObject.Properties.Name -contains 'rollback_state' -and [string]$entry.rollback_state -notin @('pending','resolved')){throw 'Invalid firewall rollback state.'}
    }
  }
  return $value
}
function Write-FirewallJournal($value){
  if(!(Test-Path -LiteralPath $data -PathType Container)){throw 'Protected product data directory is absent.'}
  $temporary=$journal+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
  try{
    [IO.File]::WriteAllText($temporary,($value|ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
    & "$env:WINDIR\System32\icacls.exe" $temporary '/inheritance:r' '/grant:r' '*S-1-5-18:(F)' '*S-1-5-32-544:(F)'|Out-Null
    if($LASTEXITCODE -ne 0){throw 'Could not protect firewall ownership journal.'}
    Move-Item -LiteralPath $temporary -Destination $journal -Force
  }finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force}}
}
function Get-ExactFirewallRule($definition){
  $rules=@(Get-NetFirewallRule -Name $definition.name -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
  if($rules.Count -eq 0){return $null}
  if($rules.Count -ne 1){throw 'Firewall rule name is ambiguous.'}
  $rule=$rules[0]
  $applications=@($rule|Get-NetFirewallApplicationFilter)
  $ports=@($rule|Get-NetFirewallPortFilter)
  $addresses=@($rule|Get-NetFirewallAddressFilter)
  $services=@($rule|Get-NetFirewallServiceFilter)
  $interfaces=@($rule|Get-NetFirewallInterfaceFilter)
  $security=@($rule|Get-NetFirewallSecurityFilter)
  if($applications.Count -eq 1 -and $ports.Count -eq 1 -and $addresses.Count -eq 1 -and $services.Count -eq 1 -and $interfaces.Count -eq 1 -and $security.Count -eq 1){
    $observed=[ordered]@{name=[string]$rule.Name;display_name=[string]$rule.DisplayName;program=[string]$applications[0].Program;protocol=[string]$ports[0].Protocol;local_port=[string]$ports[0].LocalPort;remote_port=[string]$ports[0].RemotePort;local_address=[string]$addresses[0].LocalAddress;remote_address=[string]$addresses[0].RemoteAddress;service=[string]$services[0].Service;interface_type=[string]$interfaces[0].InterfaceType;authentication=[string]$security[0].Authentication;encryption=[string]$security[0].Encryption;local_user=[string]$security[0].LocalUser;remote_user=[string]$security[0].RemoteUser;remote_machine=[string]$security[0].RemoteMachine;override_block_rules=[string]$security[0].OverrideBlockRules}
  }else{$observed=$null}
  if($applications.Count -ne 1 -or $ports.Count -ne 1 -or $addresses.Count -ne 1 -or $services.Count -ne 1 -or $interfaces.Count -ne 1 -or $security.Count -ne 1 -or
    $rule.Group -ne $group -or $rule.DisplayName -ne $definition.display_name -or
    [string]$rule.Direction -ne 'Outbound' -or [string]$rule.Action -ne 'Allow' -or
    [string]$rule.Enabled -ne 'True' -or [string]$rule.Profile -ne 'Any' -or
    -not [string]::Equals([string]$applications[0].Package,'Any',[StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals([string]$interfaces[0].InterfaceAlias,'Any',[StringComparison]::OrdinalIgnoreCase) -or -not(Test-SameDefinition $observed $definition)){
    throw 'Firewall rule does not exactly match the product definition.'
  }
  return $rule
}
function Test-JournalOwnsDefinition($value,$definition){
  return @($value.owned_rules|Where-Object{Test-SameDefinition $_ $definition}).Count -eq 1
}
function Remove-OwnedDefinition($value,$definition){
  $value.owned_rules=@($value.owned_rules|Where-Object{-not(Test-SameDefinition $_ $definition)})
}
if($mode -eq 'install'){
  $value=Read-FirewallJournal
  if($null -eq $value){$value=[ordered]@{schema_version=2;product_id='RegenBioOverseasAccess';owned_rules=@();current_operation=$null}}
  elseif($null -ne $value.current_operation -and $value.current_operation.state -eq 'applying'){throw 'An unfinished firewall operation blocks install.'}
  $value.current_operation=[ordered]@{id=[guid]::NewGuid().ToString('D');state='applying';rules=@()}
  Write-FirewallJournal $value
  foreach($definition in $definitions){
    $entry=[ordered]@{name=$definition.name;display_name=$definition.display_name;program=$definition.program;protocol=$definition.protocol;local_port=$definition.local_port;remote_port=$definition.remote_port;local_address=$definition.local_address;remote_address=$definition.remote_address;service=$definition.service;interface_type=$definition.interface_type;authentication=$definition.authentication;encryption=$definition.encryption;local_user=$definition.local_user;remote_user=$definition.remote_user;remote_machine=$definition.remote_machine;override_block_rules=$definition.override_block_rules;disposition='intended';absent_before=$null;rollback_state='pending'}
    $value.current_operation.rules+=,$entry
    Write-FirewallJournal $value
    $raw=@(Get-NetFirewallRule -Name $definition.name -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
    if($raw.Count -ne 0){
      [void](Get-ExactFirewallRule $definition)
      if(-not(Test-JournalOwnsDefinition $value $definition)){throw 'Exact pre-existing firewall rule lacks product ownership proof.'}
      $entry.absent_before=$false
      $entry.disposition='preexisting'
    }else{
      $entry.absent_before=$true
      Write-FirewallJournal $value
      New-NetFirewallRule -Name $definition.name -DisplayName $definition.display_name -Group $group -Direction Outbound -Action Allow -Program $definition.program -Protocol $definition.protocol -Profile Any -Enabled True -PolicyStore PersistentStore|Out-Null
      [void](Get-ExactFirewallRule $definition)
      $entry.disposition='created'
      if(-not(Test-JournalOwnsDefinition $value $definition)){$value.owned_rules+=,$definition}
    }
    Write-FirewallJournal $value
  }
  $value.current_operation.state='committed'
  Write-FirewallJournal $value
  exit 0
}
if($mode -eq 'rollback'){
  $value=Read-FirewallJournal
  if($null -eq $value -or $null -eq $value.current_operation){exit 0}
  $entries=@($value.current_operation.rules)
  [array]::Reverse($entries)
  foreach($entry in $entries){
    if($entry.PSObject.Properties.Name -contains 'rollback_state' -and $entry.rollback_state -eq 'resolved'){continue}
    $createdNow=$entry.disposition -eq 'created' -or ($entry.disposition -eq 'intended' -and $entry.absent_before -eq $true)
    if(-not $createdNow){continue}
    $definition=Get-Definition ([string]$entry.name)
    $exact=Get-ExactFirewallRule $definition
    if($null -ne $exact){
      Remove-NetFirewallRule -Name $definition.name -PolicyStore PersistentStore -ErrorAction Stop
      if(@(Get-NetFirewallRule -Name $definition.name -PolicyStore PersistentStore -ErrorAction SilentlyContinue).Count -ne 0){throw 'Created firewall rule deletion could not be proven.'}
    }
    Remove-OwnedDefinition $value $definition
    $entry.rollback_state='resolved'
    Write-FirewallJournal $value
  }
  $value.current_operation=$null
  if(@($value.owned_rules).Count -eq 0){Remove-Item -LiteralPath $journal -Force}else{Write-FirewallJournal $value}
  exit 0
}
if($mode -eq 'uninstall'){
  $value=Read-FirewallJournal
  if($null -eq $value){
    foreach($definition in $definitions){if(@(Get-NetFirewallRule -Name $definition.name -PolicyStore PersistentStore -ErrorAction SilentlyContinue).Count -ne 0){throw 'Firewall ownership proof is absent.'}}
    exit 0
  }
	foreach($definition in $definitions){
	  $raw=@(Get-NetFirewallRule -Name $definition.name -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
	  if($raw.Count -eq 0){continue}
	  [void](Get-ExactFirewallRule $definition)
	  $currentRules=@()
	  if($null -ne $value.current_operation){$currentRules=@($value.current_operation.rules)}
	  $currentCreated=@($currentRules|Where-Object{(Test-SameDefinition $_ $definition) -and ($_.disposition -eq 'created' -or ($_.disposition -eq 'intended' -and $_.absent_before -eq $true))}).Count -eq 1
    if(-not(Test-JournalOwnsDefinition $value $definition) -and -not $currentCreated){throw 'Firewall rule is not product-owned.'}
    Remove-NetFirewallRule -Name $definition.name -PolicyStore PersistentStore -ErrorAction Stop
  }
  foreach($definition in $definitions){if(@(Get-NetFirewallRule -Name $definition.name -PolicyStore PersistentStore -ErrorAction SilentlyContinue).Count -ne 0){throw 'Product firewall residue remains.'}}
  Remove-Item -LiteralPath $journal -Force
  exit 0
}
throw 'Unsupported firewall lifecycle mode.'`

func (windowsTrustVerifier) installFirewall() error {
	return runPowerShell(firewallLifecycleScript, "install")
}
func (windowsTrustVerifier) rollbackFirewall() error {
	return runPowerShell(firewallLifecycleScript, "rollback")
}
func (windowsTrustVerifier) uninstallFirewall() error {
	return runPowerShell(firewallLifecycleScript, "uninstall")
}
func (windowsTrustVerifier) cleanupRuntime() error {
	const script = `$ErrorActionPreference='Stop';$d='C:\ProgramData\RegenBio\OverseasAccess';$l=Join-Path $d 'runtime-owned.json';$s=@('credential.bin','sing-box.json');if(!(Test-Path -LiteralPath $l)){foreach($n in $s){if(Test-Path -LiteralPath (Join-Path $d $n)){exit 40}};exit 0};$o=Get-Content -Raw -LiteralPath $l|ConvertFrom-Json;if($o.schema_version -ne 2){exit 41};$targets=@($o.finalized);$paths=@($o.finalized);foreach($i in @($o.intents)){$t=[string]$i.target;if($t -notin $s -or [string]$i.phase -notin @('prepared','temporary-written','publishing','published')){exit 41};$targets+=$t;foreach($e in @(@('temporary','publish'),@('backup','backup'),@('replaced','replaced'))){$n=[string]$i.($e[0]);$r='^\.'+[regex]::Escape($t)+'\.'+$e[1]+'-[a-f0-9]{32}\.tmp$';if([IO.Path]::GetFileName($n)-ne $n -or $n -notmatch $r){exit 41};$paths+=$n}};foreach($n in @($o.finalized)){if($n -notin $s){exit 41}};foreach($n in $s){$p=Join-Path $d $n;if((Test-Path -LiteralPath $p)-and $targets -notcontains $n){exit 41}};foreach($n in @($paths|Select-Object -Unique)){$p=Join-Path $d $n;if(Test-Path -LiteralPath $p -PathType Leaf){$z=New-Object byte[] ((Get-Item -LiteralPath $p).Length);[IO.File]::WriteAllBytes($p,$z);Remove-Item -LiteralPath $p -Force}elseif(Test-Path -LiteralPath $p){exit 41};if(Test-Path -LiteralPath $p){exit 42}};Remove-Item -LiteralPath $l -Force;if(Test-Path -LiteralPath $l){exit 42}`
	return runPowerShell(script)
}
