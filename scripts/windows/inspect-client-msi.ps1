[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $MsiPath,
    [Parameter(Mandatory = $true)][string] $StagingPath,
    [Parameter(Mandatory = $true)][string] $WixPath,
    [Parameter(Mandatory = $true)][string] $DtfPath,
    [string] $OutputDirectory = 'build/msi-inspect'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$output = [IO.Path]::GetFullPath((Join-Path $repo $OutputDirectory))
if (-not $output.StartsWith($repo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe inspection directory.' }
if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Recurse -Force }
New-Item -ItemType Directory -Path $output | Out-Null
& $WixPath msi decompile -x (Join-Path $output 'files') -o (Join-Path $output 'decompiled.wxs') $MsiPath
if (-not $? -or $LASTEXITCODE -ne 0) { throw 'MSI decompilation failed.' }

$map = [ordered] @{
    AgentExe='overseas-agent.exe'; ClientExe='overseas-client.exe'; CredentialProvisionerFile='credential-provisioner.exe'
    InstallerVerifierFile='installer-verifier.exe'; InstallerHarnessFile='install-client.ps1'; ProvisioningGuide='PROVISIONING.md'
    SingBoxExe='sing-box.exe'; CoreManifest='sing-box.manifest.json'; CronetRuntime='libcronet.dll'; TunDriver='wintun.dll'
    SingBoxLicense='sing-box-LICENSE.txt'; WintunLicense='wintun-LICENSE.txt'; AgentPolicy='agent.yaml'; AgentPolicySignature='agent.yaml.p7s'
    ArtifactManifest='artifact-manifest.json'; ArtifactManifestSignature='artifact-manifest.json.p7s'; ClientSbom='client-sbom.json'; PayloadChecksums='SHA256SUMS'
}
$extracted = Get-ChildItem -LiteralPath (Join-Path $output 'files\File') -File
if (Compare-Object @($map.Keys | Sort-Object) @($extracted.Name | Sort-Object)) { throw 'MSI file-table allowlist mismatch.' }
$manifest = Get-Content -LiteralPath (Join-Path $StagingPath 'artifact-manifest.json') -Raw | ConvertFrom-Json
foreach ($id in $map.Keys) {
    $source = Join-Path $StagingPath $map[$id]
    $packaged = Join-Path $output ('files\File\' + $id)
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $packaged -Algorithm SHA256).Hash) { throw "Extracted payload mismatch: $id" }
}
foreach ($entry in @($manifest.files)) {
    $source = Join-Path $StagingPath ([string] $entry.name)
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne ([string] $entry.sha256).ToLowerInvariant()) { throw "Source manifest mismatch: $($entry.name)" }
    if ($entry.authenticode_required -eq $true) {
        $signature = Get-AuthenticodeSignature -LiteralPath $source
        if ($signature.Status -ne 'Valid' -or @($entry.authenticode_thumbprints) -notcontains $signature.SignerCertificate.Thumbprint.ToLowerInvariant()) { throw "Authenticode mismatch: $($entry.name)" }
    }
}
if ($manifest.mode -eq 'release') {
    Add-Type -AssemblyName System.Security
    $bytes = [IO.File]::ReadAllBytes((Join-Path $StagingPath 'artifact-manifest.json'))
    $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList @(,$bytes)
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList @($content,$true)
    $cms.Decode([Convert]::FromBase64String([IO.File]::ReadAllText((Join-Path $StagingPath 'artifact-manifest.json.p7s')).Trim()))
    $cms.CheckSignature($true)
}
else {
    if ([IO.File]::ReadAllText((Join-Path $StagingPath 'artifact-manifest.json.p7s')) -ne 'INSPECT-ONLY-NOT-SIGNED') { throw 'Inspect-only signature sentinel mismatch.' }
    if ((Get-AuthenticodeSignature -LiteralPath $MsiPath).Status -ne 'NotSigned') { throw 'Inspect-only MSI unexpectedly signed.' }
}

$forbiddenName = '(?i)credential\.bin|\.pfx$|\.pem$|\.key$'
$binaryForbiddenContent = '(?i)BEGIN (RSA |EC )?PRIVATE KEY'
$textForbiddenContent = '(?i)cleartextcredential|bearer\s+[a-z0-9._-]+|password\s*[:=]\s*[^"R\s]'
$textExtensions = @('.ps1', '.md', '.yaml', '.json', '.p7s', '.txt')
foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $output 'files') -Recurse -File)) {
    if ($file.Name -match $forbiddenName) { throw "Secret-bearing filename in MSI: $($file.Name)" }
    $text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($file.FullName))
    if ($text -match $binaryForbiddenContent) { throw "Private-key content in MSI: $($file.Name)" }
    if (($textExtensions -contains $file.Extension -or $file.Name -eq 'SHA256SUMS') -and $text -match $textForbiddenContent) {
        throw "Secret-like text content in MSI: $($file.Name)"
    }
}

Add-Type -Path $DtfPath
$database = [WixToolset.Dtf.WindowsInstaller.Database]::new((Resolve-Path $MsiPath).Path, [WixToolset.Dtf.WindowsInstaller.DatabaseOpenMode]::ReadOnly)
function Get-MsiTableRows([string] $Table) {
    $rows = @()
    $view = $database.OpenView("SELECT * FROM ``$Table``"); $view.Execute()
    while ($record = $view.Fetch()) {
        $values = for ($index = 1; $index -le $record.FieldCount; $index++) { try { $record.GetString($index) } catch { '<binary>' } }
        $rows += ,@($values)
        $record.Dispose()
    }
    $view.Dispose()
    return $rows
}
$sequence = @{}
foreach ($row in @(Get-MsiTableRows 'InstallExecuteSequence')) { $sequence[[string] $row[0]] = [int] $row[2] }
if ($sequence.VerifyPackageTrust -ge $sequence.InstallInitialize) { throw 'VerifyPackageTrust must precede InstallInitialize.' }
if ($sequence.MsiSafeRemove -ge $sequence.StopServices) { throw 'MsiSafeRemove must precede StopServices.' }
if ($sequence.VerifyInstalledPayload -ge $sequence.InstallServices -or $sequence.VerifyInstalledPayload -le $sequence.InstallFiles) { throw 'VerifyInstalledPayload must follow InstallFiles and precede InstallServices.' }
if ($sequence.RemoveExistingProducts -le $sequence.InstallInitialize) { throw 'Major upgrade removal ordering is unsafe.' }
$aclRows = @(Get-MsiTableRows 'MsiLockPermissionsEx')
$expectedSddl = @('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)', 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
foreach ($sddl in $expectedSddl) { if (@($aclRows | Where-Object { $_[3] -eq $sddl }).Count -ne 1) { throw "Required ACL row is absent: $sddl" } }
$propertyRows = @(Get-MsiTableRows 'Property')
$trustMode = @($propertyRows | Where-Object { $_[0] -eq 'PACKAGE_TRUST_MODE' } | ForEach-Object { $_[1] })
if ($trustMode.Count -ne 1 -or $trustMode[0] -notin @('INSPECT_ONLY_REFUSES_INSTALL','RELEASE_SIGNED')) { throw 'Package trust mode is invalid.' }
$customActions = @(Get-MsiTableRows 'CustomAction')
$packageTrustActions = @($customActions | Where-Object { $_[0] -eq 'VerifyPackageTrust' -and $_[1] -eq '2' -and $_[2] -eq 'InstallerVerifierBinary' })
$payloadTrustActions = @($customActions | Where-Object { $_[0] -eq 'VerifyInstalledPayload' -and $_[1] -eq '3074' -and $_[2] -eq 'InstallerVerifierBinary' })
if ($packageTrustActions.Count -ne 1 -or $payloadTrustActions.Count -ne 1) { throw 'First-party trust custom actions are invalid.' }
$packageThumbprintMatch = [regex]::Match([string] $packageTrustActions[0][3], '--thumbprint\s+"([A-Fa-f0-9]{40})"')
$payloadThumbprintMatch = [regex]::Match([string] $payloadTrustActions[0][3], '--thumbprint\s+"([A-Fa-f0-9]{40})"')
if (-not $packageThumbprintMatch.Success -or -not $payloadThumbprintMatch.Success) { throw 'Embedded corporate trust anchor is absent.' }
$embeddedCorporateThumbprint = $packageThumbprintMatch.Groups[1].Value.ToUpperInvariant()
if ($payloadThumbprintMatch.Groups[1].Value.ToUpperInvariant() -ne $embeddedCorporateThumbprint) { throw 'Package and payload trust anchors differ.' }
if ($manifest.mode -eq 'release') {
    if ($trustMode[0] -ne 'RELEASE_SIGNED' -or $embeddedCorporateThumbprint -eq ('0' * 40)) { throw 'Release trust metadata is invalid.' }
    $msiSignature = Get-AuthenticodeSignature -LiteralPath $MsiPath
    if ($msiSignature.Status -ne 'Valid' -or $null -eq $msiSignature.SignerCertificate -or $msiSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $embeddedCorporateThumbprint) {
        throw 'Release MSI signature does not match its embedded trust anchor.'
    }
    if ($cms.SignerInfos.Count -ne 1 -or $null -eq $cms.SignerInfos[0].Certificate -or
        $cms.SignerInfos[0].Certificate.Thumbprint.ToUpperInvariant() -ne $embeddedCorporateThumbprint) {
        throw 'Release manifest signer does not match the embedded trust anchor.'
    }
}
elseif ($trustMode[0] -ne 'INSPECT_ONLY_REFUSES_INSTALL' -or $embeddedCorporateThumbprint -ne ('0' * 40)) {
    throw 'Inspect-only MSI does not contain the fail-closed trust sentinel.'
}
foreach ($table in @('ServiceInstall','ServiceControl','Registry','Wix4FirewallException','Upgrade')) { [void] @(Get-MsiTableRows $table) }
$database.Dispose()
[ordered] @{ msi_sha256 = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash; payload_count = $map.Count; mode = $manifest.mode; source_commit = $manifest.source_commit } | ConvertTo-Json -Compress
