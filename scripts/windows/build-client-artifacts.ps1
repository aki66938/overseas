[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Inspect', 'Release')]
    [string] $Mode,
    [string] $OutputDirectory = 'build/msi',
    [string] $SigningCertificateThumbprint,
    [string] $SignToolPath = 'signtool.exe'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$target = [IO.Path]::GetFullPath((Join-Path $repo $OutputDirectory))
if (-not $target.StartsWith($repo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe artifact output directory.' }
$lock = Get-Content -LiteralPath (Join-Path $repo 'deploy\client\build-lock.json') -Raw | ConvertFrom-Json
$certificate = $null
if ($Mode -eq 'Release') {
    if ($SigningCertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Release requires a corporate signing certificate thumbprint.' }
    $certificate = @(Get-ChildItem Cert:\CurrentUser\My,Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $SigningCertificateThumbprint -and $_.HasPrivateKey })
    if ($certificate.Count -ne 1) { throw 'Release signing certificate is absent or ambiguous.' }
}
$workingTreeStatus = @(& git status --porcelain --untracked-files=normal)
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the Git worktree.' }
if ($workingTreeStatus.Count -ne 0) { throw 'Artifact builds require a clean Git worktree.' }

function Assert-Hash([string] $Path, [string] $Expected) {
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected.ToLowerInvariant()) { throw "Locked hash mismatch for '$([IO.Path]::GetFileName($Path))'." }
}

function Write-DetachedCms([string] $ContentPath, [string] $SignaturePath) {
    Add-Type -AssemblyName System.Security
    $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList @(,[IO.File]::ReadAllBytes($ContentPath))
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList @($content, $true)
    $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner $certificate[0]
    $signer.DigestAlgorithm = New-Object Security.Cryptography.Oid '2.16.840.1.101.3.4.2.1'
    $cms.ComputeSignature($signer)
    [IO.File]::WriteAllText($SignaturePath, [Convert]::ToBase64String($cms.Encode()), [Text.Encoding]::ASCII)
}

if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
New-Item -ItemType Directory -Path $target | Out-Null
$scratch = Join-Path $target '.extract'
$coreArchive = Join-Path $repo ('artifacts\' + $lock.sing_box.archive)
$tunArchive = Join-Path $repo ('artifacts\' + $lock.wintun.archive)
Assert-Hash $coreArchive $lock.sing_box.archive_sha256
Assert-Hash $tunArchive $lock.wintun.archive_sha256
Expand-Archive -LiteralPath $coreArchive -DestinationPath (Join-Path $scratch 'core')
Expand-Archive -LiteralPath $tunArchive -DestinationPath (Join-Path $scratch 'tun')

$copies = @{
    'overseas-agent.exe' = 'bin\overseas-agent.exe'
    'overseas-client.exe' = 'bin\overseas-client.exe'
    'credential-provisioner.exe' = 'bin\credential-provisioner.exe'
    'installer-verifier.exe' = 'bin\installer-verifier.exe'
    'install-client.ps1' = 'deploy\client\install-client.ps1'
    'PROVISIONING.md' = 'deploy\client\PROVISIONING.md'
    'agent.yaml' = 'deploy\client\agent.yaml'
    'agent.yaml.p7s' = 'deploy\client\agent.yaml.p7s'
    'sing-box.manifest.json' = 'sing-box.manifest.json'
}
foreach ($name in @($copies.Keys | Sort-Object)) { Copy-Item -LiteralPath (Join-Path $repo $copies[$name]) -Destination (Join-Path $target $name) }
$coreRoot = Join-Path $scratch ('core\sing-box-' + $lock.sing_box.version + '-windows-amd64')
Copy-Item -LiteralPath (Join-Path $coreRoot 'sing-box.exe') -Destination (Join-Path $target 'sing-box.exe')
Copy-Item -LiteralPath (Join-Path $coreRoot 'libcronet.dll') -Destination (Join-Path $target 'libcronet.dll')
Copy-Item -LiteralPath (Join-Path $coreRoot 'LICENSE') -Destination (Join-Path $target 'sing-box-LICENSE.txt')
Copy-Item -LiteralPath (Join-Path $scratch 'tun\wintun\bin\amd64\wintun.dll') -Destination (Join-Path $target 'wintun.dll')
Copy-Item -LiteralPath (Join-Path $scratch 'tun\wintun\LICENSE.txt') -Destination (Join-Path $target 'wintun-LICENSE.txt')

$wintunSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $target 'wintun.dll')
if ($wintunSignature.Status -ne 'Valid' -or $wintunSignature.SignerCertificate.Thumbprint.ToLowerInvariant() -ne $lock.wintun.dll_signer_thumbprint) { throw 'Wintun signature mismatch.' }

if ($Mode -eq 'Release') {
    $harnessPath = Join-Path $target 'install-client.ps1'
    $harness = [IO.File]::ReadAllText($harnessPath)
    $sentinel = '0000000000000000000000000000000000000000'
    if (-not $harness.Contains($sentinel)) { throw 'Installer harness trust-anchor sentinel is absent.' }
    [IO.File]::WriteAllText($harnessPath, $harness.Replace($sentinel, $SigningCertificateThumbprint.ToUpperInvariant()), (New-Object Text.UTF8Encoding($false)))
    Write-DetachedCms -ContentPath (Join-Path $target 'agent.yaml') -SignaturePath (Join-Path $target 'agent.yaml.p7s')
    foreach ($name in @('overseas-agent.exe', 'overseas-client.exe', 'credential-provisioner.exe', 'installer-verifier.exe')) {
        & $SignToolPath sign /fd SHA256 /sha1 $SigningCertificateThumbprint (Join-Path $target $name) | Out-Null
        if (-not $? -or $LASTEXITCODE -ne 0) { throw "Authenticode signing failed for '$name'." }
    }
}

$sourceCommit = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[a-f0-9]{40}$') { throw 'Could not bind artifacts to the Git commit.' }
$dataNames = @('agent.yaml', 'agent.yaml.p7s', 'artifact-manifest.json', 'artifact-manifest.json.p7s', 'client-sbom.json', 'SHA256SUMS')
$firstParty = @('overseas-agent.exe', 'overseas-client.exe', 'credential-provisioner.exe', 'installer-verifier.exe')
$files = @()
foreach ($item in @(Get-ChildItem -LiteralPath $target -File | Sort-Object Name)) {
    $required = $item.Name -eq 'wintun.dll' -or ($Mode -eq 'Release' -and $firstParty -contains $item.Name)
    $allowed = @()
    if ($required) { $allowed = @($(if ($item.Name -eq 'wintun.dll') { $lock.wintun.dll_signer_thumbprint } else { $SigningCertificateThumbprint.ToLowerInvariant() })) }
    $files += [ordered] @{
        name = $item.Name; destination = $(if ($dataNames -contains $item.Name) { 'program-data' } else { 'program-files' })
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        authenticode_required = $required; authenticode_thumbprints = $allowed
    }
}
$signerThumbprints = @($lock.wintun.dll_signer_thumbprint)
if ($Mode -eq 'Release') { $signerThumbprints += $SigningCertificateThumbprint.ToLowerInvariant() }
$manifest = [ordered] @{ schema_version = 1; product_version = '0.1.0'; source_commit = $sourceCommit; mode = $Mode.ToLowerInvariant(); signer_thumbprints = @($signerThumbprints); files = $files }
$manifestPath = Join-Path $target 'artifact-manifest.json'
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
$signaturePath = $manifestPath + '.p7s'
if ($Mode -eq 'Release') {
    Write-DetachedCms -ContentPath $manifestPath -SignaturePath $signaturePath
}
else { [IO.File]::WriteAllText($signaturePath, 'INSPECT-ONLY-NOT-SIGNED', [Text.Encoding]::ASCII) }

$sbom = [ordered] @{
    schema_version = 1; format = 'RegenBio-client-sbom'; source_commit = $sourceCommit
    components = @(
        [ordered] @{ name = 'sing-box'; version = $lock.sing_box.version; license_file = 'sing-box-LICENSE.txt'; source = $lock.sing_box.source },
        [ordered] @{ name = 'Wintun'; version = $lock.wintun.version; license = 'GPL-2.0'; attribution = 'Wintun is distributed under the GPLv2'; license_file = 'wintun-LICENSE.txt'; source = $lock.wintun.source }
    )
}
[IO.File]::WriteAllText((Join-Path $target 'client-sbom.json'), ($sbom | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
$sumLines = @(Get-ChildItem -LiteralPath $target -File | Sort-Object Name | ForEach-Object { '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name })
[IO.File]::WriteAllLines((Join-Path $target 'SHA256SUMS'), $sumLines, (New-Object Text.UTF8Encoding($false)))
Remove-Item -LiteralPath $scratch -Recurse -Force
[ordered] @{ mode = $Mode; source_commit = $sourceCommit; output = $target; signing_thumbprint = $(if ($certificate) { $certificate[0].Thumbprint } else { $null }) } | ConvertTo-Json -Compress
