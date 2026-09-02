#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $BundlePath,

    [Parameter(Mandatory = $true)]
    [string] $ServicePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$bundleRoot = [System.IO.Path]::GetFullPath($BundlePath)
$sourceService = [System.IO.Path]::GetFullPath($ServicePath)
$singBoxPath = Join-Path $bundleRoot 'sing-box.exe'
$manifestPath = Join-Path $bundleRoot 'sing-box.manifest.json'
$targetService = Join-Path $bundleRoot 'overseas-server-service.exe'

if (-not (Test-Path -LiteralPath $bundleRoot -PathType Container)) {
    throw "Bundle directory does not exist: $bundleRoot"
}
foreach ($requiredFile in @($sourceService, $singBoxPath, $manifestPath)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required package input does not exist: $requiredFile"
    }
}
if ($sourceService -eq $targetService) {
    throw 'ServicePath must be outside the bundle so packaging can verify publication.'
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ([string] $manifest.version -ne '1.13.19') {
    throw 'Bundle manifest version must be exactly 1.13.19.'
}
$singBoxHash = (Get-FileHash -LiteralPath $singBoxPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($singBoxHash -ne ([string] $manifest.executable_sha256).ToLowerInvariant()) {
    throw 'Bundle sing-box hash does not match its pinned manifest.'
}
$serviceHash = (Get-FileHash -LiteralPath $sourceService -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()

if (Test-Path -LiteralPath $targetService) {
    $publishedHash = (Get-FileHash -LiteralPath $targetService -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($publishedHash -ne $serviceHash) {
        throw 'Bundle already contains a different first-party service host.'
    }
}
else {
    $temporaryService = $targetService + '.tmp.' + [guid]::NewGuid().ToString('N')
    try {
        [System.IO.File]::Copy($sourceService, $temporaryService, $false)
        $stagedHash = (Get-FileHash -LiteralPath $temporaryService -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($stagedHash -ne $serviceHash) {
            throw 'Staged first-party service host hash changed during copy.'
        }
        [System.IO.File]::Move($temporaryService, $targetService)
    }
    finally {
        if (Test-Path -LiteralPath $temporaryService) {
            [System.IO.File]::Delete($temporaryService)
        }
    }
}

$manifest | Add-Member -MemberType NoteProperty -Name server_service_sha256 -Value $serviceHash -Force
$temporaryManifest = $manifestPath + '.tmp.' + [guid]::NewGuid().ToString('N')
$backupManifest = $manifestPath + '.backup.' + [guid]::NewGuid().ToString('N')
try {
    [System.IO.File]::WriteAllText(
        $temporaryManifest,
        ($manifest | ConvertTo-Json -Depth 10),
        (New-Object System.Text.UTF8Encoding($false))
    )
    [System.IO.File]::Replace($temporaryManifest, $manifestPath, $backupManifest)
}
finally {
    if (Test-Path -LiteralPath $temporaryManifest) {
        [System.IO.File]::Delete($temporaryManifest)
    }
    if (Test-Path -LiteralPath $backupManifest) {
        [System.IO.File]::Delete($backupManifest)
    }
}

[ordered] @{
    bundle_path = $bundleRoot
    service_path = $targetService
    server_service_sha256 = $serviceHash
} | ConvertTo-Json -Compress
