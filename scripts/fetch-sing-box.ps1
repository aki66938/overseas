[CmdletBinding()]
param(
    [string] $Version,
    [string] $ExpectedSha256,
    [string] $Destination
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Command Get-SingBoxVersionText -ErrorAction SilentlyContinue)) {
    function Get-SingBoxVersionText {
        param([Parameter(Mandatory = $true)] [string] $Path)

        return (& $Path version 2>&1 | Out-String).Trim()
    }
}

function Get-PinnedManifest {
    param([Parameter(Mandatory = $true)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Pinned manifest not found: $Path"
    }

    $manifest = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    foreach ($name in @('version', 'archive_sha256', 'acquisition_url')) {
        if (-not $manifest.PSObject.Properties.Name.Contains($name)) {
            throw "Pinned manifest is missing field '$name'."
        }
    }
    return $manifest
}

function Assert-PinnedSha256 {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [string] $Value
    )

    $normalized = $Value.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        throw "$Name is required."
    }
    if ($normalized.Contains('$(')) {
        throw "$Name must be a literal pinned SHA-256 value."
    }
    if ($normalized -notmatch '^[0-9a-f]{64}$') {
        throw "$Name must be a 64-character lowercase SHA-256 digest."
    }
    if ($normalized -match '^0{64}$') {
        throw "$Name must not be the all-zero placeholder digest."
    }
    return $normalized
}

function Remove-TemporaryPath {
    param([string] $Path)

    if (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path -LiteralPath $Path)) {
        Remove-Item -LiteralPath $Path -Recurse -Force -Confirm:$false
    }
}

function Install-SingBoxPinnedRelease {
    param(
        [string] $Version,
        [string] $ExpectedSha256,
        [string] $Destination
    )

    if ([string]::IsNullOrWhiteSpace($Version)) {
        throw 'Version is required.'
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        throw 'ExpectedSha256 is required.'
    }
    if ([string]::IsNullOrWhiteSpace($Destination)) {
        throw 'Destination is required.'
    }

    $repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $manifestPath = Join-Path $repositoryRoot 'sing-box.manifest.json'
    $manifest = Get-PinnedManifest -Path $manifestPath
    $pinnedSha256 = Assert-PinnedSha256 -Name 'Pinned manifest archive_sha256' -Value ([string] $manifest.archive_sha256)
    $requestedSha256 = Assert-PinnedSha256 -Name 'ExpectedSha256' -Value $ExpectedSha256

    if ($Version.Trim() -ne [string] $manifest.version) {
        throw "Version '$Version' does not match pinned manifest version '$($manifest.version)'."
    }
    if ($requestedSha256 -ne $pinnedSha256) {
        throw 'ExpectedSha256 does not match the pinned manifest digest.'
    }

    $officialUrl = "https://github.com/SagerNet/sing-box/releases/download/v$($manifest.version)/sing-box-$($manifest.version)-windows-amd64.zip"
    if ([string] $manifest.acquisition_url -ne $officialUrl) {
        throw 'Pinned manifest acquisition_url must be the immutable official GitHub release asset.'
    }

    $resolvedDestination = [System.IO.Path]::GetFullPath($Destination)
    if (Test-Path -LiteralPath $resolvedDestination) {
        throw "Destination already exists: $resolvedDestination"
    }

    $destinationParent = Split-Path -Parent $resolvedDestination
    if ([string]::IsNullOrWhiteSpace($destinationParent)) {
        throw "Destination parent is invalid: $Destination"
    }
    New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null

    $tempRoot = Join-Path $destinationParent ('.fetch-sing-box-' + [guid]::NewGuid().ToString('N'))
    $downloadPath = Join-Path $tempRoot ([System.IO.Path]::GetFileName($officialUrl))
    $expandRoot = Join-Path $tempRoot 'expanded'
    $stagedInstall = Join-Path $tempRoot 'publish'

    New-Item -ItemType Directory -Path $tempRoot | Out-Null

    try {
        Invoke-WebRequest -Uri $officialUrl -OutFile $downloadPath

        $archiveHash = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($archiveHash -ne $pinnedSha256) {
            throw "Archive SHA-256 mismatch: got $archiveHash"
        }

        Expand-Archive -LiteralPath $downloadPath -DestinationPath $expandRoot

        $executables = @(Get-ChildItem -LiteralPath $expandRoot -Recurse -Filter 'sing-box.exe' -File)
        if ($executables.Count -ne 1) {
            throw "Expected exactly one sing-box.exe in archive, found $($executables.Count)."
        }

        $singBoxPath = $executables[0].FullName
        $versionText = Get-SingBoxVersionText -Path $singBoxPath
        if ($versionText -notmatch '\b1\.13\.19\b') {
            throw "sing-box version output does not contain 1.13.19: $versionText"
        }

        $signature = Get-AuthenticodeSignature -LiteralPath $singBoxPath
        $executableHash = (Get-FileHash -LiteralPath $singBoxPath -Algorithm SHA256).Hash.ToLowerInvariant()

        New-Item -ItemType Directory -Path $stagedInstall | Out-Null
        [System.IO.File]::Copy($singBoxPath, (Join-Path $stagedInstall 'sing-box.exe'))

        $signerSubject = ''
        $signerThumbprint = ''
        if ($null -ne $signature.SignerCertificate) {
            if ($signature.SignerCertificate.PSObject.Properties.Name.Contains('Subject')) {
                $signerSubject = [string] $signature.SignerCertificate.Subject
            }
            if ($signature.SignerCertificate.PSObject.Properties.Name.Contains('Thumbprint')) {
                $signerThumbprint = [string] $signature.SignerCertificate.Thumbprint
            }
        }

        $runtimeManifest = [ordered] @{
            version = [string] $manifest.version
            archive_sha256 = $pinnedSha256
            executable_sha256 = $executableHash
            signer_status = [string] $signature.Status
            signer_subject = $signerSubject
            signer_thumbprint = $signerThumbprint
            acquisition_url = $officialUrl
            acquired_at_utc = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        $runtimeManifestPath = Join-Path $stagedInstall 'sing-box.manifest.json'
        [System.IO.File]::WriteAllText(
            $runtimeManifestPath,
            ($runtimeManifest | ConvertTo-Json -Depth 5),
            (New-Object System.Text.UTF8Encoding($false))
        )

        Move-Item -LiteralPath $stagedInstall -Destination $resolvedDestination -Confirm:$false
        return $resolvedDestination
    }
    finally {
        Remove-TemporaryPath -Path $tempRoot
    }
}

Install-SingBoxPinnedRelease -Version $Version -ExpectedSha256 $ExpectedSha256 -Destination $Destination
