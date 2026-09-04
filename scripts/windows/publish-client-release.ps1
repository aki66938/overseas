[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $SigningCertificateThumbprint,
    [string] $SignToolPath = 'signtool.exe',
    [string] $FinalMsiPath = 'dist/OverseasAccessSetup-RELEASE_SIGNED.msi'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$workspace = [IO.Path]::GetFullPath((Join-Path $repo '..\..\..'))
$lock = Get-Content -LiteralPath (Join-Path $repo 'deploy\client\build-lock.json') -Raw | ConvertFrom-Json
$final = [IO.Path]::GetFullPath((Join-Path $repo $FinalMsiPath))
if (-not $final.StartsWith($repo + [IO.Path]::DirectorySeparatorChar) -or [IO.Path]::GetFileName($final) -notmatch 'RELEASE_SIGNED') { throw 'Unsafe release output path.' }
if (Test-Path -LiteralPath $final) { throw 'Final release artifact already exists.' }
$id = [guid]::NewGuid().ToString('N')
$temporaryRoot = Join-Path $repo ('build\release-' + $id)
$payloadRelative = 'build/release-' + $id + '/payload'
$payload = Join-Path $repo $payloadRelative
$temporaryMsi = Join-Path $temporaryRoot 'candidate.msi'
$wixExecutable = [IO.Path]::GetFullPath((Join-Path $workspace $lock.wix.executable_path))
$utilExtension = [IO.Path]::GetFullPath((Join-Path $workspace $lock.wix.util_extension_path))
$firewallExtension = [IO.Path]::GetFullPath((Join-Path $workspace $lock.wix.firewall_extension_path))
$iisExtension = [IO.Path]::GetFullPath((Join-Path $workspace $lock.wix.iis_extension_path))
$dtf = [IO.Path]::GetFullPath((Join-Path $workspace $lock.wix.dtf_path))
$goExecutable = [IO.Path]::GetFullPath((Join-Path $workspace $lock.go.executable_path))
$workingTreeStatus = @(& git -C $repo status --porcelain --untracked-files=normal)
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the Git worktree.' }
if ($workingTreeStatus.Count -ne 0) { throw 'Release publication requires a clean Git worktree.' }

function Assert-Hash([string] $Path, [string] $Expected) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) {
        throw "Locked release tool '$([IO.Path]::GetFileName($Path))' is absent or mismatched."
    }
}
Assert-Hash $goExecutable $lock.go.executable_sha256
Assert-Hash $wixExecutable $lock.wix.executable_sha256
Assert-Hash $utilExtension $lock.wix.util_extension_sha256
Assert-Hash $firewallExtension $lock.wix.firewall_extension_sha256
Assert-Hash $iisExtension $lock.wix.iis_extension_sha256
Assert-Hash $dtf $lock.wix.dtf_sha256
if ((& $goExecutable version) -ne ('go version go' + $lock.go.version + ' windows/amd64')) { throw 'Locked Go version is mismatched.' }
if ((& $wixExecutable --version) -notmatch ('^' + [regex]::Escape($lock.wix.version) + '\+')) { throw 'Locked WiX version is mismatched.' }
$signToolCommand = Get-Command $SignToolPath -CommandType Application -ErrorAction Stop
$signTool = [IO.Path]::GetFullPath($signToolCommand.Source)
$signToolSignature = Get-AuthenticodeSignature -LiteralPath $signTool
if ($signToolSignature.Status -ne 'Valid' -or $null -eq $signToolSignature.SignerCertificate -or $signToolSignature.SignerCertificate.Subject -notmatch 'Microsoft') {
    throw 'signtool is not a verified Microsoft executable.'
}

function Assert-SafeReleaseParent([string] $Path) {
    $parent = [IO.Path]::GetFullPath((Split-Path -Parent $Path))
    if (-not [string]::Equals($parent, $repo, [StringComparison]::OrdinalIgnoreCase) -and
        -not $parent.StartsWith($repo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Release parent escapes the repository.' }
    $relative = $parent.Substring($repo.Length).TrimStart('\', '/')
    $current = $repo
    foreach ($segment in @($relative -split '[\\/]' | Where-Object { $_ })) {
        $current = Join-Path $current $segment
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
        }
        else {
            [void] [IO.Directory]::CreateDirectory($current)
            $item = Get-Item -LiteralPath $current -Force
        }
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Release parent contains a reparse point or non-directory.' }
    }
    return $parent
}

function Wait-ExclusiveFileAccess {
    param([Parameter(Mandatory = $true)][string] $Path, [int] $TimeoutSeconds = 15)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $stream.Dispose()
            return
        }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw "Timed out waiting for exclusive access to '$Path'." }
            Start-Sleep -Milliseconds 200
        }
    } while ($true)
}

function Remove-TemporaryReleaseRoot {
    param([Parameter(Mandatory = $true)][string] $Path, [int] $TimeoutSeconds = 15)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
            return
        }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw "Timed out cleaning temporary release root '$Path'." }
            Start-Sleep -Milliseconds 200
        }
        catch [UnauthorizedAccessException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw "Timed out cleaning temporary release root '$Path'." }
            Start-Sleep -Milliseconds 200
        }
    } while ($true)
}
Assert-SafeReleaseParent -Path $final | Out-Null
Assert-SafeReleaseParent -Path $temporaryMsi | Out-Null
$publicationError = $null
$cleanupError = $null
try {
    $firstParty = Join-Path $temporaryRoot 'first-party'
    [void] [IO.Directory]::CreateDirectory($firstParty)
    $builds = @(
        @('overseas-agent.exe', './cmd/overseas-agent', @()),
        @('overseas-client.exe', './cmd/overseas-client', @('-ldflags', '-H windowsgui')),
        @('installer-verifier.exe', './cmd/installer-verifier', @())
    )
    foreach ($build in $builds) {
        $arguments = @('build', '-trimpath') + @($build[2]) + @('-o', (Join-Path $firstParty $build[0]), $build[1])
        $previousGoOS = $env:GOOS; $previousGoArch = $env:GOARCH
        try { $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; & $goExecutable @arguments }
        finally { $env:GOOS = $previousGoOS; $env:GOARCH = $previousGoArch }
        if ($LASTEXITCODE -ne 0) { throw "Locked Go build failed for '$($build[0])'." }
    }
    & (Join-Path $PSScriptRoot 'build-client-artifacts.ps1') -Mode Release -OutputDirectory $payloadRelative -SigningCertificateThumbprint $SigningCertificateThumbprint -SignToolPath $signTool -FirstPartyBinaryDirectory $firstParty
    if ($LASTEXITCODE -ne 0) { throw 'Release payload build failed.' }
    & $wixExecutable build (Join-Path $repo 'deploy\client\Product.wxs') (Join-Path $repo 'deploy\client\Files.wxs') -d CorporateSigningThumbprint=$SigningCertificateThumbprint -d PackageTrustMode=RELEASE_SIGNED -bindpath $payload -arch x64 -ext $utilExtension -ext $firewallExtension -ext $iisExtension -intermediateFolder (Join-Path $temporaryRoot 'wixobj') -pdbtype none -out $temporaryMsi
    if ($LASTEXITCODE -ne 0) { throw 'wix release build failed.' }
    & $signTool sign /fd SHA256 /sha1 $SigningCertificateThumbprint $temporaryMsi | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'signtool release signing failed.' }
    & (Join-Path $PSScriptRoot 'inspect-client-msi.ps1') -MsiPath $temporaryMsi -StagingPath $payload -OutputDirectory ('build/release-' + $id + '/inspect')
    if ($LASTEXITCODE -ne 0) { throw 'Release inspection failed.' }
    Wait-ExclusiveFileAccess -Path $temporaryMsi -TimeoutSeconds 15
    [IO.File]::Move($temporaryMsi, $final)
}
catch {
    $publicationError = $_
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        try { Remove-TemporaryReleaseRoot -Path $temporaryRoot -TimeoutSeconds 15 }
        catch { $cleanupError = $_ }
    }
}
if ($null -ne $publicationError) { throw $publicationError }
if ($null -ne $cleanupError) { throw $cleanupError }
