$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptPath = Join-Path $repoRoot 'scripts\fetch-sing-box.ps1'
$manifestPath = Join-Path $repoRoot 'sing-box.manifest.json'

function Assert-RepositoryFileExists {
    param([Parameter(Mandatory = $true)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $false | Should Be $true
        return $false
    }
    return $true
}

function Get-FetchFailureMessage {
    param([Parameter(Mandatory = $true)] [scriptblock] $Action)

    try {
        & $Action
    }
    catch {
        return $_.Exception.Message
    }
    return ''
}

function Write-FakeNativeExecutable {
    param([Parameter(Mandatory = $true)] [string] $Path)

    $bytes = New-Object byte[] 128
    $bytes[0] = 0x4d
    $bytes[1] = 0x5a
    [BitConverter]::GetBytes([int] 64).CopyTo($bytes, 0x3c)
    $bytes[64] = 0x50
    $bytes[65] = 0x45
    $bytes[66] = 0
    $bytes[67] = 0
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

function Get-SingBoxVersionText {
    param([string] $Path)
    throw "unexpected unmocked Get-SingBoxVersionText call for $Path"
}

Describe 'Pinned sing-box acquisition' {
    BeforeEach {
        $global:FetchSingBoxDownloadUri = $null
        $global:FetchSingBoxMoveCalls = @()
        $global:FetchSingBoxManifest = $null
    }

    It 'keeps the pinned release manifest in source control and parses script syntax' {
        if (-not (Assert-RepositoryFileExists -Path $scriptPath)) { return }
        if (-not (Assert-RepositoryFileExists -Path $manifestPath)) { return }

        $tokens = $null
        $errors = $null
        [void] [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
        $errors.Count | Should Be 0

        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $manifest.version | Should Be '1.13.19'
        $manifest.archive_sha256 | Should Match '^[0-9a-f]{64}$'
        $manifest.archive_sha256 | Should Not Match '^(0+|a+|b+|c+|sample|\$\()'
        $manifest.acquisition_url | Should Be 'https://github.com/SagerNet/sing-box/releases/download/v1.13.19/sing-box-1.13.19-windows-amd64.zip'
    }

    It 'requires explicit version and pinned SHA before any download' {
        if (-not (Assert-RepositoryFileExists -Path $scriptPath)) { return }

        $destination = Join-Path $TestDrive 'publish'

        Mock Invoke-WebRequest {}

        $versionMessage = Get-FetchFailureMessage {
            & $scriptPath -ExpectedSha256 ('a' * 64) -Destination $destination
        }
        $versionMessage | Should Match 'Version'

        $shaMessage = Get-FetchFailureMessage {
            & $scriptPath -Version '1.13.19' -Destination $destination
        }
        $shaMessage | Should Match 'ExpectedSha256'

        Assert-MockCalled Invoke-WebRequest -Times 0 -Exactly -Scope It
    }

    It 'downloads only the immutable official release URL and removes temporary files on hash mismatch' {
        if (-not (Assert-RepositoryFileExists -Path $scriptPath)) { return }
        if (-not (Assert-RepositoryFileExists -Path $manifestPath)) { return }

        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $destination = Join-Path $TestDrive 'publish'

        Mock Invoke-WebRequest {
            $global:FetchSingBoxDownloadUri = [string] $Uri
            [System.IO.File]::WriteAllText([string] $OutFile, 'downloaded archive')
        }

        Mock Get-FileHash {
            [pscustomobject] @{ Hash = ('f' * 64) }
        } -ParameterFilter { [string] $Algorithm -eq 'SHA256' }

        Mock Expand-Archive {}
        Mock Get-AuthenticodeSignature {}
        Mock Get-SingBoxVersionText { return 'sing-box version 1.13.19' }

        $message = Get-FetchFailureMessage {
            & $scriptPath -Version '1.13.19' -ExpectedSha256 $manifest.archive_sha256 -Destination $destination
        }

        $message | Should Match 'SHA-256'
        $global:FetchSingBoxDownloadUri | Should Be $manifest.acquisition_url
        (Test-Path -LiteralPath $destination) | Should Be $false
        @(Get-ChildItem -LiteralPath $TestDrive -Directory -Filter '.fetch-sing-box-*').Count | Should Be 0
        Assert-MockCalled Invoke-WebRequest -Times 1 -Exactly -Scope It
        Assert-MockCalled Expand-Archive -Times 0 -Exactly -Scope It
    }

    It 'publishes atomically, records runtime manifest fields, and preserves an existing destination on failure' {
        if (-not (Assert-RepositoryFileExists -Path $scriptPath)) { return }
        if (-not (Assert-RepositoryFileExists -Path $manifestPath)) { return }

        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $destination = Join-Path $TestDrive 'publish'

        Mock Invoke-WebRequest {
            $global:FetchSingBoxDownloadUri = [string] $Uri
            [System.IO.File]::WriteAllText([string] $OutFile, 'downloaded archive')
        }

        Mock Get-FileHash {
            if ([string] $LiteralPath -like '*.zip') {
                return [pscustomobject] @{ Hash = $manifest.archive_sha256.ToUpperInvariant() }
            }
            return [pscustomobject] @{ Hash = ('d' * 64) }
        } -ParameterFilter { [string] $Algorithm -eq 'SHA256' }

        Mock Expand-Archive {
            $root = Join-Path ([string] $DestinationPath) 'sing-box-1.13.19-windows-amd64'
            New-Item -ItemType Directory -Path $root | Out-Null
            Write-FakeNativeExecutable -Path (Join-Path $root 'sing-box.exe')
        }

        Mock Get-AuthenticodeSignature {
            [pscustomobject] @{
                Status = 'NotSigned'
                SignerCertificate = $null
            }
        }

        Mock Get-SingBoxVersionText { return 'sing-box version 1.13.19' }

        Mock Move-Item {
            $global:FetchSingBoxMoveCalls += [pscustomobject] @{
                LiteralPath = [string] $LiteralPath
                Destination = [string] $Destination
            }
            [System.IO.Directory]::Move([string] $LiteralPath, [string] $Destination)
        } -ParameterFilter { $PSBoundParameters.ContainsKey('LiteralPath') -and $PSBoundParameters.ContainsKey('Destination') }

        & $scriptPath -Version '1.13.19' -ExpectedSha256 $manifest.archive_sha256 -Destination $destination

        $exePath = Join-Path $destination 'sing-box.exe'
        $runtimeManifestPath = Join-Path $destination 'sing-box.manifest.json'
        (Test-Path -LiteralPath $exePath -PathType Leaf) | Should Be $true
        (Test-Path -LiteralPath $runtimeManifestPath -PathType Leaf) | Should Be $true
        $runtimeManifestRaw = Get-Content -LiteralPath $runtimeManifestPath -Raw -Encoding UTF8
        $runtimeManifest = Get-Content -LiteralPath $runtimeManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $runtimeManifest.version | Should Be '1.13.19'
        $runtimeManifest.archive_sha256 | Should Be $manifest.archive_sha256
        $runtimeManifest.executable_sha256 | Should Be ('d' * 64)
        $runtimeManifest.acquisition_url | Should Be $manifest.acquisition_url
        $runtimeManifest.signer_status | Should Be 'NotSigned'
        $runtimeManifestRaw | Should Match '"acquired_at_utc"\s*:\s*"[^"]+Z"'
        $global:FetchSingBoxDownloadUri | Should Be $manifest.acquisition_url
        $global:FetchSingBoxMoveCalls.Count | Should Be 1
        Assert-MockCalled Move-Item -Times 1 -Exactly -Scope It
        Assert-MockCalled Expand-Archive -Times 1 -Exactly -Scope It
        Assert-MockCalled Get-AuthenticodeSignature -Times 1 -Exactly -Scope It
        Assert-MockCalled Get-SingBoxVersionText -Times 1 -Exactly -Scope It

        Remove-Item -LiteralPath $destination -Recurse -Force
        New-Item -ItemType Directory -Path $destination | Out-Null
        Set-Content -LiteralPath (Join-Path $destination 'sing-box.exe') -Value 'preserve-me'
        $existingMessage = Get-FetchFailureMessage {
            & $scriptPath -Version '1.13.19' -ExpectedSha256 $manifest.archive_sha256 -Destination $destination
        }
        $existingMessage | Should Match 'already exists'
        (Get-Content -LiteralPath (Join-Path $destination 'sing-box.exe') -Raw -Encoding UTF8).Trim() | Should Be 'preserve-me'
    }
}
