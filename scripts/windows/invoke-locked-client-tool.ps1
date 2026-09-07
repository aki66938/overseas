[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Go', 'Wix')][string] $Tool,
    [Parameter()][string] $GoOS,
    [Parameter()][string] $GoArch,
    [Parameter(Mandatory = $true)][string[]] $ToolArguments
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
. (Join-Path $PSScriptRoot 'client-payload-tools.ps1')
$workspace = Get-ClientWorkspace -Repository $repo
$lock = Get-Content -LiteralPath (Join-Path $repo 'deploy\client\build-lock.json') -Raw | ConvertFrom-Json

function Assert-LockedHash {
    param([string] $Path, [string] $Expected)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) {
        throw "Locked client tool '$([IO.Path]::GetFileName($Path))' is absent or mismatched."
    }
}

function Resolve-LockedPath {
    param([string] $RelativePath)
    $path = [IO.Path]::GetFullPath((Join-Path $workspace $RelativePath))
    if (-not $path.StartsWith($workspace + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Locked client tool path escapes the workspace.'
    }
    return $path
}

$goExecutable = Resolve-LockedPath $lock.go.executable_path
$wixExecutable = Resolve-LockedPath $lock.wix.executable_path
$utilExtension = Resolve-LockedPath $lock.wix.util_extension_path
$firewallExtension = Resolve-LockedPath $lock.wix.firewall_extension_path
$iisExtension = Resolve-LockedPath $lock.wix.iis_extension_path
$dtf = Resolve-LockedPath $lock.wix.dtf_path
Assert-LockedHash $goExecutable $lock.go.executable_sha256
Assert-LockedHash $wixExecutable $lock.wix.executable_sha256
Assert-LockedHash $utilExtension $lock.wix.util_extension_sha256
Assert-LockedHash $firewallExtension $lock.wix.firewall_extension_sha256
Assert-LockedHash $iisExtension $lock.wix.iis_extension_sha256
Assert-LockedHash $dtf $lock.wix.dtf_sha256
if ((& $goExecutable version) -ne ('go version go' + $lock.go.version + ' windows/amd64')) { throw 'Locked Go version output is mismatched.' }
if ((& $wixExecutable --version) -notmatch ('^' + [regex]::Escape($lock.wix.version) + '\+')) { throw 'Locked WiX version output is mismatched.' }

$executable = if ($Tool -eq 'Go') { $goExecutable } else { $wixExecutable }
if ($Tool -eq 'Wix' -and (-not [string]::IsNullOrWhiteSpace($GoOS) -or -not [string]::IsNullOrWhiteSpace($GoArch))) {
    throw 'Go environment overrides are invalid for WiX.'
}
if (-not [string]::IsNullOrWhiteSpace($GoOS)) { $env:GOOS = $GoOS }
if (-not [string]::IsNullOrWhiteSpace($GoArch)) { $env:GOARCH = $GoArch }
if ($Tool -eq 'Wix') {
    if (@($ToolArguments | Where-Object { $_ -eq '-ext' }).Count -ne 0) {
        throw 'WiX extension paths are supplied only by the verified tool wrapper.'
    }
    $ToolArguments = @($ToolArguments) + @('-ext', $utilExtension, '-ext', $firewallExtension, '-ext', $iisExtension)
}
& $executable @ToolArguments
exit $LASTEXITCODE
