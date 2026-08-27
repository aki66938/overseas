[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ConfigPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $OutputPath = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..\artifacts\probe-telecom-down.json')
    ),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $PocProbePath = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..\bin\poc-probe.exe')
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ConfiguredTelecomInterface {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $values = @()
    foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        if ($line -notmatch '^telecom_interface\s*:\s*(?<value>.+?)\s*$') {
            continue
        }
        $value = $Matches['value'].Trim()
        if ($value.StartsWith("'") -and $value.EndsWith("'") -and $value.Length -ge 2) {
            $value = $value.Substring(1, $value.Length - 2).Replace("''", "'")
        }
        elseif ($value.StartsWith('"') -and $value.EndsWith('"') -and $value.Length -ge 2) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        else {
            $value = ($value -split '\s+#', 2)[0].Trim()
        }
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $values += $value
        }
    }
    if ($values.Count -ne 1) {
        throw 'Config must contain exactly one non-empty top-level telecom_interface value.'
    }
    return [string] $values[0]
}

function Get-TelecomPathState {
    param(
        [Parameter(Mandatory = $true)]
        [string] $InterfaceAlias
    )

    $adapters = @(Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop)
    if ($adapters.Count -ne 1 -or [int] $adapters[0].ifIndex -le 0) {
        throw "Telecom interface '$InterfaceAlias' must resolve to one canonical adapter."
    }
    $adapter = $adapters[0]
    $activeRoutes = @(Get-NetRoute `
        -InterfaceIndex ([int] $adapter.ifIndex) `
        -AddressFamily IPv4 `
        -ErrorAction Stop | Where-Object {
            $null -eq $_.PSObject.Properties['State'] -or $_.State.ToString() -ne 'Dead'
        })
    return [pscustomobject] @{
        Alias = $InterfaceAlias
        Index = [int] $adapter.ifIndex
        InterfaceUp = $adapter.Status.ToString() -eq 'Up'
        ActiveRouteCount = $activeRoutes.Count
    }
}

$resolvedConfigPath = (Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop).Path
$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $resolvedOutputPath) {
    throw "Evidence path already exists and will not be replaced: $resolvedOutputPath"
}
$outputDirectory = [System.IO.Path]::GetDirectoryName($resolvedOutputPath)
if ([string]::IsNullOrWhiteSpace($outputDirectory) -or -not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    throw "Evidence output directory does not exist: $outputDirectory"
}

$telecomInterface = Get-ConfiguredTelecomInterface -Path $resolvedConfigPath
[void] (Read-Host "Disconnect telecom client manually, then press Enter to verify interface '$telecomInterface'")
$downState = Get-TelecomPathState -InterfaceAlias $telecomInterface
if ($downState.InterfaceUp -and $downState.ActiveRouteCount -gt 0) {
    throw "Telecom path is still active on interface '$telecomInterface'; probe was not run."
}

try {
    $resolvedProbePath = [System.IO.Path]::GetFullPath($PocProbePath)
    if (-not (Test-Path -LiteralPath $resolvedProbePath -PathType Leaf)) {
        throw "poc-probe executable does not exist: $resolvedProbePath"
    }
    $PocProbePath = $resolvedProbePath
    & $PocProbePath probe --config $resolvedConfigPath --out $resolvedOutputPath
    if ($LASTEXITCODE -ne 0) {
        throw "poc-probe failed with exit code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $resolvedOutputPath -PathType Leaf)) {
        throw 'poc-probe did not create down-state evidence.'
    }
}
finally {
    [void] (Read-Host "Reconnect telecom client manually, then press Enter to verify interface '$telecomInterface'")
    $restoredState = Get-TelecomPathState -InterfaceAlias $telecomInterface
    if (-not $restoredState.InterfaceUp -or $restoredState.ActiveRouteCount -eq 0) {
        throw "Telecom path was not restored on interface '$telecomInterface'."
    }
}

"NO_LEAK_EVIDENCE_WRITTEN: $resolvedOutputPath"
