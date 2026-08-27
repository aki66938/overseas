[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ConfigPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$')]
    [string] $RunId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $OutputPath = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..\artifacts\probe-telecom-down.json')
    ),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $MonitorOutputPath = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..\artifacts\probe-telecom-down-monitor.json')
    ),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $PocProbePath = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..\bin\poc-probe.exe')
    ),

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $PocProbeSha256,

    [Parameter()]
    [ValidateRange(25, 5000)]
    [int] $MonitorIntervalMilliseconds = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-NativeArgument {
    param([Parameter(Mandatory = $true)] [string] $Value)
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"{0}"' -f $Value.Replace('"', '\"')
}

function Assert-NativeWindowsExecutable {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($stream.Length -lt 68 -or $reader.ReadUInt16() -ne 0x5a4d) {
            throw 'poc-probe.exe is not a native Windows executable.'
        }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 4)) {
            throw 'poc-probe.exe is not a native Windows executable.'
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw 'poc-probe.exe is not a native Windows executable.'
        }
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
        elseif ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Stop-LiveNativeProcess {
    param([Parameter(Mandatory = $true)] [object] $Process)

    $cleanupFailures = @()
    $hasExited = $false
    try {
        $hasExited = [bool] $Process.HasExited
    }
    catch {
        # An unreadable process state is not evidence that the process exited.
        # Continue with kill/wait and retain the polling failure.
        $cleanupFailures += "read child exit state: $($_.Exception.Message)"
    }
    if (-not $hasExited) {
        try {
            $Process.Kill()
        }
        catch {
            $cleanupFailures += "kill child: $($_.Exception.Message)"
        }
        try {
            if (-not $Process.WaitForExit(5000)) {
                $cleanupFailures += 'wait for child: timed out after kill'
            }
        }
        catch {
            $cleanupFailures += "wait for child: $($_.Exception.Message)"
        }
    }
    if ($cleanupFailures.Count -ne 0) {
        throw "poc-probe child cleanup failed: $($cleanupFailures -join '; ')"
    }
}

function Write-NewJson {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [object] $Value
    )
    $json = $Value | ConvertTo-Json -Depth 10
    $stream = $null
    $writer = $null
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $writer = New-Object System.IO.StreamWriter(
            $stream,
            (New-Object System.Text.UTF8Encoding($false))
        )
        $writer.Write($json)
        $writer.Flush()
        $stream.Flush($true)
    }
    finally {
        if ($null -ne $writer) {
            $writer.Dispose()
        }
        elseif ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Get-TelecomPathState {
    param(
        [Parameter(Mandatory = $true)] [string] $InterfaceAlias,
        [Parameter(Mandatory = $true)] [string[]] $RoutePrefixes
    )
    $adapters = @(Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop)
    if ($adapters.Count -ne 1 -or [int] $adapters[0].ifIndex -le 0) {
        throw "Telecom interface '$InterfaceAlias' must resolve to one canonical adapter."
    }
    $adapter = $adapters[0]
    $configuredRoutes = @(Get-NetRoute `
        -InterfaceIndex ([int] $adapter.ifIndex) `
        -AddressFamily IPv4 `
        -PolicyStore ActiveStore `
        -ErrorAction Stop | Where-Object {
            $stateIsActive = $null -eq $_.PSObject.Properties['State'] -or $_.State.ToString() -ne 'Dead'
            $stateIsActive -and $RoutePrefixes -ccontains [string] $_.DestinationPrefix
        })
    return [pscustomobject] @{
        Alias = $InterfaceAlias
        Index = [int] $adapter.ifIndex
        InterfaceUp = $adapter.Status.ToString() -eq 'Up'
        ConfiguredRoutes = $configuredRoutes
    }
}

function ConvertTo-MonitorRoutes {
    param([Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Routes)
    $result = @()
    foreach ($route in $Routes) {
        $state = if ($null -eq $route.PSObject.Properties['State']) { 'UnknownActive' } else { $route.State.ToString() }
        $nextHop = if ($null -eq $route.PSObject.Properties['NextHop']) { 'Unknown' } else { [string] $route.NextHop }
        $result += [ordered] @{
            destination_prefix = [string] $route.DestinationPrefix
            next_hop = $nextHop
            state = $state
        }
    }
    return @($result)
}

function New-MonitorEvidence {
    param(
        [Parameter(Mandatory = $true)] [string] $Run,
        [Parameter(Mandatory = $true)] [string] $Digest,
        [Parameter(Mandatory = $true)] [datetime] $Started,
        [Parameter(Mandatory = $true)] [datetime] $Finished,
        [Parameter(Mandatory = $true)] [int] $Samples,
        [Parameter(Mandatory = $true)] [string[]] $RoutePrefixes,
        [Parameter(Mandatory = $true)] [bool] $ReconnectDetected,
        [Parameter(Mandatory = $true)] [bool] $ReconnectInterfaceUp,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $ReconnectRoutes,
        [Parameter()] [datetime] $ReconnectAt
    )
    $evidence = [ordered] @{
        schema_version = 1
        run_id = $Run
        config_digest = $Digest
        started_at = $Started.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
        finished_at = $Finished.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
        sample_count = $Samples
        telecom_route_prefixes = @($RoutePrefixes)
        reconnect_detected = $ReconnectDetected
        reconnect_interface_up = $ReconnectInterfaceUp
        reconnect_routes = @(ConvertTo-MonitorRoutes -Routes $ReconnectRoutes)
    }
    if ($ReconnectDetected) {
        $evidence['reconnect_at'] = $ReconnectAt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
    }
    return $evidence
}

$resolvedConfigPath = (Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop).Path
$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$resolvedMonitorOutputPath = [System.IO.Path]::GetFullPath($MonitorOutputPath)
foreach ($evidencePath in @($resolvedOutputPath, $resolvedMonitorOutputPath)) {
    if (Test-Path -LiteralPath $evidencePath) {
        throw "Evidence path already exists and will not be replaced: $evidencePath"
    }
    $directory = [System.IO.Path]::GetDirectoryName($evidencePath)
    if ([string]::IsNullOrWhiteSpace($directory) -or -not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "Evidence output directory does not exist: $directory"
    }
}

$resolvedProbePath = [System.IO.Path]::GetFullPath($PocProbePath)
if (-not (Test-Path -LiteralPath $resolvedProbePath -PathType Leaf)) {
    throw "poc-probe executable does not exist: $resolvedProbePath"
}
if (-not [System.IO.Path]::GetFileName($resolvedProbePath).Equals('poc-probe.exe', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The native executable must have the exact filename poc-probe.exe; script wrappers are refused.'
}
$probeLockStream = $null
$probeProcess = $null
try {
    # FileShare.Read permits Windows to map/execute this exact file but denies
    # writers and deleters until both trusted native invocations are complete.
    $probeLockStream = [System.IO.File]::Open(
        $resolvedProbePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    Assert-NativeWindowsExecutable -Path $resolvedProbePath
    $actualHash = (Get-FileHash -LiteralPath $resolvedProbePath -Algorithm SHA256 -ErrorAction Stop).Hash
    if (-not $actualHash.Equals($PocProbeSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The native poc-probe.exe SHA256 does not match the caller-supplied value.'
    }

$metadataOutputPath = Join-Path ([System.IO.Path]::GetDirectoryName($resolvedOutputPath)) ('.poc-config-{0}.out' -f ([guid]::NewGuid().ToString('N')))
$metadataErrorPath = Join-Path ([System.IO.Path]::GetDirectoryName($resolvedOutputPath)) ('.poc-config-{0}.err' -f ([guid]::NewGuid().ToString('N')))
try {
    $metadataProcess = Start-Process `
        -FilePath $resolvedProbePath `
        -ArgumentList @('describe-config', '--config', (ConvertTo-NativeArgument $resolvedConfigPath)) `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $metadataOutputPath `
        -RedirectStandardError $metadataErrorPath `
        -ErrorAction Stop
    if ([int] $metadataProcess.ExitCode -ne 0) {
        throw "poc-probe describe-config failed with exit code $($metadataProcess.ExitCode)."
    }
    $metadata = Get-Content -LiteralPath $metadataOutputPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
finally {
    foreach ($temporaryPath in @($metadataOutputPath, $metadataErrorPath)) {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

$metadataNames = @($metadata.PSObject.Properties.Name)
if ($metadataNames.Count -ne 3 -or $metadataNames -notcontains 'telecom_interface' -or $metadataNames -notcontains 'telecom_route_prefixes' -or $metadataNames -notcontains 'config_digest') {
    throw 'poc-probe describe-config returned an invalid metadata structure.'
}
$telecomInterface = [string] $metadata.telecom_interface
$telecomRoutePrefixes = @($metadata.telecom_route_prefixes | ForEach-Object { [string] $_ })
$configDigest = [string] $metadata.config_digest
if ([string]::IsNullOrWhiteSpace($telecomInterface) -or $telecomRoutePrefixes.Count -eq 0 -or @($telecomRoutePrefixes | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -ne 0 -or $configDigest -notmatch '^[0-9a-f]{64}$') {
    throw 'poc-probe describe-config returned invalid monitor inputs.'
}

[void] (Read-Host "Disconnect telecom client manually, then press Enter to verify interface '$telecomInterface'")
try {
    $downState = Get-TelecomPathState -InterfaceAlias $telecomInterface -RoutePrefixes $telecomRoutePrefixes
    if (@($downState.ConfiguredRoutes).Count -ne 0) {
        throw "A configured telecom external/default route remains active on interface '$telecomInterface'; probe was not run."
    }
    $downInterfaceWasUp = [bool] $downState.InterfaceUp
    $monitorStartedAt = [datetime]::UtcNow
    $probeArguments = @(
        'probe',
        '--config', (ConvertTo-NativeArgument $resolvedConfigPath),
        '--run-id', $RunId,
        '--out', (ConvertTo-NativeArgument $resolvedOutputPath)
    )
    $probeProcess = Start-Process `
        -FilePath $resolvedProbePath `
        -ArgumentList $probeArguments `
        -NoNewWindow `
        -PassThru `
        -ErrorAction Stop

    $sampleCount = 0
    $reconnectDetected = $false
    $reconnectAt = [datetime]::MinValue
    $reconnectState = $null
    while ($true) {
        $currentState = Get-TelecomPathState -InterfaceAlias $telecomInterface -RoutePrefixes $telecomRoutePrefixes
        $sampleCount++
        if ((-not $downInterfaceWasUp -and $currentState.InterfaceUp) -or @($currentState.ConfiguredRoutes).Count -ne 0) {
            $reconnectDetected = $true
            $reconnectAt = [datetime]::UtcNow
            $reconnectState = $currentState
            break
        }

        if ($probeProcess.WaitForExit($MonitorIntervalMilliseconds)) {
            # One final sample closes the race between process exit and the
            # preceding poll.
            $currentState = Get-TelecomPathState -InterfaceAlias $telecomInterface -RoutePrefixes $telecomRoutePrefixes
            $sampleCount++
            if ((-not $downInterfaceWasUp -and $currentState.InterfaceUp) -or @($currentState.ConfiguredRoutes).Count -ne 0) {
                $reconnectDetected = $true
                $reconnectAt = [datetime]::UtcNow
                $reconnectState = $currentState
            }
            break
        }
    }

    $monitorFinishedAt = [datetime]::UtcNow
    $reconnectInterfaceForEvidence = $false
    $reconnectRoutesForEvidence = @()
    if ($reconnectDetected) {
        $reconnectInterfaceForEvidence = [bool] $reconnectState.InterfaceUp
        $reconnectRoutesForEvidence = @($reconnectState.ConfiguredRoutes)
    }
    $monitorEvidence = New-MonitorEvidence `
        -Run $RunId `
        -Digest $configDigest `
        -Started $monitorStartedAt `
        -Finished $monitorFinishedAt `
        -Samples $sampleCount `
        -RoutePrefixes $telecomRoutePrefixes `
        -ReconnectDetected $reconnectDetected `
        -ReconnectInterfaceUp $reconnectInterfaceForEvidence `
        -ReconnectRoutes $reconnectRoutesForEvidence `
        -ReconnectAt $reconnectAt
    Write-NewJson -Path $resolvedMonitorOutputPath -Value $monitorEvidence

    if ($reconnectDetected) {
        throw "Telecom path automatically reconnected while poc-probe was running; explicit failure evidence was written to $resolvedMonitorOutputPath"
    }
    if ([int] $probeProcess.ExitCode -ne 0) {
        throw "poc-probe failed with exit code $($probeProcess.ExitCode)."
    }
    if (-not (Test-Path -LiteralPath $resolvedOutputPath -PathType Leaf)) {
        throw 'poc-probe did not create down-state evidence.'
    }
}
finally {
    $childCleanupError = $null
    if ($null -ne $probeProcess) {
        try {
            Stop-LiveNativeProcess -Process $probeProcess
        }
        catch {
            $childCleanupError = $_.Exception
        }
    }

    $restoreError = $null
    try {
        [void] (Read-Host "Reconnect telecom client manually, then press Enter to verify interface '$telecomInterface'")
        $restoredState = Get-TelecomPathState -InterfaceAlias $telecomInterface -RoutePrefixes $telecomRoutePrefixes
        if (-not $restoredState.InterfaceUp -or @($restoredState.ConfiguredRoutes).Count -eq 0) {
            throw "Telecom path was not restored on interface '$telecomInterface'; reconnect it manually before continuing."
        }
    }
    catch {
        $restoreError = $_.Exception
    }
    if ($null -ne $restoreError) {
        throw $restoreError
    }
    if ($null -ne $childCleanupError) {
        throw $childCleanupError
    }
}

"NO_LEAK_EVIDENCE_WRITTEN: $resolvedOutputPath"
"NO_LEAK_MONITOR_WRITTEN: $resolvedMonitorOutputPath"
}
finally {
    if ($null -ne $probeLockStream) {
        $probeLockStream.Dispose()
    }
}
