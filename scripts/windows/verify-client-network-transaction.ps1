[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $RepositoryPath,
    [Parameter(Mandatory = $true)][string] $GoExecutable,
    [Parameter(Mandatory = $true)][string] $EvidencePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not [IO.Path]::IsPathRooted($RepositoryPath) -or [IO.Path]::GetFullPath($RepositoryPath) -ne $RepositoryPath) {
    throw 'RepositoryPath must be absolute and clean.'
}
if (-not [IO.Path]::IsPathRooted($GoExecutable) -or [IO.Path]::GetFullPath($GoExecutable) -ne $GoExecutable) {
    throw 'GoExecutable must be absolute and clean.'
}
if (-not [IO.Path]::IsPathRooted($EvidencePath) -or [IO.Path]::GetFullPath($EvidencePath) -ne $EvidencePath) {
    throw 'EvidencePath must be absolute and clean.'
}
if (-not [IO.Directory]::Exists($RepositoryPath) -or
    -not [IO.File]::Exists((Join-Path $RepositoryPath 'go.mod')) -or
    -not [IO.Directory]::Exists((Join-Path $RepositoryPath 'internal\agent'))) {
    throw 'RepositoryPath is not the expected Go repository.'
}
if (-not [IO.File]::Exists($GoExecutable)) {
    throw 'GoExecutable does not exist.'
}
if ([IO.File]::Exists($EvidencePath) -or -not [IO.Directory]::Exists((Split-Path -Parent $EvidencePath))) {
    throw 'EvidencePath must be new and its parent must exist.'
}
$traceEvidencePath = $EvidencePath + '.trace.json'
if ([IO.File]::Exists($traceEvidencePath) -or [IO.Directory]::Exists($traceEvidencePath)) {
    throw 'Trace evidence sidecar path must be new.'
}
$maxTraceEvidenceBytes = 65536

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Local administrator rights are required.'
}
if ($identity.User.Value -ne 'S-1-5-18') {
    throw 'This transaction gate must run as LocalSystem (S-1-5-18).'
}
$service = Get-Service RegenBioOverseasAccessAgent -ErrorAction SilentlyContinue
if ($null -ne $service -and $service.Status -ne 'Stopped') {
    throw 'The installed agent service must be stopped during the transaction gate.'
}

function Get-TransactionResidue {
    return [pscustomobject]@{
        ManagedRuleCount = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group 'RegenBioOverseasAccess.Managed' -ErrorAction SilentlyContinue).Count
        DiagnosticRuleCount = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group 'RegenBio.Diagnostic' -ErrorAction SilentlyContinue).Count
        ProductRouteCount = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -in 4096,8192 }).Count
        ProductTUNCount = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq 'RegenBioOverseasAccess' }).Count
        NetworkStateExists = [IO.File]::Exists('C:\ProgramData\RegenBio\OverseasAccess\network-state.json')
    }
}

function Test-TerminalResidueZero {
    param($Residue)
    if ($null -eq $Residue) { return $false }
    return [int] $Residue.managed_rules -eq 0 -and
        [int] $Residue.product_routes -eq 0 -and
        [int] $Residue.product_tuns -eq 0 -and
        [int] $Residue.core_processes -eq 0 -and
        -not [bool] $Residue.snapshot
}

function Test-TraceLifecycle {
    param($TraceEvidence)
    if ($null -eq $TraceEvidence -or [int] $TraceEvidence.schema_version -ne 1) { return $false }
    $beforePublish = @($TraceEvidence.before_publish)
    $afterPublish = @($TraceEvidence.after_publish)
    $afterRestore = @($TraceEvidence.after_restore)
    if ($beforePublish.Count -eq 0 -or $afterPublish.Count -le $beforePublish.Count -or $afterRestore.Count -le $afterPublish.Count) {
        return $false
    }
    if ([uint64] $beforePublish[-1].sequence -ne [uint64] $afterPublish[$beforePublish.Count - 1].sequence -or
        [uint64] $afterPublish[-1].sequence -ne [uint64] $afterRestore[$afterPublish.Count - 1].sequence) {
        return $false
    }
    $previousSequence = [uint64] 0
    foreach ($event in $afterRestore) {
        if ([int] $event.schema_version -ne 1 -or [uint64] $event.sequence -le $previousSequence -or [uint64] $event.generation -ne 1) {
            return $false
        }
        $previousSequence = [uint64] $event.sequence
    }
    foreach ($stage in @('network_capture', 'adapter_scan', 'firewall_publish', 'active_store_verify', 'network_restore', 'residue_verify')) {
        $started = @($afterRestore | Where-Object { $_.stage -eq $stage -and $_.event -eq 'started' })
        $succeeded = @($afterRestore | Where-Object { $_.stage -eq $stage -and $_.event -eq 'succeeded' })
        $failed = @($afterRestore | Where-Object { $_.stage -eq $stage -and $_.event -eq 'failed' })
        if ($started.Count -lt 1 -or $started.Count -ne $succeeded.Count -or $failed.Count -ne 0) {
            return $false
        }
    }
    $terminalResidueEvents = @($afterRestore | Where-Object { $_.stage -eq 'residue_verify' -and $_.event -eq 'succeeded' })
    if ($terminalResidueEvents.Count -eq 0 -or -not (Test-TerminalResidueZero -Residue $terminalResidueEvents[-1].residue)) {
        return $false
    }
    return $true
}

$before = Get-TransactionResidue
if ($before.ManagedRuleCount -ne 0 -or $before.DiagnosticRuleCount -ne 0 -or
    $before.ProductRouteCount -ne 0 -or $before.ProductTUNCount -ne 0 -or
    $before.NetworkStateExists) {
    throw 'Transaction gate refused existing product or diagnostic residue.'
}

$previousGate = $env:OVERSEAS_ACCESS_NETWORK_GATE
$previousTraceEvidencePath = $env:OVERSEAS_ACCESS_TRACE_EVIDENCE_PATH
$previousErrorActionPreference = $ErrorActionPreference
$exitCode = -1
$output = ''
$invocationError = $null
try {
    $env:OVERSEAS_ACCESS_NETWORK_GATE = '1'
    $env:OVERSEAS_ACCESS_TRACE_EVIDENCE_PATH = $traceEvidencePath
    Push-Location -LiteralPath $RepositoryPath
    try {
        $ErrorActionPreference = 'Continue'
        $output = (& $GoExecutable test ./internal/agent -run '^TestLiveWindowsPowerShellProtectionTransaction$' -count=1 -v 2>&1 | Out-String)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
        Pop-Location
    }
}
catch {
    $invocationError = $_.Exception.Message
}
finally {
    $env:OVERSEAS_ACCESS_NETWORK_GATE = $previousGate
    $env:OVERSEAS_ACCESS_TRACE_EVIDENCE_PATH = $previousTraceEvidencePath
}

$after = Get-TransactionResidue
$traceEvidence = $null
$traceEvidenceError = $null
try {
    if (-not [IO.File]::Exists($traceEvidencePath)) { throw 'The Go gate did not publish trace evidence.' }
    $traceInfo = Get-Item -LiteralPath $traceEvidencePath -Force
    if ($traceInfo.Length -le 0 -or $traceInfo.Length -gt $maxTraceEvidenceBytes) { throw 'Trace evidence is empty or exceeds 65536 bytes.' }
    $traceEvidence = [IO.File]::ReadAllText($traceEvidencePath, (New-Object Text.UTF8Encoding($false))) | ConvertFrom-Json
}
catch {
    $traceEvidenceError = [string] $_.Exception.Message
    if ($traceEvidenceError.Length -gt 512) { $traceEvidenceError = $traceEvidenceError.Substring(0, 512) }
}
$traceLifecycleComplete = Test-TraceLifecycle -TraceEvidence $traceEvidence
$terminalResidueZero = $null -ne $traceEvidence -and (Test-TerminalResidueZero -Residue $traceEvidence.terminal_residue)
$safeOutput = [string]::Join(' ', @($output -split '\s+' | Where-Object { $_ }))
if ($safeOutput.Length -gt 4096) {
    $safeOutput = $safeOutput.Substring(0, 4096)
}
$success = $exitCode -eq 0 -and [string]::IsNullOrWhiteSpace($invocationError) -and
    [string]::IsNullOrWhiteSpace($traceEvidenceError) -and $traceLifecycleComplete -and $terminalResidueZero -and
    $after.ManagedRuleCount -eq 0 -and $after.DiagnosticRuleCount -eq 0 -and
    $after.ProductRouteCount -eq 0 -and $after.ProductTUNCount -eq 0 -and
    -not $after.NetworkStateExists
$evidence = [ordered]@{
    SchemaVersion = 2
    Identity = $identity.Name
    SID = $identity.User.Value
    Success = $success
    GoExitCode = $exitCode
    Output = $safeOutput
    InvocationError = $invocationError
    Residue = $after
    TraceLifecycleComplete = $traceLifecycleComplete
    TerminalResidueZero = $terminalResidueZero
    TraceEvidenceError = $traceEvidenceError
    TraceEvidence = $traceEvidence
}
$json = $evidence | ConvertTo-Json -Depth 12
$bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
$stream = New-Object IO.FileStream $EvidencePath, ([IO.FileMode]::CreateNew), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
try {
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
}
finally {
    $stream.Dispose()
}
if (Test-Path -LiteralPath $traceEvidencePath -PathType Leaf) {
    Remove-Item -LiteralPath $traceEvidencePath -Force
}
if (-not $success) {
    throw 'LocalSystem network transaction gate failed or left residue.'
}
