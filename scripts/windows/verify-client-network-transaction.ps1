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

$before = Get-TransactionResidue
if ($before.ManagedRuleCount -ne 0 -or $before.DiagnosticRuleCount -ne 0 -or
    $before.ProductRouteCount -ne 0 -or $before.ProductTUNCount -ne 0 -or
    $before.NetworkStateExists) {
    throw 'Transaction gate refused existing product or diagnostic residue.'
}

$previousGate = $env:OVERSEAS_ACCESS_NETWORK_GATE
$previousErrorActionPreference = $ErrorActionPreference
$exitCode = -1
$output = ''
$invocationError = $null
try {
    $env:OVERSEAS_ACCESS_NETWORK_GATE = '1'
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
}

$after = Get-TransactionResidue
$safeOutput = [string]::Join(' ', @($output -split '\s+' | Where-Object { $_ }))
if ($safeOutput.Length -gt 4096) {
    $safeOutput = $safeOutput.Substring(0, 4096)
}
$success = $exitCode -eq 0 -and [string]::IsNullOrWhiteSpace($invocationError) -and
    $after.ManagedRuleCount -eq 0 -and $after.DiagnosticRuleCount -eq 0 -and
    $after.ProductRouteCount -eq 0 -and $after.ProductTUNCount -eq 0 -and
    -not $after.NetworkStateExists
$evidence = [ordered]@{
    SchemaVersion = 1
    Identity = $identity.Name
    SID = $identity.User.Value
    Success = $success
    GoExitCode = $exitCode
    Output = $safeOutput
    InvocationError = $invocationError
    Residue = $after
}
$json = $evidence | ConvertTo-Json -Depth 6
$bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
$stream = New-Object IO.FileStream $EvidencePath, ([IO.FileMode]::CreateNew), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
try {
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
}
finally {
    $stream.Dispose()
}
if (-not $success) {
    throw 'LocalSystem network transaction gate failed or left residue.'
}
