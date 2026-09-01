[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $EvidencePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not [IO.Path]::IsPathRooted($EvidencePath) -or [IO.Path]::GetFullPath($EvidencePath) -ne $EvidencePath) {
    throw 'EvidencePath must be absolute and clean.'
}
if ([IO.File]::Exists($EvidencePath)) {
    throw 'EvidencePath already exists.'
}
$parent = Split-Path -Parent $EvidencePath
if (-not [IO.Directory]::Exists($parent)) {
    throw 'EvidencePath parent does not exist.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Local administrator rights are required.'
}
if ($identity.User.Value -ne 'S-1-5-18') {
    throw 'This verification gate must run as LocalSystem (S-1-5-18).'
}

function Get-ProtectableAdapters {
    $indices = @(Get-NetIPInterface | Where-Object { [int]$_.InterfaceIndex -gt 0 } |
        Select-Object -ExpandProperty InterfaceIndex | Sort-Object -Unique)
    $result = @()
    foreach ($index in $indices) {
        $matches = @(Get-NetAdapter -IncludeHidden -InterfaceIndex ([int]$index) -ErrorAction SilentlyContinue)
        if ($matches.Count -eq 0) {
            continue
        }
        if ($matches.Count -ne 1) {
            throw 'adapter_identity_join: IP interface did not resolve to exactly one adapter.'
        }
        $adapter = $matches[0]
        if ([int]$adapter.InterfaceIndex -le 0 -or
            [string]::IsNullOrWhiteSpace([string]$adapter.InterfaceGuid) -or
            [string]::IsNullOrWhiteSpace([string]$adapter.InterfaceAlias)) {
            throw 'adapter_identity_join: adapter identity is incomplete.'
        }
        $result += [pscustomobject]@{
            InterfaceIndex = [int]$adapter.InterfaceIndex
            InterfaceGuid = [string]$adapter.InterfaceGuid
            InterfaceAlias = [string]$adapter.InterfaceAlias
            Status = [string]$adapter.Status
        }
    }
    return @($result | Sort-Object InterfaceGuid)
}

function Get-Residue {
    $managed = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group 'RegenBioOverseasAccess.Managed' -ErrorAction SilentlyContinue)
    $diagnostic = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group 'RegenBio.Diagnostic' -ErrorAction SilentlyContinue)
    $routes = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -in 4096,8192 })
    $tun = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq 'RegenBioOverseasAccess' })
    $stateExists = [IO.File]::Exists('C:\ProgramData\RegenBio\OverseasAccess\network-state.json')
    return [pscustomobject]@{
        ManagedRuleCount = $managed.Count
        DiagnosticRuleCount = $diagnostic.Count
        ProductRouteCount = $routes.Count
        ProductTUNCount = $tun.Count
        NetworkStateExists = $stateExists
    }
}

$before = Get-Residue
if ($before.ManagedRuleCount -ne 0 -or $before.DiagnosticRuleCount -ne 0 -or
    $before.ProductRouteCount -ne 0 -or $before.ProductTUNCount -ne 0 -or
    $before.NetworkStateExists) {
    throw 'Preflight refused existing product or diagnostic residue.'
}

$adapters = @(Get-ProtectableAdapters)
if ($adapters.Count -eq 0) {
    throw 'No protectable IP-stack adapters were discovered.'
}

$created = New-Object Collections.Generic.List[string]
$results = New-Object Collections.Generic.List[object]
$probeFailure = $null
try {
    foreach ($adapter in $adapters) {
        $suffix = ([string]$adapter.InterfaceGuid).Trim('{}').Replace('-', '')
        $name = 'RegenBio.Diagnostic.Preflight.' + $suffix
        if (Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction SilentlyContinue) {
            throw ('Diagnostic rule name collision: ' + $name)
        }
        New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group 'RegenBio.Diagnostic' -Direction Outbound -Action Block -Protocol TCP -RemoteAddress @('192.0.2.1/32', '2001:db8::1/128') -InterfaceAlias ([string]$adapter.InterfaceAlias) -Profile Any | Out-Null
        $created.Add($name)

        $rule = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction Stop)
        if ($rule.Count -ne 1 -or [string]$rule[0].Group -ne 'RegenBio.Diagnostic' -or
            [string]$rule[0].Direction -ne 'Outbound' -or [string]$rule[0].Action -ne 'Block') {
            throw ('ActiveStore rule metadata mismatch: ' + $name)
        }
        $aliases = @(($rule[0] | Get-NetFirewallInterfaceFilter).InterfaceAlias)
        if ($aliases.Count -ne 1 -or [string]$aliases[0] -ne [string]$adapter.InterfaceAlias) {
            throw ('ActiveStore interface mismatch: ' + $name)
        }
        $addresses = @(($rule[0] | Get-NetFirewallAddressFilter).RemoteAddress)
        if ($addresses.Count -ne 2 -or $addresses -notcontains '192.0.2.1' -or $addresses -notcontains '2001:db8::1') {
            throw ('ActiveStore address mismatch: ' + $name)
        }
        $results.Add([pscustomobject]@{
            InterfaceIndex = $adapter.InterfaceIndex
            InterfaceGuid = $adapter.InterfaceGuid
            InterfaceAlias = $adapter.InterfaceAlias
            Status = $adapter.Status
            Verified = $true
        })
    }
}
catch {
    $probeFailure = $_.Exception.Message
}
finally {
    foreach ($name in @($created)) {
        Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue
    }
}

$after = Get-Residue
$residue = $after.ManagedRuleCount -ne 0 -or $after.DiagnosticRuleCount -ne 0 -or
    $after.ProductRouteCount -ne 0 -or $after.ProductTUNCount -ne 0 -or
    $after.NetworkStateExists
$success = [string]::IsNullOrWhiteSpace($probeFailure) -and -not $residue
$evidence = [ordered]@{
    SchemaVersion = 1
    Identity = $identity.Name
    SID = $identity.User.Value
    Success = $success
    AdapterCount = $adapters.Count
    Results = $results.ToArray()
    Residue = $after
    Error = $probeFailure
}
$json = $evidence | ConvertTo-Json -Depth 7
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
    throw 'Firewall interface preflight failed or left residue.'
}
