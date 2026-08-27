[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $SnapshotPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $WireGuardInterface,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $TelecomInterface,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $EmployeeInterface,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $WireGuardSubnet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-PocSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [hashtable] $ExpectedInterfaces
    )

    if (-not [System.IO.Path]::IsPathRooted($SnapshotPath)) {
        throw 'SnapshotPath must be an absolute path.'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Snapshot does not exist: $Path"
    }

    try {
        $data = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Snapshot is not valid JSON: $($_.Exception.Message)"
    }

    foreach ($property in @(
        'SchemaVersion', 'CapturedAtUtc', 'ComputerName', 'RequiredInterfaces',
        'NetIPInterfaces', 'Routes', 'Nat', 'FirewallRules',
        'FirewallAddressFilters', 'Adapters'
    )) {
        if ($null -eq $data.PSObject.Properties[$property]) {
            throw "Snapshot is missing required property '$property'."
        }
    }
    if ($data.SchemaVersion -ne 1) {
        throw "Unsupported snapshot schema version '$($data.SchemaVersion)'."
    }
    if ($data.ComputerName -ne $env:COMPUTERNAME) {
        throw "Snapshot belongs to computer '$($data.ComputerName)', not '$env:COMPUTERNAME'."
    }

    foreach ($role in $ExpectedInterfaces.Keys) {
        $entries = @($data.RequiredInterfaces | Where-Object { $_.Role -eq $role })
        if ($entries.Count -ne 1) {
            throw "Snapshot must contain exactly one required interface for role '$role'."
        }
        $entry = $entries[0]
        if ($entry.Alias -ne $ExpectedInterfaces[$role] -or [int] $entry.InterfaceIndex -le 0) {
            throw "Snapshot required interface '$role' does not match the configured alias or index."
        }
        if ($entry.AddressFamily -ne 'IPv4' -or $entry.Forwarding -notin @('Enabled', 'Disabled')) {
            throw "Snapshot lacks valid IPv4 forwarding state for required interface index $($entry.InterfaceIndex)."
        }
        if (@($data.NetIPInterfaces | Where-Object { [int] $_.InterfaceIndex -eq [int] $entry.InterfaceIndex }).Count -eq 0) {
            throw "Snapshot inventory lacks required interface index $($entry.InterfaceIndex)."
        }
    }

    return $data
}

function Assert-IPv4NetworkPrefix {
    param([string] $Prefix)

    $parts = $Prefix.Split('/')
    $address = $null
    $prefixLength = 0
    if (
        $parts.Count -ne 2 -or
        -not [System.Net.IPAddress]::TryParse($parts[0], [ref] $address) -or
        $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        -not [int]::TryParse($parts[1], [ref] $prefixLength) -or
        $prefixLength -lt 1 -or
        $prefixLength -gt 32
    ) {
        throw "WireGuardSubnet must be an absolute IPv4 CIDR prefix: '$Prefix'."
    }

    $bytes = $address.GetAddressBytes()
    $value = ([uint32] $bytes[0] -shl 24) -bor
        ([uint32] $bytes[1] -shl 16) -bor
        ([uint32] $bytes[2] -shl 8) -bor
        [uint32] $bytes[3]
    $hostBits = 32 - $prefixLength
    $hostMask = if ($hostBits -eq 0) { [uint32] 0 } else { [uint32] ([math]::Pow(2, $hostBits) - 1) }
    if (($value -band $hostMask) -ne 0) {
        throw "WireGuardSubnet must use the network address, not a host address: '$Prefix'."
    }
}

if (-not [System.IO.Path]::IsPathRooted($SnapshotPath)) {
    throw 'SnapshotPath must be an absolute path.'
}
$SnapshotPath = [System.IO.Path]::GetFullPath($SnapshotPath)

$configuredAliases = @($WireGuardInterface, $TelecomInterface, $EmployeeInterface)
if ($configuredAliases.Where({ [string]::IsNullOrWhiteSpace($_) }).Count -ne 0) {
    throw 'Interface aliases must not be empty or whitespace.'
}
$aliases = @($configuredAliases | Select-Object -Unique)
if ($aliases.Count -ne 3) {
    throw 'WireGuard, telecom, and employee interfaces must be distinct.'
}
Assert-IPv4NetworkPrefix -Prefix $WireGuardSubnet

$wireGuardAdapter = Get-NetAdapter -Name $WireGuardInterface -ErrorAction Stop
$telecomAdapter = Get-NetAdapter -Name $TelecomInterface -ErrorAction Stop
$employeeAdapter = Get-NetAdapter -Name $EmployeeInterface -ErrorAction Stop

$expectedInterfaces = @{
    WireGuard = $WireGuardInterface
    Telecom = $TelecomInterface
    Employee = $EmployeeInterface
}
$snapshot = Assert-PocSnapshot -Path $SnapshotPath -ExpectedInterfaces $expectedInterfaces

foreach ($entry in $snapshot.RequiredInterfaces) {
    $currentAdapter = Get-NetAdapter -InterfaceIndex ([int] $entry.InterfaceIndex) -ErrorAction Stop
    if ($currentAdapter.Name -ne $entry.Alias) {
        throw "Current adapter at required interface index $($entry.InterfaceIndex) is not '$($entry.Alias)'."
    }
}

if ($null -ne (Get-NetNat -Name OverseasPocNat -ErrorAction SilentlyContinue)) {
    throw "NAT 'OverseasPocNat' already exists; refusing to overwrite owned state."
}
if (@(Get-NetFirewallRule -Group 'Overseas Gateway PoC' -ErrorAction SilentlyContinue).Count -ne 0) {
    throw "Firewall group 'Overseas Gateway PoC' already exists; refusing to overwrite owned state."
}

# Windows Firewall block rules take precedence over overlapping allow rules. The
# employee-interface block therefore provides fail-closed behavior without a
# nonexistent numeric firewall-rule priority.
if ($PSCmdlet.ShouldProcess($EmployeeInterface, 'Create fail-closed WireGuard subnet block')) {
    New-NetFirewallRule -DisplayName 'Overseas Gateway PoC - Block employee fallback' -Group 'Overseas Gateway PoC' -Direction Outbound -Action Block -InterfaceAlias $EmployeeInterface -LocalAddress $WireGuardSubnet -Profile Any -Enabled True -ErrorAction Stop | Out-Null
}

if ($PSCmdlet.ShouldProcess($WireGuardInterface, 'Allow WireGuard subnet ingress')) {
    New-NetFirewallRule -DisplayName 'Overseas Gateway PoC - Allow WireGuard ingress' -Group 'Overseas Gateway PoC' -Direction Inbound -Action Allow -InterfaceAlias $WireGuardInterface -RemoteAddress $WireGuardSubnet -Profile Any -Enabled True -ErrorAction Stop | Out-Null
}

if ($PSCmdlet.ShouldProcess($TelecomInterface, 'Allow WireGuard subnet egress through telecom')) {
    New-NetFirewallRule -DisplayName 'Overseas Gateway PoC - Allow telecom egress' -Group 'Overseas Gateway PoC' -Direction Outbound -Action Allow -InterfaceAlias $TelecomInterface -LocalAddress $WireGuardSubnet -Profile Any -Enabled True -ErrorAction Stop | Out-Null
}

if ($PSCmdlet.ShouldProcess('OverseasPocNat', "Create NAT for $WireGuardSubnet")) {
    New-NetNat -Name OverseasPocNat -InternalIPInterfaceAddressPrefix $WireGuardSubnet -ErrorAction Stop | Out-Null
}

if ($PSCmdlet.ShouldProcess($WireGuardInterface, 'Enable IPv4 forwarding')) {
    Set-NetIPInterface -InterfaceIndex $wireGuardAdapter.ifIndex -Forwarding Enabled -AddressFamily IPv4 -ErrorAction Stop
}

if ($PSCmdlet.ShouldProcess($TelecomInterface, 'Enable IPv4 forwarding')) {
    Set-NetIPInterface -InterfaceIndex $telecomAdapter.ifIndex -Forwarding Enabled -AddressFamily IPv4 -ErrorAction Stop
}
