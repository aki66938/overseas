[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $SnapshotPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-PocSnapshot {
    param([Parameter(Mandatory = $true)][string] $Path)

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

    $requiredRoles = @('WireGuard', 'Telecom', 'Employee')
    foreach ($role in $requiredRoles) {
        $roleEntries = @($data.RequiredInterfaces | Where-Object { $_.Role -eq $role })
        if ($roleEntries.Count -ne 1 -or [int] $roleEntries[0].InterfaceIndex -le 0) {
            throw "Snapshot lacks the required interface index for role '$role'."
        }
        $entry = $roleEntries[0]
        if ($entry.AddressFamily -ne 'IPv4' -or $entry.Forwarding -notin @('Enabled', 'Disabled')) {
            throw "Snapshot lacks valid forwarding state for required interface index $($entry.InterfaceIndex)."
        }
        if (@($data.NetIPInterfaces | Where-Object { [int] $_.InterfaceIndex -eq [int] $entry.InterfaceIndex }).Count -eq 0) {
            throw "Snapshot inventory lacks required interface index $($entry.InterfaceIndex)."
        }
    }

    return $data
}

if (-not [System.IO.Path]::IsPathRooted($SnapshotPath)) {
    throw 'SnapshotPath must be an absolute path.'
}
$SnapshotPath = [System.IO.Path]::GetFullPath($SnapshotPath)
$snapshot = Assert-PocSnapshot -Path $SnapshotPath

$requiredInterfaceIndexes = @($snapshot.RequiredInterfaces | ForEach-Object { [int] $_.InterfaceIndex })
if ($requiredInterfaceIndexes.Count -ne 3 -or @($requiredInterfaceIndexes | Select-Object -Unique).Count -ne 3) {
    throw 'Snapshot required interface indexes must be present and distinct.'
}

foreach ($required in $snapshot.RequiredInterfaces) {
    $adapter = Get-NetAdapter -InterfaceIndex ([int] $required.InterfaceIndex) -ErrorAction Stop
    if ($adapter.Name -ne $required.Alias) {
        throw "Adapter mismatch at required interface index $($required.InterfaceIndex); rollback aborted."
    }
}

$forwardingEntriesToRestore = @()
foreach ($role in @('WireGuard', 'Telecom')) {
    $forwardingEntriesToRestore += @($snapshot.RequiredInterfaces | Where-Object { $_.Role -eq $role })[0]
}

$ownedRules = @(Get-NetFirewallRule -Group 'Overseas Gateway PoC' -ErrorAction SilentlyContinue)
$ownedNat = Get-NetNat -Name OverseasPocNat -ErrorAction SilentlyContinue

foreach ($rule in $ownedRules) {
    if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Remove firewall rule in group 'Overseas Gateway PoC'")) {
        Remove-NetFirewallRule -InputObject $rule -Confirm:$false -ErrorAction Stop
    }
}

if ($null -ne $ownedNat -and $PSCmdlet.ShouldProcess('OverseasPocNat', 'Remove owned NAT')) {
    Remove-NetNat -Name OverseasPocNat -Confirm:$false -ErrorAction Stop
}

foreach ($entry in $forwardingEntriesToRestore) {
    if ($PSCmdlet.ShouldProcess("interface index $($entry.InterfaceIndex)", "Restore IPv4 forwarding to $($entry.Forwarding)")) {
        Set-NetIPInterface -InterfaceIndex $entry.InterfaceIndex -Forwarding $entry.Forwarding -AddressFamily $entry.AddressFamily -ErrorAction Stop
    }
}
