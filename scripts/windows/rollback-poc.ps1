[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $SnapshotPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'poc-networking-common.ps1')

if (-not [System.IO.Path]::IsPathRooted($SnapshotPath)) {
    throw 'SnapshotPath must be an absolute path.'
}
$SnapshotPath = [System.IO.Path]::GetFullPath($SnapshotPath)

# Recovery authorization is bound by the envelope hash, SnapshotId, machine,
# adapters, baseline route, and owned-state metadata. It deliberately does not
# expire: an old but verified recovery artifact must remain usable in an outage.
$snapshot = Read-PocSnapshot -Path $SnapshotPath -SkipAgeValidation

$wireGuardEntry = Get-PocRequiredInterface -Snapshot $snapshot -Role 'WireGuard'
$telecomEntry = Get-PocRequiredInterface -Snapshot $snapshot -Role 'Telecom'
$employeeEntry = Get-PocRequiredInterface -Snapshot $snapshot -Role 'Employee'
$adaptersByRole = @{
    WireGuard = Get-NetAdapter -Name $wireGuardEntry.Alias -ErrorAction Stop
    Telecom = Get-NetAdapter -Name $telecomEntry.Alias -ErrorAction Stop
    Employee = Get-NetAdapter -Name $employeeEntry.Alias -ErrorAction Stop
}
Assert-PocAdaptersMatchSnapshot -Snapshot $snapshot -AdaptersByRole $adaptersByRole

$currentRoutes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
$defaultRoute = Get-PocSoleEmployeeDefaultRoute `
    -EmployeeInterfaceIndex ([int] $employeeEntry.InterfaceIndex) `
    -EmployeeInterfaceAlias $employeeEntry.Alias `
    -Routes $currentRoutes
Assert-PocDefaultRouteMatchesSnapshot -Snapshot $snapshot -CurrentDefaultRoute $defaultRoute

$currentEmployeeForwarding = @(Get-NetIPInterface -InterfaceIndex ([int] $employeeEntry.InterfaceIndex) -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
if ($currentEmployeeForwarding.Count -ne 1 -or $currentEmployeeForwarding[0].Forwarding.ToString() -ne $employeeEntry.Forwarding) {
    throw 'Employee-interface forwarding drifted after the snapshot; rollback aborted.'
}

$forwardingStates = @()
foreach ($entry in @($wireGuardEntry, $telecomEntry)) {
    $current = @(Get-NetIPInterface -InterfaceIndex ([int] $entry.InterfaceIndex) -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
    if ($current.Count -ne 1) {
        throw "Interface index $($entry.InterfaceIndex) does not have exactly one active IPv4 forwarding state."
    }
    $currentValue = $current[0].Forwarding.ToString()
    if ($currentValue -ne $entry.Forwarding -and $currentValue -ne 'Enabled') {
        throw "Interface index $($entry.InterfaceIndex) is neither applied nor at its snapshot forwarding baseline."
    }
    $forwardingStates += [pscustomobject] @{
        Entry = $entry
        NeedsRestore = $currentValue -ne $entry.Forwarding
    }
}

$ownedRuleNames = @(
    'OverseasPocBlockEmployeeInternet',
    'OverseasPocAllowWireGuardIngress',
    'OverseasPocAllowTelecomInternet'
)
$persistentByName = @{}
$subnetCandidates = @()
$descriptionPattern = '^SnapshotId={0}; WireGuardSubnet=(?<Subnet>[^;]+); OperatorWhitelist=Required$' -f [regex]::Escape([string] $snapshot.SnapshotId)
foreach ($name in $ownedRuleNames) {
    $matches = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
    if ($matches.Count -gt 1) {
        throw "Persistent firewall rule '$name' is duplicated and cannot be safely rolled back."
    }
    $persistentByName[$name] = $matches
    if ($matches.Count -eq 0) { continue }
    if ((Get-PocFirewallRuleGroup -Rule $matches[0]) -cne 'Overseas Gateway PoC') {
        throw "Persistent firewall rule '$name' conflicts with transaction ownership."
    }
    $metadataMatch = [regex]::Match([string] $matches[0].Description, $descriptionPattern)
    if (-not $metadataMatch.Success) {
        throw "Persistent firewall rule '$name' does not belong to this snapshot transaction."
    }
    $subnetCandidates += $metadataMatch.Groups['Subnet'].Value
}

$allNat = @(Get-NetNat -ErrorAction Stop)
$ownedNat = $null
if ($allNat.Count -gt 1 -or ($allNat.Count -eq 1 -and $allNat[0].Name -cne 'OverseasPocNat')) {
    throw 'Current WinNAT state contains foreign or conflicting state; rollback aborted.'
}
if ($allNat.Count -eq 1) {
    $ownedNat = $allNat[0]
    $subnetCandidates += [string] $ownedNat.InternalIPInterfaceAddressPrefix
}

$hasPersistentOwnedRule = @($persistentByName.Values | ForEach-Object { @($_) } | Where-Object { $null -ne $_ }).Count -ne 0
if ($null -eq $ownedNat -and -not $hasPersistentOwnedRule -and @($forwardingStates | Where-Object { $_.NeedsRestore }).Count -ne 0) {
    throw 'Forwarding differs from baseline but no transaction-owned NAT or persistent rule remains; refusing to restore potentially unrelated state.'
}

$snapshotWireGuardPrefixes = @()
foreach ($route in @($snapshot.Routes | Where-Object {
    [int] $_.InterfaceIndex -eq [int] $wireGuardEntry.InterfaceIndex -and
    $_.DestinationPrefix.ToString() -ne '0.0.0.0/0'
})) {
    try {
        $prefix = ConvertTo-PocIPv4Prefix -Prefix $route.DestinationPrefix.ToString() -RequireNetworkAddress
        $snapshotWireGuardPrefixes += $prefix
    }
    catch {
        continue
    }
}
$snapshotWireGuardSubnets = @($snapshotWireGuardPrefixes | ForEach-Object { $_.Text } | Select-Object -Unique)
$currentWireGuardAddresses = @(Get-NetIPAddress -InterfaceIndex ([int] $wireGuardEntry.InterfaceIndex) -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
    [int] $_.InterfaceIndex -eq [int] $wireGuardEntry.InterfaceIndex
})
$baselineSubnetCandidates = @()
foreach ($address in $currentWireGuardAddresses) {
    try {
        $addressPrefix = ConvertTo-PocIPv4Prefix -Prefix ("{0}/{1}" -f $address.IPAddress, $address.PrefixLength)
        foreach ($routePrefix in $snapshotWireGuardPrefixes) {
            if ($routePrefix.Start -eq $addressPrefix.Start -and $routePrefix.End -eq $addressPrefix.End) {
                $baselineSubnetCandidates += $routePrefix.Text
            }
        }
    }
    catch {
        continue
    }
}
$baselineSubnetCandidates = @($baselineSubnetCandidates | Select-Object -Unique)
$subnetCandidates = @($subnetCandidates | Select-Object -Unique)
if ($subnetCandidates.Count -gt 1) {
    throw 'Owned PoC state contains conflicting WireGuard subnet metadata.'
}
if ($subnetCandidates.Count -eq 1) {
    $wireGuardSubnet = $subnetCandidates[0]
    if ($snapshotWireGuardSubnets -notcontains $wireGuardSubnet) {
        throw 'Owned PoC state does not match the WireGuard subnet recorded by the snapshot.'
    }
}
elseif ($baselineSubnetCandidates.Count -eq 1) {
    # No owned state is also valid: this supports a pristine preview and a
    # retry after an earlier rollback already removed all owned resources.
    $wireGuardSubnet = $baselineSubnetCandidates[0]
}
else {
    throw 'The verified snapshot and current WireGuard address do not identify exactly one rollback subnet.'
}
[void] (ConvertTo-PocIPv4Prefix -Prefix $wireGuardSubnet -RequireNetworkAddress)

$description = "SnapshotId=$($snapshot.SnapshotId); WireGuardSubnet=$wireGuardSubnet; OperatorWhitelist=Required"
$definitions = @(Get-PocFirewallDefinitions `
    -WireGuardInterface $wireGuardEntry.Alias `
    -TelecomInterface $telecomEntry.Alias `
    -EmployeeInterface $employeeEntry.Alias `
    -WireGuardSubnet $wireGuardSubnet)

foreach ($definition in $definitions) {
    $persistent = @($persistentByName[$definition.Name])
    if ($persistent.Count -eq 0) { continue }
    Assert-PocFirewallRuleMatchesDefinition `
        -Rule $persistent[0] `
        -Definition $definition `
        -Description $description `
        -StoreLabel 'PersistentStore'
}

# Missing effective rules are an emergency-cleanup signal, not a reason to
# leave NAT and forwarding active. Any effective rule that does exist must
# still match this exact transaction, including Profile Any.
Assert-PocFirewallRulesActive -Definitions $definitions -Description $description -AllowMissing

$target = "remove owned OverseasPocNat/rules if present and restore snapshot forwarding on indices $($wireGuardEntry.InterfaceIndex)/$($telecomEntry.InterfaceIndex)"
if ($PSCmdlet.ShouldProcess($target, 'Roll back the complete Overseas Gateway PoC networking transaction')) {
    if ($null -ne $ownedNat) {
        Remove-NetNat -Name OverseasPocNat -Confirm:$false -ErrorAction Stop | Out-Null
    }

    foreach ($state in $forwardingStates) {
        if (-not $state.NeedsRestore) { continue }
        $entry = $state.Entry
        Set-NetIPInterface `
            -InterfaceIndex ([int] $entry.InterfaceIndex) `
            -Forwarding $entry.Forwarding `
            -AddressFamily IPv4 `
            -PolicyStore ActiveStore `
            -Confirm:$false `
            -ErrorAction Stop | Out-Null
    }

    foreach ($definition in $definitions) {
        if (@($persistentByName[$definition.Name]).Count -eq 0) { continue }
        Remove-NetFirewallRule `
            -PolicyStore PersistentStore `
            -Name $definition.Name `
            -Confirm:$false `
            -ErrorAction Stop | Out-Null
    }

    if ($null -ne (Get-NetNat -Name OverseasPocNat -ErrorAction SilentlyContinue)) {
        throw 'Rollback verification failed: OverseasPocNat is still present.'
    }
    foreach ($entry in @($wireGuardEntry, $telecomEntry)) {
        $current = @(Get-NetIPInterface -InterfaceIndex ([int] $entry.InterfaceIndex) -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
        if ($current.Count -ne 1 -or $current[0].Forwarding.ToString() -ne $entry.Forwarding) {
            throw "Rollback verification failed for forwarding on interface index $($entry.InterfaceIndex)."
        }
    }
    foreach ($definition in $definitions) {
        if ($null -ne (Get-NetFirewallRule -PolicyStore PersistentStore -Name $definition.Name -ErrorAction SilentlyContinue)) {
            throw "Rollback verification failed: firewall rule '$($definition.Name)' remains persistent."
        }
        if ($null -ne (Get-NetFirewallRule -PolicyStore ActiveStore -Name $definition.Name -ErrorAction SilentlyContinue)) {
            throw "Rollback verification failed: firewall rule '$($definition.Name)' is still effective."
        }
    }
}
