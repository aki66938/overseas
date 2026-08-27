[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $SnapshotPath,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int] $MaximumSnapshotAgeMinutes = 240
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'poc-networking-common.ps1')

if (-not [System.IO.Path]::IsPathRooted($SnapshotPath)) {
    throw 'SnapshotPath must be an absolute path.'
}
$SnapshotPath = [System.IO.Path]::GetFullPath($SnapshotPath)
$snapshot = Read-PocSnapshot -Path $SnapshotPath -MaximumAgeMinutes $MaximumSnapshotAgeMinutes

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
foreach ($entry in @($wireGuardEntry, $telecomEntry)) {
    $current = @(Get-NetIPInterface -InterfaceIndex ([int] $entry.InterfaceIndex) -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
    if ($current.Count -ne 1 -or $current[0].Forwarding.ToString() -ne 'Enabled') {
        throw "Interface index $($entry.InterfaceIndex) is not in the expected applied forwarding state."
    }
}

$allNat = @(Get-NetNat -ErrorAction Stop)
if ($allNat.Count -ne 1 -or $allNat[0].Name -cne 'OverseasPocNat') {
    throw 'Current WinNAT state does not match the exact applied PoC transaction.'
}
$wireGuardSubnet = [string] $allNat[0].InternalIPInterfaceAddressPrefix
[void] (ConvertTo-PocIPv4Prefix -Prefix $wireGuardSubnet -RequireNetworkAddress)
$description = "SnapshotId=$($snapshot.SnapshotId); WireGuardSubnet=$wireGuardSubnet; OperatorWhitelist=Required"
$definitions = @(Get-PocFirewallDefinitions `
    -WireGuardInterface $wireGuardEntry.Alias `
    -TelecomInterface $telecomEntry.Alias `
    -EmployeeInterface $employeeEntry.Alias `
    -WireGuardSubnet $wireGuardSubnet)

foreach ($definition in $definitions) {
    $persistent = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $definition.Name -ErrorAction SilentlyContinue)
    if ($persistent.Count -ne 1 -or (Get-PocFirewallRuleGroup -Rule $persistent[0]) -cne 'Overseas Gateway PoC' -or $persistent[0].Description -cne $description) {
        throw "Persistent firewall rule '$($definition.Name)' does not belong to this snapshot transaction."
    }
}
Assert-PocFirewallRulesActive -Definitions $definitions -Description $description

$target = "OverseasPocNat, firewall rules $(@($definitions.Name) -join '/'), and forwarding on indices $($wireGuardEntry.InterfaceIndex)/$($telecomEntry.InterfaceIndex)"
if ($PSCmdlet.ShouldProcess($target, 'Roll back the complete Overseas Gateway PoC networking transaction')) {
    Remove-NetNat -Name OverseasPocNat -Confirm:$false -ErrorAction Stop | Out-Null

    foreach ($entry in @($wireGuardEntry, $telecomEntry)) {
        Set-NetIPInterface `
            -InterfaceIndex ([int] $entry.InterfaceIndex) `
            -Forwarding $entry.Forwarding `
            -AddressFamily IPv4 `
            -PolicyStore ActiveStore `
            -ErrorAction Stop | Out-Null
    }

    foreach ($definition in $definitions) {
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
        if ($null -ne (Get-NetFirewallRule -PolicyStore ActiveStore -Name $definition.Name -ErrorAction SilentlyContinue)) {
            throw "Rollback verification failed: firewall rule '$($definition.Name)' is still effective."
        }
    }
}
