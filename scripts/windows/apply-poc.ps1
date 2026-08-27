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
    [string] $WireGuardSubnet,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]] $InternalCidrs,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int] $MaximumSnapshotAgeMinutes = 240
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'poc-networking-common.ps1')

function Invoke-PocApplyCompensation {
    param(
        [Parameter(Mandatory = $true)] [object[]] $Definitions,
        [Parameter(Mandatory = $true)] [object[]] $ForwardingEntries,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [int[]] $ForwardingAttempted,
        [Parameter(Mandatory = $true)] [bool] $NatAttempted,
        [Parameter(Mandatory = $true)] [bool] $FirewallAttempted
    )

    $failures = @()
    if ($NatAttempted) {
        try {
            if ($null -ne (Get-NetNat -Name OverseasPocNat -ErrorAction SilentlyContinue)) {
                Remove-NetNat -Name OverseasPocNat -Confirm:$false -ErrorAction Stop | Out-Null
            }
        }
        catch {
            $failures += "remove NAT: $($_.Exception.Message)"
        }
    }

    foreach ($entry in $ForwardingEntries) {
        if ($ForwardingAttempted -notcontains [int] $entry.InterfaceIndex) { continue }
        try {
            Set-NetIPInterface -InterfaceIndex ([int] $entry.InterfaceIndex) -Forwarding $entry.Forwarding -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        }
        catch {
            $failures += "restore forwarding on index $($entry.InterfaceIndex): $($_.Exception.Message)"
        }
    }

    if ($FirewallAttempted) {
        foreach ($definition in $Definitions) {
            try {
                if ($null -ne (Get-NetFirewallRule -PolicyStore PersistentStore -Name $definition.Name -ErrorAction SilentlyContinue)) {
                    Remove-NetFirewallRule -PolicyStore PersistentStore -Name $definition.Name -Confirm:$false -ErrorAction Stop | Out-Null
                }
            }
            catch {
                $failures += "remove firewall rule '$($definition.Name)': $($_.Exception.Message)"
            }
        }
    }

    return $failures
}

if (-not [System.IO.Path]::IsPathRooted($SnapshotPath)) {
    throw 'SnapshotPath must be an absolute path.'
}
$SnapshotPath = [System.IO.Path]::GetFullPath($SnapshotPath)

$configuredAliases = @($WireGuardInterface, $TelecomInterface, $EmployeeInterface)
if (@($configuredAliases | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -ne 0) {
    throw 'Interface aliases must not be empty or whitespace.'
}
if (@($configuredAliases | Select-Object -Unique).Count -ne 3) {
    throw 'WireGuard, telecom, and employee interface aliases must be distinct.'
}

$wireGuardAdapter = Get-NetAdapter -Name $WireGuardInterface -ErrorAction Stop
$telecomAdapter = Get-NetAdapter -Name $TelecomInterface -ErrorAction Stop
$employeeAdapter = Get-NetAdapter -Name $EmployeeInterface -ErrorAction Stop
$adaptersByRole = @{
    WireGuard = $wireGuardAdapter
    Telecom = $telecomAdapter
    Employee = $employeeAdapter
}
$resolvedIndexes = @(
    [int] $wireGuardAdapter.ifIndex,
    [int] $telecomAdapter.ifIndex,
    [int] $employeeAdapter.ifIndex
)
if ($resolvedIndexes.Where({ $_ -le 0 }).Count -ne 0 -or @($resolvedIndexes | Select-Object -Unique).Count -ne 3) {
    throw 'WireGuard, telecom, and employee interfaces must resolve to distinct canonical indices.'
}

$snapshot = Read-PocSnapshot -Path $SnapshotPath -MaximumAgeMinutes $MaximumSnapshotAgeMinutes
foreach ($roleAndAlias in @(
    @{ Role = 'WireGuard'; Alias = $WireGuardInterface }
    @{ Role = 'Telecom'; Alias = $TelecomInterface }
    @{ Role = 'Employee'; Alias = $EmployeeInterface }
)) {
    $saved = Get-PocRequiredInterface -Snapshot $snapshot -Role $roleAndAlias.Role
    if ($saved.Alias -cne $roleAndAlias.Alias) {
        throw "Configured interface for role '$($roleAndAlias.Role)' does not match the snapshot."
    }
}
Assert-PocAdaptersMatchSnapshot -Snapshot $snapshot -AdaptersByRole $adaptersByRole -RequireBaselineForwarding

$currentRoutes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
$defaultRoute = Get-PocSoleEmployeeDefaultRoute -EmployeeInterfaceIndex ([int] $employeeAdapter.ifIndex) -EmployeeInterfaceAlias $EmployeeInterface -Routes $currentRoutes
Assert-PocDefaultRouteMatchesSnapshot -Snapshot $snapshot -CurrentDefaultRoute $defaultRoute

$currentAddresses = @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
Assert-PocWireGuardSubnetAvailable `
    -WireGuardSubnet $WireGuardSubnet `
    -InternalCidrs $InternalCidrs `
    -WireGuardInterfaceIndex ([int] $wireGuardAdapter.ifIndex) `
    -IPAddresses $currentAddresses `
    -Routes $currentRoutes

if (@($snapshot.Nat).Count -ne 0) {
    throw 'Snapshot contains existing WinNAT state and cannot authorize this transaction.'
}
$existingNat = @(Get-NetNat -ErrorAction Stop)
if ($existingNat.Count -ne 0) {
    throw 'Existing WinNAT state does not permit safe creation of OverseasPocNat.'
}

$definitions = @(Get-PocFirewallDefinitions `
    -WireGuardInterface $WireGuardInterface `
    -TelecomInterface $TelecomInterface `
    -EmployeeInterface $EmployeeInterface `
    -WireGuardSubnet $WireGuardSubnet)
$ownedNames = @($definitions | ForEach-Object { $_.Name })
$savedOwnedRules = @($snapshot.FirewallRules | Where-Object {
    $_.Group -eq 'Overseas Gateway PoC' -or $ownedNames -contains $_.Name
})
if ($savedOwnedRules.Count -ne 0) {
    throw 'Snapshot already contains PoC-owned firewall state.'
}
$existingOwnedRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group 'Overseas Gateway PoC' -ErrorAction SilentlyContinue)
foreach ($name in $ownedNames) {
    $existingOwnedRules += @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
}
if (@($existingOwnedRules | Where-Object { $null -ne $_ } | Select-Object -Unique).Count -ne 0) {
    throw 'PoC-owned firewall state already exists in PersistentStore.'
}

$description = "SnapshotId=$($snapshot.SnapshotId); WireGuardSubnet=$WireGuardSubnet; OperatorWhitelist=Required"
$forwardingEntries = @(
    (Get-PocRequiredInterface -Snapshot $snapshot -Role 'WireGuard'),
    (Get-PocRequiredInterface -Snapshot $snapshot -Role 'Telecom')
)
$forwardingAttempted = @()
$natAttempted = $false
$firewallAttempted = $false
$target = "OverseasPocNat, three exact firewall rules, and IPv4 forwarding on indices $($wireGuardAdapter.ifIndex)/$($telecomAdapter.ifIndex)"

# Destination authorization is deliberately not duplicated here. The telecom
# operator whitelist remains the enforcement boundary; poc-probe only tests
# configured approved targets. The local rules enforce interface fail-closed
# behavior while the operator continues to decide which destinations are legal.
if ($PSCmdlet.ShouldProcess($target, 'Apply the complete Overseas Gateway PoC networking transaction')) {
    try {
        $firewallAttempted = $true
        foreach ($definition in $definitions) {
            New-NetFirewallRule `
                -PolicyStore PersistentStore `
                -Name $definition.Name `
                -DisplayName $definition.DisplayName `
                -Description $description `
                -Group 'Overseas Gateway PoC' `
                -Direction $definition.Direction `
                -Action $definition.Action `
                -InterfaceAlias $definition.InterfaceAlias `
                -RemoteAddress $definition.RemoteAddress `
                -Profile Any `
                -Enabled True `
                -ErrorAction Stop | Out-Null
        }

        # If local firewall rules are not merged into effective policy, abort
        # before NAT or forwarding can expose traffic and compensate the rules.
        Assert-PocFirewallRulesActive -Definitions $definitions -Description $description

        $natAttempted = $true
        New-NetNat -Name OverseasPocNat -InternalIPInterfaceAddressPrefix $WireGuardSubnet -ErrorAction Stop | Out-Null

        foreach ($entry in $forwardingEntries) {
            $forwardingAttempted += [int] $entry.InterfaceIndex
            Set-NetIPInterface -InterfaceIndex ([int] $entry.InterfaceIndex) -Forwarding Enabled -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        }
    }
    catch {
        $primaryFailure = $_.Exception.Message
        $compensationFailures = @(Invoke-PocApplyCompensation `
            -Definitions $definitions `
            -ForwardingEntries $forwardingEntries `
            -ForwardingAttempted $forwardingAttempted `
            -NatAttempted $natAttempted `
            -FirewallAttempted $firewallAttempted)
        if ($compensationFailures.Count -ne 0) {
            throw "Apply transaction failed: $primaryFailure Compensation also failed: $($compensationFailures -join '; ')"
        }
        throw "Apply transaction failed and was compensated: $primaryFailure"
    }
}
