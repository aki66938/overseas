[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $WireGuardInterface,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $TelecomInterface,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $EmployeeInterface,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $ArtifactsDirectory = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..\artifacts')
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [System.IO.Path]::IsPathRooted($ArtifactsDirectory)) {
    throw 'ArtifactsDirectory must be an absolute path.'
}

$ArtifactsDirectory = [System.IO.Path]::GetFullPath($ArtifactsDirectory)
if (-not (Test-Path -LiteralPath $ArtifactsDirectory -PathType Container)) {
    throw "ArtifactsDirectory does not exist: $ArtifactsDirectory"
}

$configuredAliases = @($WireGuardInterface, $TelecomInterface, $EmployeeInterface)
if ($configuredAliases.Where({ [string]::IsNullOrWhiteSpace($_) }).Count -ne 0) {
    throw 'Interface aliases must not be empty or whitespace.'
}

$uniqueAliases = @($configuredAliases | Select-Object -Unique)
if ($uniqueAliases.Count -ne 3) {
    throw 'WireGuard, telecom, and employee interfaces must be distinct.'
}

$wireGuardAdapter = Get-NetAdapter -Name $WireGuardInterface -ErrorAction Stop
$telecomAdapter = Get-NetAdapter -Name $TelecomInterface -ErrorAction Stop
$employeeAdapter = Get-NetAdapter -Name $EmployeeInterface -ErrorAction Stop
$netIPInterfaces = @(Get-NetIPInterface -ErrorAction Stop)

$wireGuardIPv4 = @($netIPInterfaces | Where-Object {
    [int] $_.InterfaceIndex -eq [int] $wireGuardAdapter.ifIndex -and $_.AddressFamily.ToString() -eq 'IPv4'
})
$telecomIPv4 = @($netIPInterfaces | Where-Object {
    [int] $_.InterfaceIndex -eq [int] $telecomAdapter.ifIndex -and $_.AddressFamily.ToString() -eq 'IPv4'
})
$employeeIPv4 = @($netIPInterfaces | Where-Object {
    [int] $_.InterfaceIndex -eq [int] $employeeAdapter.ifIndex -and $_.AddressFamily.ToString() -eq 'IPv4'
})
if ($wireGuardIPv4.Count -ne 1 -or $telecomIPv4.Count -ne 1 -or $employeeIPv4.Count -ne 1) {
    throw 'Each required adapter must have exactly one IPv4 interface entry.'
}
$wireGuardIPv4 = $wireGuardIPv4[0]
$telecomIPv4 = $telecomIPv4[0]
$employeeIPv4 = $employeeIPv4[0]

$snapshot = [ordered] @{
    SchemaVersion = 1
    CapturedAtUtc = [DateTime]::UtcNow.ToString('o')
    ComputerName = $env:COMPUTERNAME
    RequiredInterfaces = @(
        [ordered] @{ Role = 'WireGuard'; Alias = $WireGuardInterface; InterfaceIndex = $wireGuardAdapter.ifIndex; AddressFamily = 'IPv4'; Forwarding = $wireGuardIPv4.Forwarding.ToString() }
        [ordered] @{ Role = 'Telecom'; Alias = $TelecomInterface; InterfaceIndex = $telecomAdapter.ifIndex; AddressFamily = 'IPv4'; Forwarding = $telecomIPv4.Forwarding.ToString() }
        [ordered] @{ Role = 'Employee'; Alias = $EmployeeInterface; InterfaceIndex = $employeeAdapter.ifIndex; AddressFamily = 'IPv4'; Forwarding = $employeeIPv4.Forwarding.ToString() }
    )
    NetIPInterfaces = $netIPInterfaces
    Routes = @(Get-NetRoute -ErrorAction Stop)
    Nat = @(Get-NetNat -ErrorAction Stop)
    FirewallRules = @(Get-NetFirewallRule -ErrorAction Stop)
    FirewallAddressFilters = @(Get-NetFirewallAddressFilter -ErrorAction Stop)
    Adapters = @(Get-NetAdapter -ErrorAction Stop)
}

$fileName = 'poc-networking-{0:yyyyMMdd-HHmmss-fffffff}.json' -f (Get-Date)
$snapshotPath = Join-Path $ArtifactsDirectory $fileName
$json = $snapshot | ConvertTo-Json -Depth 12

if ($PSCmdlet.ShouldProcess($snapshotPath, 'Create pre-change networking snapshot')) {
    $stream = $null
    $writer = $null
    try {
        $stream = [System.IO.File]::Open(
            $snapshotPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $writer = New-Object System.IO.StreamWriter(
            $stream,
            (New-Object System.Text.UTF8Encoding($false))
        )
        $writer.Write($json)
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

$snapshotPath
