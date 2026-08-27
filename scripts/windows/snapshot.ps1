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
. (Join-Path $PSScriptRoot 'poc-networking-common.ps1')

if (-not [System.IO.Path]::IsPathRooted($ArtifactsDirectory)) {
    throw 'ArtifactsDirectory must be an absolute path.'
}
$ArtifactsDirectory = [System.IO.Path]::GetFullPath($ArtifactsDirectory)
if (-not (Test-Path -LiteralPath $ArtifactsDirectory -PathType Container)) {
    throw "ArtifactsDirectory does not exist: $ArtifactsDirectory"
}

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
$adapterIndexes = @(
    [int] $wireGuardAdapter.ifIndex,
    [int] $telecomAdapter.ifIndex,
    [int] $employeeAdapter.ifIndex
)
if ($adapterIndexes.Where({ $_ -le 0 }).Count -ne 0 -or @($adapterIndexes | Select-Object -Unique).Count -ne 3) {
    throw 'WireGuard, telecom, and employee interfaces must resolve to distinct canonical indices.'
}

$netIPInterfaces = @(Get-NetIPInterface -ErrorAction Stop)
$requiredInterfaces = @()
foreach ($roleAndAdapter in @(
    @{ Role = 'WireGuard'; Alias = $WireGuardInterface; Adapter = $wireGuardAdapter }
    @{ Role = 'Telecom'; Alias = $TelecomInterface; Adapter = $telecomAdapter }
    @{ Role = 'Employee'; Alias = $EmployeeInterface; Adapter = $employeeAdapter }
)) {
    $ipv4 = @($netIPInterfaces | Where-Object {
        [int] $_.InterfaceIndex -eq [int] $roleAndAdapter.Adapter.ifIndex -and
        $_.AddressFamily.ToString() -eq 'IPv4'
    })
    if ($ipv4.Count -ne 1 -or $ipv4[0].Forwarding.ToString() -notin @('Enabled', 'Disabled')) {
        throw "Role '$($roleAndAdapter.Role)' must have exactly one valid IPv4 forwarding entry."
    }
    $requiredInterfaces += [ordered] @{
        Role = $roleAndAdapter.Role
        Alias = $roleAndAdapter.Alias
        InterfaceIndex = [int] $roleAndAdapter.Adapter.ifIndex
        AddressFamily = 'IPv4'
        Forwarding = $ipv4[0].Forwarding.ToString()
    }
}

$snapshotPayload = [ordered] @{
    SnapshotId = [guid]::NewGuid().ToString('D')
    # Compact UTC avoids Windows PowerShell 5.1 ConvertFrom-Json converting an
    # ISO 8601 value into a Kind=Unspecified DateTime and shifting it twice.
    CapturedAtUtc = [datetime]::UtcNow.ToString("yyyyMMdd'T'HHmmss.fffffff'Z'")
    ComputerName = $env:COMPUTERNAME
    RequiredInterfaces = $requiredInterfaces
    NetIPInterfaces = $netIPInterfaces
    Routes = @(Get-NetRoute -ErrorAction Stop)
    Nat = @(Get-NetNat -ErrorAction Stop)
    FirewallRules = @(Get-NetFirewallRule -ErrorAction Stop)
    FirewallAddressFilters = @(Get-NetFirewallAddressFilter -ErrorAction Stop)
    Adapters = @(Get-NetAdapter -ErrorAction Stop)
}

$payloadJson = $snapshotPayload | ConvertTo-Json -Compress -Depth 20
$payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
$envelope = [ordered] @{
    SchemaVersion = 2
    IntegrityAlgorithm = 'SHA256'
    PayloadBase64 = [Convert]::ToBase64String($payloadBytes)
    PayloadSha256 = Get-PocSha256Hex -Bytes $payloadBytes
}
$json = $envelope | ConvertTo-Json -Depth 5

$fileName = 'poc-networking-{0:yyyyMMdd-HHmmss-fffffff}-{1}.json' -f (Get-Date), ([guid]::NewGuid().ToString('N'))
$snapshotPath = Join-Path $ArtifactsDirectory $fileName
$temporaryPath = Join-Path $ArtifactsDirectory ('.{0}.tmp' -f ([guid]::NewGuid().ToString('N')))
$published = $false

if ($PSCmdlet.ShouldProcess($snapshotPath, 'Atomically create an integrity-protected pre-change networking snapshot')) {
    try {
        $stream = $null
        $writer = $null
        try {
            $stream = [System.IO.File]::Open(
                $temporaryPath,
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

        Move-Item -LiteralPath $temporaryPath -Destination $snapshotPath -Confirm:$false -ErrorAction Stop
        $published = $true
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

if ($published) {
    $snapshotPath
}
