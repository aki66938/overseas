#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Install', 'Status', 'Rollback')]
    [Parameter(Mandatory = $true)]
    [string] $Mode,

    [string] $BundlePath,

    [string] $ConfigPath,

    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $ExpectedSingBoxSha256,

    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $ExpectedConfigSha256,

    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $ExpectedServerServiceSha256,

    [string] $EmployeeCIDR,

    [ValidateRange(1, 65535)]
    [int] $ServerPort,

    [string] $EvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$savedGlobalWhatIfPreference = $global:WhatIfPreference
try {
    $global:WhatIfPreference = $false
    Import-Module Microsoft.PowerShell.Utility,CimCmdlets,NetTCPIP,NetSecurity -ErrorAction Stop
}
finally {
    $global:WhatIfPreference = $savedGlobalWhatIfPreference
}

$InvocationParameters = @{}
foreach ($invocationKey in $PSBoundParameters.Keys) {
    $InvocationParameters[$invocationKey] = $PSBoundParameters[$invocationKey]
}

$ExpectedVmAddress = '172.20.9.15'
$ExpectedEmployeeCIDR = '172.20.8.0/22'
$ExpectedServerPort = 18443
$TelecomProxyAddress = '127.0.0.1'
$TelecomProxyPort = 8080
$ConnectProbeUri = 'https://www.google.com/generate_204'
$ServiceName = 'RegenBioOverseasAccessServer'
$ServerServiceName = 'overseas-server-service.exe'
$RuntimeManifestName = 'runtime-manifest.json'
$InstallRoot = 'C:\Program Files\RegenBio\OverseasAccessServer'
$DataRoot = 'C:\ProgramData\RegenBio\OverseasAccessServer'
$OwnerMarkerName = 'owner.json'
$FirewallAllowEmployee = 'RegenBioOverseasAccess-AllowEmployee-In'
$FirewallBlockManagement = 'RegenBioOverseasAccess-BlockManagement-Employee'
$FirewallNames = @($FirewallAllowEmployee, $FirewallBlockManagement)
$ManagementPorts = @('22', '3389', '5985', '5986')
$OwnershipPrefix = 'RegenBioOverseasAccessServer;TransactionId='

function ConvertTo-ServerJson {
    param([Parameter(Mandatory = $true)] $Value)

    return ($Value | ConvertTo-Json -Compress -Depth 20)
}

function Write-ServerJson {
    param([Parameter(Mandatory = $true)] $Value)

    Write-Output (ConvertTo-ServerJson -Value $Value)
}

function Get-TransactionJournalPath {
    param([Parameter(Mandatory = $true)] [string] $BaselinePath)

    return ([System.IO.Path]::GetFullPath($BaselinePath) + '.transaction.json')
}

function Get-StringSha256 {
    param([AllowEmptyString()] [string] $Value)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Write-AtomicJson {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] $Value
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parentPath = [System.IO.Path]::GetDirectoryName($fullPath)
    if ([string]::IsNullOrWhiteSpace($parentPath) -or -not (Test-Path -LiteralPath $parentPath -PathType Container)) {
        throw "Evidence parent directory does not exist: $parentPath"
    }
    if (Test-Path -LiteralPath $fullPath) {
        throw "Refusing to replace existing atomic evidence: $fullPath"
    }

    $temporaryPath = $fullPath + '.tmp.' + [guid]::NewGuid().ToString('N')
    $stream = $null
    $writer = $null
    try {
        $stream = New-Object System.IO.FileStream(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $writer = New-Object System.IO.StreamWriter($stream, (New-Object System.Text.UTF8Encoding($false)))
        $stream = $null
        $writer.Write((ConvertTo-ServerJson -Value $Value))
        $writer.Flush()
        $writer.Dispose()
        $writer = $null
        Move-Item -LiteralPath $temporaryPath -Destination $fullPath -Confirm:$false
    }
    finally {
        if ($null -ne $writer) {
            $writer.Dispose()
        }
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -Confirm:$false
        }
    }
}

function Test-ServerAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-SupportedServerHost {
    if (-not (Test-ServerAdministrator)) {
        throw 'Server deployment requires an elevated Administrator token.'
    }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $version = $null
    if (-not [version]::TryParse([string] $os.Version, [ref] $version)) {
        throw "Unsupported Windows version: $($os.Version)"
    }
    if ($version.Major -lt 10 -or [string] $os.OSArchitecture -notmatch '^64') {
        throw "Unsupported Windows host: $($os.Caption) $($os.Version) $($os.OSArchitecture)"
    }

    $vmAddresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
        [string] $_.IPAddress -eq $ExpectedVmAddress
    })
    if ($vmAddresses.Count -ne 1) {
        throw "Expected VM address $ExpectedVmAddress was not found exactly once."
    }

    return [pscustomobject] @{
        OperatingSystem = [ordered] @{
            Caption = [string] $os.Caption
            Version = [string] $os.Version
            Architecture = [string] $os.OSArchitecture
        }
        VmAddress = $ExpectedVmAddress
        VmInterfaceIndex = [int] $vmAddresses[0].InterfaceIndex
    }
}

function Assert-InstallInputs {
    if (-not $InvocationParameters.ContainsKey('EmployeeCIDR')) {
        throw 'EmployeeCIDR must be supplied explicitly for Install.'
    }
    if (-not $InvocationParameters.ContainsKey('ServerPort')) {
        throw 'ServerPort must be supplied explicitly for Install.'
    }
    if ($EmployeeCIDR -ne $ExpectedEmployeeCIDR) {
        throw "EmployeeCIDR must be exactly $ExpectedEmployeeCIDR for this PoC."
    }
    if ($ServerPort -ne $ExpectedServerPort) {
        throw "ServerPort must be exactly $ExpectedServerPort for this PoC."
    }

    foreach ($requiredName in @('BundlePath', 'ConfigPath', 'ExpectedSingBoxSha256', 'ExpectedConfigSha256', 'ExpectedServerServiceSha256', 'EvidencePath')) {
        if (-not $InvocationParameters.ContainsKey($requiredName) -or [string]::IsNullOrWhiteSpace([string] $InvocationParameters[$requiredName])) {
            throw "$requiredName must be supplied explicitly for Install."
        }
    }
}

function Assert-RollbackInputs {
    if (-not $InvocationParameters.ContainsKey('EvidencePath') -or [string]::IsNullOrWhiteSpace($EvidencePath)) {
        throw 'EvidencePath must be supplied explicitly for Rollback.'
    }
}

function Get-ExactService {
    return @(Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue)
}

function Get-ExactFirewallRule {
    param([Parameter(Mandatory = $true)] [string] $Name)

    return @(Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue)
}

function Assert-NoOwnedResourceCollision {
    if (@(Get-ExactService).Count -ne 0) {
        throw "Service $ServiceName already exists; use Rollback before Install."
    }
    foreach ($firewallName in $FirewallNames) {
        if (@(Get-ExactFirewallRule -Name $firewallName).Count -ne 0) {
            throw "Firewall rule $firewallName already exists; refusing ambiguous ownership."
        }
    }
    if (Test-Path -LiteralPath $InstallRoot) {
        throw "Install path already exists: $InstallRoot"
    }
    if (Test-Path -LiteralPath $DataRoot) {
        throw "Data path already exists: $DataRoot"
    }
}

function Test-PortSpecificationIncludes {
    param(
        [Parameter(Mandatory = $true)] $Specification,
        [Parameter(Mandatory = $true)] [int] $Port
    )

    foreach ($specificationValue in @($Specification)) {
        foreach ($entry in @([string] $specificationValue -split ',')) {
            $trimmed = $entry.Trim()
            if ($trimmed -eq 'Any' -or $trimmed -eq [string] $Port) { return $true }
            if ($trimmed -match '^(?<rangeStart>\d+)-(?<rangeEnd>\d+)$') {
                $rangeStart = [int] $Matches.rangeStart
                $rangeEnd = [int] $Matches.rangeEnd
                if ($Port -ge $rangeStart -and $Port -le $rangeEnd) { return $true }
            }
        }
    }
    return $false
}

function Assert-NoConflictingServerPortAllow {
    $installedExecutable = Join-Path $InstallRoot 'sing-box.exe'
    $allowRules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
        [string] $_.Enabled -match '^(True|1)$' -and
        [string] $_.Direction -eq 'Inbound' -and
        [string] $_.Action -eq 'Allow'
    })

    foreach ($rule in $allowRules) {
        $portFilters = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $portApplies = @($portFilters | Where-Object {
            [string] $_.Protocol -in @('Any', 'TCP', '6') -and
            (Test-PortSpecificationIncludes -Specification $_.LocalPort -Port $ServerPort)
        }).Count -ne 0
        if (-not $portApplies) { continue }

        $applicationFilters = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $programApplies = @($applicationFilters | Where-Object {
            [string]::IsNullOrWhiteSpace([string] $_.Package) -and
            ([string]::IsNullOrWhiteSpace([string] $_.Program) -or
                [string] $_.Program -eq 'Any' -or
                [string] $_.Program -eq $installedExecutable)
        }).Count -ne 0
        if (-not $programApplies) { continue }

        $serviceFilters = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $serviceApplies = @($serviceFilters | Where-Object {
            [string]::IsNullOrWhiteSpace([string] $_.Service) -or
            [string] $_.Service -eq 'Any' -or
            [string] $_.Service -eq $ServiceName
        }).Count -ne 0
        if (-not $serviceApplies) { continue }

        $addressFilters = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $remoteAddresses = @($addressFilters | ForEach-Object { @($_.RemoteAddress) } | ForEach-Object { [string] $_ })
        $outsideApprovedCidr = @($remoteAddresses | Where-Object { $_ -ne $ExpectedEmployeeCIDR }).Count -ne 0
        if ($outsideApprovedCidr -or $remoteAddresses.Count -eq 0) {
            throw "Existing firewall rule $($rule.Name) can expose TCP $ServerPort outside $ExpectedEmployeeCIDR."
        }
    }
}

function Get-VerifiedInputEvidence {
    $savedVerificationWhatIf = $global:WhatIfPreference
    try {
        $global:WhatIfPreference = $false
    $singBoxPath = Join-Path ([System.IO.Path]::GetFullPath($BundlePath)) 'sing-box.exe'
    $serverServicePath = Join-Path ([System.IO.Path]::GetFullPath($BundlePath)) $ServerServiceName
    $manifestPath = Join-Path ([System.IO.Path]::GetFullPath($BundlePath)) 'sing-box.manifest.json'
    if (-not (Test-Path -LiteralPath $singBoxPath -PathType Leaf)) {
        throw "Pinned sing-box executable not found: $singBoxPath"
    }
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Pinned sing-box runtime manifest not found: $manifestPath"
    }
    if (-not (Test-Path -LiteralPath $serverServicePath -PathType Leaf)) {
        throw "Pinned first-party server service host not found: $serverServicePath"
    }
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "Rendered server config not found: $ConfigPath"
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ([string] $manifest.version -ne '1.13.19') {
        throw "Pinned sing-box manifest version is not 1.13.19."
    }
    $actualSingBoxHash = (Get-FileHash -LiteralPath $singBoxPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $actualServerServiceHash = (Get-FileHash -LiteralPath $serverServicePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $actualConfigHash = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($actualSingBoxHash -ne $ExpectedSingBoxSha256.ToLowerInvariant()) {
        throw 'sing-box SHA-256 verification failed.'
    }
    if ($actualSingBoxHash -ne ([string] $manifest.executable_sha256).ToLowerInvariant()) {
        throw 'sing-box runtime manifest hash verification failed.'
    }
    if ($actualServerServiceHash -ne $ExpectedServerServiceSha256.ToLowerInvariant() -or
        $actualServerServiceHash -ne ([string] $manifest.server_service_sha256).ToLowerInvariant()) {
        throw 'First-party server service host SHA-256 verification failed.'
    }
    if ($actualConfigHash -ne $ExpectedConfigSha256.ToLowerInvariant()) {
        throw 'Server config SHA-256 verification failed.'
    }

    & $singBoxPath check -c $ConfigPath *> $null
    $nativeLaunchSucceeded = $?
    $nativeExitCode = $LASTEXITCODE
    if (-not $nativeLaunchSucceeded -or $nativeExitCode -ne 0) {
        throw "sing-box check failed (launch=$nativeLaunchSucceeded exit=$nativeExitCode)."
    }

    return [pscustomobject] @{
        SingBoxPath = $singBoxPath
        ServerServicePath = $serverServicePath
        ManifestPath = $manifestPath
        SingBoxSha256 = $actualSingBoxHash
        ServerServiceSha256 = $actualServerServiceHash
        ConfigSha256 = $actualConfigHash
    }
    }
    finally {
        $global:WhatIfPreference = $savedVerificationWhatIf
    }
}

function Get-TelecomConnectEvidence {
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {
        [int] $_.LocalPort -eq $TelecomProxyPort
    })
    if ($listeners.Count -ne 1) {
        throw "Expected exactly one telecom listener on TCP $TelecomProxyPort."
    }
    $listener = $listeners[0]
    if ([string] $listener.LocalAddress -notin @('127.0.0.1', '::1', '0.0.0.0', '::')) {
        throw "TCP $TelecomProxyPort listener address is unsupported: $($listener.LocalAddress)."
    }
    if ([int64] $listener.OwningProcess -le 0) {
        throw "TCP $TelecomProxyPort has no valid owning process."
    }

    $process = Get-Process -Id ([int] $listener.OwningProcess) -ErrorAction Stop
    if ($process.HasExited) {
        throw "The process owning TCP $TelecomProxyPort has exited."
    }

    $probe = Invoke-WebRequest `
        -Uri $ConnectProbeUri `
        -Proxy "http://${TelecomProxyAddress}:$TelecomProxyPort" `
        -Method Head `
        -TimeoutSec 15 `
        -UseBasicParsing `
        -ErrorAction Stop
    if ([int] $probe.StatusCode -lt 200 -or [int] $probe.StatusCode -ge 400) {
        throw "HTTP CONNECT probe through TCP $TelecomProxyPort failed with status $($probe.StatusCode)."
    }

    return [pscustomobject] @{
        Listener = [ordered] @{
            LocalAddress = [string] $listener.LocalAddress
            LocalPort = [int] $listener.LocalPort
            OwningProcess = [int] $listener.OwningProcess
        }
        Process = [ordered] @{
            Id = [int] $process.Id
            Name = [string] $process.ProcessName
            Path = [string] $process.Path
        }
        ConnectProbe = [ordered] @{
            Proxy = "${TelecomProxyAddress}:$TelecomProxyPort"
            Method = 'HTTPS_HEAD_via_CONNECT'
            StatusCode = [int] $probe.StatusCode
            Succeeded = $true
        }
    }
}

function Assert-ServerPortAvailable {
    $existingListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {
        [int] $_.LocalPort -eq $ServerPort
    })
    if ($existingListeners.Count -ne 0) {
        $owners = @($existingListeners | ForEach-Object { [string] $_.OwningProcess } | Sort-Object -Unique)
        throw "TCP $ServerPort already has a listener (owner PID(s): $($owners -join ','))."
    }
}

function Get-BaselineEvidence {
    param(
        [Parameter(Mandatory = $true)] $HostEvidence,
        [Parameter(Mandatory = $true)] $InputEvidence,
        [Parameter(Mandatory = $true)] $TelecomEvidence,
        [Parameter(Mandatory = $true)] [string] $TransactionId
    )

    $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
        [ordered] @{
            Name = [string] $_.Name
            State = [string] $_.State
            StartMode = [string] $_.StartMode
            ServicePathSha256 = Get-StringSha256 -Value ([string] $_.PathName)
        }
    })
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
        [ordered] @{
            LocalAddress = [string] $_.LocalAddress
            LocalPort = [int] $_.LocalPort
            OwningProcess = [int] $_.OwningProcess
        }
    })
    $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object {
        [ordered] @{
            DestinationPrefix = [string] $_.DestinationPrefix
            NextHop = [string] $_.NextHop
            InterfaceIndex = [int] $_.InterfaceIndex
            RouteMetric = [int] $_.RouteMetric
        }
    })
    $firewallRules = @(Get-NetFirewallRule -ErrorAction Stop | ForEach-Object {
        $rule = $_
        $portFilters = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue)
        $addressFilters = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue)
        [ordered] @{
            Name = [string] $rule.Name
            DisplayName = [string] $rule.DisplayName
            Direction = [string] $rule.Direction
            Action = [string] $rule.Action
            Enabled = [string] $rule.Enabled
            LocalPort = @($portFilters | ForEach-Object { [string] $_.LocalPort })
            RemoteAddress = @($addressFilters | ForEach-Object { [string] $_.RemoteAddress })
        }
    })

    return [ordered] @{
        SchemaVersion = 1
        Kind = 'RegenBioOverseasAccessServerBaseline'
        TransactionId = $TransactionId
        CapturedAtUtc = [datetime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
        ComputerName = $env:COMPUTERNAME
        ExpectedVmAddress = $ExpectedVmAddress
        Host = $HostEvidence
        Services = $services
        Listeners = $listeners
        Routes = $routes
        FirewallRules = $firewallRules
        Telecom8080Owner = $TelecomEvidence
        SingBoxSha256 = $InputEvidence.SingBoxSha256
        ServerServiceSha256 = $InputEvidence.ServerServiceSha256
        ConfigSha256 = $InputEvidence.ConfigSha256
        ConnectProbe = $TelecomEvidence.ConnectProbe
        BaselinePublished = $false
        OriginalOwnedResources = [ordered] @{
            ServicePresent = $false
            FirewallRulesPresent = @()
            InstallRootPresent = $false
            DataRootPresent = $false
        }
    }
}

function Protect-ServiceDataPath {
    param([Parameter(Mandatory = $true)] [string] $Path)

    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /t /c *> $null
    $nativeLaunchSucceeded = $?
    $nativeExitCode = $LASTEXITCODE
    if (-not $nativeLaunchSucceeded -or $nativeExitCode -ne 0) {
        throw "Failed to apply service-only ACLs (launch=$nativeLaunchSucceeded exit=$nativeExitCode)."
    }

    & icacls.exe $Path /setowner '*S-1-5-32-544' /t /c *> $null
    $nativeLaunchSucceeded = $?
    $nativeExitCode = $LASTEXITCODE
    if (-not $nativeLaunchSucceeded -or $nativeExitCode -ne 0) {
        throw "Failed to set the service path owner (launch=$nativeLaunchSucceeded exit=$nativeExitCode)."
    }
}

function Remove-OwnedFirewallRule {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [string] $TransactionId
    )

    $rules = @(Get-ExactFirewallRule -Name $Name)
    foreach ($rule in $rules) {
        $expectedDescription = $OwnershipPrefix + $TransactionId
        if ([string] $rule.Description -ne $expectedDescription) {
            throw "Refusing to remove unowned firewall rule $Name."
        }
        Remove-NetFirewallRule -Name $Name -Confirm:$false -ErrorAction Stop
    }
}

function Remove-OwnedService {
    param([Parameter(Mandatory = $true)] [string] $TransactionId)

    $expectedBinaryPath = '"' + (Join-Path $InstallRoot $ServerServiceName) + '"'
    $services = @(Get-ExactService)
    foreach ($service in $services) {
        $expectedDescription = $OwnershipPrefix + $TransactionId
        if ([string] $service.Description -ne $expectedDescription) {
            throw "Refusing to remove unowned service $ServiceName."
        }
        if ([string] $service.PathName -ne $expectedBinaryPath) {
            throw "Refusing to remove $ServiceName with an unexpected binary path."
        }
        if ([string] $service.State -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -Confirm:$false -ErrorAction Stop
        }
        $deleteResult = Invoke-CimMethod -InputObject $service -MethodName Delete -ErrorAction Stop
        if ($null -ne $deleteResult.ReturnValue -and [int] $deleteResult.ReturnValue -ne 0) {
            throw "Service deletion returned $($deleteResult.ReturnValue)."
        }
    }
}

function Remove-OwnedDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $TransactionId
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    $markerPath = Join-Path $Path $OwnerMarkerName
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
        if ([string] $marker.TransactionId -ne $TransactionId -or [string] $marker.Kind -ne 'RegenBioOverseasAccessServerOwner') {
            throw "Refusing to remove directory with an invalid owner marker: $Path"
        }
    }
    else {
        throw "Refusing to remove an unmarked directory: $Path"
    }
    Remove-Item -LiteralPath $Path -Recurse -Force -Confirm:$false -ErrorAction Stop
}

function Compensate-InstallTransaction {
    param(
        [Parameter(Mandatory = $true)] [string] $TransactionId,
        [Parameter(Mandatory = $true)] $Owned
    )

    $errors = New-Object System.Collections.Generic.List[string]

    foreach ($firewallName in @($FirewallBlockManagement, $FirewallAllowEmployee)) {
        if (@(Get-ExactFirewallRule -Name $firewallName).Count -ne 0) {
            try { Remove-OwnedFirewallRule -Name $firewallName -TransactionId $TransactionId } catch { $errors.Add($_.Exception.Message) }
        }
    }

    $serviceRemovalProven = $true
    if (@(Get-ExactService).Count -ne 0) {
        try {
            Remove-OwnedService -TransactionId $TransactionId
            $serviceRemovalProven = @(Get-ExactService).Count -eq 0
            if (-not $serviceRemovalProven) { $errors.Add("Service $ServiceName remains after compensation.") }
        }
        catch {
            $serviceRemovalProven = $false
            $errors.Add($_.Exception.Message)
        }
    }

    if ($serviceRemovalProven) {
        if ($Owned.DataRoot -or (Test-Path -LiteralPath $DataRoot)) {
            try { Remove-OwnedDirectory -Path $DataRoot -TransactionId $TransactionId } catch { $errors.Add($_.Exception.Message) }
        }
        if ($Owned.InstallRoot -or (Test-Path -LiteralPath $InstallRoot)) {
            try { Remove-OwnedDirectory -Path $InstallRoot -TransactionId $TransactionId } catch { $errors.Add($_.Exception.Message) }
        }
    }

    if ($errors.Count -ne 0) {
        throw ('Install compensation was incomplete: ' + ($errors -join '; '))
    }
}

function New-ManagementFirewallRule {
    param([Parameter(Mandatory = $true)] [string] $OwnershipDescription)

    New-NetFirewallRule `
        -Name $FirewallBlockManagement `
        -DisplayName 'RegenBio Overseas Access - block employee management access' `
        -Description $OwnershipDescription `
        -Direction Inbound `
        -Action Block `
        -Enabled True `
        -Profile Any `
        -Protocol TCP `
        -LocalPort $ManagementPorts `
        -RemoteAddress $ExpectedEmployeeCIDR `
        -Confirm:$false `
        -ErrorAction Stop | Out-Null
}

function Install-ServerTransaction {
    Assert-InstallInputs
    $hostEvidence = Assert-SupportedServerHost
    $inputEvidence = Get-VerifiedInputEvidence
    $telecomEvidence = Get-TelecomConnectEvidence
    Assert-ServerPortAvailable
    Assert-NoOwnedResourceCollision
    Assert-NoConflictingServerPortAllow

    $journalPath = Get-TransactionJournalPath -BaselinePath $EvidencePath
    if (Test-Path -LiteralPath $EvidencePath) {
        throw "Baseline evidence already exists: $EvidencePath"
    }
    if (Test-Path -LiteralPath $journalPath) {
        throw "Transaction journal already exists: $journalPath"
    }

    $transactionId = [guid]::NewGuid().ToString('D')
    $baseline = Get-BaselineEvidence `
        -HostEvidence $hostEvidence `
        -InputEvidence $inputEvidence `
        -TelecomEvidence $telecomEvidence `
        -TransactionId $transactionId

    if (-not $PSCmdlet.ShouldProcess(
        "$ExpectedVmAddress service=$ServiceName port=$ServerPort employee=$EmployeeCIDR",
        'Publish baseline evidence and install the transactional sing-box server'
    )) {
        Write-ServerJson -Value ([ordered] @{
            SchemaVersion = 1
            Mode = 'Install'
            WhatIf = $true
            MutationPerformed = $false
            TransactionId = $transactionId
            Baseline = $baseline
        })
        return
    }

    $owned = [pscustomobject] @{
        InstallRoot = $false
        DataRoot = $false
        Service = $false
        FirewallRules = New-Object System.Collections.Generic.List[string]
    }
    $stagedExecutable = $null
    $stagedServerService = $null
    $stagedConfig = $null
    $BaselinePublished = $false
    try {
        $baseline.BaselinePublished = $true
        Write-AtomicJson -Path $EvidencePath -Value $baseline
        $publishedBaseline = Get-Content -LiteralPath $EvidencePath -Raw | ConvertFrom-Json
        if ([string] $publishedBaseline.TransactionId -ne $transactionId) {
            throw 'Atomic baseline evidence verification failed.'
        }
        $BaselinePublished = $true

        $transactionRecord = [ordered] @{
            SchemaVersion = 1
            Kind = 'RegenBioOverseasAccessServerTransaction'
            State = 'WriteAhead'
            TransactionId = $transactionId
            CreatedAtUtc = [datetime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
            ServiceName = $ServiceName
            FirewallRules = @($FirewallNames)
            InstallRoot = $InstallRoot
            DataRoot = $DataRoot
            OwnerMarkerName = $OwnerMarkerName
            EvidencePath = [System.IO.Path]::GetFullPath($EvidencePath)
            EvidenceSha256 = (Get-FileHash -LiteralPath $EvidencePath -Algorithm SHA256).Hash.ToLowerInvariant()
            SingBoxSha256 = $inputEvidence.SingBoxSha256
            ServerServiceSha256 = $inputEvidence.ServerServiceSha256
            ConfigSha256 = $inputEvidence.ConfigSha256
            EmployeeCIDR = $EmployeeCIDR
            ServerPort = $ServerPort
            OriginalOwnedResources = $baseline.OriginalOwnedResources
        }
        Write-AtomicJson -Path $journalPath -Value $transactionRecord

        New-Item -ItemType Directory -Path $InstallRoot -ErrorAction Stop -Confirm:$false | Out-Null
        $owned.InstallRoot = $true
        Write-AtomicJson -Path (Join-Path $InstallRoot $OwnerMarkerName) -Value ([ordered] @{
            Kind = 'RegenBioOverseasAccessServerOwner'
            TransactionId = $transactionId
        })
        New-Item -ItemType Directory -Path $DataRoot -ErrorAction Stop -Confirm:$false | Out-Null
        $owned.DataRoot = $true

        Protect-ServiceDataPath -Path $InstallRoot
        Protect-ServiceDataPath -Path $DataRoot
        Write-AtomicJson -Path (Join-Path $DataRoot $OwnerMarkerName) -Value ([ordered] @{
            Kind = 'RegenBioOverseasAccessServerOwner'
            TransactionId = $transactionId
        })

        $installedExecutable = Join-Path $InstallRoot 'sing-box.exe'
        $installedServerService = Join-Path $InstallRoot $ServerServiceName
        $installedConfig = Join-Path $DataRoot 'config.json'
        $installedRuntimeManifest = Join-Path $DataRoot $RuntimeManifestName
        $stagedExecutable = $installedExecutable + '.stage.' + $transactionId
        $stagedServerService = $installedServerService + '.stage.' + $transactionId
        $stagedConfig = $installedConfig + '.stage.' + $transactionId
        Copy-Item -LiteralPath $inputEvidence.SingBoxPath -Destination $stagedExecutable -ErrorAction Stop -Confirm:$false
        Move-Item -LiteralPath $stagedExecutable -Destination $installedExecutable -Confirm:$false
        $stagedExecutable = $null
        Copy-Item -LiteralPath $inputEvidence.ServerServicePath -Destination $stagedServerService -ErrorAction Stop -Confirm:$false
        Move-Item -LiteralPath $stagedServerService -Destination $installedServerService -Confirm:$false
        $stagedServerService = $null

        Copy-Item -LiteralPath $ConfigPath -Destination $stagedConfig -ErrorAction Stop -Confirm:$false
        Move-Item -LiteralPath $stagedConfig -Destination $installedConfig -Confirm:$false
        $stagedConfig = $null

        Write-AtomicJson -Path $installedRuntimeManifest -Value ([ordered] @{
            schema_version = 1
            kind = 'RegenBioOverseasAccessServerRuntime'
            sing_box_sha256 = $inputEvidence.SingBoxSha256
            signer_allowlist = @()
        })

        $InstalledSingBoxSha256 = (Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $InstalledServerServiceSha256 = (Get-FileHash -LiteralPath $installedServerService -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $InstalledConfigSha256 = (Get-FileHash -LiteralPath $installedConfig -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($InstalledSingBoxSha256 -ne $inputEvidence.SingBoxSha256 -or
            $InstalledServerServiceSha256 -ne $inputEvidence.ServerServiceSha256 -or
            $InstalledConfigSha256 -ne $inputEvidence.ConfigSha256) {
            throw 'Installed service host, sing-box, or config hash does not match the verified source.'
        }

        $ownershipDescription = $OwnershipPrefix + $transactionId
        $binaryPath = '"' + $installedServerService + '"'
        New-Service `
            -Name $ServiceName `
            -BinaryPathName $binaryPath `
            -DisplayName 'RegenBio Overseas Access Server' `
            -Description $ownershipDescription `
            -StartupType Automatic `
            -Confirm:$false `
            -ErrorAction Stop | Out-Null
        $owned.Service = $true

        New-NetFirewallRule `
            -Name $FirewallAllowEmployee `
            -DisplayName 'RegenBio Overseas Access - allow approved employees' `
            -Description $ownershipDescription `
            -Direction Inbound `
            -Action Allow `
            -Enabled True `
            -Profile Any `
            -Protocol TCP `
            -LocalPort $ServerPort `
            -RemoteAddress $EmployeeCIDR `
            -Program $installedExecutable `
            -Confirm:$false `
            -ErrorAction Stop | Out-Null
        $owned.FirewallRules.Add($FirewallAllowEmployee)

        New-ManagementFirewallRule -OwnershipDescription $ownershipDescription
        $owned.FirewallRules.Add($FirewallBlockManagement)

        Start-Service -Name $ServiceName -Confirm:$false -ErrorAction Stop

        Write-ServerJson -Value ([ordered] @{
            SchemaVersion = 1
            Mode = 'Install'
            Status = 'Installed'
            WhatIf = $false
            MutationPerformed = $true
            TransactionId = $transactionId
            BaselinePublished = $BaselinePublished
            EvidencePath = [System.IO.Path]::GetFullPath($EvidencePath)
        })
    }
    catch {
        $installFailure = $_
        try {
            Compensate-InstallTransaction -TransactionId $transactionId -Owned $owned
        }
        catch {
            throw "Install failed: $($installFailure.Exception.Message). Critical compensation failure: $($_.Exception.Message)"
        }
        throw "Install failed and was compensated: $($installFailure.Exception.Message)"
    }
    finally {
        foreach ($stagedPath in @($stagedConfig, $stagedServerService, $stagedExecutable)) {
            if (-not [string]::IsNullOrWhiteSpace([string] $stagedPath) -and (Test-Path -LiteralPath $stagedPath)) {
                Remove-Item -LiteralPath $stagedPath -Force -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-ServerStatus {
    $service = @(Get-ExactService)
    $firewall = @()
    foreach ($name in $FirewallNames) {
        $firewall += @(Get-ExactFirewallRule -Name $name | ForEach-Object {
            [ordered] @{
                Name = [string] $_.Name
                Enabled = [string] $_.Enabled
                Direction = [string] $_.Direction
                Action = [string] $_.Action
                Description = [string] $_.Description
            }
        })
    }

    $journalPresent = $false
    if ($InvocationParameters.ContainsKey('EvidencePath') -and -not [string]::IsNullOrWhiteSpace($EvidencePath)) {
        $journalPresent = Test-Path -LiteralPath (Get-TransactionJournalPath -BaselinePath $EvidencePath) -PathType Leaf
    }

    Write-ServerJson -Value ([ordered] @{
        SchemaVersion = 1
        Mode = 'Status'
        MutationPerformed = $false
        ServiceName = $ServiceName
        Service = @($service | ForEach-Object {
            [ordered] @{ Name = [string] $_.Name; State = [string] $_.State; PathName = [string] $_.PathName; Description = [string] $_.Description }
        })
        FirewallRules = $firewall
        InstallRootPresent = Test-Path -LiteralPath $InstallRoot -PathType Container
        DataRootPresent = Test-Path -LiteralPath $DataRoot -PathType Container
        TransactionPresent = $journalPresent
    })
}

function Rollback-ServerTransaction {
    Assert-RollbackInputs
    if (-not (Test-ServerAdministrator)) {
        throw 'Server rollback requires an elevated Administrator token.'
    }
    if (-not (Test-Path -LiteralPath $EvidencePath -PathType Leaf)) {
        throw "Baseline evidence does not exist: $EvidencePath"
    }

    $baseline = Get-Content -LiteralPath $EvidencePath -Raw | ConvertFrom-Json
    $parsedId = [guid]::Empty
    if ([string] $baseline.Kind -ne 'RegenBioOverseasAccessServerBaseline' -or
        -not [guid]::TryParse([string] $baseline.TransactionId, [ref] $parsedId)) {
        throw 'Baseline evidence is invalid.'
    }

    $transactionId = $parsedId.ToString('D')
    $journalPath = Get-TransactionJournalPath -BaselinePath $EvidencePath
    $journalPresent = Test-Path -LiteralPath $journalPath -PathType Leaf
    $ownedResourcesPresent = @(Get-ExactService).Count -ne 0 -or
        @($FirewallNames | Where-Object { @(Get-ExactFirewallRule -Name $_).Count -ne 0 }).Count -ne 0 -or
        (Test-Path -LiteralPath $InstallRoot) -or (Test-Path -LiteralPath $DataRoot)

    if (-not $journalPresent) {
        if ($ownedResourcesPresent) {
            throw 'Transaction journal is missing while candidate owned resources remain; refusing unsafe rollback.'
        }
        Write-ServerJson -Value ([ordered] @{
            SchemaVersion = 1
            Mode = 'Rollback'
            Status = 'AlreadyRolledBack'
            WhatIf = [bool] $WhatIfPreference
            MutationPerformed = $false
            TransactionId = $transactionId
            OriginalOwnedResourcesRestored = $true
        })
        return
    }

    $transaction = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
    $journalId = [guid]::Empty
    if ([string] $transaction.Kind -ne 'RegenBioOverseasAccessServerTransaction' -or
        -not [guid]::TryParse([string] $transaction.TransactionId, [ref] $journalId) -or
        $journalId.ToString('D') -ne $transactionId) {
        throw 'Transaction journal is invalid or does not match baseline evidence.'
    }
    $actualEvidenceHash = (Get-FileHash -LiteralPath $EvidencePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($actualEvidenceHash -ne ([string] $transaction.EvidenceSha256).ToLowerInvariant()) {
        throw 'Baseline evidence hash no longer matches the transaction journal.'
    }
    if ([string] $transaction.ServiceName -ne $ServiceName -or
        [string] $transaction.InstallRoot -ne $InstallRoot -or
        [string] $transaction.DataRoot -ne $DataRoot) {
        throw 'Transaction record targets do not match the fixed server resources.'
    }
    if (@($transaction.FirewallRules).Count -ne $FirewallNames.Count -or
        @($transaction.FirewallRules | Where-Object { $FirewallNames -notcontains [string] $_ }).Count -ne 0) {
        throw 'Transaction firewall ownership set is invalid.'
    }

    if (-not $PSCmdlet.ShouldProcess(
        "$ExpectedVmAddress transaction=$transactionId",
        'Remove only transaction-owned server resources and restore the captured absent originals'
    )) {
        Write-ServerJson -Value ([ordered] @{
            SchemaVersion = 1
            Mode = 'Rollback'
            WhatIf = $true
            MutationPerformed = $false
            TransactionId = $transactionId
        })
        return
    }

    foreach ($firewallName in @($FirewallBlockManagement, $FirewallAllowEmployee)) {
        Remove-OwnedFirewallRule -Name $firewallName -TransactionId $transactionId
    }
    Remove-OwnedService -TransactionId $transactionId

    if (@(Get-ExactService).Count -ne 0) {
        throw "Rollback could not prove removal of $ServiceName."
    }
    foreach ($firewallName in $FirewallNames) {
        if (@(Get-ExactFirewallRule -Name $firewallName).Count -ne 0) {
            throw "Rollback could not prove removal of $firewallName."
        }
    }

    Remove-OwnedDirectory -Path $DataRoot -TransactionId $transactionId
    Remove-OwnedDirectory -Path $InstallRoot -TransactionId $transactionId
    if ((Test-Path -LiteralPath $DataRoot) -or (Test-Path -LiteralPath $InstallRoot)) {
        throw 'Rollback could not prove removal of transaction-owned directories.'
    }

    Remove-Item -LiteralPath $journalPath -Force -Confirm:$false -ErrorAction Stop

    Write-ServerJson -Value ([ordered] @{
        SchemaVersion = 1
        Mode = 'Rollback'
        Status = 'RolledBack'
        WhatIf = $false
        MutationPerformed = $true
        TransactionId = $transactionId
        OriginalOwnedResourcesRestored = $true
    })
}

switch ($Mode) {
    'Install' { Install-ServerTransaction; break }
    'Status' { Get-ServerStatus; break }
    'Rollback' { Rollback-ServerTransaction; break }
    default { throw "Unsupported mode: $Mode" }
}
