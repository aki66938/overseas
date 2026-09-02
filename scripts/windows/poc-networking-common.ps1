Set-StrictMode -Version Latest

function Get-PocSha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]] $Bytes
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function ConvertTo-PocIPv4Prefix {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Prefix,

        [switch] $RequireNetworkAddress
    )

    $parts = $Prefix.Split('/')
    $address = $null
    $prefixLength = 0
    if (
        $parts.Count -ne 2 -or
        -not [System.Net.IPAddress]::TryParse($parts[0], [ref] $address) -or
        $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        -not [int]::TryParse($parts[1], [ref] $prefixLength) -or
        $prefixLength -lt 0 -or
        $prefixLength -gt 32
    ) {
        throw "Invalid IPv4 CIDR prefix: '$Prefix'."
    }

    $bytes = $address.GetAddressBytes()
    $value =
        ([uint64] $bytes[0] * 16777216) +
        ([uint64] $bytes[1] * 65536) +
        ([uint64] $bytes[2] * 256) +
        [uint64] $bytes[3]
    $size = [uint64] [math]::Pow(2, 32 - $prefixLength)
    $start = [uint64] ([math]::Floor($value / $size) * $size)
    $end = $start + $size - 1
    if ($RequireNetworkAddress -and $value -ne $start) {
        throw "CIDR prefix must use its network address: '$Prefix'."
    }

    return [pscustomobject] @{
        Text = $Prefix
        Start = $start
        End = $end
        PrefixLength = $prefixLength
    }
}

function Test-PocPrefixOverlap {
    param(
        [Parameter(Mandatory = $true)] $First,
        [Parameter(Mandatory = $true)] $Second
    )

    return [uint64] $First.Start -le [uint64] $Second.End -and [uint64] $Second.Start -le [uint64] $First.End
}

function Read-PocSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [ValidateRange(1, 1440)]
        [int] $MaximumAgeMinutes = 240,

        [switch] $SkipAgeValidation
    )

    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        throw 'SnapshotPath must be an absolute path.'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Snapshot does not exist: $Path"
    }

    try {
        $envelope = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Snapshot is not valid JSON: $($_.Exception.Message)"
    }

    foreach ($property in @('SchemaVersion', 'IntegrityAlgorithm', 'PayloadBase64', 'PayloadSha256')) {
        if ($null -eq $envelope.PSObject.Properties[$property]) {
            throw "Snapshot is missing envelope property '$property'."
        }
    }
    if ([int] $envelope.SchemaVersion -ne 2 -or $envelope.IntegrityAlgorithm -ne 'SHA256') {
        throw 'Snapshot uses an unsupported schema or integrity algorithm.'
    }

    try {
        $payloadBytes = [Convert]::FromBase64String([string] $envelope.PayloadBase64)
    }
    catch {
        throw 'Snapshot integrity payload is not valid base64.'
    }
    $actualHash = Get-PocSha256Hex -Bytes $payloadBytes
    if ($actualHash -cne [string] $envelope.PayloadSha256) {
        throw 'Snapshot integrity check failed.'
    }

    try {
        $payload = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Snapshot integrity payload is not valid JSON: $($_.Exception.Message)"
    }

    foreach ($property in @(
        'SnapshotId', 'CapturedAtUtc', 'ComputerName', 'RequiredInterfaces',
        'NetIPInterfaces', 'Routes', 'Nat', 'FirewallRules',
        'FirewallAddressFilters', 'Adapters'
    )) {
        if ($null -eq $payload.PSObject.Properties[$property]) {
            throw "Snapshot payload is missing required property '$property'."
        }
    }

    $snapshotId = [guid]::Empty
    if (-not [guid]::TryParse([string] $payload.SnapshotId, [ref] $snapshotId) -or $snapshotId -eq [guid]::Empty) {
        throw 'SnapshotId must be a non-empty GUID.'
    }
    $capturedAt = [datetime]::MinValue
    if (-not [datetime]::TryParseExact(
        [string] $payload.CapturedAtUtc,
        "yyyyMMdd'T'HHmmss.fffffff'Z'",
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal,
        [ref] $capturedAt
    )) {
        throw 'Snapshot CapturedAtUtc is invalid.'
    }
    $capturedAt = $capturedAt.ToUniversalTime()
    $now = [datetime]::UtcNow
    if ($capturedAt -gt $now.AddMinutes(5)) {
        throw 'Snapshot capture time is unreasonably far in the future.'
    }
    $snapshotAgeMinutes = ($now - $capturedAt).TotalMinutes
    if (-not $SkipAgeValidation -and $snapshotAgeMinutes -gt $MaximumAgeMinutes) {
        throw "Snapshot is stale (captured $($capturedAt.ToString('o')), now $($now.ToString('o')), age $([math]::Round($snapshotAgeMinutes, 1)) minutes); maximum age is $MaximumAgeMinutes minutes."
    }
    if ($payload.ComputerName -cne $env:COMPUTERNAME) {
        throw "Snapshot belongs to computer '$($payload.ComputerName)', not '$env:COMPUTERNAME'."
    }

    $roles = @('WireGuard', 'Telecom', 'Employee')
    $indexes = @()
    foreach ($role in $roles) {
        $entries = @($payload.RequiredInterfaces | Where-Object { $_.Role -ceq $role })
        if ($entries.Count -ne 1) {
            throw "Snapshot must contain exactly one required interface for role '$role'."
        }
        $entry = $entries[0]
        if ([string]::IsNullOrWhiteSpace([string] $entry.Alias) -or [int] $entry.InterfaceIndex -le 0) {
            throw "Snapshot required interface '$role' has an invalid alias or index."
        }
        if ($entry.AddressFamily -ne 'IPv4' -or $entry.Forwarding -notin @('Enabled', 'Disabled')) {
            throw "Snapshot required interface '$role' has invalid IPv4 forwarding state."
        }
        $indexes += [int] $entry.InterfaceIndex

        $inventoryMatches = @($payload.NetIPInterfaces | Where-Object {
            [int] $_.InterfaceIndex -eq [int] $entry.InterfaceIndex -and
            $_.AddressFamily.ToString() -eq 'IPv4'
        })
        if ($inventoryMatches.Count -ne 1) {
            throw "Snapshot inventory lacks exactly one IPv4 entry for interface index $($entry.InterfaceIndex)."
        }
    }
    if (@($indexes | Select-Object -Unique).Count -ne 3) {
        throw 'Snapshot required interface indices must be distinct.'
    }

    return $payload
}

function Get-PocRequiredInterface {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] [string] $Role
    )

    return @($Snapshot.RequiredInterfaces | Where-Object { $_.Role -ceq $Role })[0]
}

function Assert-PocAdaptersMatchSnapshot {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] [hashtable] $AdaptersByRole,
        [switch] $RequireBaselineForwarding
    )

    $indexes = @()
    foreach ($role in @('WireGuard', 'Telecom', 'Employee')) {
        $entry = Get-PocRequiredInterface -Snapshot $Snapshot -Role $role
        $adapter = $AdaptersByRole[$role]
        if ($null -eq $adapter -or $adapter.Name -cne $entry.Alias -or [int] $adapter.ifIndex -ne [int] $entry.InterfaceIndex) {
            throw "Current adapter for role '$role' does not match the snapshot alias and index."
        }
        $indexes += [int] $adapter.ifIndex

        $indexAdapter = Get-NetAdapter -InterfaceIndex ([int] $entry.InterfaceIndex) -ErrorAction Stop
        if ($indexAdapter.Name -cne $entry.Alias) {
            throw "Current adapter at interface index $($entry.InterfaceIndex) does not match the snapshot."
        }

        if ($RequireBaselineForwarding) {
            $current = @(Get-NetIPInterface -InterfaceIndex ([int] $entry.InterfaceIndex) -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
            if ($current.Count -ne 1 -or $current[0].Forwarding.ToString() -ne $entry.Forwarding) {
                throw "Current forwarding state for role '$role' no longer matches the snapshot baseline."
            }
        }
    }
    if (@($indexes | Select-Object -Unique).Count -ne 3) {
        throw 'WireGuard, telecom, and employee interfaces must resolve to distinct canonical indices.'
    }
}

function Get-PocSoleEmployeeDefaultRoute {
    param(
        [Parameter(Mandatory = $true)] [int] $EmployeeInterfaceIndex,
        [Parameter(Mandatory = $true)] [string] $EmployeeInterfaceAlias,
        [Parameter(Mandatory = $true)] [object[]] $Routes
    )

    $defaultRoutes = @($Routes | Where-Object {
        $_.DestinationPrefix.ToString() -eq '0.0.0.0/0' -and
        ($null -eq $_.PSObject.Properties['State'] -or $_.State.ToString() -eq 'Alive')
    })
    if ($defaultRoutes.Count -ne 1) {
        throw 'The employee interface must own the sole active IPv4 default route.'
    }
    $route = $defaultRoutes[0]
    if ([int] $route.InterfaceIndex -ne $EmployeeInterfaceIndex -or $route.InterfaceAlias -cne $EmployeeInterfaceAlias) {
        throw 'The employee interface must own the sole active IPv4 default route.'
    }
    return $route
}

function Assert-PocDefaultRouteMatchesSnapshot {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] $CurrentDefaultRoute
    )

    $snapshotDefaults = @($Snapshot.Routes | Where-Object {
        $_.DestinationPrefix.ToString() -eq '0.0.0.0/0' -and
        ($null -eq $_.PSObject.Properties['State'] -or $_.State.ToString() -eq 'Alive')
    })
    if ($snapshotDefaults.Count -ne 1) {
        throw 'Snapshot does not contain exactly one active IPv4 default route.'
    }
    $saved = $snapshotDefaults[0]
    if (
        [int] $saved.InterfaceIndex -ne [int] $CurrentDefaultRoute.InterfaceIndex -or
        $saved.InterfaceAlias -cne $CurrentDefaultRoute.InterfaceAlias -or
        $saved.NextHop.ToString() -cne $CurrentDefaultRoute.NextHop.ToString()
    ) {
        throw 'Current default route no longer matches the snapshot baseline.'
    }
}

function Assert-PocWireGuardSubnetAvailable {
    param(
        [Parameter(Mandatory = $true)] [string] $WireGuardSubnet,
        [Parameter(Mandatory = $true)] [string[]] $InternalCidrs,
        [Parameter(Mandatory = $true)] [int] $WireGuardInterfaceIndex,
        [Parameter(Mandatory = $true)] [object[]] $IPAddresses,
        [Parameter(Mandatory = $true)] [object[]] $Routes
    )

    $wireGuard = ConvertTo-PocIPv4Prefix -Prefix $WireGuardSubnet -RequireNetworkAddress
    if ($wireGuard.PrefixLength -lt 1) {
        throw 'WireGuardSubnet must be narrower than the IPv4 default route.'
    }
    if ($InternalCidrs.Count -eq 0) {
        throw 'InternalCidrs must contain at least one IPv4 CIDR.'
    }
    foreach ($cidr in $InternalCidrs) {
        $internal = ConvertTo-PocIPv4Prefix -Prefix $cidr -RequireNetworkAddress
        if (Test-PocPrefixOverlap -First $wireGuard -Second $internal) {
            throw "WireGuardSubnet overlaps configured internal CIDR '$cidr'."
        }
    }

    $cgnat = ConvertTo-PocIPv4Prefix -Prefix '100.64.0.0/10' -RequireNetworkAddress
    $wireGuardUsesCgnat = Test-PocPrefixOverlap -First $wireGuard -Second $cgnat
    foreach ($ip in $IPAddresses) {
        if ($ip.AddressFamily.ToString() -ne 'IPv4') { continue }
        $current = ConvertTo-PocIPv4Prefix -Prefix ("{0}/{1}" -f $ip.IPAddress, $ip.PrefixLength)
        $isExpectedWireGuardAddress =
            [int] $ip.InterfaceIndex -eq $WireGuardInterfaceIndex -and
            $current.Start -eq $wireGuard.Start -and
            $current.End -eq $wireGuard.End
        if (-not $isExpectedWireGuardAddress -and (Test-PocPrefixOverlap -First $wireGuard -Second $current)) {
            throw "WireGuardSubnet overlaps a current address on interface index $($ip.InterfaceIndex)."
        }
        if (
            $wireGuardUsesCgnat -and
            [int] $ip.InterfaceIndex -ne $WireGuardInterfaceIndex -and
            (Test-PocPrefixOverlap -First $cgnat -Second $current)
        ) {
            throw "WireGuardSubnet uses CGNAT space while current CGNAT use exists on interface index $($ip.InterfaceIndex)."
        }
    }

    foreach ($route in $Routes) {
        if ($route.DestinationPrefix.ToString() -eq '0.0.0.0/0') { continue }
        try {
            $current = ConvertTo-PocIPv4Prefix -Prefix $route.DestinationPrefix.ToString()
        }
        catch {
            continue
        }
        $isExpectedWireGuardRoute =
            [int] $route.InterfaceIndex -eq $WireGuardInterfaceIndex -and
            $current.Start -eq $wireGuard.Start -and
            $current.End -eq $wireGuard.End
        if (-not $isExpectedWireGuardRoute -and (Test-PocPrefixOverlap -First $wireGuard -Second $current)) {
            throw "WireGuardSubnet overlaps a current route on interface index $($route.InterfaceIndex)."
        }
        if (
            $wireGuardUsesCgnat -and
            [int] $route.InterfaceIndex -ne $WireGuardInterfaceIndex -and
            (Test-PocPrefixOverlap -First $cgnat -Second $current)
        ) {
            throw "WireGuardSubnet uses CGNAT space while a current route uses CGNAT space."
        }
    }
}

function Get-PocFirewallDefinitions {
    param(
        [Parameter(Mandatory = $true)] [string] $WireGuardInterface,
        [Parameter(Mandatory = $true)] [string] $TelecomInterface,
        [Parameter(Mandatory = $true)] [string] $EmployeeInterface,
        [Parameter(Mandatory = $true)] [string] $WireGuardSubnet
    )

    return @(
        [pscustomobject] @{
            Name = 'OverseasPocBlockEmployeeInternet'
            DisplayName = 'Overseas Gateway PoC - Block employee public internet'
            Direction = 'Outbound'
            Action = 'Block'
            InterfaceAlias = $EmployeeInterface
            RemoteAddress = 'Internet'
        }
        [pscustomobject] @{
            Name = 'OverseasPocAllowWireGuardIngress'
            DisplayName = 'Overseas Gateway PoC - Allow WireGuard ingress'
            Direction = 'Inbound'
            Action = 'Allow'
            InterfaceAlias = $WireGuardInterface
            RemoteAddress = $WireGuardSubnet
        }
        [pscustomobject] @{
            Name = 'OverseasPocAllowTelecomInternet'
            DisplayName = 'Overseas Gateway PoC - Allow telecom public internet'
            Direction = 'Outbound'
            Action = 'Allow'
            InterfaceAlias = $TelecomInterface
            RemoteAddress = 'Internet'
        }
    )
}

function Get-PocFirewallRuleName {
    param([Parameter(Mandatory = $true)] $Rule)

    if ($null -ne $Rule.PSObject.Properties['Name'] -and -not [string]::IsNullOrWhiteSpace([string] $Rule.Name)) {
        return [string] $Rule.Name
    }
    return [string] $Rule.InstanceID
}

function Get-PocFirewallRuleGroup {
    param([Parameter(Mandatory = $true)] $Rule)

    if ($null -ne $Rule.PSObject.Properties['Group'] -and -not [string]::IsNullOrWhiteSpace([string] $Rule.Group)) {
        return [string] $Rule.Group
    }
    return [string] $Rule.RuleGroup
}

function Get-PocFirewallRuleProfile {
    param([Parameter(Mandatory = $true)] $Rule)

    if ($null -ne $Rule.PSObject.Properties['Profile']) {
        return @($Rule.Profile)
    }
    if ($null -ne $Rule.PSObject.Properties['Profiles']) {
        return @($Rule.Profiles)
    }
    return @()
}

function Assert-PocFirewallRuleMatchesDefinition {
    param(
        [Parameter(Mandatory = $true)] $Rule,
        [Parameter(Mandatory = $true)] $Definition,
        [Parameter(Mandatory = $true)] [string] $Description,
        [Parameter(Mandatory = $true)] [string] $StoreLabel
    )

    $directionValues = if ($Definition.Direction -eq 'Inbound') { @('Inbound', '1') } else { @('Outbound', '2') }
    $actionValues = if ($Definition.Action -eq 'Allow') { @('Allow', '2') } else { @('Block', '4') }
    $profiles = @(Get-PocFirewallRuleProfile -Rule $Rule | ForEach-Object { $_.ToString() })
    $profileIsAny = $profiles.Count -eq 1 -and $profiles[0] -in @('Any', '0')
    if (
        (Get-PocFirewallRuleGroup -Rule $Rule) -cne 'Overseas Gateway PoC' -or
        $directionValues -notcontains $Rule.Direction.ToString() -or
        $actionValues -notcontains $Rule.Action.ToString() -or
        @('True', '1') -notcontains $Rule.Enabled.ToString() -or
        -not $profileIsAny -or
        $Rule.Description -cne $Description
    ) {
        throw "Firewall rule '$($Definition.Name)' has unexpected settings, ownership, or profile in $StoreLabel."
    }

    $addressFilters = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $remoteAddresses = @($addressFilters | ForEach-Object { @($_.RemoteAddress) })
    if ($remoteAddresses.Count -ne 1 -or $remoteAddresses[0].ToString() -cne $Definition.RemoteAddress) {
        throw "Firewall rule '$($Definition.Name)' has an unexpected remote scope in $StoreLabel."
    }
    $interfaceFilters = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $interfaces = @($interfaceFilters | ForEach-Object { @($_.InterfaceAlias) })
    if ($interfaces.Count -ne 1 -or $interfaces[0].ToString() -cne $Definition.InterfaceAlias) {
        throw "Firewall rule '$($Definition.Name)' has an unexpected interface in $StoreLabel (got '$($interfaces -join ',')', expected '$($Definition.InterfaceAlias)')."
    }
}

function Assert-PocFirewallRulesActive {
    param(
        [Parameter(Mandatory = $true)] [object[]] $Definitions,
        [Parameter(Mandatory = $true)] [string] $Description,
        [switch] $AllowMissing
    )

    $activeRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group 'Overseas Gateway PoC' -ErrorAction Stop)
    foreach ($definition in $Definitions) {
        $matches = @($activeRules | Where-Object { (Get-PocFirewallRuleName -Rule $_) -ceq $definition.Name })
        if ($matches.Count -eq 0 -and $AllowMissing) {
            continue
        }
        if ($matches.Count -ne 1) {
            throw "Firewall rule '$($definition.Name)' is not effective in ActiveStore; local policy may be inactive."
        }
        Assert-PocFirewallRuleMatchesDefinition `
            -Rule $matches[0] `
            -Definition $definition `
            -Description $Description `
            -StoreLabel 'ActiveStore'
    }
}
