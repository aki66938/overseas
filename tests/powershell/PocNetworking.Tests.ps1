$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptRoot = Join-Path $repoRoot 'scripts\windows'
$snapshotScript = Join-Path $scriptRoot 'snapshot.ps1'
$applyScript = Join-Path $scriptRoot 'apply-poc.ps1'
$rollbackScript = Join-Path $scriptRoot 'rollback-poc.ps1'

function ConvertTo-TestSnapshotEnvelope {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [string] $SnapshotId = '11111111-2222-4333-8444-555555555555',

        [int] $AgeHours = 0
    )

    $payload = [ordered] @{
        SnapshotId = $SnapshotId
        CapturedAtUtc = [datetime]::UtcNow.AddHours($(if ($PSBoundParameters.ContainsKey('AgeHours')) { -$AgeHours } else { 0 })).ToString("yyyyMMdd'T'HHmmss.fffffff'Z'")
        ComputerName = $env:COMPUTERNAME
        RequiredInterfaces = @(
            [ordered] @{ Role = 'WireGuard'; Alias = 'wg-overseas-poc'; InterfaceIndex = 19; AddressFamily = 'IPv4'; Forwarding = 'Disabled' }
            [ordered] @{ Role = 'Telecom'; Alias = 'Telecom-Client'; InterfaceIndex = 11; AddressFamily = 'IPv4'; Forwarding = 'Disabled' }
            [ordered] @{ Role = 'Employee'; Alias = 'Ethernet'; InterfaceIndex = 7; AddressFamily = 'IPv4'; Forwarding = 'Disabled' }
        )
        NetIPInterfaces = @(
            [ordered] @{ InterfaceAlias = 'Ethernet'; InterfaceIndex = 7; AddressFamily = 'IPv4'; Forwarding = 'Disabled' }
            [ordered] @{ InterfaceAlias = 'Telecom-Client'; InterfaceIndex = 11; AddressFamily = 'IPv4'; Forwarding = 'Disabled' }
            [ordered] @{ InterfaceAlias = 'wg-overseas-poc'; InterfaceIndex = 19; AddressFamily = 'IPv4'; Forwarding = 'Disabled' }
        )
        Routes = @(
            [ordered] @{ InterfaceAlias = 'Ethernet'; InterfaceIndex = 7; DestinationPrefix = '0.0.0.0/0'; NextHop = '172.20.10.1'; State = 'Alive' }
            [ordered] @{ InterfaceAlias = 'Ethernet'; InterfaceIndex = 7; DestinationPrefix = '10.0.0.0/8'; NextHop = '172.20.10.1'; State = 'Alive' }
            [ordered] @{ InterfaceAlias = 'wg-overseas-poc'; InterfaceIndex = 19; DestinationPrefix = '100.127.77.0/24'; NextHop = '0.0.0.0'; State = 'Alive' }
        )
        Nat = @()
        FirewallRules = @()
        FirewallAddressFilters = @()
        Adapters = @(
            [ordered] @{ Name = 'Ethernet'; ifIndex = 7; Status = 'Up' }
            [ordered] @{ Name = 'Telecom-Client'; ifIndex = 11; Status = 'Up' }
            [ordered] @{ Name = 'wg-overseas-poc'; ifIndex = 19; Status = 'Up' }
        )
    }

    $payloadJson = $payload | ConvertTo-Json -Compress -Depth 20
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = ([System.BitConverter]::ToString($sha256.ComputeHash($payloadBytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }

    $envelope = [ordered] @{
        SchemaVersion = 2
        IntegrityAlgorithm = 'SHA256'
        PayloadBase64 = [Convert]::ToBase64String($payloadBytes)
        PayloadSha256 = $hash
    }
    [System.IO.File]::WriteAllText(
        $Path,
        ($envelope | ConvertTo-Json -Depth 5),
        (New-Object System.Text.UTF8Encoding($false))
    )

    return [pscustomobject] @{ Path = $Path; SnapshotId = $SnapshotId }
}

function New-TestAdapter {
    param([string] $Name, [int] $Index)
    return [pscustomobject] @{ Name = $Name; ifIndex = $Index; InterfaceIndex = $Index; Status = 'Up' }
}

function Get-TestFailureMessage {
    param([Parameter(Mandatory = $true)][scriptblock] $Action)

    try {
        & $Action
    }
    catch {
        return $_.Exception.Message
    }
    return ''
}

function New-TestFirewallCimRule {
    param(
        [string] $RuleName,
        [string] $RuleDisplayName,
        [string] $RuleGroup,
        [string] $RuleDirection,
        [string] $RuleAction,
        [string] $RuleDescription
    )

    return New-CimInstance `
        -ClassName MSFT_NetFirewallRule `
        -Namespace root/standardcimv2 `
        -ClientOnly `
        -Property @{
            InstanceID = $RuleName
            ElementName = $RuleDisplayName
            RuleGroup = $RuleGroup
            Direction = $(if ($RuleDirection -eq 'Inbound') { 1 } else { 2 })
            Action = $(if ($RuleAction -eq 'Allow') { 2 } else { 4 })
            Enabled = 1
            Description = $RuleDescription
        }
}

function New-TestIPInterface {
    param([string] $Alias, [int] $Index, [string] $Forwarding = 'Disabled')
    return [pscustomobject] @{
        InterfaceAlias = $Alias
        InterfaceIndex = $Index
        AddressFamily = 'IPv4'
        Forwarding = $Forwarding
    }
}

function New-TestIPAddress {
    param([string] $Alias, [int] $Index, [string] $Address, [int] $PrefixLength)
    return [pscustomobject] @{
        InterfaceAlias = $Alias
        InterfaceIndex = $Index
        AddressFamily = 'IPv4'
        IPAddress = $Address
        PrefixLength = $PrefixLength
    }
}

function New-TestRoute {
    param([string] $Alias, [int] $Index, [string] $Prefix, [string] $NextHop = '0.0.0.0')
    return [pscustomobject] @{
        InterfaceAlias = $Alias
        InterfaceIndex = $Index
        AddressFamily = 'IPv4'
        DestinationPrefix = $Prefix
        NextHop = $NextHop
        State = 'Alive'
    }
}

function Add-TestAppliedState {
    param(
        [string] $SnapshotId = '11111111-2222-4333-8444-555555555555',
        [string] $WireGuardSubnet = '100.127.77.0/24'
    )

    $description = "SnapshotId=$SnapshotId; WireGuardSubnet=$WireGuardSubnet; OperatorWhitelist=Required"
    foreach ($definition in @(
        @{ Name = 'OverseasPocBlockEmployeeInternet'; DisplayName = 'Overseas Gateway PoC - Block employee public internet'; Direction = 'Outbound'; Action = 'Block'; InterfaceAlias = 'Ethernet'; RemoteAddress = 'Internet' }
        @{ Name = 'OverseasPocAllowWireGuardIngress'; DisplayName = 'Overseas Gateway PoC - Allow WireGuard ingress'; Direction = 'Inbound'; Action = 'Allow'; InterfaceAlias = 'wg-overseas-poc'; RemoteAddress = $WireGuardSubnet }
        @{ Name = 'OverseasPocAllowTelecomInternet'; DisplayName = 'Overseas Gateway PoC - Allow telecom public internet'; Direction = 'Outbound'; Action = 'Allow'; InterfaceAlias = 'Telecom-Client'; RemoteAddress = 'Internet' }
    )) {
        $global:PocTestRules[$definition.Name] = New-TestFirewallCimRule `
            -RuleName $definition.Name `
            -RuleDisplayName $definition.DisplayName `
            -RuleGroup 'Overseas Gateway PoC' `
            -RuleDirection $definition.Direction `
            -RuleAction $definition.Action `
            -RuleDescription $description
        $global:PocTestRuleMetadata[$definition.Name] = [pscustomobject] @{
            InterfaceAlias = $definition.InterfaceAlias
            RemoteAddress = $definition.RemoteAddress
        }
    }
    $global:PocTestNat = [pscustomobject] @{
        Name = 'OverseasPocNat'
        InternalIPInterfaceAddressPrefix = $WireGuardSubnet
    }
    $global:PocTestForwarding[19] = 'Enabled'
    $global:PocTestForwarding[11] = 'Enabled'
}

Describe 'Windows PoC networking transactions' {
    BeforeEach {
        $global:PocTestAdapters = @{
            'wg-overseas-poc' = New-TestAdapter 'wg-overseas-poc' 19
            'Telecom-Client' = New-TestAdapter 'Telecom-Client' 11
            'Ethernet' = New-TestAdapter 'Ethernet' 7
        }
        $global:PocTestForwarding = @{ 19 = 'Disabled'; 11 = 'Disabled'; 7 = 'Disabled' }
        $global:PocTestIPAddresses = @(
            (New-TestIPAddress 'wg-overseas-poc' 19 '100.127.77.1' 24)
            (New-TestIPAddress 'Telecom-Client' 11 '198.51.100.2' 24)
            (New-TestIPAddress 'Ethernet' 7 '172.20.10.50' 24)
        )
        $global:PocTestRoutes = @(
            (New-TestRoute 'Ethernet' 7 '0.0.0.0/0' '172.20.10.1')
            (New-TestRoute 'Ethernet' 7 '10.0.0.0/8' '172.20.10.1')
            (New-TestRoute 'wg-overseas-poc' 19 '100.127.77.0/24')
        )
        $global:PocTestRules = @{}
        $global:PocTestRuleMetadata = @{}
        $global:PocTestNat = $null
        $global:PocTestActiveStoreEnabled = $true
        $global:PocTestFailTelecomEnableOnce = $false
        $global:PocTestTelecomEnableFailed = $false

        Mock Get-NetAdapter {
            if ($null -ne $Name) {
                if (-not $global:PocTestAdapters.ContainsKey([string] $Name)) {
                    throw "adapter not found: $Name"
                }
                return $global:PocTestAdapters[[string] $Name]
            }

            foreach ($adapter in $global:PocTestAdapters.Values) {
                if ([int] $adapter.ifIndex -eq [int] @($InterfaceIndex)[0]) {
                    return $adapter
                }
            }
            throw "adapter index not found: $InterfaceIndex"
        }

        Mock Get-NetIPInterface {
            $items = @()
            foreach ($adapter in $global:PocTestAdapters.Values) {
                $items += New-TestIPInterface $adapter.Name $adapter.ifIndex $global:PocTestForwarding[[int] $adapter.ifIndex]
            }
            if ($null -ne $InterfaceIndex) {
                return @($items | Where-Object { [int] $_.InterfaceIndex -eq [int] @($InterfaceIndex)[0] })
            }
            return $items
        }

        Mock Get-NetIPAddress { return $global:PocTestIPAddresses }
        Mock Get-NetRoute { return $global:PocTestRoutes }

        Mock Get-NetNat {
            if ($null -eq $global:PocTestNat) { return }
            if ($null -eq $Name -or [string] @($Name)[0] -eq $global:PocTestNat.Name) { return $global:PocTestNat }
        }

        Mock Get-NetFirewallRule {
            if ($PolicyStore -eq 'ActiveStore' -and -not $global:PocTestActiveStoreEnabled) {
                return
            }
            if ($null -ne $Name) {
                $ruleName = [string] @($Name)[0]
                if ($global:PocTestRules.ContainsKey($ruleName)) { return $global:PocTestRules[$ruleName] }
                return
            }
            if ($null -ne $Group) {
                return @($global:PocTestRules.GetEnumerator() | Where-Object {
                    $_.Value.RuleGroup -eq [string] $Group
                } | ForEach-Object { $_.Value })
            }
            return @($global:PocTestRules.Values)
        }

        Mock Get-NetFirewallAddressFilter {
            $metadata = $global:PocTestRuleMetadata[[string] $AssociatedNetFirewallRule.InstanceID]
            return [pscustomobject] @{ RemoteAddress = @($metadata.RemoteAddress) }
        }

        Mock Get-NetFirewallInterfaceFilter {
            $metadata = $global:PocTestRuleMetadata[[string] $AssociatedNetFirewallRule.InstanceID]
            return [pscustomobject] @{ InterfaceAlias = @($metadata.InterfaceAlias) }
        }

        Mock New-NetFirewallRule {
            $ruleName = [string] @($Name)[0]
            $global:PocTestRules[$ruleName] = New-TestFirewallCimRule `
                -RuleName $ruleName `
                -RuleDisplayName ([string] $DisplayName) `
                -RuleGroup ([string] $Group) `
                -RuleDirection ([string] $Direction) `
                -RuleAction ([string] $Action) `
                -RuleDescription ([string] $Description)
            $global:PocTestRuleMetadata[$ruleName] = [pscustomobject] @{
                InterfaceAlias = $(switch ($ruleName) {
                    'OverseasPocBlockEmployeeInternet' { 'Ethernet' }
                    'OverseasPocAllowWireGuardIngress' { 'wg-overseas-poc' }
                    'OverseasPocAllowTelecomInternet' { 'Telecom-Client' }
                })
                RemoteAddress = [string] @($RemoteAddress)[0]
            }
            return $global:PocTestRules[$ruleName]
        }

        Mock Remove-NetFirewallRule {
            if ($null -ne $Name) {
                $ruleName = [string] @($Name)[0]
                $global:PocTestRules.Remove($ruleName)
                $global:PocTestRuleMetadata.Remove($ruleName)
            }
            elseif ($null -ne $InputObject) {
                $ruleName = [string] $InputObject.InstanceID
                $global:PocTestRules.Remove($ruleName)
                $global:PocTestRuleMetadata.Remove($ruleName)
            }
        }

        Mock New-NetNat {
            $global:PocTestNat = [pscustomobject] @{
                Name = [string] $Name
                InternalIPInterfaceAddressPrefix = [string] $InternalIPInterfaceAddressPrefix
            }
            return $global:PocTestNat
        }

        Mock Remove-NetNat {
            if ([string] @($Name)[0] -eq 'OverseasPocNat') { $global:PocTestNat = $null }
        }

        Mock Set-NetIPInterface {
            if (
                $global:PocTestFailTelecomEnableOnce -and
                -not $global:PocTestTelecomEnableFailed -and
                [int] @($InterfaceIndex)[0] -eq 11 -and
                [string] $Forwarding -eq 'Enabled'
            ) {
                $global:PocTestTelecomEnableFailed = $true
                throw 'injected telecom forwarding failure'
            }
            $global:PocTestForwarding[[int] @($InterfaceIndex)[0]] = [string] $Forwarding
        }
    }

    It 'uses one transaction confirmation and WhatIf performs no apply or rollback mutation' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -Path (Join-Path $TestDrive 'fresh.json')

        & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('10.0.0.0/8') -WhatIf
        Add-TestAppliedState -SnapshotId $snapshot.SnapshotId
        & $rollbackScript -SnapshotPath $snapshot.Path -WhatIf

        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
        Assert-MockCalled New-NetNat -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-NetIPInterface -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-NetFirewallRule -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-NetNat -Times 0 -Exactly -Scope It

        foreach ($path in @($applyScript, $rollbackScript)) {
            $text = Get-Content -LiteralPath $path -Raw
            ([regex]::Matches($text, '\$PSCmdlet\.ShouldProcess\(')).Count | Should Be 1
        }
    }

    It 'automatically compensates every owned change after an injected partial apply failure' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -Path (Join-Path $TestDrive 'compensate.json')
        $global:PocTestFailTelecomEnableOnce = $true

        $message = Get-TestFailureMessage { & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('10.0.0.0/8') -Confirm:$false }
        $message | Should Match 'injected telecom forwarding failure'

        $global:PocTestRules.Count | Should Be 0
        $global:PocTestNat | Should BeNullOrEmpty
        $global:PocTestForwarding[19] | Should Be 'Disabled'
        $global:PocTestForwarding[11] | Should Be 'Disabled'
        Assert-MockCalled Remove-NetFirewallRule -Times 3 -Exactly -Scope It
        Assert-MockCalled Remove-NetNat -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'OverseasPocNat' }
    }

    It 'rejects a stale snapshot before any mutation' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -AgeHours 8 -Path (Join-Path $TestDrive 'stale.json')

        $message = Get-TestFailureMessage { & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('10.0.0.0/8') -Confirm:$false }
        $message | Should Match 'stale'

        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
        Assert-MockCalled New-NetNat -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-NetIPInterface -Times 0 -Exactly -Scope It
    }

    It 'rejects an edited snapshot whose integrity hash no longer matches' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -Path (Join-Path $TestDrive 'edited.json')
        $envelope = Get-Content -LiteralPath $snapshot.Path -Raw | ConvertFrom-Json
        $payloadJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($envelope.PayloadBase64))
        $payloadJson = $payloadJson.Replace('Telecom-Client', 'Unrelated-Adapter')
        $envelope.PayloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson))
        [System.IO.File]::WriteAllText($snapshot.Path, ($envelope | ConvertTo-Json -Depth 5))

        $message = Get-TestFailureMessage { & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('10.0.0.0/8') -Confirm:$false }
        $message | Should Match 'integrity'

        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
    }

    It 'rejects overlap with configured internal CIDRs or another current interface' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -Path (Join-Path $TestDrive 'overlap.json')

        $message = Get-TestFailureMessage { & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('100.127.77.128/25') -Confirm:$false }
        $message | Should Match 'overlap'

        $global:PocTestIPAddresses += New-TestIPAddress 'Ethernet' 7 '100.127.77.20' 32
        $message = Get-TestFailureMessage { & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('10.0.0.0/8') -Confirm:$false }
        $message | Should Match 'overlap'

        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
    }

    It 'rejects active CGNAT use even when it is elsewhere in shared address space' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -Path (Join-Path $TestDrive 'cgnat.json')
        $global:PocTestIPAddresses += New-TestIPAddress 'Telecom-Client' 11 '100.100.20.30' 32

        $message = Get-TestFailureMessage { & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('10.0.0.0/8') -Confirm:$false }
        $message | Should Match 'CGNAT'

        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
    }

    It 'rejects distinct aliases that resolve to the same canonical interface index' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -Path (Join-Path $TestDrive 'same-index.json')
        $global:PocTestAdapters['Telecom-Client'] = New-TestAdapter 'Telecom-Client' 7

        $message = Get-TestFailureMessage { & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('10.0.0.0/8') -Confirm:$false }
        $message | Should Match 'indices'

        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
    }

    It 'requires the employee interface to own the sole active IPv4 default route' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -Path (Join-Path $TestDrive 'default-route.json')
        $global:PocTestRoutes += New-TestRoute 'Telecom-Client' 11 '0.0.0.0/0' '198.51.100.1'

        $message = Get-TestFailureMessage { & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('10.0.0.0/8') -Confirm:$false }
        $message | Should Match 'sole active IPv4 default route'

        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
    }

    It 'refuses existing WinNAT state before mutation' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -Path (Join-Path $TestDrive 'existing-nat.json')
        $global:PocTestNat = [pscustomobject] @{ Name = 'ExistingNat'; InternalIPInterfaceAddressPrefix = '192.0.2.0/24' }

        $message = Get-TestFailureMessage { & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('10.0.0.0/8') -Confirm:$false }
        $message | Should Match 'WinNAT'

        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
        Assert-MockCalled New-NetNat -Times 0 -Exactly -Scope It
    }

    It 'fails and compensates when local firewall policy is absent from ActiveStore' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -Path (Join-Path $TestDrive 'inactive-policy.json')
        $global:PocTestActiveStoreEnabled = $false

        $message = Get-TestFailureMessage { & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('10.0.0.0/8') -Confirm:$false }
        $message | Should Match 'ActiveStore'

        $global:PocTestRules.Count | Should Be 0
        $global:PocTestNat | Should BeNullOrEmpty
        Assert-MockCalled Get-NetFirewallRule -Times 1 -Scope It -ParameterFilter { $PolicyStore -eq 'ActiveStore' -and $Group -eq 'Overseas Gateway PoC' }
        Assert-MockCalled New-NetNat -Times 0 -Exactly -Scope It
        Assert-MockCalled Set-NetIPInterface -Times 0 -Exactly -Scope It
    }

    It 'blocks public Internet on the employee interface while retaining internal routes' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -Path (Join-Path $TestDrive 'public-block.json')

        & $applyScript -SnapshotPath $snapshot.Path -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -WireGuardSubnet '100.127.77.0/24' -InternalCidrs @('10.0.0.0/8') -Confirm:$false

        $block = $global:PocTestRules['OverseasPocBlockEmployeeInternet']
        $metadata = $global:PocTestRuleMetadata['OverseasPocBlockEmployeeInternet']
        $block.Action.ToString() | Should Be 'Block'
        $metadata.InterfaceAlias | Should Be 'Ethernet'
        $metadata.RemoteAddress | Should Be 'Internet'
        $metadata.PSObject.Properties['LocalAddress'] | Should BeNullOrEmpty
        @($global:PocTestRoutes | Where-Object { $_.DestinationPrefix -eq '10.0.0.0/8' }).Count | Should Be 1
        Assert-MockCalled New-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter {
            [string] @($Name)[0] -eq 'OverseasPocBlockEmployeeInternet' -and
            @($InterfaceAlias)[0].IsMatch('Ethernet') -and
            [string] @($RemoteAddress)[0] -eq 'Internet' -and
            [string] $Action -eq 'Block'
        }
    }

    It 'rolls back only exact transaction-owned resources and leaves another group rule untouched' {
        $snapshot = ConvertTo-TestSnapshotEnvelope -Path (Join-Path $TestDrive 'rollback.json')
        Add-TestAppliedState -SnapshotId $snapshot.SnapshotId
        $global:PocTestRules['UnrelatedSameGroupRule'] = New-TestFirewallCimRule -RuleName 'UnrelatedSameGroupRule' -RuleDisplayName 'Unrelated' -RuleGroup 'Overseas Gateway PoC' -RuleDirection 'Outbound' -RuleAction 'Block' -RuleDescription 'not owned by this transaction'
        $global:PocTestRuleMetadata['UnrelatedSameGroupRule'] = [pscustomobject] @{ InterfaceAlias = 'Ethernet'; RemoteAddress = '203.0.113.0/24' }

        & $rollbackScript -SnapshotPath $snapshot.Path -Confirm:$false

        $global:PocTestRules.ContainsKey('UnrelatedSameGroupRule') | Should Be $true
        foreach ($name in @('OverseasPocBlockEmployeeInternet', 'OverseasPocAllowWireGuardIngress', 'OverseasPocAllowTelecomInternet')) {
            $global:PocTestRules.ContainsKey($name) | Should Be $false
        }
        $global:PocTestNat | Should BeNullOrEmpty
        $global:PocTestForwarding[19] | Should Be 'Disabled'
        $global:PocTestForwarding[11] | Should Be 'Disabled'
        Assert-MockCalled Remove-NetFirewallRule -Times 3 -Exactly -Scope It
        Assert-MockCalled Remove-NetFirewallRule -Times 0 -Exactly -Scope It -ParameterFilter { $Name -eq 'UnrelatedSameGroupRule' -or $null -ne $InputObject }
        Assert-MockCalled Set-NetIPInterface -Times 0 -Exactly -Scope It -ParameterFilter { [int] @($InterfaceIndex)[0] -eq 7 }
    }
}

Describe 'Windows PoC snapshot safety' {
    BeforeEach {
        Mock Get-NetAdapter {
            if ($Name -eq 'wg-overseas-poc') { return New-TestAdapter 'wg-overseas-poc' 19 }
            if ($Name -eq 'Telecom-Client') { return New-TestAdapter 'Telecom-Client' 11 }
            if ($Name -eq 'Ethernet') { return New-TestAdapter 'Ethernet' 7 }
            return @(
                (New-TestAdapter 'wg-overseas-poc' 19)
                (New-TestAdapter 'Telecom-Client' 11)
                (New-TestAdapter 'Ethernet' 7)
            )
        }
        Mock Get-NetIPInterface {
            return @(
                (New-TestIPInterface 'wg-overseas-poc' 19)
                (New-TestIPInterface 'Telecom-Client' 11)
                (New-TestIPInterface 'Ethernet' 7)
            )
        }
        Mock Get-NetRoute { return @((New-TestRoute 'Ethernet' 7 '0.0.0.0/0' '172.20.10.1')) }
        Mock Get-NetNat { return @() }
        Mock Get-NetFirewallRule { return @() }
        Mock Get-NetFirewallAddressFilter { return @() }
    }

    It 'does not report a nonexistent snapshot path under WhatIf' {
        $output = @(& $snapshotScript -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -ArtifactsDirectory $TestDrive -WhatIf)

        @($output | Where-Object { [string] $_ -match '\.json$' }).Count | Should Be 0
        @(Get-ChildItem -LiteralPath $TestDrive -File).Count | Should Be 0
    }

    It 'removes a temporary file when atomic snapshot publication fails' {
        Mock Move-Item { throw 'injected publication failure' }

        $message = Get-TestFailureMessage { & $snapshotScript -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -ArtifactsDirectory $TestDrive -Confirm:$false }
        $message | Should Match 'injected publication failure'

        @(Get-ChildItem -LiteralPath $TestDrive -File).Count | Should Be 0
    }

    It 'rejects aliases that resolve to one canonical index before writing a snapshot' {
        Mock Get-NetAdapter {
            if ($Name -eq 'wg-overseas-poc') { return New-TestAdapter 'wg-overseas-poc' 19 }
            if ($Name -eq 'Telecom-Client') { return New-TestAdapter 'Telecom-Client' 7 }
            if ($Name -eq 'Ethernet') { return New-TestAdapter 'Ethernet' 7 }
        }

        $message = Get-TestFailureMessage { & $snapshotScript -WireGuardInterface 'wg-overseas-poc' -TelecomInterface 'Telecom-Client' -EmployeeInterface 'Ethernet' -ArtifactsDirectory $TestDrive -Confirm:$false }
        $message | Should Match 'indices'

        @(Get-ChildItem -LiteralPath $TestDrive -File).Count | Should Be 0
    }
}

Describe 'Windows PoC script syntax' {
    It 'parses every PowerShell script without errors' {
        foreach ($path in @($snapshotScript, $applyScript, $rollbackScript)) {
            $tokens = $null
            $errors = $null
            [void] [System.Management.Automation.Language.Parser]::ParseFile($path, [ref] $tokens, [ref] $errors)
            $errors.Count | Should Be 0
        }
    }
}
