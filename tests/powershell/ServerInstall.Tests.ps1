$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptPath = Join-Path $repoRoot 'deploy\server\install-server.ps1'
$packageScriptPath = Join-Path $repoRoot 'scripts\windows\package-server-service.ps1'
$makefilePath = Join-Path $repoRoot 'Makefile'

function Get-ServerInstallFailureMessage {
    param([Parameter(Mandatory = $true)][scriptblock] $Action)

    try {
        & $Action
    }
    catch {
        return $_.Exception.Message
    }
    return ''
}

Describe 'Transactional sing-box server deployment' {
    It 'exists, parses in Windows PowerShell 5.1, and exposes only explicit modes' {
        (Test-Path -LiteralPath $scriptPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { return }

        $tokens = $null
        $errors = $null
        [void] [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
        $errors.Count | Should Be 0

        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Match "ValidateSet\('Install',\s*'Status',\s*'Rollback'\)"
        $text | Should Match 'Mandatory\s*=\s*\$true[^\]]*\]\s*\[string\]\s*\$Mode'
    }

    It 'requires the employee CIDR and sing-box port to be caller-explicit before any discovery or mutation' {
        (Test-Path -LiteralPath $scriptPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { return }

        Mock Get-CimInstance { throw 'discovery must not run' }
        Mock Get-NetIPAddress { throw 'discovery must not run' }
        Mock New-Service { throw 'mutation must not run' }
        Mock New-NetFirewallRule { throw 'mutation must not run' }

        $missingBoth = Get-ServerInstallFailureMessage {
            & $scriptPath -Mode Install -BundlePath 'C:\missing' -ConfigPath 'C:\missing.json' `
                -ExpectedSingBoxSha256 ('a' * 64) -ExpectedConfigSha256 ('b' * 64) `
                -EvidencePath 'C:\missing-baseline.json' -WhatIf
        }
        $missingBoth | Should Match 'EmployeeCIDR'

        $missingPort = Get-ServerInstallFailureMessage {
            & $scriptPath -Mode Install -BundlePath 'C:\missing' -ConfigPath 'C:\missing.json' `
                -ExpectedSingBoxSha256 ('a' * 64) -ExpectedConfigSha256 ('b' * 64) `
                -EmployeeCIDR '172.20.8.0/22' -EvidencePath 'C:\missing-baseline.json' -WhatIf
        }
        $missingPort | Should Match 'ServerPort'

        Assert-MockCalled Get-CimInstance -Times 0 -Exactly -Scope It
        Assert-MockCalled Get-NetIPAddress -Times 0 -Exactly -Scope It
        Assert-MockCalled New-Service -Times 0 -Exactly -Scope It
        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
    }

    It 'pins the VM, upstream, employee scope, port, service, paths, and exact firewall resources' {
        (Test-Path -LiteralPath $scriptPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { return }
        $text = Get-Content -LiteralPath $scriptPath -Raw

        foreach ($literal in @(
            '172.20.9.15',
            '172.20.8.0/22',
            '127.0.0.1',
            '8080',
            '18443',
            'RegenBioOverseasAccessServer',
            'C:\Program Files\RegenBio\OverseasAccessServer',
            'C:\ProgramData\RegenBio\OverseasAccessServer',
            'RegenBioOverseasAccess-AllowEmployee-In',
            'RegenBioOverseasAccess-Block8080-Remote',
            'RegenBioOverseasAccess-BlockManagement-Employee'
        )) {
            $text | Should Match ([regex]::Escape($literal))
        }

        $block8080Start = $text.IndexOf("-DisplayName 'RegenBio Overseas Access - keep telecom proxy local only'")
        $block8080End = $text.IndexOf('$owned.FirewallRules.Add($FirewallBlock8080)', $block8080Start)
        $block8080 = $text.Substring($block8080Start, $block8080End - $block8080Start)
        $block8080 | Should Match '-LocalAddress\s+\$ExpectedVmAddress'
    }

    It 'registers the pinned first-party SCM host with fixed runtime paths and no service argv' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Match 'overseas-server-service\.exe'
        $text | Should Match 'ExpectedServerServiceSha256'
        $text | Should Match 'server_service_sha256'
        $text | Should Match 'runtime-manifest\.json'
        $text | Should Not Match '(?i)winsw'

        $start = $text.IndexOf('New-Service')
        $end = $text.IndexOf('$owned.Service = $true')
        $serviceBlock = $text.Substring($start, $end - $start)
        $text | Should Match '\$binaryPath\s*=\s*[^\r\n]*\$installedServerService'
        $serviceBlock | Should Not Match 'run\s+-c'
        $serviceBlock | Should Not Match 'installedConfig'
        $serviceBlock | Should Not Match 'sing-box\.exe'
    }

    It 'contains every pre-mutation gate and the complete baseline evidence contract' {
        (Test-Path -LiteralPath $scriptPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { return }
        $text = Get-Content -LiteralPath $scriptPath -Raw

        foreach ($gate in @(
            'WindowsPrincipal',
            'Win32_OperatingSystem',
            'Get-NetIPAddress',
            'Get-NetTCPConnection',
            'OwningProcess',
            'Invoke-WebRequest',
            'Get-FileHash',
            'check',
            'BaselinePublished'
        )) {
            $text | Should Match ([regex]::Escape($gate))
        }

        foreach ($field in @(
            'Services',
            'Listeners',
            'Routes',
            'FirewallRules',
            'Telecom8080Owner',
            'SingBoxSha256',
            'ConfigSha256',
            'ConnectProbe'
        )) {
            $text | Should Match ([regex]::Escape($field))
        }

        $baselineIndex = $text.IndexOf('BaselinePublished')
        $firstServiceMutation = $text.IndexOf('New-Service')
        $baselineIndex | Should BeGreaterThan -1
        $firstServiceMutation | Should BeGreaterThan $baselineIndex
    }

    It 'uses one ShouldProcess boundary, atomic evidence, reverse compensation, and a finally cleanup path' {
        (Test-Path -LiteralPath $scriptPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { return }
        $text = Get-Content -LiteralPath $scriptPath -Raw

        ([regex]::Matches($text, 'SupportsShouldProcess\s*=\s*\$true', 'IgnoreCase')).Count | Should Be 1
        $text | Should Match '\$PSCmdlet\.ShouldProcess\('
        $text | Should Match 'Write-AtomicJson'
        $text | Should Match 'CreateNew'
        $text | Should Match 'Move-Item\s+[^\r\n]*-LiteralPath[^\r\n]*-Destination'
        $text | Should Match 'Compensate-InstallTransaction'
        $text | Should Match '\bfinally\s*\{'
        $text | Should Match 'TransactionId='
    }

    It 'protects ProgramData before config publication, rehashes installed inputs, and journals before service start' {
        (Test-Path -LiteralPath $scriptPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { return }
        $text = Get-Content -LiteralPath $scriptPath -Raw

        $protectIndex = $text.IndexOf('Protect-ServiceDataPath -Path $DataRoot')
        $configCopyIndex = $text.IndexOf('Copy-Item -LiteralPath $ConfigPath')
        $installedHashIndex = $text.IndexOf('InstalledConfigSha256')
        $serviceStartIndex = $text.IndexOf('Start-Service -Name $ServiceName')

        $protectIndex | Should BeGreaterThan -1
        $configCopyIndex | Should BeGreaterThan $protectIndex
        $installedHashIndex | Should BeGreaterThan $configCopyIndex
        $serviceStartIndex | Should BeGreaterThan $installedHashIndex
        $text | Should Match '/setowner[^\r\n]*\*S-1-5-32-544'
        $text | Should Match 'Assert-ServerPortAvailable'
        $text.IndexOf('Assert-ServerPortAvailable') | Should BeLessThan $text.IndexOf('$PSCmdlet.ShouldProcess(')
    }

    It 'publishes an external write-ahead journal before system mutation and tags both owned roots' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $journalIndex = $text.IndexOf('Write-AtomicJson -Path $journalPath')
        $firstRootMutation = $text.IndexOf('New-Item -ItemType Directory -Path $InstallRoot')

        $text | Should Match 'Get-TransactionJournalPath'
        $text | Should Match 'owner\.json'
        $text | Should Match 'EvidencePath must be supplied explicitly for Rollback'
        $journalIndex | Should BeGreaterThan -1
        $firstRootMutation | Should BeGreaterThan $journalIndex
    }

    It 'compensates in dependency-safe reverse order and never deletes backing files while the service remains' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $start = $text.IndexOf('function Compensate-InstallTransaction')
        $end = $text.IndexOf('function Install-ServerTransaction')
        $body = $text.Substring($start, $end - $start)

        $firewallIndex = $body.IndexOf('$FirewallBlockManagement')
        $serviceIndex = $body.IndexOf('Remove-OwnedService')
        $dataIndex = $body.IndexOf('Remove-OwnedDirectory -Path $DataRoot')
        $firewallIndex | Should BeGreaterThan -1
        $serviceIndex | Should BeGreaterThan $firewallIndex
        $dataIndex | Should BeGreaterThan $serviceIndex
        $body | Should Match 'serviceRemovalProven'
        $text | Should Match '\$expectedBinaryPath'
        $text | Should Not Match 'PathName\s+-notlike'
    }

    It 'rejects effective broad inbound allows on the server port and does not disclose service argv in baseline evidence' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Match 'Assert-NoConflictingServerPortAllow'
        $text | Should Match 'Get-NetFirewallApplicationFilter'
        $text | Should Match 'Get-NetFirewallServiceFilter'
        $text | Should Match 'Test-PortSpecificationIncludes'
        $text | Should Match '\$ServiceName'
        $text | Should Match 'rangeStart'
        $text | Should Match 'rangeEnd'
        $text | Should Match 'ServicePathSha256'

        $start = $text.IndexOf('function Get-BaselineEvidence')
        $end = $text.IndexOf('function Protect-ServiceDataPath')
        $body = $text.Substring($start, $end - $start)
        $body | Should Not Match 'PathName\s*='
    }

    It 'keeps rollback recoverable and idempotent until exact absence is proven' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $start = $text.IndexOf('function Rollback-ServerTransaction')
        $body = $text.Substring($start)
        $body | Should Match 'AlreadyRolledBack'
        $body | Should Match 'OriginalOwnedResourcesRestored'
        $proofIndex = $body.IndexOf('Rollback could not prove removal')
        $journalRemovalIndex = $body.IndexOf('Remove-Item -LiteralPath $journalPath')
        $proofIndex | Should BeGreaterThan -1
        $journalRemovalIndex | Should BeGreaterThan $proofIndex
    }

    It 'has no dynamic execution, wildcard deletion, plaintext secret parameter, or secret-bearing native argv' {
        (Test-Path -LiteralPath $scriptPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { return }

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
        $errors.Count | Should Be 0
        $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
        @($commands | Where-Object { $_.GetCommandName() -eq 'Invoke-Expression' }).Count | Should Be 0

        $parameters = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ParameterAst] }, $true))
        @($parameters | Where-Object { $_.Name.VariablePath.UserPath -match '(?i)secret|password|token|pin|credential' }).Count | Should Be 0

        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Not Match '(?im)^\s*Remove-Item[^\r\n]*(\*|\?)'
        $text | Should Not Match '(?im)^\s*&[^\r\n]*(secret|password|token|pin|credential)'
    }

    It 'captures native launch success and exit status immediately after each native check' {
        (Test-Path -LiteralPath $scriptPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { return }
        $lines = @(Get-Content -LiteralPath $scriptPath)
        $nativeCount = 0

        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\s*&\s+') {
                $nativeCount++
                ($i + 2) | Should BeLessThan $lines.Count
                $lines[$i + 1] | Should Match '^\s*\$nativeLaunchSucceeded\s*=\s*\$\?\s*$'
                $lines[$i + 2] | Should Match '^\s*\$nativeExitCode\s*=\s*\$LASTEXITCODE\s*$'
            }
        }

        $nativeCount | Should BeGreaterThan 0
    }

    It 'runs the complete Install preflight under WhatIf and makes zero persistent changes' {
        (Test-Path -LiteralPath $scriptPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { return }

        $bundlePath = Join-Path $TestDrive 'bundle'
        New-Item -ItemType Directory -Path $bundlePath | Out-Null
        $singBoxPath = Join-Path $bundlePath 'sing-box.exe'
        $fakeSourcePath = Join-Path $TestDrive 'fake-sing-box.cs'
        [System.IO.File]::WriteAllText(
            $fakeSourcePath,
            'public static class ServerInstallFakeSingBox { public static int Main(string[] args) { System.Console.WriteLine("SING_BOX_CHECK_CHATTER"); return 0; } }',
            (New-Object System.Text.UTF8Encoding($false))
        )
        $cscPath = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        & $cscPath /nologo /target:exe "/out:$singBoxPath" $fakeSourcePath
        if ($LASTEXITCODE -ne 0) { throw "test fixture compilation failed: $LASTEXITCODE" }
        $serverServicePath = Join-Path $bundlePath 'overseas-server-service.exe'
        Copy-Item -LiteralPath $singBoxPath -Destination $serverServicePath
        $configPath = Join-Path $TestDrive 'server-config.json'
        [System.IO.File]::WriteAllText($configPath, '{"inbounds":[],"outbounds":[]}', (New-Object System.Text.UTF8Encoding($false)))
        $singHash = (Get-FileHash -LiteralPath $singBoxPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $manifest = [ordered] @{ version = '1.13.19'; executable_sha256 = $singHash; server_service_sha256 = $singHash }
        [System.IO.File]::WriteAllText(
            (Join-Path $bundlePath 'sing-box.manifest.json'),
            ($manifest | ConvertTo-Json),
            (New-Object System.Text.UTF8Encoding($false))
        )
        $evidencePath = Join-Path $TestDrive 'baseline.json'

        Mock Get-CimInstance {
            if ($ClassName -eq 'Win32_OperatingSystem') {
                return [pscustomobject] @{ Version = '10.0.19045'; OSArchitecture = '64-bit'; Caption = 'Windows 10 Enterprise LTSC' }
            }
            return @()
        }
        Mock Get-NetIPAddress { return [pscustomobject] @{ IPAddress = '172.20.9.15'; AddressFamily = 'IPv4'; InterfaceIndex = 4 } }
        Mock Get-NetTCPConnection {
            if ($LocalPort -eq 18443) { return @() }
            return [pscustomobject] @{ LocalAddress = '127.0.0.1'; LocalPort = 8080; State = 'Listen'; OwningProcess = 4242 }
        }
        Mock Get-Process { return [pscustomobject] @{ Id = 4242; ProcessName = 'TelecomClient'; Path = 'C:\Program Files\Telecom\client.exe'; HasExited = $false } }
        Mock Invoke-WebRequest { return [pscustomobject] @{ StatusCode = 204 } }
        Mock Get-NetRoute { return @() }
        Mock Get-NetFirewallRule { return @() }
        Mock Get-NetFirewallPortFilter { return @() }
        Mock Get-NetFirewallAddressFilter { return @() }
        Mock New-Service { throw 'WhatIf attempted service mutation' }
        Mock Start-Service { throw 'WhatIf attempted service mutation' }
        Mock Stop-Service { throw 'WhatIf attempted service mutation' }
        Mock Invoke-CimMethod { throw 'WhatIf attempted service mutation' }
        Mock New-NetFirewallRule { throw 'WhatIf attempted firewall mutation' }
        Mock Remove-NetFirewallRule { throw 'WhatIf attempted firewall mutation' }
        Mock Copy-Item { throw 'WhatIf attempted file mutation' }
        Mock Move-Item { throw 'WhatIf attempted file mutation' }
        Mock Remove-Item { throw 'WhatIf attempted file mutation' }

        $outputs = @(
            & $scriptPath `
                -Mode Install `
                -BundlePath $bundlePath `
                -ConfigPath $configPath `
                -ExpectedSingBoxSha256 $singHash `
                -ExpectedConfigSha256 $configHash `
                -ExpectedServerServiceSha256 $singHash `
                -EmployeeCIDR '172.20.8.0/22' `
                -ServerPort 18443 `
                -EvidencePath $evidencePath `
                -WhatIf
        )

        $outputs.Count | Should Be 1
        $json = $outputs[0]
        $result = $json | ConvertFrom-Json
        $result.Mode | Should Be 'Install'
        $result.WhatIf | Should Be $true
        (Test-Path -LiteralPath $evidencePath) | Should Be $false
        Assert-MockCalled New-Service -Times 0 -Exactly -Scope It
        Assert-MockCalled Get-NetTCPConnection -Times 1 -Exactly -Scope It -ParameterFilter { $LocalPort -eq 18443 }
        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
        Assert-MockCalled Copy-Item -Times 0 -Exactly -Scope It
        Assert-MockCalled Move-Item -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-Item -Times 0 -Exactly -Scope It
    }

    It 'packages the first-party service host into the pinned bundle manifest without network access' {
        (Test-Path -LiteralPath $packageScriptPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $packageScriptPath -PathType Leaf)) { return }

        $bundlePath = Join-Path $TestDrive 'package-bundle'
        New-Item -ItemType Directory -Path $bundlePath | Out-Null
        $singBoxPath = Join-Path $bundlePath 'sing-box.exe'
        $serviceSourcePath = Join-Path $TestDrive 'overseas-server-service.exe'
        [System.IO.File]::WriteAllBytes($singBoxPath, [byte[]](1, 2, 3))
        [System.IO.File]::WriteAllBytes($serviceSourcePath, [byte[]](4, 5, 6))
        $singHash = (Get-FileHash -LiteralPath $singBoxPath -Algorithm SHA256).Hash.ToLowerInvariant()
        [System.IO.File]::WriteAllText(
            (Join-Path $bundlePath 'sing-box.manifest.json'),
            ([ordered] @{ version = '1.13.19'; executable_sha256 = $singHash } | ConvertTo-Json),
            (New-Object System.Text.UTF8Encoding($false))
        )

        $output = & $packageScriptPath -BundlePath $bundlePath -ServicePath $serviceSourcePath | ConvertFrom-Json
        $packagedService = Join-Path $bundlePath 'overseas-server-service.exe'
        $manifest = Get-Content -LiteralPath (Join-Path $bundlePath 'sing-box.manifest.json') -Raw | ConvertFrom-Json
        $serviceHash = (Get-FileHash -LiteralPath $serviceSourcePath -Algorithm SHA256).Hash.ToLowerInvariant()

        $output.server_service_sha256 | Should Be $serviceHash
        $manifest.server_service_sha256 | Should Be $serviceHash
        (Get-FileHash -LiteralPath $packagedService -Algorithm SHA256).Hash.ToLowerInvariant() | Should Be $serviceHash
    }

    It 'wires a dedicated dual-PowerShell server deployment test target without breaking legacy phony targets' {
        $makefile = Get-Content -LiteralPath $makefilePath -Raw
        $makefile | Should Match '(?m)^\.PHONY:\s+test\s+build\s*$'
        $makefile | Should Match '(?m)^test-server-install:'
        $makefile | Should Match '(?m)^build-server-service:'
        $makefile | Should Match '(?m)^package-server-service:'
        $makefile | Should Match 'go\)?\s+build[^\r\n]*cmd/overseas-server-service'
        $makefile | Should Match 'package-server-service\.ps1'
        $makefile | Should Match 'powershell\.exe\s+-NoProfile[^\r\n]*ServerInstall\.Tests\.ps1'
        $makefile | Should Match 'pwsh[^\r\n]*ServerInstall\.Tests\.ps1'
        ([regex]::Matches($makefile, 'FailedCount')).Count | Should Be 2
        ([regex]::Matches($makefile, 'exit\s+1')).Count | Should BeGreaterThan 1
    }
}

Describe 'Transactional server behavioral refusal gates' {
    It 'executes OS, VM IP, hash, 8080 owner, CONNECT, 18443 listener, and broad-firewall refusals before mutation' {
        $bundlePath = Join-Path $TestDrive 'negative-bundle'
        New-Item -ItemType Directory -Path $bundlePath | Out-Null
        $singBoxPath = Join-Path $bundlePath 'sing-box.exe'
        $fakeSourcePath = Join-Path $TestDrive 'negative-fake-sing-box.cs'
        [System.IO.File]::WriteAllText(
            $fakeSourcePath,
            'public static class NegativeFakeSingBox { public static int Main(string[] args) { return 0; } }',
            (New-Object System.Text.UTF8Encoding($false))
        )
        $cscPath = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        & $cscPath /nologo /target:exe "/out:$singBoxPath" $fakeSourcePath
        if ($LASTEXITCODE -ne 0) { throw "test fixture compilation failed: $LASTEXITCODE" }
        $serverServicePath = Join-Path $bundlePath 'overseas-server-service.exe'
        Copy-Item -LiteralPath $singBoxPath -Destination $serverServicePath
        $configPath = Join-Path $TestDrive 'negative-server-config.json'
        [System.IO.File]::WriteAllText($configPath, '{"inbounds":[],"outbounds":[]}', (New-Object System.Text.UTF8Encoding($false)))
        $singHash = (Get-FileHash -LiteralPath $singBoxPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
        [System.IO.File]::WriteAllText(
            (Join-Path $bundlePath 'sing-box.manifest.json'),
            ([ordered] @{ version = '1.13.19'; executable_sha256 = $singHash; server_service_sha256 = $singHash } | ConvertTo-Json),
            (New-Object System.Text.UTF8Encoding($false))
        )
        $firewallRuleType = 'Microsoft.Management.Infrastructure.CimInstance#root/standardcimv2/MSFT_NetFirewallRule'
        Update-TypeData -TypeName $firewallRuleType -MemberType AliasProperty -MemberName Name -Value InstanceID -Force
        Update-TypeData -TypeName $firewallRuleType -MemberType ScriptProperty -MemberName Enabled -Value { 'True' } -Force
        Update-TypeData -TypeName $firewallRuleType -MemberType ScriptProperty -MemberName Direction -Value { 'Inbound' } -Force
        Update-TypeData -TypeName $firewallRuleType -MemberType ScriptProperty -MemberName Action -Value { 'Allow' } -Force
        $global:Task7BroadRule = New-CimInstance -ClassName MSFT_NetFirewallRule -Namespace root/standardcimv2 -ClientOnly -Property @{
            InstanceID = 'Existing-Broad-Allow'; DisplayName = 'Existing-Broad-Allow'; Enabled = 1; Direction = 1; Action = 2
        }

        $global:Task7NegativeScenario = ''
        Mock Get-CimInstance {
            if ($ClassName -eq 'Win32_OperatingSystem') {
                if ($global:Task7NegativeScenario -eq 'OS') {
                    return [pscustomobject] @{ Version = '6.1.7601'; OSArchitecture = '64-bit'; Caption = 'Unsupported Windows' }
                }
                return [pscustomobject] @{ Version = '10.0.19045'; OSArchitecture = '64-bit'; Caption = 'Windows 10 Enterprise LTSC' }
            }
            return @()
        }
        Mock Get-NetIPAddress {
            if ($global:Task7NegativeScenario -eq 'IP') { return @() }
            return [pscustomobject] @{ IPAddress = '172.20.9.15'; AddressFamily = 'IPv4'; InterfaceIndex = 4 }
        }
        Mock Get-NetTCPConnection {
            if ($LocalPort -eq 18443) {
                if ($global:Task7NegativeScenario -eq 'ServerPort') {
                    return [pscustomobject] @{ LocalAddress = '0.0.0.0'; LocalPort = 18443; State = 'Listen'; OwningProcess = 8181 }
                }
                return @()
            }
            if ($global:Task7NegativeScenario -eq 'Owner8080') {
                return [pscustomobject] @{ LocalAddress = '0.0.0.0'; LocalPort = 8080; State = 'Listen'; OwningProcess = 4242 }
            }
            return [pscustomobject] @{ LocalAddress = '127.0.0.1'; LocalPort = 8080; State = 'Listen'; OwningProcess = 4242 }
        }
        Mock Get-Process { return [pscustomobject] @{ Id = 4242; ProcessName = 'TelecomClient'; Path = 'C:\Program Files\Telecom\client.exe'; HasExited = $false } }
        Mock Invoke-WebRequest {
            if ($global:Task7NegativeScenario -eq 'Connect') { throw 'CONNECT refused by test' }
            return [pscustomobject] @{ StatusCode = 204 }
        }
        Mock Get-NetFirewallRule {
            if ($global:Task7NegativeScenario -in @('Firewall', 'FirewallMulti') -and [string]::IsNullOrWhiteSpace([string] $Name)) {
                return $global:Task7BroadRule
            }
            return @()
        }
        Mock Get-NetFirewallPortFilter {
            if ($global:Task7NegativeScenario -eq 'FirewallMulti') {
                return [pscustomobject] @{ Protocol = 'TCP'; LocalPort = @('443', '18443') }
            }
            return [pscustomobject] @{ Protocol = 'TCP'; LocalPort = '18000-19000' }
        }
        Mock Get-NetFirewallApplicationFilter { return [pscustomobject] @{ Program = 'Any' } }
        Mock Get-NetFirewallServiceFilter { return [pscustomobject] @{ Service = 'RegenBioOverseasAccessServer' } }
        Mock Get-NetFirewallAddressFilter { return [pscustomobject] @{ RemoteAddress = 'Any' } }
        Mock Get-NetRoute { return @() }
        Mock New-Service { throw 'mutation must not run' }
        Mock New-NetFirewallRule { throw 'mutation must not run' }

        $invokeInstall = {
            param([string] $ExpectedHash)
            Get-ServerInstallFailureMessage {
                & $scriptPath -Mode Install -BundlePath $bundlePath -ConfigPath $configPath `
                    -ExpectedSingBoxSha256 $ExpectedHash -ExpectedConfigSha256 $configHash `
                    -ExpectedServerServiceSha256 $singHash -EmployeeCIDR '172.20.8.0/22' `
                    -ServerPort 18443 -EvidencePath (Join-Path $TestDrive ($global:Task7NegativeScenario + '.json')) -WhatIf
            }
        }

        foreach ($case in @(
            [pscustomobject] @{ Scenario = 'OS'; Hash = $singHash; Pattern = 'Unsupported Windows host' },
            [pscustomobject] @{ Scenario = 'IP'; Hash = $singHash; Pattern = 'Expected VM address' },
            [pscustomobject] @{ Scenario = 'Hash'; Hash = ('f' * 64); Pattern = 'sing-box SHA-256 verification failed' },
            [pscustomobject] @{ Scenario = 'Owner8080'; Hash = $singHash; Pattern = 'loopback-only' },
            [pscustomobject] @{ Scenario = 'Connect'; Hash = $singHash; Pattern = 'CONNECT refused by test' },
            [pscustomobject] @{ Scenario = 'ServerPort'; Hash = $singHash; Pattern = 'already has a listener' },
            [pscustomobject] @{ Scenario = 'Firewall'; Hash = $singHash; Pattern = 'can expose TCP 18443' },
            [pscustomobject] @{ Scenario = 'FirewallMulti'; Hash = $singHash; Pattern = 'can expose TCP 18443' }
        )) {
            $global:Task7NegativeScenario = $case.Scenario
            $message = & $invokeInstall $case.Hash
            $message | Should Match ([regex]::Escape($case.Pattern))
        }

        Assert-MockCalled New-Service -Times 0 -Exactly -Scope It
        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
    }
}

Describe 'Server firewall and directory ownership units' {
    It 'passes management ports to New-NetFirewallRule as four separate values' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
        $definition = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'New-ManagementFirewallRule'
        }, $true))[0]
        $null -ne $definition | Should Be $true
        if ($null -eq $definition) { return }
        . ([scriptblock]::Create($definition.Extent.Text))

        $managementAssignment = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -eq 'ManagementPorts'
        }, $true))[0]
        . ([scriptblock]::Create($managementAssignment.Extent.Text))

        $FirewallBlockManagement = 'RegenBioOverseasAccess-BlockManagement-Employee'
        $ExpectedEmployeeCIDR = '172.20.8.0/22'
        Mock New-NetFirewallRule { return [pscustomobject] @{ Name = $Name } }

        New-ManagementFirewallRule -OwnershipDescription 'RegenBioOverseasAccessServer;TransactionId=test' | Out-Null

        Assert-MockCalled New-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter {
            $Name -eq 'RegenBioOverseasAccess-BlockManagement-Employee' -and
            $Direction -eq 'Inbound' -and $Action -eq 'Block' -and
            $RemoteAddress -eq '172.20.8.0/22' -and
            (@($LocalPort) -join ',') -eq '22,3389,5985,5986' -and
            @($LocalPort).Count -eq 4
        }
    }

    It 'recognizes exact ports, ranges, and Any across CIM multi-value arrays' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
        $definition = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Test-PortSpecificationIncludes'
        }, $true))[0]
        . ([scriptblock]::Create($definition.Extent.Text))
        (Test-PortSpecificationIncludes -Specification @('443', '18443') -Port 18443) | Should Be $true
        (Test-PortSpecificationIncludes -Specification @('80', '18000-19000') -Port 18443) | Should Be $true
        (Test-PortSpecificationIncludes -Specification @('80', 'Any') -Port 18443) | Should Be $true
        (Test-PortSpecificationIncludes -Specification @('443', '8443') -Port 18443) | Should Be $false
    }

    It 'never removes an empty directory whose transaction marker was not published' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
        $definition = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Remove-OwnedDirectory'
        }, $true))[0]
        $unitDefinition = $definition.Extent.Text -replace '^function Remove-OwnedDirectory', 'function Invoke-RemoveOwnedDirectoryUnderTest'
        . ([scriptblock]::Create($unitDefinition))
        @($definition.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) -contains 'AllowEmptyUnmarked' | Should Be $false

        $OwnerMarkerName = 'owner.json'
        $transactionId = [guid]::NewGuid().ToString('D')
        $partialDirectory = Join-Path $TestDrive 'created-before-marker'
        New-Item -ItemType Directory -Path $partialDirectory | Out-Null

        $failureMessage = ''
        try {
            Invoke-RemoveOwnedDirectoryUnderTest -Path $partialDirectory -TransactionId $transactionId
        }
        catch {
            $failureMessage = $_.Exception.Message
        }
        $failureMessage | Should Match 'unmarked directory'
        (Test-Path -LiteralPath $partialDirectory -PathType Container) | Should Be $true

        $markedDirectory = Join-Path $TestDrive 'marked-owned-directory'
        New-Item -ItemType Directory -Path $markedDirectory | Out-Null
        [System.IO.File]::WriteAllText(
            (Join-Path $markedDirectory $OwnerMarkerName),
            ([ordered] @{ Kind = 'RegenBioOverseasAccessServerOwner'; TransactionId = $transactionId } | ConvertTo-Json),
            (New-Object System.Text.UTF8Encoding($false))
        )
        Invoke-RemoveOwnedDirectoryUnderTest -Path $markedDirectory -TransactionId $transactionId
        (Test-Path -LiteralPath $markedDirectory) | Should Be $false
    }
}
