$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$installerPath = Join-Path $repoRoot 'deploy/client/install-client.ps1'
$ErrorActionPreference = 'Stop'
function Get-UpgradeFailure {
    param([scriptblock] $Action)
    try { & $Action } catch { return $_.Exception.Message }
    return ''
}

Describe 'Client upgrade restoration protocol' {
    BeforeEach {
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($installerPath, [ref]$tokens, [ref]$errors)
        foreach ($name in @('Assert-RestorationResponse', 'Read-BoundedPipeFrame', 'Request-ControlledDisconnect','Assert-TunAbsent','Assert-OwnedRoutesAbsent','Assert-DnsRestored','Assert-NetworkRestored','Assert-ServiceAbsent','Assert-OwnedFirewallAbsent')) {
            $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
            if ($null -ne $definition) { . ([scriptblock]::Create($definition.Extent.Text)) }
        }
    }

    It 'accepts successful legacy disconnected and prepared restoration replies' {
        (Get-Command Assert-RestorationResponse -ErrorAction SilentlyContinue) | Should Not BeNullOrEmpty
        foreach ($state in @('disconnected', 'prepared')) {
            (Get-UpgradeFailure { Assert-RestorationResponse -Response ([pscustomobject]@{id='request1';state=$state}) -RequestId 'request1' }) | Should Be ''
        }
    }

    It 'accepts only version one idle status from a versioned reply' {
        (Get-UpgradeFailure { Assert-RestorationResponse -Response ([pscustomobject]@{id='request1';version=1;status=[pscustomobject]@{state='idle'}}) -RequestId 'request1' }) | Should Be ''
        (Get-UpgradeFailure { Assert-RestorationResponse -Response ([pscustomobject]@{id='request1';version=2;status=[pscustomobject]@{state='idle'}}) -RequestId 'request1' }) | Should Match 'protocol'
    }

    It 'rejects mismatched ids errors active and failed safe states' {
        foreach ($response in @(
            @{id='other';state='prepared'}, @{id='request1';state='connected'},
            @{id='request1';state='failed_safe'}, @{id='request1';state='prepared';error_code='restore_failed'},
            @{id='request1';version=1;status=@{state='idle';error_code='restore_failed'}},
            @{id='request1';state='idle'}, @{id='request1';version=1;status=@{state='prepared'}}
        )) {
            (Get-UpgradeFailure { Assert-RestorationResponse -Response ($response | ConvertTo-Json | ConvertFrom-Json) -RequestId 'request1' }) | Should Not Be ''
        }
    }

    It 'reads a complete UTF8 newline frame and rejects truncated or oversized frames' {
        $stream = New-Object IO.MemoryStream -ArgumentList @(,[Text.Encoding]::UTF8.GetBytes("{`"id`":`"request1`"}`n"))
        try { (Read-BoundedPipeFrame -Stream $stream) | Should Be '{"id":"request1"}' } finally { $stream.Dispose() }
        foreach ($frame in @('no-newline', (('x' * 65537) + "`n"))) {
            $stream = New-Object IO.MemoryStream -ArgumentList @(,[Text.Encoding]::UTF8.GetBytes($frame))
            try { (Get-UpgradeFailure { Read-BoundedPipeFrame -Stream $stream }) | Should Not Be '' } finally { $stream.Dispose() }
        }
    }

    It 'bounds a real asynchronous pipe that never sends a reply' {
        $name = 'RegenBioInstallerTest-' + [guid]::NewGuid().ToString('N')
        $server = New-Object IO.Pipes.NamedPipeServerStream($name, [IO.Pipes.PipeDirection]::Out, 1, [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous)
        $client = New-Object IO.Pipes.NamedPipeClientStream('.', $name, [IO.Pipes.PipeDirection]::In, [IO.Pipes.PipeOptions]::Asynchronous)
        try {
            $connection = $server.WaitForConnectionAsync()
            $client.Connect(1000)
            $connection.Wait(1000) | Should Be $true
            $timer = [Diagnostics.Stopwatch]::StartNew()
            (Get-UpgradeFailure { Read-BoundedPipeFrame -Stream $client -TimeoutMilliseconds 100 }) | Should Match 'timed out'
            $timer.ElapsedMilliseconds | Should BeLessThan 3000
        }
        finally { $client.Dispose(); $server.Dispose() }
    }

    It 'lets absent service proceed to the callers independent residue proof' {
        $ServiceName = 'RegenBioInstallerTest-Absent'
        Mock Get-Service { return @() }
        (Get-UpgradeFailure { Request-ControlledDisconnect }) | Should Be ''
        Assert-MockCalled Get-Service -Times 1 -Exactly
        $text = Get-Content -LiteralPath $installerPath -Raw
        $text | Should Match 'if\s*\(\$MsiPreRemove\)[\s\S]*Request-ControlledDisconnect\s+Assert-NetworkRestored'
    }

    It 'proves a stopped service baseline without starting a replacement service during old removal' {
        $ServiceName = 'RegenBioInstallerTest-Stopped'
        Mock Get-Service { [pscustomobject]@{Name='RegenBioInstallerTest-Stopped';Status='Stopped'} }
        Mock Start-Service { throw 'must not start replacement service' }
        function Assert-NetworkRestored { $script:proofCalled = $true }
        $script:proofCalled = $false
        (Get-UpgradeFailure { Request-ControlledDisconnect }) | Should Be ''
        $script:proofCalled | Should Be $true
        function Assert-NetworkRestored { throw 'residue remains' }
        (Get-UpgradeFailure { Request-ControlledDisconnect }) | Should Match 'residue remains'
        Assert-MockCalled Start-Service -Times 0 -Exactly
    }

    It 'rejects every network enumeration failure instead of treating it as zero residue' {
        $TunAlias = 'RegenBioInstallerTest'; $RuntimeFirewallGroup = 'RegenBioInstallerTest'
        $DataRoot = $TestDrive
        foreach ($command in @('Get-NetAdapter','Get-NetRoute','Get-DnsClientServerAddress','Get-NetFirewallRule')) { Mock $command { return @() } }
        foreach ($command in @('Get-NetAdapter','Get-NetRoute','Get-DnsClientServerAddress','Get-NetFirewallRule')) {
            Mock $command {
                param($ErrorAction)
                if ($ErrorAction -eq 'Stop') { throw 'enumeration failed' }
                return @()
            }
            (Get-UpgradeFailure { Assert-NetworkRestored }) | Should Match 'enumeration failed'
            Mock $command { return @() }
        }
    }

    It 'keeps every embedded restoration function byte equivalent to the authoritative harness' {
        $embedded = [IO.File]::ReadAllText((Join-Path $repoRoot 'cmd/installer-verifier/upgrade_restore_windows.go')).Replace("`r`n", "`n")
        foreach ($name in @('Assert-RestorationResponse','Read-BoundedPipeFrame','Request-ControlledDisconnect','Assert-TunAbsent','Assert-OwnedRoutesAbsent','Assert-DnsRestored','Assert-NetworkRestored')) {
            $definition = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name}, $true)
            $embedded.Contains($definition.Extent.Text.Replace("`r`n", "`n")) | Should Be $true
        }
    }

    It 'rejects terminal service and firewall discovery failures while permitting proven empty stores' {
        $ServiceName = 'RegenBioInstallerTest'; $RuntimeFirewallGroup = 'RegenBioInstallerTest'; $OwnedFirewallRules = @('RegenBioInstallerTest-Rule')
        Mock Get-Service { param($ErrorAction); if ($ErrorAction -eq 'Stop') { throw 'service enumeration failed' }; return @() }
        Mock Get-NetFirewallRule { param($ErrorAction); if ($ErrorAction -eq 'Stop') { throw 'firewall enumeration failed' }; return @() }
        (Get-UpgradeFailure { Assert-ServiceAbsent }) | Should Match 'service enumeration failed'
        (Get-UpgradeFailure { Assert-OwnedFirewallAbsent }) | Should Match 'firewall enumeration failed'
        Mock Get-Service { return @() }; Mock Get-NetFirewallRule { return @() }
        (Get-UpgradeFailure { Assert-ServiceAbsent }) | Should Be ''
        (Get-UpgradeFailure { Assert-OwnedFirewallAbsent }) | Should Be ''
    }

    It 'flushes verified replacement files before old cleanup and restores state before any new service start' {
        [xml]$product = Get-Content (Join-Path $repoRoot 'deploy/client/Product.wxs') -Raw
        $package = $product.Wix.Package
        $package.MajorUpgrade.Schedule | Should Be 'afterInstallExecute'
        $sequence = $package.InstallExecuteSequence
        @($sequence.Custom | Where-Object { $_.Action -eq 'PrepareClientUpgrade' })[0].Before | Should Be 'StopServices'
        @($sequence.Custom | Where-Object { $_.Action -eq 'BackupUpgradeSnapshot' })[0].After | Should Be 'RollbackUpgradeSnapshot'
        @($sequence.Custom | Where-Object { $_.Action -eq 'RestoreUpgradeSnapshot' })[0].After | Should Be 'RemoveExistingProducts'
        $sequence.InstallExecute.Sequence | Should Be '6500'
        $sequence.StartServices.Sequence | Should Be '6550'
        $sequence.InstallExecuteAgain.After | Should Be 'CommitUpgradeSnapshot'
        $sequence.InstallExecuteAgain.Condition | Should Be 'NOT REMOVE~="ALL"'
    }
}
