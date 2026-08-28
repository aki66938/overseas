$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptPath = Join-Path $repoRoot 'deploy\client\install-client.ps1'
$productPath = Join-Path $repoRoot 'deploy\client\Product.wxs'
$filesPath = Join-Path $repoRoot 'deploy\client\Files.wxs'
$makefilePath = Join-Path $repoRoot 'Makefile'

function Get-ClientInstallFailureMessage {
    param([Parameter(Mandatory = $true)][scriptblock] $Action)

    try { & $Action }
    catch { return $_.Exception.Message }
    return ''
}

Describe 'Transactional Windows client installer' {
    It 'exists, parses in Windows PowerShell 5.1, and exposes only explicit lifecycle modes' {
        (Test-Path -LiteralPath $scriptPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { return }

        $tokens = $null
        $errors = $null
        [void] [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
        $errors.Count | Should Be 0
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Match "ValidateSet\('Install',\s*'Repair',\s*'Uninstall',\s*'Status'\)"
        $text | Should Match 'Mandatory\s*=\s*\$true[\s\S]*?\[string\]\s*\$Mode'
        $text | Should Match 'TransactionId='
    }

    It 'requires elevation before discovery or mutation for every mutating mode' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $elevation = $text.IndexOf('Assert-Elevated')
        $firstDiscovery = $text.IndexOf('Get-Service')
        $firstMutation = $text.IndexOf('$PSCmdlet.ShouldProcess(')
        $elevation | Should BeGreaterThan -1
        $firstDiscovery | Should BeGreaterThan $elevation
        $firstMutation | Should BeGreaterThan $elevation
        $text | Should Match '\$Mode\s+-in\s+@\(''Install'',\s*''Repair'',\s*''Uninstall''\)'
    }

    It 'verifies every payload hash and required signature before the transaction journal or mutation' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        foreach ($literal in @('overseas-agent.exe', 'overseas-client.exe', 'sing-box.exe', 'sing-box.manifest.json', 'agent.yaml', 'agent.yaml.p7s', 'wintun.dll')) {
            $text | Should Match ([regex]::Escape($literal))
        }
        $hashIndex = $text.IndexOf('Assert-PayloadHashes')
        $signatureIndex = $text.IndexOf('Assert-PayloadSignatures')
        $journalIndex = $text.IndexOf('Write-TransactionJournal')
        $mutationIndex = $text.IndexOf('$PSCmdlet.ShouldProcess(')
        $hashIndex | Should BeGreaterThan -1
        $signatureIndex | Should BeGreaterThan $hashIndex
        $journalIndex | Should BeGreaterThan $signatureIndex
        $mutationIndex | Should BeGreaterThan $journalIndex
        $text | Should Match 'Get-AuthenticodeSignature'
        $text | Should Match 'SignedCms'
        $text | Should Match 'CheckSignature\(\$true\)'
        $text | Should Not Match '(?i)Invoke-WebRequest|Start-BitsTransfer|System\.Net\.WebClient|HttpClient'
    }

    It 'authenticates the payload manifest with a code-pinned signer before trusting its contents' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Match '\$TrustedManifestSignerThumbprint\s*=\s*''[A-F0-9]{40}'''
        $readStart = $text.IndexOf('function Read-PayloadManifest')
        $readEnd = $text.IndexOf('function Assert-PayloadHashes')
        $body = $text.Substring($readStart, $readEnd - $readStart)
        $body | Should Match 'Assert-DetachedSignatureWithPinnedSigner'
        $body | Should Match '\.p7s'
        $body.IndexOf('Assert-DetachedSignatureWithPinnedSigner') | Should BeLessThan $body.IndexOf('ConvertFrom-Json')
        $body | Should Match '\[IO\.File\]::ReadAllBytes\(\$Path\)'
        $body | Should Match 'Encoding\]::UTF8\.GetString\(\$manifestBytes\)'
        $body | Should Not Match 'Get-Content\s+-LiteralPath\s+\$Path'
    }

    It 'pins absolute owned roots and applies restrictive ACLs before publishing files' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        foreach ($literal in @(
            'C:\Program Files\RegenBio\OverseasAccess',
            'C:\ProgramData\RegenBio\OverseasAccess',
            'RegenBioOverseasAccessAgent',
            'SYSTEM:(OI)(CI)(F)',
            'Administrators:(OI)(CI)(F)',
            'Users:(OI)(CI)(RX)'
        )) { $text | Should Match ([regex]::Escape($literal)) }
        $aclIndex = $text.IndexOf('Protect-OwnedDirectory')
        $copyIndex = $text.IndexOf('Copy-PayloadFile')
        $aclIndex | Should BeGreaterThan -1
        $copyIndex | Should BeGreaterThan $aclIndex
        $text | Should Match '/inheritance:r'
        $text | Should Match '/setowner[^\r\n]*\*S-1-5-32-544'
    }

    It 'registers delayed-auto service recovery and only exact owned firewall rules' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        foreach ($literal in @(
            'RegenBioOverseasAccess-AllowAgent-Out',
            'RegenBioOverseasAccess-AllowCoreTCP-Out',
            'RegenBioOverseasAccess-AllowCoreUDP-Out',
            'RegenBio Overseas Access Agent'
        )) { $text | Should Match ([regex]::Escape($literal)) }
        $text | Should Match 'DelayedAutoStart\s*=\s*\$true'
        $text | Should Match 'ChangeServiceConfig2'
        $text | Should Match 'ResetPeriod'
        $text | Should Match 'RestartService'
        $text | Should Match 'New-NetFirewallRule'
        $text | Should Match '-PolicyStore\s+ActiveStore'
        $text | Should Not Match '(?i)-DisplayGroup|Get-NetFirewallRule\s+-DisplayName\s+[^\r\n]*\*'
    }

    It 'creates only owned start-menu shortcut and journals rollback compensation in reverse order' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Match 'RegenBio Overseas Access\.lnk'
        $text | Should Match 'Windows Script Host Object Model'
        $start = $text.IndexOf('function Undo-ClientTransaction')
        $end = $text.IndexOf('function Install-ClientTransaction')
        $body = $text.Substring($start, $end - $start)
        $firewallIndex = $body.IndexOf('Remove-OwnedFirewallRules')
        $shortcutIndex = $body.IndexOf('Remove-OwnedShortcut')
        $serviceIndex = $body.IndexOf('Remove-OwnedService')
        $installIndex = $body.IndexOf('Remove-OwnedDirectory -Path $InstallRoot')
        $dataIndex = $body.IndexOf('Remove-OwnedDirectory -Path $DataRoot')
        $firewallIndex | Should BeGreaterThan -1
        $shortcutIndex | Should BeGreaterThan $firewallIndex
        $serviceIndex | Should BeGreaterThan $shortcutIndex
        $installIndex | Should BeGreaterThan $serviceIndex
        $dataIndex | Should BeGreaterThan $installIndex
        $text | Should Match '\bcatch\s*\{[^}]*Undo-ClientTransaction'
    }

    It 'disconnects through the fixed pipe before service removal and refuses success without restoration proof' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $start = $text.IndexOf('function Uninstall-ClientTransaction')
        $body = $text.Substring($start)
        $disconnectIndex = $body.IndexOf('Request-ControlledDisconnect')
        $proofIndex = $body.IndexOf('Assert-NetworkRestored')
        $serviceIndex = $body.IndexOf('Remove-OwnedService')
        $disconnectIndex | Should BeGreaterThan -1
        $proofIndex | Should BeGreaterThan $disconnectIndex
        $serviceIndex | Should BeGreaterThan $proofIndex
        $text | Should Match ([regex]::Escape('\\.\pipe\RegenBioOverseasAccess'))
        $text | Should Match 'restoration could not be proven'
        $text | Should Match 'Refusing to remove the client'
    }

    It 'removes only manifest-owned resources and proves no service TUN route DNS or firewall residue' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        foreach ($proof in @('Assert-ServiceAbsent', 'Assert-TunAbsent', 'Assert-OwnedRoutesAbsent', 'Assert-DnsRestored', 'Assert-OwnedFirewallAbsent')) {
            $text | Should Match ([regex]::Escape($proof))
        }
        $text | Should Match 'owner\.json'
        $text | Should Match 'Assert-OwnedPath'
        $text | Should Match 'Get-NetAdapter'
        $text | Should Match 'Get-NetRoute'
        $text | Should Match 'Get-DnsClientServerAddress'
        $text | Should Not Match '(?im)^\s*Remove-Item[^\r\n]*(\*|\?)'
        $text | Should Not Match '(?i)Remove-NetRoute\s+-DestinationPrefix\s+0\.0\.0\.0/0'
    }

    It 'makes repair idempotent and rejects downgrade before mutation' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Match 'Assert-NotDowngrade'
        $text | Should Match '\[version\]'
        $text | Should Match 'requested version .* older than installed version'
        $text | Should Match 'Repair-ClientTransaction'
        $text | Should Match 'Ensure-OwnedFirewallRules'
        $text | Should Match 'Ensure-OwnedService'
        $text | Should Match 'AlreadyCurrent'
    }

    It 'has no dynamic execution plaintext-secret parameter secret-bearing native argv or registry write' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
        $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
        @($commands | Where-Object { $_.GetCommandName() -eq 'Invoke-Expression' }).Count | Should Be 0
        $parameters = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ParameterAst] }, $true))
        @($parameters | Where-Object { $_.Name.VariablePath.UserPath -match '(?i)secret|password|token|pin|credential' }).Count | Should Be 0
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Not Match '(?i)New-ItemProperty|Set-ItemProperty[^\r\n]*(secret|password|token|pin|credential)'
        $text | Should Not Match '(?im)^\s*&[^\r\n]*(secret|password|token|pin|credential)'
        $text | Should Not Match '(?i)Write-(Host|Output|Verbose|Debug|Information)[^\r\n]*(secret|password|token|pin|credential)'
    }

    It 'runs the complete install preflight under WhatIf without persistent mutation' {
        Mock Get-AuthenticodeSignature { throw 'signature gate reached safely' }
        Mock New-Service { throw 'mutation must not run' }
        Mock New-NetFirewallRule { throw 'mutation must not run' }
        Mock Copy-Item { throw 'mutation must not run' }
        $message = Get-ClientInstallFailureMessage {
            & $scriptPath -Mode Install -BundlePath (Join-Path $TestDrive 'missing') -PayloadManifestPath (Join-Path $TestDrive 'missing.json') -WhatIf
        }
        $message | Should Match 'BundlePath|payload manifest|signature gate'
        Assert-MockCalled New-Service -Times 0 -Exactly -Scope It
        Assert-MockCalled New-NetFirewallRule -Times 0 -Exactly -Scope It
        Assert-MockCalled Copy-Item -Times 0 -Exactly -Scope It
    }

    It 'defines a per-machine x64 WiX v4 package with native service shortcut and upgrade behavior' {
        (Test-Path -LiteralPath $productPath -PathType Leaf) | Should Be $true
        (Test-Path -LiteralPath $filesPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path -LiteralPath $productPath) -or -not (Test-Path -LiteralPath $filesPath)) { return }
        $product = Get-Content -LiteralPath $productPath -Raw
        $files = Get-Content -LiteralPath $filesPath -Raw
        $product | Should Match 'http://wixtoolset\.org/schemas/v4/wxs'
        $product | Should Match 'Scope="perMachine"'
        $product | Should Match '<MajorUpgrade[^>]*DowngradeErrorMessage='
        $product | Should Match 'Manufacturer="RegenBio"'
        $product | Should Match 'RegenBio Overseas Access'
        $files | Should Match '<ServiceInstall[^>]*Name="RegenBioOverseasAccessAgent"'
        $files | Should Match 'Account="LocalSystem"'
        $files | Should Match 'Start="auto"'
        $files | Should Match '<ServiceControl'
        $files | Should Match '<Shortcut'
        $files | Should Match 'Name="DelayedAutostart"[\s\S]*Value="1"'
        $files | Should Match '<util:ServiceConfig[\s\S]*FirstFailureActionType="restart"'
    }

    It 'uses a fixed deferred elevated pre-remove gate where native service control cannot prove restoration' {
        $script = Get-Content -LiteralPath $scriptPath -Raw
        $product = Get-Content -LiteralPath $productPath -Raw
        $files = Get-Content -LiteralPath $filesPath -Raw
        $script | Should Match '\[switch\]\s*\$MsiPreRemove'
        $script | Should Match 'if\s*\(\$MsiPreRemove\)[\s\S]*Request-ControlledDisconnect[\s\S]*Assert-NetworkRestored'
        $files | Should Match 'install-client\.ps1'
        $product | Should Match '<CustomAction[^>]*Id="MsiSafeRemove"[^>]*Execute="deferred"[^>]*Impersonate="no"[^>]*Return="check"'
        $product | Should Match '<SetProperty[^>]*Id="MsiSafeRemove"[^>]*-MsiPreRemove'
        $product | Should Match '<Custom[^>]*Action="MsiSafeRemove"[^>]*Before="StopServices"'
    }

    It 'embeds exactly the allowlisted non-secret payload and uses no secret MSI property or network source' {
        $product = Get-Content -LiteralPath $productPath -Raw
        $files = Get-Content -LiteralPath $filesPath -Raw
        foreach ($file in @('overseas-agent.exe', 'overseas-client.exe', 'sing-box.exe', 'sing-box.manifest.json', 'libcronet.dll', 'wintun.dll', 'agent.yaml', 'agent.yaml.p7s', 'install-client.ps1', 'LICENSE')) {
            $files | Should Match ([regex]::Escape($file))
        }
        $combined = $product + "`n" + $files
        $combined | Should Not Match '(?i)credential\.bin|password|secret|token|private.?key|\.pfx|\.pem'
        $combined | Should Not Match '(?i)DownloadUrl|https?://(?!wixtoolset\.org/schemas/)'
        $combined | Should Not Match '<CustomAction[^>]*(ExeCommand|CommandLine)[^>]*(credential|password|secret|token|pin)'
    }

    It 'wires reproducible local WiX restore MSI build inspection and dual-Pester targets' {
        $text = Get-Content -LiteralPath $makefilePath -Raw
        $text | Should Match '(?m)^WIX\s*\?='
        $text | Should Match '(?m)^msi:'
        $text | Should Match '-bindpath'
        $text | Should Match '-arch x64'
        $text | Should Match 'OverseasAccessSetup\.msi'
        $text | Should Match '(?m)^inspect-msi:'
        $text | Should Match '(?m)^test-client-install:'
        ([regex]::Matches($text, 'ClientInstall\.Tests\.ps1')).Count | Should Be 2
        $text | Should Match 'powershell\.exe'
        $text | Should Match 'pwsh'
    }
}
