$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptPath = Join-Path $repoRoot 'deploy\client\install-client.ps1'
$productPath = Join-Path $repoRoot 'deploy\client\Product.wxs'
$filesPath = Join-Path $repoRoot 'deploy\client\Files.wxs'
$makefilePath = Join-Path $repoRoot 'Makefile'
$buildLockPath = Join-Path $repoRoot 'deploy\client\build-lock.json'
$checksumsLockPath = Join-Path $repoRoot 'deploy\client\checksums.lock'
$artifactBuilderPath = Join-Path $repoRoot 'scripts\windows\build-client-artifacts.ps1'
$msiInspectorPath = Join-Path $repoRoot 'scripts\windows\inspect-client-msi.ps1'
$releasePublisherPath = Join-Path $repoRoot 'scripts\windows\publish-client-release.ps1'
$verifierWindowsPath = Join-Path $repoRoot 'cmd\installer-verifier\main_windows.go'
$verifierMainPath = Join-Path $repoRoot 'cmd\installer-verifier\main.go'
$runtimeOwnerPath = Join-Path $repoRoot 'internal\runtimeowner\owner.go'
$credentialWriterPath = Join-Path $repoRoot 'cmd\credential-provisioner\main_windows.go'
$configWriterPath = Join-Path $repoRoot 'cmd\overseas-agent\main_windows.go'
$realTestPathCommand = Get-Command Test-Path -CommandType Cmdlet

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
        foreach ($literal in @('overseas-agent.exe', 'overseas-client.exe', 'installer-verifier.exe', 'install-client.ps1', 'sing-box.exe', 'sing-box.manifest.json', 'agent.yaml', 'agent.yaml.p7s', 'wintun.dll', 'sing-box-LICENSE.txt', 'wintun-LICENSE.txt')) {
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
        $text | Should Match ([regex]::Escape("foreach (`$name in @('overseas-agent.exe', 'overseas-client.exe', 'installer-verifier.exe', 'wintun.dll'))"))
        $text | Should Not Match '(?i)Invoke-WebRequest|Start-BitsTransfer|System\.Net\.WebClient|HttpClient'

        $requiredStart = $text.IndexOf('$RequiredPayloads = @(')
        $requiredEnd = $text.IndexOf('function Assert-Elevated')
        $requiredBlock = $text.Substring($requiredStart, $requiredEnd - $requiredStart)
        $requiredBlock | Should Match ([regex]::Escape("'client-sbom.json'"))
        $requiredBlock | Should Match ([regex]::Escape("'SHA256SUMS'"))
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
        $rootIndex = $body.IndexOf('Remove-OwnedRoot')
        $firewallIndex | Should BeGreaterThan -1
        $shortcutIndex | Should BeGreaterThan $firewallIndex
        $serviceIndex | Should BeGreaterThan $shortcutIndex
        $rootIndex | Should BeGreaterThan $serviceIndex
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

    It 'behaviorally refuses a pre-existing root without an exact ownership marker' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $start = $text.IndexOf('function Assert-InstallCollisions')
        $end = $text.IndexOf('function ', $start + 10)
        $start | Should BeGreaterThan -1
        if ($start -lt 0) { return }
        if ($end -lt 0) { $end = $text.Length }
        Invoke-Expression $text.Substring($start, $end - $start)
        function Test-ValidRootMarker { return $false }
        function Test-JournalOwnsResource { return $false }
        Mock Test-Path { return $true }
        (Get-ClientInstallFailureMessage { Assert-InstallCollisions }) | Should Match 'pre-existing unowned root'
    }

    It 'journals each resource before creation and publishes exact per-root markers' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Match '\$RootOwnerFileName\s*=\s*''\.regenbio-overseas-access\.owner\.json'''
        $text | Should Match 'function Write-TransactionPhase'
        $text | Should Match 'PendingResource'
        $text | Should Match 'CreatedResources'
        $installStart = $text.IndexOf('function Install-ClientTransaction')
        $installEnd = $text.IndexOf('function Repair-ClientTransaction')
        $body = $text.Substring($installStart, $installEnd - $installStart)
        $body.IndexOf("Write-TransactionPhase -Path `$JournalPath -Phase 'CreatingInstallRoot'") | Should BeLessThan $body.IndexOf('Protect-OwnedDirectory -Path $InstallRoot')
        $body.IndexOf('Write-RootOwnershipMarker -Root $InstallRoot') | Should BeGreaterThan $body.IndexOf('Protect-OwnedDirectory -Path $InstallRoot')
        $body.IndexOf("Write-TransactionPhase -Path `$JournalPath -Phase 'CreatingDataRoot'") | Should BeLessThan $body.IndexOf('Protect-OwnedDirectory -Path $DataRoot')
        $body.IndexOf('Write-RootOwnershipMarker -Root $DataRoot') | Should BeGreaterThan $body.IndexOf('Protect-OwnedDirectory -Path $DataRoot')
    }

    It 'never overwrites or removes a shortcut whose exact target is not owned' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Match 'function Test-OwnedShortcut'
        $text | Should Match '\.TargetPath'
        $text | Should Match 'TargetPath\),\s*\(Join-Path\s+\$InstallRoot\s+''overseas-client\.exe''\)'
        $removeStart = $text.IndexOf('function Remove-OwnedShortcut')
        $removeEnd = $text.IndexOf('function Remove-OwnedService')
        $removeBody = $text.Substring($removeStart, $removeEnd - $removeStart)
        $removeBody | Should Match 'Test-OwnedShortcut'
        $removeBody | Should Match 'not installer-owned'
    }

    It 'uses the durable journal to resume partial ownership without accepting foreign resources' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Match 'function Test-JournalOwnsResource'
        $text | Should Match 'function Assert-RemoveOwnership'
        $text | Should Match 'Assert-InstallCollisions\s+-JournalPath\s+\$resumePath'
        $text | Should Match 'Assert-RemoveOwnership\s+-JournalPath\s+\$resumePath'
        $text | Should Match 'Test-JournalOwnsResource\s+-JournalPath\s+\$JournalPath\s+-Resource\s+\$root'
        $removeCheck = $text.IndexOf('Assert-RemoveOwnership -JournalPath $resumePath')
        $uninstallDecision = $text.IndexOf('if (-not $PSCmdlet.ShouldProcess($InstallRoot, "Uninstall client;')
        $removeCheck | Should BeGreaterThan -1
        $removeCheck | Should BeLessThan $uninstallDecision
    }

    It 'keeps repair and uninstall resumable and deletes ownership proof last' {
        $text = Get-Content -LiteralPath $scriptPath -Raw
        $text | Should Match 'Get-ResumableJournal'
        $text | Should Match "-Phase\s+'RepairPayloads'"
        $text | Should Match "-Phase\s+'UninstallDisconnect'"
        $text | Should Match 'Resume-ClientTransaction'
        $uninstallStart = $text.IndexOf('function Uninstall-ClientTransaction')
        $statusStart = $text.IndexOf('function Get-ClientStatus')
        $body = $text.Substring($uninstallStart, $statusStart - $uninstallStart)
        $proofIndex = $body.IndexOf('Assert-OwnedFirewallAbsent')
        $rootIndex = $body.IndexOf('Remove-OwnedRoot')
        $journalIndex = $body.IndexOf('Remove-Item -LiteralPath $JournalPath')
        $proofIndex | Should BeGreaterThan -1
        $rootIndex | Should BeGreaterThan $proofIndex
        $journalIndex | Should BeGreaterThan $rootIndex
        $body | Should Match 'catch\s*\{[\s\S]*Write-TransactionPhase[\s\S]*throw'
        $body | Should Match 'Remove-OwnedRoot\s+-Root\s+\$root\s+-JournalPath\s+\$JournalPath'
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
        $message | Should Match 'BundlePath|payload manifest|signature gate|Could not find file'
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
        $files | Should Match 'Start="demand"'
        $files | Should Match '<ServiceControl'
        $files | Should Match '<Shortcut'
        $files | Should Not Match 'Name="DelayedAutostart"'
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
        $product | Should Not Match 'NOT\s+UPGRADINGPRODUCTCODE'
    }

    It 'fails untrusted install repair and upgrade before InstallInitialize using a first-party Binary action' {
        $product = Get-Content -LiteralPath $productPath -Raw
        $files = Get-Content -LiteralPath $filesPath -Raw
        $product | Should Match 'INSPECT_ONLY_REFUSES_INSTALL'
        $product | Should Match '<Binary[^>]*Id="InstallerVerifierBinary"[^>]*installer-verifier\.exe'
        $product | Should Match '<CustomAction[^>]*Id="VerifyPackageTrust"[^>]*BinaryRef="InstallerVerifierBinary"[^>]*Execute="immediate"[^>]*Return="check"'
        $product | Should Match '<Custom[^>]*Action="VerifyPackageTrust"[^>]*Before="InstallInitialize"'
        $product | Should Match 'OriginalDatabase'
        $product | Should Match 'NOT Installed OR REINSTALL OR WIX_UPGRADE_DETECTED'
        $files | Should Match 'installer-verifier\.exe'
    }

    It 'verifies the installed signed payload after files and before service or firewall mutation' {
        $product = Get-Content -LiteralPath $productPath -Raw
        $product | Should Match '<CustomAction[^>]*Id="VerifyInstalledPayload"[^>]*BinaryRef="InstallerVerifierBinary"[^>]*Execute="deferred"[^>]*Impersonate="no"[^>]*Return="check"'
        $product | Should Match '<Custom[^>]*Action="VerifyInstalledPayload"[^>]*Before="InstallServices"'
        $product | Should Match 'After InstallFiles; before InstallServices'
        $product | Should Match 'artifact-manifest\.json'
        $product | Should Match 'artifact-manifest\.json\.p7s'
    }

    It 'embeds exactly the allowlisted non-secret payload and uses no secret MSI property or network source' {
        $product = Get-Content -LiteralPath $productPath -Raw
        $files = Get-Content -LiteralPath $filesPath -Raw
        foreach ($file in @('overseas-agent.exe', 'overseas-client.exe', 'sing-box.exe', 'sing-box.manifest.json', 'libcronet.dll', 'wintun.dll', 'agent.yaml', 'agent.yaml.p7s', 'install-client.ps1', 'LICENSE')) {
            $files | Should Match ([regex]::Escape($file))
        }
        $combined = $product + "`n" + $files
        $combined | Should Not Match '(?i)<File[^>]*(credential\.bin|password|secret|token|private.?key|\.pfx|\.pem)'
        $combined | Should Not Match '(?i)<Property[^>]*(credential|password|secret|token|pin)'
        $combined | Should Not Match '(?i)DownloadUrl|https?://(?!wixtoolset\.org/schemas/)'
        $combined | Should Not Match '<CustomAction[^>]*(ExeCommand|CommandLine)[^>]*(credential|password|secret|token|pin)'
    }

    It 'leaves the demand-start service stopped after installation' {
        $files = Get-Content -LiteralPath $filesPath -Raw
        $script = Get-Content -LiteralPath $scriptPath -Raw
        $files | Should Match 'Start="demand"'
        $files | Should Not Match 'credential-provisioner\.exe|PROVISIONING\.md'
        $files | Should Not Match '<ServiceControl[^>]*Start="install"'
        $installStart = $script.IndexOf('function Install-ClientTransaction')
        $installEnd = $script.IndexOf('function Uninstall-ClientTransaction', $installStart)
        $script.Substring($installStart, $installEnd - $installStart) | Should Not Match 'Start-Service'
    }

    It 'wires reproducible local WiX restore MSI build inspection and dual-Pester targets' {
        $text = Get-Content -LiteralPath $makefilePath -Raw
        $text | Should Match 'invoke-locked-client-tool\.ps1'
        $text | Should Not Match '(?m)^(WIX|WIX_UTIL_EXT|WIX_FIREWALL_EXT|DTF)\s*:='
        $text | Should Match '(?m)^msi:'
        $text | Should Match '-bindpath'
        $text | Should Match "'-arch','x64'"
        $text | Should Match 'OverseasAccessSetup\.msi'
        $text | Should Match '(?m)^inspect-msi:'
        $text | Should Match '(?m)^test-client-install:'
        ([regex]::Matches($text, 'ClientInstall\.Tests\.ps1')).Count | Should Be 2
        $text | Should Match 'powershell\.exe'
        $text | Should Match 'pwsh'
    }

    It 'locks every external artifact and packages Wintun attribution distinctly' {
        (Test-Path -LiteralPath $buildLockPath -PathType Leaf) | Should Be $true
        (Test-Path -LiteralPath $checksumsLockPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path $buildLockPath) -or -not (Test-Path $checksumsLockPath)) { return }
        $lock = Get-Content -LiteralPath $buildLockPath -Raw | ConvertFrom-Json
        $lock.schema_version | Should Be 2
        $lock.go.version | Should Be '1.27.0'
        $lock.wix.version | Should Be '4.0.6'
        $lock.sing_box.version | Should Be '1.13.19'
        $lock.wintun.version | Should Be '0.14.1'
        $lock.wintun.archive_sha256 | Should Match '^[a-f0-9]{64}$'
        $checksums = Get-Content -LiteralPath $checksumsLockPath -Raw
        $checksums | Should Match 'wintun-0\.14\.1\.zip'
        $checksums | Should Match 'sing-box-1\.13\.19-windows-amd64\.zip'
        $files = Get-Content -LiteralPath $filesPath -Raw
        $files | Should Match 'wintun-LICENSE\.txt'
        $files | Should Match 'Wintun Prebuilt Binaries License'
        $files | Should Not Match '(?i)GPL|General Public License'
    }

    It 'builds canonical manifest SBOM and checksums offline and signs only from an external certificate store' {
        (Test-Path -LiteralPath $artifactBuilderPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path $artifactBuilderPath)) { return }
        $text = Get-Content -LiteralPath $artifactBuilderPath -Raw
        $text | Should Match "ValidateSet\('Inspect',\s*'Release'\)"
        $text | Should Match 'artifact-manifest\.json'
        $text | Should Match 'artifact-manifest\.json\.p7s'
        $text | Should Match 'client-sbom\.json'
        $text | Should Match 'SHA256SUMS'
        $text | Should Match 'git\s+-C\s+\$repo\s+rev-parse\s+HEAD'
        $text | Should Match 'git\s+-C\s+\$repo\s+status\s+--porcelain'
        $text | Should Match 'INSPECT-ONLY-NOT-SIGNED'
        $text | Should Match 'Cert:\\(CurrentUser|LocalMachine)\\My'
        $text | Should Match 'HasPrivateKey'
        $text | Should Not Match '(?i)New-SelfSignedCertificate|Import-PfxCertificate|password|Invoke-WebRequest|Start-BitsTransfer|HttpClient'
        $text.IndexOf("if (`$Mode -eq 'Release')") | Should BeLessThan $text.IndexOf('Remove-Item -LiteralPath $target -Recurse')
        $text.IndexOf('git -C $repo status --porcelain') | Should BeLessThan $text.IndexOf('Remove-Item -LiteralPath $target -Recurse')
    }

    It 'recursively verifies every extracted byte signature and secret scan against the source manifest' {
        (Test-Path -LiteralPath $msiInspectorPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path $msiInspectorPath)) { return }
        $text = Get-Content -LiteralPath $msiInspectorPath -Raw
        $text | Should Match 'Get-ChildItem[^\r\n]*-Recurse'
        $text | Should Match 'Compare-Object'
        $text | Should Match 'Get-FileHash'
        $text | Should Match 'Get-AuthenticodeSignature'
        $text | Should Match 'SignedCms'
        $text | Should Match 'MsiLockPermissionsEx'
        $text | Should Match 'InstallExecuteSequence'
        $text | Should Match 'VerifyPackageTrust.*InstallInitialize'
        $text | Should Match 'MsiSafeRemove.*StopServices'
        $text | Should Match 'VerifyInstalledPayload.*InstallServices'
        $text | Should Match 'D:P\(A;OICI;FA;;;SY\)'
        $text | Should Match 'INSPECT_ONLY_REFUSES_INSTALL|RELEASE_SIGNED'
        $text | Should Match 'BEGIN \(RSA \|EC \)\?PRIVATE KEY'
        $text | Should Match 'credential|secret|token'
        $text | Should Match '\$binaryForbiddenContent'
        $text | Should Match '\$textExtensions'
        $text | Should Match 'if\s*\(\(?\$textExtensions\s+-contains\s+\$file\.Extension'
        $text | Should Match '\$embeddedCorporateThumbprint'
        $text | Should Match 'manifest\.mode\s+-eq\s+''release''[\s\S]*Get-AuthenticodeSignature\s+-LiteralPath\s+\$MsiPath'
        $text | Should Match 'SignerInfos\[0\]\.Certificate\.Thumbprint[\s\S]*embeddedCorporateThumbprint'
    }

    It 'exposes separate inspect-only and externally signed release MSI targets' {
        $text = Get-Content -LiteralPath $makefilePath -Raw
        $text | Should Match '(?m)^release-msi:'
        $text | Should Match 'SIGNING_CERT_THUMBPRINT'
        $text | Should Match 'CLIENT_RELEASE_MSI\s*\?=.*RELEASE_SIGNED\.msi'
        $text | Should Match 'build-client-artifacts\.ps1'
        $text | Should Match 'inspect-client-msi\.ps1'
    }

    It 'owns and resumably removes the generated runtime config after process termination' {
        $script = Get-Content -LiteralPath $scriptPath -Raw
        $files = Get-Content -LiteralPath $filesPath -Raw
        $product = Get-Content -LiteralPath $productPath -Raw
        $script | Should Match 'runtime-owned\.json'
        $script | Should Match 'sing-box\.json'
        $script | Should Match 'Clear-OwnedSensitiveRuntimeFiles'
        $script.IndexOf('Remove-OwnedService') | Should BeLessThan $script.IndexOf('Clear-OwnedSensitiveRuntimeFiles')
        $script | Should Match 'SensitiveCleanupIncomplete'
        $files | Should Match '<RemoveFile[^>]*Name="sing-box\.json"'
        $product | Should Match 'CleanupOwnedRuntime'
    }

    It 'passes only fixed payload paths to the embedded deferred verifier and sequences first-party firewall rollback' {
        $product = Get-Content -LiteralPath $productPath -Raw
        $files = Get-Content -LiteralPath $filesPath -Raw
        $product | Should Not Match '<SetProperty[^>]*Id="VerifyInstalledPayload"'
        $product | Should Match 'ExeCommand="payload --program-files &quot;C:\\Program Files\\RegenBio\\OverseasAccess&quot; --program-data &quot;C:\\ProgramData\\RegenBio\\OverseasAccess&quot; --manifest &quot;C:\\ProgramData\\RegenBio\\OverseasAccess\\artifact-manifest\.json&quot; --signature &quot;C:\\ProgramData\\RegenBio\\OverseasAccess\\artifact-manifest\.json\.p7s&quot; --thumbprint &quot;\$\(var\.CorporateSigningThumbprint\)&quot;"'
        $product | Should Not Match '\[CustomActionData\]'
        $product | Should Match 'RollbackClientFirewall'
        $product | Should Match 'InstallClientFirewall'
        $files | Should Not Match 'fire:FirewallException'
        $files | Should Not Match 'xmlns:fire'
    }

    It 'enforces exact trust-root coverage locked tools and atomic release publication' {
        $builder = Get-Content -LiteralPath $artifactBuilderPath -Raw
        $inspector = Get-Content -LiteralPath $msiInspectorPath -Raw
        $inspector | Should Match '\$expectedPayloadCommand'
        $inspector | Should Match '\$payloadDataActions\.Count -ne 0'
        $builder | Should Match 'go\.version'
        $builder | Should Match 'wix\.sdk_sha256'
        $builder | Should Match '\[IO\.Directory\]::Move\('
        $builder | Should Match 'finally[\s\S]*Remove-Item[^\r\n]*temporary'
        $builder | Should Match 'Wintun Prebuilt Binaries License'
        $inspector | Should Match 'trustRootNames'
        $inspector | Should Match 'Compare-Object[^\r\n]*coveredNames[^\r\n]*payloadNames'
        $inspector | Should Match 'InstallClientFirewall.*InstallServices'
        (Test-Path -LiteralPath $releasePublisherPath -PathType Leaf) | Should Be $true
        if (Test-Path -LiteralPath $releasePublisherPath) {
            $publisher = Get-Content -LiteralPath $releasePublisherPath -Raw
            $publisher | Should Match 'build-client-artifacts\.ps1[\s\S]*wix[\s\S]*signtool[\s\S]*inspect-client-msi\.ps1[\s\S]*\[IO\.File\]::Move'
            $publisher | Should Match 'finally[\s\S]*Remove-TemporaryReleaseRoot'
        }
    }

    It 'journals exact MSI firewall intent and ownership before mutation and separates rollback from uninstall' {
        $verifier = (Get-Content -LiteralPath $verifierWindowsPath -Raw) + "`n" + (Get-Content -LiteralPath $verifierMainPath -Raw)
        $product = Get-Content -LiteralPath $productPath -Raw
        $verifier | Should Match 'msi-firewall-owned\.json'
        $verifier | Should Match 'schema_version'
        $verifier | Should Match 'current_operation'
        $verifier | Should Match "'intended'"
        $verifier | Should Match "'created'"
        $verifier | Should Match "'preexisting'"
        $verifier | Should Match 'Get-NetFirewallApplicationFilter'
        $verifier | Should Match 'Get-NetFirewallPortFilter'
        $verifier | Should Match 'Get-NetFirewallSecurityFilter'
        $verifier | Should Match 'Write-FirewallJournal'
        $verifier | Should Match "icacls\.exe[^\r\n]*/inheritance:r[^\r\n]*S-1-5-18[^\r\n]*S-1-5-32-544"
        $verifier.IndexOf('Write-FirewallJournal') | Should BeLessThan $verifier.IndexOf('New-NetFirewallRule')
        $verifier | Should Match 'firewall-rollback'
        $verifier | Should Match 'firewall-uninstall'
        $product | Should Match 'Id="RollbackClientFirewall"[^>]*ExeCommand="firewall-rollback"'
        $product | Should Match 'Id="RemoveClientFirewall"[^>]*ExeCommand="firewall-uninstall"'
        $product | Should Match 'Action="RemoveClientFirewall"[^>]*Condition="REMOVE~=&quot;ALL&quot;"'
        $source = Get-Content -LiteralPath $verifierWindowsPath -Raw
        $match = [regex]::Match($source, '(?s)const firewallLifecycleScript = `(.*?)`\r?\n\r?\nfunc \(windowsTrustVerifier\) installFirewall')
        $match.Success | Should Be $true
        if ($match.Success) {
            $tokens = $null
            $parseErrors = $null
            [Management.Automation.Language.Parser]::ParseInput($match.Groups[1].Value, [ref] $tokens, [ref] $parseErrors) | Out-Null
            @($parseErrors).Count | Should Be 0
        }
    }

    It 'executes MSI firewall install repair failure rollback and uninstall against mocked state' {
        Mock Test-Path { param($LiteralPath, $PathType); if ($PathType) { & $realTestPathCommand -LiteralPath $LiteralPath -PathType $PathType } else { & $realTestPathCommand -LiteralPath $LiteralPath } }
        $source = Get-Content -LiteralPath $verifierWindowsPath -Raw
        $match = [regex]::Match($source, '(?s)const firewallLifecycleScript = `(.*?)`\r?\n\r?\nfunc \(windowsTrustVerifier\) installFirewall')
        $match.Success | Should Be $true
        if (-not $match.Success) { return }
        $data = Join-Path $TestDrive 'firewall-state'
        New-Item -ItemType Directory -Path $data | Out-Null
        $lifecycleText = $match.Groups[1].Value.Replace("`$data='C:\ProgramData\RegenBio\OverseasAccess'", "`$data='" + $data.Replace("'", "''") + "'")
        $lifecycleText = $lifecycleText -replace '& "\$env:WINDIR\\System32\\icacls\.exe"[^\r\n]*', '$global:LASTEXITCODE=0'
        $lifecycleText = $lifecycleText -replace 'exit 0', 'return'
        foreach ($command in @('Get-NetFirewallRule','Get-NetFirewallApplicationFilter','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter','Get-NetFirewallServiceFilter','Get-NetFirewallInterfaceFilter','Get-NetFirewallSecurityFilter','New-NetFirewallRule','Remove-NetFirewallRule')) {
            $lifecycleText = $lifecycleText.Replace($command, ('Test-' + $command))
        }
        $lifecycle = [scriptblock]::Create($lifecycleText)
        $script:firewallState = @{}
        $script:createCount = 0
        $script:failAt = 0
        $script:publishConcurrentRuleOnFailure = $false
        function Test-Get-NetFirewallRule { param($Name,$PolicyStore,$ErrorAction); if ($script:firewallState.ContainsKey($Name)) { return ($script:firewallState[$Name].Rule) } }
        function Test-Get-NetFirewallApplicationFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process { return ($InputObject.App) } }
        function Test-Get-NetFirewallPortFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process { return ($InputObject.Port) } }
        function Test-Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process { return ($InputObject.Address) } }
        function Test-Get-NetFirewallServiceFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process { return ($InputObject.ServiceFilter) } }
        function Test-Get-NetFirewallInterfaceFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process { return ($InputObject.InterfaceFilter) } }
        function Test-Get-NetFirewallSecurityFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process { return ($InputObject.SecurityFilter) } }
        function New-TestFirewallRecord {
            param($Name,$DisplayName,$Group,$Direction,$Action,$Program,$Protocol,$Profile,$Enabled)
            $record = [pscustomobject]@{}
            $record | Add-Member Rule ([pscustomobject]@{ Name=$Name; DisplayName=$DisplayName; Group=$Group; Direction=$Direction; Action=$Action; Enabled=$Enabled; Profile=$Profile })
            $record.Rule | Add-Member App ([pscustomobject]@{ Program=$Program; Package='Any' })
            $record.Rule | Add-Member Port ([pscustomobject]@{ Protocol=$Protocol; LocalPort='Any'; RemotePort='Any' })
            $record.Rule | Add-Member Address ([pscustomobject]@{ LocalAddress='Any'; RemoteAddress='Any' })
            $record.Rule | Add-Member ServiceFilter ([pscustomobject]@{ Service='Any' })
            $record.Rule | Add-Member InterfaceFilter ([pscustomobject]@{ InterfaceType='Any'; InterfaceAlias='Any' })
            $record.Rule | Add-Member SecurityFilter ([pscustomobject]@{ Authentication='NotRequired'; Encryption='NotRequired'; LocalUser='Any'; RemoteUser='Any'; RemoteMachine='Any'; OverrideBlockRules=$false })
            return $record
        }
        function Test-New-NetFirewallRule {
            param($Name,$DisplayName,$Group,$Direction,$Action,$Program,$Protocol,$Profile,$Enabled,$PolicyStore)
            $script:createCount++
            if ($script:failAt -eq $script:createCount) {
                if ($script:publishConcurrentRuleOnFailure) {
                    $script:firewallState[$Name] = New-TestFirewallRecord -Name $Name -DisplayName 'Foreign concurrent rule' -Group 'Foreign.Owner' -Direction Outbound -Action Block -Program 'C:\Foreign\foreign.exe' -Protocol $Protocol -Profile Any -Enabled $true
                }
                throw 'injected firewall creation failure'
            }
            $record = New-TestFirewallRecord -Name $Name -DisplayName $DisplayName -Group $Group -Direction $Direction -Action $Action -Program $Program -Protocol $Protocol -Profile $Profile -Enabled $Enabled
            $script:firewallState[$Name] = $record
        }
        function Test-Remove-NetFirewallRule { param($Name,$PolicyStore,$ErrorAction); [void]$script:firewallState.Remove($Name) }

        [IO.File]::WriteAllText((Join-Path $data 'msi-firewall-owned.json'), '{"schema_version":2,"product_id":"RegenBioOverseasAccess","owned_rules":[],"current_operation":null}')
        Test-New-NetFirewallRule -Name 'RegenBioOverseasAccess-AllowAgent-Out' -DisplayName 'RegenBioOverseasAccess-AllowAgent-Out' -Group 'RegenBioOverseasAccess.Installer' -Direction Outbound -Action Allow -Program 'C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe' -Protocol TCP -Profile Any -Enabled $true -PolicyStore PersistentStore
        { & $lifecycle 'install' } | Should Throw 'ownership proof'
        $script:firewallState.Clear(); [IO.File]::WriteAllText((Join-Path $data 'msi-firewall-owned.json'), '{"schema_version":2,"product_id":"RegenBioOverseasAccess","owned_rules":[],"current_operation":null}'); $script:createCount = 0
        & $lifecycle 'install'
        $script:firewallState.Count | Should Be 3
        & $lifecycle 'install' # exact journal-owned repair
        $script:createCount | Should Be 3
        & $lifecycle 'rollback' # repair rollback preserves rules created by the prior install
        $script:firewallState.Count | Should Be 3
        $script:firewallState['RegenBioOverseasAccess-AllowAgent-Out'].Rule.SecurityFilter.Authentication = 'Required'
        { & $lifecycle 'uninstall' } | Should Throw 'exactly match'
        $script:firewallState['RegenBioOverseasAccess-AllowAgent-Out'].Rule.SecurityFilter.Authentication = 'NotRequired'
        & $lifecycle 'uninstall'
        $script:firewallState.Count | Should Be 0

        $script:createCount = 0; $script:failAt = 2
        { & $lifecycle 'install' } | Should Throw 'injected firewall creation failure'
        $script:firewallState.Count | Should Be 1
        & $lifecycle 'rollback'
        $script:firewallState.Count | Should Be 0

        # A foreign process wins the same-name race after our absence proof and failed create.
        $script:createCount = 0; $script:failAt = 2; $script:publishConcurrentRuleOnFailure = $true
        [IO.File]::WriteAllText((Join-Path $data 'msi-firewall-owned.json'), '{"schema_version":2,"product_id":"RegenBioOverseasAccess","owned_rules":[],"current_operation":null}')
        { & $lifecycle 'install' } | Should Throw 'injected firewall creation failure'
        { & $lifecycle 'rollback' } | Should Throw 'exactly match'
        $script:firewallState.ContainsKey('RegenBioOverseasAccess-AllowCoreTCP-Out') | Should Be $true
        (Test-Path -LiteralPath (Join-Path $data 'msi-firewall-owned.json') -PathType Leaf) | Should Be $true
        $concurrentJournal = Get-Content -LiteralPath (Join-Path $data 'msi-firewall-owned.json') -Raw | ConvertFrom-Json
        $concurrentJournal.current_operation | Should Not BeNullOrEmpty

        # A created rule is replaced or drifts before rollback; name alone is not ownership proof.
        $script:firewallState.Clear(); $script:createCount = 0; $script:failAt = 2; $script:publishConcurrentRuleOnFailure = $false
        [IO.File]::WriteAllText((Join-Path $data 'msi-firewall-owned.json'), '{"schema_version":2,"product_id":"RegenBioOverseasAccess","owned_rules":[],"current_operation":null}')
        { & $lifecycle 'install' } | Should Throw 'injected firewall creation failure'
        $script:firewallState['RegenBioOverseasAccess-AllowAgent-Out'].Rule.App.Program = 'C:\Foreign\replacement.exe'
        { & $lifecycle 'rollback' } | Should Throw 'exactly match'
        $script:firewallState.ContainsKey('RegenBioOverseasAccess-AllowAgent-Out') | Should Be $true
        (Test-Path -LiteralPath (Join-Path $data 'msi-firewall-owned.json') -PathType Leaf) | Should Be $true
        $driftJournal = Get-Content -LiteralPath (Join-Path $data 'msi-firewall-owned.json') -Raw | ConvertFrom-Json
        @($driftJournal.current_operation.rules | Where-Object { $_.name -eq 'RegenBioOverseasAccess-AllowCoreTCP-Out' -and $_.rollback_state -eq 'resolved' }).Count | Should Be 1
    }

    It 'publishes the generated config through schema-v2 intents and finalization' {
        $owner = Get-Content -LiteralPath $runtimeOwnerPath -Raw
        $config = Get-Content -LiteralPath $configWriterPath -Raw
        $verifier = Get-Content -LiteralPath $verifierWindowsPath -Raw
        $owner | Should Match 'SchemaVersion\s+int[^\r\n]*json:"schema_version"'
        $owner | Should Match 'Intents\s+\[\]ownershipIntent[^\r\n]*json:"intents"'
        $owner | Should Match 'Finalized\s+\[\]string[^\r\n]*json:"finalized"'
        foreach ($field in @('Target', 'Temporary', 'Backup', 'Replaced', 'Phase')) { $owner | Should Match ("$field\s+string") }
        $owner | Should Match 'lockRuntimeOwnership'
        $owner | Should Match 'func Publish\('
        $config | Should Match 'runtimeowner\.Publish\('
        $config.IndexOf('runtimeowner.Publish(') | Should BeLessThan $config.IndexOf('os.OpenFile(')
        $verifier | Should Match ([regex]::Escape("`$s=@('credential.bin','sing-box.json')"))
        $verifier | Should Match ([regex]::Escape('if(!(Test-Path -LiteralPath $l)){foreach($n in $s){if(Test-Path -LiteralPath (Join-Path $d $n)){exit 40}};exit 0}'))
        $verifier | Should Match '\$o\.intents'
        $verifier | Should Match '\$o\.finalized'
    }

    It 'securely cleans every structured crash-residue path before deleting the ledger' {
        Mock Test-Path { param($LiteralPath, $PathType); if ($PathType) { & $realTestPathCommand -LiteralPath $LiteralPath -PathType $PathType } else { & $realTestPathCommand -LiteralPath $LiteralPath } }
        $script = Get-Content -LiteralPath $scriptPath -Raw
        $start = $script.IndexOf('function Clear-OwnedSensitiveRuntimeFiles')
        $end = $script.IndexOf('function Remove-OwnedDirectory', $start)
        Invoke-Expression $script.Substring($start, $end - $start)
        $script:DataRoot = Join-Path $TestDrive 'runtime'
        New-Item -ItemType Directory -Path $script:DataRoot | Out-Null
        $script:RuntimeOwnershipPath = Join-Path $script:DataRoot 'runtime-owned.json'
        $intent = [ordered]@{
            target = 'sing-box.json'; temporary = '.sing-box.json.publish-11111111111111111111111111111111.tmp'
            backup = '.sing-box.json.backup-22222222222222222222222222222222.tmp'
            replaced = '.sing-box.json.replaced-33333333333333333333333333333333.tmp'; phase = 'published'
        }
        [IO.File]::WriteAllText($script:RuntimeOwnershipPath, ([ordered]@{ schema_version = 2; intents = @($intent); finalized = @('sing-box.json') } | ConvertTo-Json -Depth 6))
        foreach ($name in @($intent.target, $intent.temporary, $intent.backup, $intent.replaced)) {
            [IO.File]::WriteAllText((Join-Path $script:DataRoot $name), 'sensitive-residue')
        }
        Clear-OwnedSensitiveRuntimeFiles
        @(Get-ChildItem -LiteralPath $script:DataRoot -Force).Count | Should Be 0
    }

    It 'keeps root ownership proof for foreign residue and makes a failed root delete resumable' {
        $script = Get-Content -LiteralPath $scriptPath -Raw
        $start = $script.IndexOf('function Remove-OwnedRoot')
        $end = $script.IndexOf('function ', $start + 10)
        $start | Should BeGreaterThan -1
        if ($start -lt 0) { return }
        if ($end -lt 0) { $end = $script.Length }
        $body = $script.Substring($start, $end - $start)
        $body | Should Match 'Get-ChildItem[^\r\n]*Where-Object'
        $body.IndexOf('Get-ChildItem') | Should BeLessThan $body.IndexOf('Remove-RootOwnershipMarker')
        $body.IndexOf('Write-TransactionPhase') | Should BeLessThan $body.IndexOf('Remove-RootOwnershipMarker')
        $body.IndexOf('Remove-RootOwnershipMarker') | Should BeLessThan $body.IndexOf('Remove-Item -LiteralPath $Root')
        $body | Should Match 'if\s*\(Test-Path[^\r\n]*\)\s*\{\s*throw'
        $script | Should Match 'Test-UninstallJournalOwnsRootDeletion'
        $script | Should Match 'RootDeletionIncomplete''\s+-PendingResource\s+\$pendingRoot'
    }

    It 'preserves the pending root when deletion fails after marker removal' {
        Mock Test-Path { param($LiteralPath, $PathType); if ($PathType) { & $realTestPathCommand -LiteralPath $LiteralPath -PathType $PathType } else { & $realTestPathCommand -LiteralPath $LiteralPath } }
        $script = Get-Content -LiteralPath $scriptPath -Raw
        $start = $script.IndexOf('function Uninstall-ClientTransaction')
        $end = $script.IndexOf('function Get-ClientStatus', $start)
        Invoke-Expression $script.Substring($start, $end - $start)
        $script:InstallRoot = 'C:\Program Files\RegenBio\OverseasAccess'
        $script:DataRoot = 'C:\ProgramData\RegenBio\OverseasAccess'
        $script:ShortcutPath = Join-Path $TestDrive 'absent-shortcut.lnk'
        $journalPath = Join-Path $TestDrive 'uninstall.json'
        [IO.File]::WriteAllText($journalPath, '{"SchemaVersion":2,"Operation":"Uninstall","Phase":"DeletingRoot","PendingResource":"C:\\Program Files\\RegenBio\\OverseasAccess"}')
        foreach ($name in @('Resume-ClientTransaction','Request-ControlledDisconnect','Assert-NetworkRestored','Remove-OwnedFirewallRules','Remove-OwnedShortcut','Remove-OwnedService','Clear-OwnedSensitiveRuntimeFiles','Assert-ServiceAbsent','Assert-TunAbsent','Assert-OwnedRoutesAbsent','Assert-DnsRestored','Assert-OwnedFirewallAbsent')) {
            Set-Item -Path ('function:' + $name) -Value { }
        }
        function Remove-OwnedRoot { throw 'injected root delete failure' }
        $script:phaseWrites = @()
        function Write-TransactionPhase { param($Path,$Phase,$PendingResource,$CompletedResource); $script:phaseWrites += ,@($Phase,$PendingResource) }
        { Uninstall-ClientTransaction -TransactionId ([guid]::NewGuid()) -JournalPath $journalPath } | Should Throw 'injected root delete failure'
        $script:phaseWrites[-1][0] | Should Be 'RootDeletionIncomplete'
        $script:phaseWrites[-1][1] | Should Be $script:InstallRoot
    }

    It 'binds Make and the release publisher to hash-verified Go WiX and extension executables' {
        $lock = Get-Content -LiteralPath $buildLockPath -Raw | ConvertFrom-Json
        $makefile = Get-Content -LiteralPath $makefilePath -Raw
        $publisher = Get-Content -LiteralPath $releasePublisherPath -Raw
        $lock.schema_version | Should Be 2
        $lock.go.executable_sha256 | Should Match '^[a-f0-9]{64}$'
        $lock.wix.executable_sha256 | Should Match '^[a-f0-9]{64}$'
        $lock.wix.util_extension_sha256 | Should Match '^[a-f0-9]{64}$'
        $lock.wix.firewall_extension_sha256 | Should Match '^[a-f0-9]{64}$'
        $makefile | Should Match 'invoke-locked-client-tool\.ps1'
        $makefile | Should Not Match '(?m)^GO\s*\?='
        $makefile | Should Not Match '(?m)^WIX\s*\?='
        $makefile | Should Not Match "'-ext'"
        $publisher | Should Not Match '\[Parameter\(Mandatory\s*=\s*\$true\)\]\[string\]\s*\$(WixPath|UtilExtensionPath|DtfPath)'
        $publisher | Should Match 'executable_sha256'
        $publisher | Should Match 'util_extension_sha256'
        $publisher | Should Match '\$goExecutable\s+@arguments'
        $publisher | Should Match '-FirstPartyBinaryDirectory\s+\$firstParty'
        $publisher | Should Match 'git\s+-C\s+\$repo\s+status'
        $inspector = Get-Content -LiteralPath $msiInspectorPath -Raw
        $inspector | Should Not Match '\[string\]\s+\$(WixPath|DtfPath)'
        $inspector | Should Match 'Resolve-VerifiedTool'
        $inspector | Should Match 'dtf_sha256'
        $wrapper = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\windows\invoke-locked-client-tool.ps1') -Raw
        $wrapper | Should Match "WiX extension paths are supplied only by the verified tool wrapper"
        $wrapper | Should Match '\$ToolArguments\s*=\s*@\(\$ToolArguments\)[^\r\n]*\$utilExtension[^\r\n]*\$firewallExtension'
    }

    It 'creates only a validated release parent and atomically publishes after a clean-checkout proof' {
        $builder = Get-Content -LiteralPath $artifactBuilderPath -Raw
        $publisher = Get-Content -LiteralPath $releasePublisherPath -Raw
        foreach ($text in @($builder, $publisher)) {
            $text | Should Match 'Assert-SafeReleaseParent'
            $text | Should Match '\[IO\.(Directory|File)\]::Move\('
            $text.IndexOf('git -C $repo status --porcelain') | Should BeLessThan $text.IndexOf('Assert-SafeReleaseParent')
        }
    }

    It 'waits for exclusive MSI access before atomic publication and bounds temporary cleanup retries' {
        $publisher = Get-Content -LiteralPath $releasePublisherPath -Raw
        $inspector = Get-Content -LiteralPath $msiInspectorPath -Raw
        $publisher | Should Match 'function Wait-ExclusiveFileAccess'
        $publisher | Should Match '\[IO\.File\]::Open\([^\r\n]*FileShare\]::None'
        $publisher | Should Match 'Wait-ExclusiveFileAccess\s+-Path\s+\$temporaryMsi\s+-TimeoutSeconds\s+15'
        $publisher | Should Match 'function Remove-TemporaryReleaseRoot'
        $publisher | Should Match 'Remove-TemporaryReleaseRoot\s+-Path\s+\$temporaryRoot\s+-TimeoutSeconds\s+15'
        $publisher | Should Match '\$publicationError\s*=\s*\$_'
        $publisher | Should Match 'if\s*\(\$null\s+-ne\s+\$publicationError\)\s*\{\s*throw\s+\$publicationError'
        $inspector | Should Match '\$database\.Dispose\(\)'
        $inspector | Should Match '\[GC\]::Collect\(\)'
        $inspector | Should Match '\[GC\]::WaitForPendingFinalizers\(\)'
        $inspector | Should Match "@\('ServiceInstall','ServiceControl','RemoveFile','Upgrade'\)"
        $inspector | Should Not Match "@\('ServiceInstall','ServiceControl','Registry','RemoveFile','Upgrade'\)"
    }

    It 'uses only the Wintun Prebuilt Binaries License attribution' {
        $combined = @(
            (Get-Content -LiteralPath $filesPath -Raw),
            (Get-Content -LiteralPath $artifactBuilderPath -Raw),
            (Get-Content -LiteralPath $buildLockPath -Raw),
            (Get-Content -LiteralPath $checksumsLockPath -Raw)
        ) -join "`n"
        $combined | Should Match 'Wintun Prebuilt Binaries License'
        $combined | Should Not Match '(?i)GPL|General Public License'
    }

    It 'packages a disconnected proxy-neutral schema two HTTP CONNECT client' {
        $files = Get-Content -LiteralPath $filesPath -Raw
        $product = Get-Content -LiteralPath (Join-Path $repoRoot 'deploy\client\Product.wxs') -Raw
        $script = Get-Content -LiteralPath $scriptPath -Raw
        $policy = Get-Content -LiteralPath (Join-Path $repoRoot 'deploy\client\agent.yaml') -Raw
        $builder = Get-Content -LiteralPath $artifactBuilderPath -Raw
        $publisher = Get-Content -LiteralPath $releasePublisherPath -Raw
        $verifier = Get-Content -LiteralPath (Join-Path $repoRoot 'cmd\installer-verifier\main_windows.go') -Raw
        $combined = @($files, $product, $script, $builder, $publisher) -join "`n"

        $policy | Should Match '(?m)^\s*schema_version:\s*2\s*$'
        $policy | Should Match '(?m)^\s*transport:\s*http-connect\s*$'
        $policy | Should Match '(?m)^\s*address:\s*172\.20\.9\.15\s*$'
        $policy | Should Match '(?m)^\s*port:\s*8080\s*$'
        $policy | Should Not Match '(?i)credential|18443|shadowsocks'
        $combined | Should Not Match '(?i)credential-provisioner\.exe|PROVISIONING\.md|credential\.bin'
        $verifier | Should Not Match "expectedPayloadNames[^\r\n]*(credential-provisioner\.exe|PROVISIONING\.md)"
        $files | Should Match '<ServiceInstall[\s\S]*Start="demand"'
        $files | Should Not Match '<ServiceControl[^>]*Start="install"'
        $combined | Should Not Match '(?i)netsh\s+winhttp|Internet Settings|FlClash'
        $installStart = $script.IndexOf('function Install-ClientTransaction')
        $installEnd = $script.IndexOf('function Repair-ClientTransaction', $installStart)
        $repairEnd = $script.IndexOf('function Uninstall-ClientTransaction', $installEnd)
        $script.Substring($installStart, $repairEnd - $installStart) | Should Not Match '(?i)Start-Service'
    }
}
