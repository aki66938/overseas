$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptPath = Join-Path $repoRoot 'deploy\client\install-client.ps1'
$productPath = Join-Path $repoRoot 'deploy\client\Product.wxs'
$filesPath = Join-Path $repoRoot 'deploy\client\Files.wxs'
$makefilePath = Join-Path $repoRoot 'Makefile'
$buildLockPath = Join-Path $repoRoot 'deploy\client\build-lock.json'
$checksumsLockPath = Join-Path $repoRoot 'deploy\client\checksums.lock'
$artifactBuilderPath = Join-Path $repoRoot 'scripts\windows\build-client-artifacts.ps1'
$msiInspectorPath = Join-Path $repoRoot 'scripts\windows\inspect-client-msi.ps1'

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
        foreach ($literal in @('overseas-agent.exe', 'overseas-client.exe', 'credential-provisioner.exe', 'installer-verifier.exe', 'install-client.ps1', 'PROVISIONING.md', 'sing-box.exe', 'sing-box.manifest.json', 'agent.yaml', 'agent.yaml.p7s', 'wintun.dll', 'sing-box-LICENSE.txt', 'wintun-LICENSE.txt')) {
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
        $text | Should Match ([regex]::Escape("foreach (`$name in @('overseas-agent.exe', 'overseas-client.exe', 'credential-provisioner.exe', 'installer-verifier.exe', 'wintun.dll'))"))
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
        $payloadIndex = $body.IndexOf('Remove-OwnedPayloadFiles')
        $markerIndex = $body.IndexOf('Remove-RootOwnershipMarker')
        $firewallIndex | Should BeGreaterThan -1
        $shortcutIndex | Should BeGreaterThan $firewallIndex
        $serviceIndex | Should BeGreaterThan $shortcutIndex
        $payloadIndex | Should BeGreaterThan $serviceIndex
        $markerIndex | Should BeGreaterThan $payloadIndex
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
        $markerIndex = $body.IndexOf('Remove-RootOwnershipMarker')
        $journalIndex = $body.IndexOf('Remove-Item -LiteralPath $JournalPath')
        $proofIndex | Should BeGreaterThan -1
        $markerIndex | Should BeGreaterThan $proofIndex
        $journalIndex | Should BeGreaterThan $markerIndex
        $body | Should Match 'catch\s*\{[\s\S]*Write-TransactionPhase[\s\S]*throw'
        $body | Should Match 'if\s*\(Test-Path\s+-LiteralPath\s+\$root\s+-PathType\s+Container\)\s*\{\s*Remove-OwnedPayloadFiles'
        $body | Should Match 'if\s*\(Test-Path\s+-LiteralPath\s+\$root\s+-PathType\s+Container\)\s*\{[\s\S]*Remove-RootOwnershipMarker'
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
        $combined | Should Not Match '(?i)credential\.bin|password|secret|token|private.?key|\.pfx|\.pem'
        $combined | Should Not Match '(?i)DownloadUrl|https?://(?!wixtoolset\.org/schemas/)'
        $combined | Should Not Match '<CustomAction[^>]*(ExeCommand|CommandLine)[^>]*(credential|password|secret|token|pin)'
    }

    It 'packages a stdin-only credential provisioner and leaves the service stopped until provisioning' {
        $files = Get-Content -LiteralPath $filesPath -Raw
        $script = Get-Content -LiteralPath $scriptPath -Raw
        $files | Should Match 'credential-provisioner\.exe'
        $files | Should Match 'PROVISIONING\.md'
        $files | Should Not Match '<ServiceControl[^>]*Start="install"'
        $script | Should Match '\$CredentialPath\s*=\s*Join-Path\s+\$DataRoot\s+''credential\.bin'''
        $script | Should Match 'if\s*\(Test-Path\s+-LiteralPath\s+\$CredentialPath\s+-PathType\s+Leaf\)\s*\{[\s\S]*Start-Service'
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

    It 'locks every external artifact and packages Wintun attribution distinctly' {
        (Test-Path -LiteralPath $buildLockPath -PathType Leaf) | Should Be $true
        (Test-Path -LiteralPath $checksumsLockPath -PathType Leaf) | Should Be $true
        if (-not (Test-Path $buildLockPath) -or -not (Test-Path $checksumsLockPath)) { return }
        $lock = Get-Content -LiteralPath $buildLockPath -Raw | ConvertFrom-Json
        $lock.schema_version | Should Be 1
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
        $files | Should Match 'Wintun is distributed under the GPLv2'
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
        $text | Should Match 'git\s+rev-parse\s+HEAD'
        $text | Should Match 'git\s+status\s+--porcelain'
        $text | Should Match 'INSPECT-ONLY-NOT-SIGNED'
        $text | Should Match 'Cert:\\(CurrentUser|LocalMachine)\\My'
        $text | Should Match 'HasPrivateKey'
        $text | Should Not Match '(?i)New-SelfSignedCertificate|Import-PfxCertificate|password|Invoke-WebRequest|Start-BitsTransfer|HttpClient'
        $text.IndexOf("if (`$Mode -eq 'Release')") | Should BeLessThan $text.IndexOf('Remove-Item -LiteralPath $target -Recurse')
        $text.IndexOf('git status --porcelain') | Should BeLessThan $text.IndexOf('Remove-Item -LiteralPath $target -Recurse')
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
        $text | Should Match 'build-client-artifacts\.ps1'
        $text | Should Match 'inspect-client-msi\.ps1'
    }
}
