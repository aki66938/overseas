$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$runbookPath = Join-Path $repositoryRoot 'docs\poc-runbook.md'
$makefilePath = Join-Path $repositoryRoot 'Makefile'
$gitignorePath = Join-Path $repositoryRoot '.gitignore'

function Assert-DocumentationFileExists {
    param([Parameter(Mandatory = $true)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $false | Should Be $true
        return $false
    }
    return $true
}

Describe 'Windows forwarding PoC operator documentation' {
    It 'documents the hardened evidence sequence and its bindings' {
        if (-not (Assert-DocumentationFileExists -Path $runbookPath)) { return }
        $runbook = Get-Content -LiteralPath $runbookPath -Raw

        foreach ($text in @(
            'written operator approval',
            'operator-approved HTTPS target',
            'VM console access',
            'recovery snapshot',
            'current telecom PIN holder availability',
            'maintenance window',
            '100.127.77.0/24',
            '100.64.0.0/10',
            'SchemaVersion = 2',
            'PayloadBase64',
            'PayloadSha256',
            'describe-config',
            'config_digest',
            'telecom_route_prefixes',
            'Get-FileHash',
            'PocProbeSha256',
            'probe-telecom-up.json',
            'probe-telecom-down.json',
            'probe-telecom-down-monitor.json',
            'inventory-before.json',
            'inventory-after.json',
            'verdict.json',
            'Rollback verification failed',
            'WhatIf'
        )) {
            $runbook | Should Match ([regex]::Escape($text))
        }

        foreach ($command in @(
            'poc-probe.exe inventory --config $ConfigPath --run-id $RunId --out $InventoryBeforePath',
            'apply-poc.ps1 -SnapshotPath $SnapshotPath',
            'poc-probe.exe probe --config $ConfigPath --run-id $RunId --out $ProbeUpPath',
            'assert-no-leak.ps1 -ConfigPath $ConfigPath -RunId $RunId',
            'rollback-poc.ps1 -SnapshotPath $SnapshotPath',
            'poc-probe.exe inventory --config $ConfigPath --run-id $RunId --out $InventoryAfterPath',
            'poc-probe.exe verdict --config $ConfigPath --run-id $RunId --artifacts $ArtifactsPath --out $VerdictPath'
        )) {
            $runbook | Should Match ([regex]::Escape($command))
        }
    }

    It 'guards every native invocation immediately with launch and exit signals' {
        if (-not (Assert-DocumentationFileExists -Path $runbookPath)) { return }
        $lines = @(Get-Content -LiteralPath $runbookPath)
        $commands = @()

        for ($index = 0; $index -lt $lines.Count; $index++) {
            $command = $null
            if ($lines[$index] -match '^make\s+(test|build)\s*$') {
                $command = 'make ' + $Matches[1].ToLowerInvariant()
            }
            elseif ($lines[$index] -match '(?i)\.\\bin\\poc-probe\.exe\s+(preflight|describe-config|inventory|probe|verdict)\b') {
                $command = 'poc-probe.exe ' + $Matches[1].ToLowerInvariant()
            }
            if ($null -eq $command) { continue }

            $commands += $command
            ($index + 3 -lt $lines.Count) | Should Be $true

            $launchCapture = $lines[$index + 1].Trim()
            $launchMatch = [regex]::Match($launchCapture, '^\$(?<prefix>[A-Za-z][A-Za-z0-9]*)Succeeded\s*=\s*\$\?\s*$')
            $launchMatch.Success | Should Be $true
            $prefix = $launchMatch.Groups['prefix'].Value

            $exitCapture = $lines[$index + 2].Trim()
            $exitCapture | Should Match ('^\$' + [regex]::Escape($prefix) + 'ExitCode\s*=\s*\$LASTEXITCODE\s*$')

            $guard = $lines[$index + 3].Trim()
            $escapedCommand = [regex]::Escape($command)
            $guardPattern = '^if\s*\(\s*-not\s+\$' + [regex]::Escape($prefix) + 'Succeeded\s+-or\s+\$' + [regex]::Escape($prefix) + 'ExitCode\s+-ne\s+0\s*\)\s*\{\s*throw\s+[''\"]' + $escapedCommand + ' failed to launch or exited with code \$' + [regex]::Escape($prefix) + 'ExitCode\.[''\"]\s*\}\s*$'
            $guard | Should Match $guardPattern

            if ($command -eq 'make build') {
                ($index + 4 -lt $lines.Count) | Should Be $true
                $artifactGuard = $lines[$index + 4].Trim()
                $artifactGuard | Should Match '^if\s*\(\s*-not\s*\(Test-Path\s+-LiteralPath\s+\.\\bin\\poc-probe\.exe\s+-PathType\s+Leaf\s*\)\s*\)\s*\{\s*throw\s+[''\"]make build did not produce bin\\poc-probe\.exe\.[''\"]\s*\}\s*$'
            }
        }

        ($commands -join ',') | Should Be 'make test,make build,poc-probe.exe preflight,poc-probe.exe describe-config,poc-probe.exe inventory,poc-probe.exe probe,poc-probe.exe inventory,poc-probe.exe verdict'
    }

    It 'provides reproducible Go and Pester build targets' {
        if (-not (Assert-DocumentationFileExists -Path $makefilePath)) { return }
        $makefile = Get-Content -LiteralPath $makefilePath -Raw

        $makefile | Should Match '(?m)^LOCKED_CLIENT_TOOL\s*:='
        $makefile | Should Match '(?m)^\.PHONY:\s+test\s+build\s*$'
        $makefile | Should Match '(?m)^test:\s*$'
        $makefile | Should Match 'invoke-locked-client-tool\.ps1'
        $makefile | Should Match "'test','\./\.\.\.'"
        $makefile | Should Match ([regex]::Escape('Invoke-Pester tests/powershell -Output Detailed'))
        $makefile | Should Match '(?m)^build:\s*$'
        $makefile | Should Match "'build','-trimpath','-o','bin/poc-probe\.exe','\./cmd/poc-probe'"
    }

    It 'keeps generated configuration and evidence out of source control' {
        if (-not (Assert-DocumentationFileExists -Path $gitignorePath)) { return }
        $gitignore = Get-Content -LiteralPath $gitignorePath -Raw

        foreach ($entry in @('/configs/poc.yaml', '/artifacts/*', '!/artifacts/.gitkeep', '/artifacts/.poc-config-*', '/artifacts/*.tmp', 'bin/')) {
            $gitignore | Should Match ([regex]::Escape($entry))
        }
    }
}

$singBoxRunbookPath = Join-Path $repositoryRoot 'docs\sing-box-poc-runbook.md'

function Get-SingBoxRunbookLines {
    if (-not (Test-Path -LiteralPath $singBoxRunbookPath -PathType Leaf)) {
        throw "Runbook is missing: $singBoxRunbookPath"
    }
    return @(Get-Content -LiteralPath $singBoxRunbookPath)
}

function Assert-True {
    param([Parameter(Mandatory = $true)][bool] $Condition, [Parameter(Mandatory = $true)][string] $Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Equal {
    param($Actual, $Expected, [Parameter(Mandatory = $true)][string] $Message)
    if ($Actual -cne $Expected) { throw "$Message Expected '$Expected'; got '$Actual'." }
}

function Assert-Matches {
    param([Parameter(Mandatory = $true)][string] $Text, [Parameter(Mandatory = $true)][string] $Pattern, [Parameter(Mandatory = $true)][string] $Message)
    if ($Text -notmatch $Pattern) { throw "$Message Missing pattern: $Pattern" }
}

function Assert-NotMatches {
    param([Parameter(Mandatory = $true)][string] $Text, [Parameter(Mandatory = $true)][string] $Pattern, [Parameter(Mandatory = $true)][string] $Message)
    if ($Text -match $Pattern) { throw "$Message Unexpected pattern: $Pattern" }
}

function Assert-GuardedNativeCommand {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]] $Lines,
        [Parameter(Mandatory = $true)][string] $Command,
        [Parameter(Mandatory = $true)][string] $Prefix
    )

    $index = [Array]::IndexOf($Lines, $Command)
    Assert-True -Condition ($index -gt -1) -Message "Missing native command: $Command"
    Assert-True -Condition (($index + 3) -lt $Lines.Count) -Message "Missing guard after native command: $Command"
    Assert-Equal -Actual $Lines[$index + 1].Trim() -Expected ('$' + $Prefix + 'Succeeded = $?') -Message "Missing immediate launch capture after $Command"
    Assert-Equal -Actual $Lines[$index + 2].Trim() -Expected ('$' + $Prefix + 'ExitCode = $LASTEXITCODE') -Message "Missing immediate exit capture after $Command"
    Assert-Equal -Actual $Lines[$index + 3].Trim() -Expected ("if (-not `$$Prefix`Succeeded -or `$$Prefix`ExitCode -ne 0) { throw '$Command failed to launch or exited with code `$$Prefix`ExitCode.' }") -Message "Missing abort guard after $Command"
}

Describe 'sing-box PoC deployment and acceptance runbook' {
	It 'contains syntactically valid PowerShell blocks' {
		$runbook = Get-Content -LiteralPath $singBoxRunbookPath -Raw
		$blocks = [regex]::Matches($runbook, '(?ms)^```powershell\r?\n(.*?)^```\s*$')
		Assert-True -Condition ($blocks.Count -gt 0) -Message 'Runbook has no PowerShell blocks.'
		foreach ($block in $blocks) {
			try { [void] [scriptblock]::Create($block.Groups[1].Value) }
			catch { throw "Runbook PowerShell block does not parse: $($_.Exception.Message)" }
		}
	}

    It 'exists and records fixed facts and external inputs without live opt-in' {
        Assert-True -Condition (Test-Path -LiteralPath $singBoxRunbookPath -PathType Leaf) -Message "Runbook is missing: $singBoxRunbookPath"
        $runbook = Get-Content -LiteralPath $singBoxRunbookPath -Raw

        foreach ($text in @(
            '172.20.9.15/22', '172.20.10.1', 'interface index 4',
            'DESKTOP-1BVR2H6', '127.0.0.1:8080',
            'actual SSH SHA256 host key fingerprint',
            'corporate signer thumbprint and signed artifacts',
            'credential supplied pipe-only',
            'physical disposable host identity/token',
            'new empty baseline directory',
            'operator stop/go approval',
            'OVERSEAS_ACCESS_INTEGRATION=1 must never be set',
            'developer workstation is not the designated host',
            'remote attestation captured from VM101',
            'source commit',
            'credential-source',
            'server-attestation.json',
			'server_attestation_run_nonce',
            'The only allowed runtime sing-box client config is the product-owned ACL-protected runtime file'
        )) {
            Assert-Matches -Text $runbook -Pattern ([regex]::Escape($text)) -Message 'Missing required runbook input or fact.'
        }

        Assert-NotMatches -Text $runbook -Pattern 'BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY' -Message 'Runbook must not contain a private key.'
        Assert-NotMatches -Text $runbook -Pattern '(?m)^\s*\$env:OVERSEAS_ACCESS_INTEGRATION\s*=' -Message 'Runbook must not enable live integration.'
    }

    It 'puts a stop/go checkpoint before every real mutation group and names exact rollback' {
        $runbook = Get-Content -LiteralPath $singBoxRunbookPath -Raw

        foreach ($text in @(
            'STOP/GO — server install',
            'STOP/GO — standard-client activation',
            'STOP/GO — custom-MSI install',
            'STOP/GO — lifecycle and uninstall',
            'STOP/GO — agent fault',
            'STOP/GO — core fault',
            'STOP/GO — UI fault',
            'STOP/GO — forced reboot',
            'STOP/GO — rollback',
            'deploy\server\install-server.ps1 -Mode Rollback',
            'msiexec.exe /x $CorporateSignedMsiPath /qn /norestart',
			'Confirm the standard sing-box process is gone'
        )) {
            Assert-Matches -Text $runbook -Pattern ([regex]::Escape($text)) -Message 'Missing required stop/go or rollback contract.'
        }
    }

    It 'requires guarded SSH, VM inventory, baseline, telecom CONNECT, and server operations' {
        $lines = Get-SingBoxRunbookLines

        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh-keyscan.exe -t ed25519 $VmSshHost > $ScannedHostKeyPath' -Prefix 'SshKeyscan'
        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh-keygen.exe -lf $ScannedHostKeyPath -E sha256' -Prefix 'SshKeygen'
        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmFactsCommand > $VmFactsPath' -Prefix 'VmFacts'
        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmBaselineCommand > $VmBaselinePath' -Prefix 'VmBaseline'
        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $TelecomConnectCommand > $TelecomConnectPath' -Prefix 'TelecomConnect'
        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmCanonicalStateCommand > $VmWhatIfBeforePath' -Prefix 'VmWhatIfBefore'
        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerWhatIfCommand > $ServerWhatIfPath' -Prefix 'ServerWhatIf'
        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmCanonicalStateCommand > $VmWhatIfAfterPath' -Prefix 'VmWhatIfAfter'
        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerInstallCommand > $ServerInstallPath' -Prefix 'ServerInstall'
        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerStatusCommand > $ServerStatusPath' -Prefix 'ServerStatus'
        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerAttestationCommand > $ServerAttestationPath' -Prefix 'ServerAttestation'
        Assert-GuardedNativeCommand -Lines $lines -Command '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerRollbackCommand > $ServerRollbackPath' -Prefix 'ServerRollback'

        $runbook = $lines -join "`n"
        foreach ($text in @(
            'Get-ComputerInfo', 'Get-NetAdapter', 'Get-NetRoute', 'Get-DnsClientServerAddress',
            'Get-NetTCPConnection', 'Get-Service', 'Get-Process', 'Get-NetFirewallRule',
            'sing-box absence/presence', 'direct Google failure',
            'curl.exe --proxy http://127.0.0.1:8080',
            '-Mode Install', '-Mode Status', '-Mode Rollback', '-WhatIf',
            'Compare-CanonicalStateSnapshots',
            'zero changes after WhatIf',
			'server-WhatIf filesystem registry scheduled tasks server-owned state',
			'filesystem', 'registry', 'scheduled_tasks', 'server_service', 'server_firewall', 'server_owned_state',
			'host_key_fingerprint', 'run_nonce', 'service_sha256', 'core_sha256', 'config_sha256',
			'service_pid', 'core_pid', 'core_parent_pid', 'listener_image_path', 'listener_image_sha256',
			'$PinnedKnownHostsFingerprint -cne $ActualHostKeyFingerprint',
			'$ServerAttestationValue.host_identity -cne ''DESKTOP-1BVR2H6''',
			'$ServerAttestationValue.run_nonce -cne $ServerAttestationRunNonce'
        )) {
            Assert-Matches -Text $runbook -Pattern ([regex]::Escape($text)) -Message 'Missing required VM evidence or server-operation contract.'
        }

		$canonicalLine = @($lines | Where-Object { $_ -like '$VmCanonicalStateCommand =*' })
		Assert-Equal -Actual $canonicalLine.Count -Expected 1 -Message 'Canonical WhatIf command must be declared exactly once.'
		Assert-NotMatches -Text $canonicalLine[0] -Pattern 'Get-Process|Test-NetConnection|captured_utc|ObservedAt|ProcessId' -Message 'Canonical WhatIf snapshot contains volatile state.'
    }

    It 'gates the standard client, MSI verification, pipe-only provisioning, and lifecycle capture' {
        $lines = Get-SingBoxRunbookLines
        $runbook = $lines -join "`n"

        Assert-GuardedNativeCommand -Lines $lines -Command '& $StagedVerifierPath verify-bundle --bundle $ReleaseBundlePath --msi $CorporateSignedMsiPath --fixture-manifest $FixtureManifestPath --fixture-signature $FixtureManifestSignaturePath --release-manifest $ReleaseArtifactManifestPath --release-signature $ReleaseArtifactManifestSignaturePath --expected-commit $ExpectedSourceCommit --expected-msi-sha256 $ExpectedMsiSha256 --expected-fixture-sha256 $ExpectedFixtureManifestSha256 --expected-release-sha256 $ExpectedReleaseManifestSha256 --fixture-signer $FixtureManifestSignerThumbprint --release-signer $ReleaseManifestSignerThumbprint --msi-signer $MsiSignerThumbprint --evidence $VerifierEvidencePath' -Prefix 'InstallerVerifier'
		Assert-GuardedNativeCommand -Lines $lines -Command '& $ActionHelperPath provision-credential' -Prefix 'CredentialProvisioning'
        Assert-GuardedNativeCommand -Lines $lines -Command '& git.exe ls-remote $ApprovedGitProbeRepository > $GitProbePath' -Prefix 'GitProbe'
        Assert-GuardedNativeCommand -Lines $lines -Command '& taskkill.exe /PID $AgentCapture.pid /T /F' -Prefix 'AgentKill'
        Assert-GuardedNativeCommand -Lines $lines -Command '& taskkill.exe /PID $CoreCapture.pid /T /F' -Prefix 'CoreKill'
        Assert-GuardedNativeCommand -Lines $lines -Command '& taskkill.exe /PID $UiCapture.pid /T /F' -Prefix 'UiKill'
        Assert-GuardedNativeCommand -Lines $lines -Command '& shutdown.exe /r /t 0 /f' -Prefix 'Reboot'
        Assert-GuardedNativeCommand -Lines $lines -Command '& msiexec.exe /i $CorporateSignedMsiPath /qn /norestart /l*v $MsiInstallLogPath' -Prefix 'MsiInstall'
        Assert-GuardedNativeCommand -Lines $lines -Command '& msiexec.exe /x $CorporateSignedMsiPath /qn /norestart /l*v $MsiUninstallLogPath' -Prefix 'MsiUninstall'

        foreach ($text in @(
            'standard-client gate PASS is required before custom MSI',
            'Get-AuthenticodeSignature', '$CorporateSignerThumbprint',
			'Get-FileHash', '$StandardSingBoxSha256', '$StandardClientTemplateSha256',
			'sing-box version 1.13.19', 'Test-SingBoxStdinConfigSupport',
			'$StandardStartInfo.Arguments = ''run -c stdin''',
			'$StandardStartInfo.RedirectStandardInput = $true',
			'$StandardClientProcess.StandardInput.Write($StandardRuntimeJson)',
			"`$StandardInbound = @(`$StandardTemplate.inbounds | Where-Object { `$_.type -eq 'tun' -and `$_.interface_name -ceq 'RegenBioStandardAcceptance' })",
			'if ($StandardInbound.Count -ne 1)',
            '$StandardClientProcess.HasExited',
			'$StandardClientProcess.Kill()', '$StandardClientProcess.WaitForExit()', '$StandardClientProcess.Dispose()',
			'$StandardTunnel[0].password = $null', '$StandardTemplate = $null',
			'$env:OVERSEAS_ACCESS_FIXTURE_ACTION_CONFIG = $ActionConfigPath',
			'finally { Remove-Item Env:OVERSEAS_ACCESS_FIXTURE_ACTION_CONFIG -ErrorAction SilentlyContinue }',
			'provision-credential', 'source stdout is connected directly to provisioner stdin by the Go helper',
            'Install must leave the agent stopped before provisioning.',
            'credential.bin was not created',
            'Agent service did not reach Running after provisioning',
            'browser', 'Git', 'HTTPS', 'corporate DNS', 'AD', 'EC',
            'direct access to VM:8080 failure', 'service stop leak failure',
            'telecom-process stop leak failure', 'node loss', 'telecom loss',
            '20 clean enable/disable cycles', 'exact final-state restoration',
            'nonce receipt', 'leak receipt', 'route/DNS/firewall snapshots',
            'redacted logs', 'one full workday',
            'Never accept preset PID variables',
			'Capture-ManagedProcess',
			"`$CoreCapture = Capture-ManagedProcess -ParentServiceName 'RegenBioOverseasAccessAgent' -ExpectedPath 'C:\Program Files\RegenBio\OverseasAccess\sing-box.exe'",
			"`$UiCapture = Capture-ManagedProcess -ExpectedPath 'C:\Program Files\RegenBio\OverseasAccess\overseas-client.exe'"
        )) {
            Assert-Matches -Text $runbook -Pattern ([regex]::Escape($text)) -Message 'Missing required client acceptance contract.'
        }

        Assert-NotMatches -Text $runbook -Pattern '\$AgentProcessId\b' -Message 'Runbook must not rely on preset agent PID variables.'
        Assert-NotMatches -Text $runbook -Pattern '\$CoreProcessId\b' -Message 'Runbook must not rely on preset core PID variables.'
        Assert-NotMatches -Text $runbook -Pattern '\$UiProcessId\b' -Message 'Runbook must not rely on preset UI PID variables.'
		Assert-NotMatches -Text $runbook -Pattern 'AnonymousPipeServerStream|RedirectStandardInput\s+\$clientHandle|\$StandardClientConfigPath|run'',''-c'',\$StandardClient' -Message 'Runbook must not stage plaintext or fake a pipe handle.'
		Assert-NotMatches -Text $runbook -Pattern "Capture-ManagedProcess -ServiceName 'RegenBioOverseasAccessAgent' -ExpectedPath 'C:\\Program Files\\RegenBio\\OverseasAccess\\(sing-box|overseas-client)\.exe'" -Message 'Core/UI capture must not reuse the agent SCM PID.'
    }

    It 'requires evidence collection, zero-drift comparison, and a fail verdict on mandatory failure' {
        $runbook = Get-Content -LiteralPath $singBoxRunbookPath -Raw
        foreach ($text in @(
            'Get-FileHash', 'Compress-Archive', 'baseline-vm.json', 'baseline-physical.json',
            'server-whatif.json', 'server-install.json', 'server-status.json',
			'server-rollback.json', 'server-attestation.json', 'standard-client-evidence.json', 'custom-client.json',
            'lifecycle-20-cycles.json', 'installer-verifier.json', 'verdict.json',
            'FAIL', 'Never label a partial test PASS', 'zero changes after WhatIf',
            'Compare-CanonicalStateSnapshots', 'filesystem', 'registry', 'scheduled tasks', 'server-owned state'
        )) {
            Assert-Matches -Text $runbook -Pattern ([regex]::Escape($text)) -Message 'Missing required evidence or verdict contract.'
        }
    }
}
