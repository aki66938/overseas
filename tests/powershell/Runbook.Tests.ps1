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

        $makefile | Should Match '(?m)^GO\s+\?=\s+go\s*$'
        $makefile | Should Match '(?m)^\.PHONY:\s+test\s+build\s*$'
        $makefile | Should Match '(?m)^test:\s*$'
        $makefile | Should Match ([regex]::Escape('$(GO) test ./...'))
        $makefile | Should Match ([regex]::Escape('Invoke-Pester tests/powershell -Output Detailed'))
        $makefile | Should Match '(?m)^build:\s*$'
        $makefile | Should Match ([regex]::Escape('$(GO) build -trimpath -o bin/poc-probe.exe ./cmd/poc-probe'))
    }

    It 'keeps generated configuration and evidence out of source control' {
        if (-not (Assert-DocumentationFileExists -Path $gitignorePath)) { return }
        $gitignore = Get-Content -LiteralPath $gitignorePath -Raw

        foreach ($entry in @('/configs/poc.yaml', '/artifacts/*', '!/artifacts/.gitkeep', '/artifacts/.poc-config-*', '/artifacts/*.tmp', 'bin/')) {
            $gitignore | Should Match ([regex]::Escape($entry))
        }
    }
}
