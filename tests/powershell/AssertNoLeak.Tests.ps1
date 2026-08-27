$scriptPath = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..\scripts\windows\assert-no-leak.ps1')
)

function Get-NoLeakFailureMessage {
    param([scriptblock] $Action)
    try {
        & $Action
        return $null
    }
    catch {
        return $_.Exception.Message
    }
}

Describe 'Windows PoC no-leak orchestration' {
    It 'has valid PowerShell syntax' {
        $tokens = $null
        $errors = $null
        [void] [System.Management.Automation.Language.Parser]::ParseFile(
            $scriptPath,
            [ref] $tokens,
            [ref] $errors
        )
        $errors.Count | Should Be 0
    }

    It 'contains only manual disconnect and reconnect gates around the configured probe' {
        $source = Get-Content -LiteralPath $scriptPath -Raw

        ([regex]::Matches($source, '(?i)Read-Host')).Count | Should Be 2
        $source | Should Match '(?i)Get-NetAdapter'
        $source | Should Match '(?i)Get-NetRoute'
        $source | Should Match '(?i)&\s+\$PocProbePath\s+probe\s+--config\s+\$resolvedConfigPath\s+--out\s+\$resolvedOutputPath'
        $source | Should Not Match '(?i)rasdial|Set-NetAdapter|Disable-NetAdapter|Enable-NetAdapter'
        $source | Should Not Match '(?i)\bpin\b|Get-Credential|password|credential'
    }

    It 'refuses to replace existing down-state evidence before any prompt' {
        $configPath = Join-Path $TestDrive 'existing-poc.yaml'
        $outputPath = Join-Path $TestDrive 'existing-probe-telecom-down.json'
        Set-Content -LiteralPath $configPath -Value 'telecom_interface: Telecom-Client'
        Set-Content -LiteralPath $outputPath -Value 'preserve-me'
        Mock Read-Host { throw 'prompt must not run' }

        $message = Get-NoLeakFailureMessage {
            & $scriptPath -ConfigPath $configPath -OutputPath $outputPath -PocProbePath 'missing.exe'
        }

        $message | Should Match 'already exists'
        (Get-Content -LiteralPath $outputPath -Raw).Trim() | Should Be 'preserve-me'
        Assert-MockCalled Read-Host -Times 0 -Exactly -Scope It
    }

    It 'does not probe while the telecom interface and route remain active' {
        $configPath = Join-Path $TestDrive 'active-poc.yaml'
        $outputPath = Join-Path $TestDrive 'active-probe-telecom-down.json'
        Set-Content -LiteralPath $configPath -Value 'telecom_interface: Telecom-Client'
        Mock Read-Host { return '' }
        Mock Get-NetAdapter { return [pscustomobject] @{ Name = 'Telecom-Client'; ifIndex = 11; Status = 'Up' } }
        Mock Get-NetRoute { return @([pscustomobject] @{ State = 'Alive' }) }

        $message = Get-NoLeakFailureMessage {
            & $scriptPath -ConfigPath $configPath -OutputPath $outputPath -PocProbePath 'must-not-run.exe'
        }

        $message | Should Match 'still active'
        (Test-Path -LiteralPath $outputPath) | Should Be $false
        Assert-MockCalled Read-Host -Times 1 -Exactly -Scope It
        Assert-MockCalled Get-NetAdapter -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'Telecom-Client' }
        Assert-MockCalled Get-NetRoute -Times 1 -Exactly -Scope It -ParameterFilter { $InterfaceIndex -eq 11 -and $AddressFamily -eq 'IPv4' }
    }

    It 'runs only the configured probe after down-state proof and requires restored path state' {
        $configPath = Join-Path $TestDrive 'success-poc.yaml'
        $outputPath = Join-Path $TestDrive 'success-probe-telecom-down.json'
        $fakeProbePath = Join-Path $TestDrive 'fake-poc-probe.cmd'
        Set-Content -LiteralPath $configPath -Value 'telecom_interface: Telecom-Client'
        Set-Content -LiteralPath $fakeProbePath -Value @(
            '@echo off',
            'echo [] > "%~5"',
            'exit /b 0'
        )
        $global:NoLeakAdapterReads = 0
        Mock Read-Host { return '' }
        Mock Get-NetAdapter {
            $global:NoLeakAdapterReads++
            if ($global:NoLeakAdapterReads -eq 1) {
                return [pscustomobject] @{ Name = 'Telecom-Client'; ifIndex = 11; Status = 'Down' }
            }
            return [pscustomobject] @{ Name = 'Telecom-Client'; ifIndex = 11; Status = 'Up' }
        }
        Mock Get-NetRoute { return @([pscustomobject] @{ State = 'Alive' }) }

        & $scriptPath -ConfigPath $configPath -OutputPath $outputPath -PocProbePath $fakeProbePath

        (Test-Path -LiteralPath $outputPath -PathType Leaf) | Should Be $true
        (Get-Content -LiteralPath $outputPath -Raw).Trim() | Should Be '[]'
        Assert-MockCalled Read-Host -Times 2 -Exactly -Scope It
        Assert-MockCalled Get-NetAdapter -Times 2 -Exactly -Scope It -ParameterFilter { $Name -eq 'Telecom-Client' }
        Assert-MockCalled Get-NetRoute -Times 2 -Exactly -Scope It -ParameterFilter { $InterfaceIndex -eq 11 -and $AddressFamily -eq 'IPv4' }
    }
}
