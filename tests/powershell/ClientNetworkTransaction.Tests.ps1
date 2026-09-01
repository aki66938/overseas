$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptPath = Join-Path $repo 'scripts\windows\verify-client-network-transaction.ps1'

Describe 'Client LocalSystem network transaction gate' {
    It 'exists and parses in Windows PowerShell 5.1' {
        Test-Path -LiteralPath $scriptPath -PathType Leaf | Should Be $true
        $tokens = $null
        $errors = $null
        [void] [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
        @($errors).Count | Should Be 0
    }

    It 'requires LocalSystem and clean absolute inputs before invoking the exact live test' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match ([regex]::Escape('[IO.Path]::IsPathRooted($RepositoryPath)'))
        $source | Should Match ([regex]::Escape('[IO.Path]::IsPathRooted($GoExecutable)'))
        $source | Should Match ([regex]::Escape('[IO.Path]::IsPathRooted($EvidencePath)'))
        $source | Should Match ([regex]::Escape('S-1-5-18'))
        $source | Should Match ([regex]::Escape("OVERSEAS_ACCESS_NETWORK_GATE"))
        $source | Should Match ([regex]::Escape("^TestLiveWindowsPowerShellProtectionTransaction$"))
        $source | Should Not Match 'Invoke-Expression|Start-Process|schtasks|psexec'
    }

    It 'refuses product residue and emits create-new bounded evidence' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match ([regex]::Escape('network-state.json'))
        $source | Should Match ([regex]::Escape('RegenBioOverseasAccess.Managed'))
        $source | Should Match ([regex]::Escape('RegenBio.Diagnostic'))
        $source | Should Match ([regex]::Escape('RouteMetric -in 4096,8192'))
        $source | Should Match ([regex]::Escape('[IO.FileMode]::CreateNew'))
        $source | Should Match ([regex]::Escape('4096'))
        $source | Should Match 'finally'
    }

    It 'runs only the internal agent package and restores the caller environment' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match ([regex]::Escape("test ./internal/agent"))
        $source | Should Match ([regex]::Escape('$previousGate'))
        $source | Should Match ([regex]::Escape('$env:OVERSEAS_ACCESS_NETWORK_GATE = $previousGate'))
        $source | Should Match 'Push-Location'
        $source | Should Match 'Pop-Location'
    }

    It 'does not turn native Go stderr progress into a terminating PowerShell exception' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match ([regex]::Escape('$previousErrorActionPreference'))
        $source | Should Match ([regex]::Escape('$ErrorActionPreference = ''Continue'''))
        $source | Should Match ([regex]::Escape('$ErrorActionPreference = $previousErrorActionPreference'))
    }
}
