$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptPath = Join-Path $repo 'scripts\windows\verify-client-firewall-interfaces.ps1'

Describe 'LocalSystem client firewall interface gate' {
    It 'exists and parses in Windows PowerShell 5.1' {
        Test-Path -LiteralPath $scriptPath -PathType Leaf | Should Be $true
        $tokens = $null
        $errors = $null
        [void] [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
        @($errors).Count | Should Be 0
    }

    It 'requires absolute create-new evidence and LocalSystem identity' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match ([regex]::Escape('[IO.Path]::IsPathRooted($EvidencePath)'))
        $source | Should Match ([regex]::Escape('[IO.FileMode]::CreateNew'))
        $source | Should Match ([regex]::Escape('S-1-5-18'))
        $source | Should Match ([regex]::Escape('WindowsPrincipal'))
        $source | Should Not Match 'Invoke-Expression|Start-Process|schtasks|psexec'
    }

    It 'uses the approved IP-stack join without driver or adapter-name blacklists' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match 'Get-NetIPInterface'
        $source | Should Match ([regex]::Escape('Get-NetAdapter -IncludeHidden -InterfaceIndex'))
        $source | Should Match 'Sort-Object -Unique'
        $source | Should Not Match 'WAN Miniport|Hyper-V|InterfaceDescription|Status -ne'
    }

    It 'uses only fixed documentation addresses and owned diagnostic rule names' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match ([regex]::Escape('192.0.2.1/32'))
        $source | Should Match ([regex]::Escape('2001:db8::1/128'))
        $source | Should Match ([regex]::Escape('RegenBio.Diagnostic.Preflight.'))
        $source | Should Match ([regex]::Escape("-PolicyStore PersistentStore"))
        $source | Should Match ([regex]::Escape("-PolicyStore ActiveStore"))
    }

    It 'cleans every temporary rule in finally and proves zero product residue' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match 'finally'
        $source | Should Match ([regex]::Escape('Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name'))
        $source | Should Match ([regex]::Escape('RegenBioOverseasAccess.Managed'))
        $source | Should Match ([regex]::Escape('RegenBio.Diagnostic'))
        $source | Should Match ([regex]::Escape('RouteMetric -in 4096,8192'))
        $source | Should Match ([regex]::Escape('RegenBioOverseasAccess'))
        $source | Should Match ([regex]::Escape('network-state.json'))
        $source | Should Match 'residue'
    }

    It 'materializes generic result lists before Windows PowerShell 5.1 serialization' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match ([regex]::Escape('$results.ToArray()'))
        $source | Should Not Match ([regex]::Escape('Results = @($results)'))
    }

    It 'materializes firewall filter properties as arrays in Windows PowerShell 5.1' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match ([regex]::Escape('@(($rule[0] | Get-NetFirewallInterfaceFilter).InterfaceAlias)'))
        $source | Should Match ([regex]::Escape('@(($rule[0] | Get-NetFirewallAddressFilter).RemoteAddress)'))
        $source | Should Not Match ([regex]::Escape('@($rule[0] | Get-NetFirewallInterfaceFilter).InterfaceAlias'))
        $source | Should Not Match ([regex]::Escape('@($rule[0] | Get-NetFirewallAddressFilter).RemoteAddress'))
    }

    It 'accepts the Windows Firewall canonical host-address rendering' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match ([regex]::Escape('$addresses -notcontains ''192.0.2.1'''))
        $source | Should Match ([regex]::Escape('$addresses -notcontains ''2001:db8::1'''))
    }
}
