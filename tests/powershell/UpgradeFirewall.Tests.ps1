$repoRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
function Get-UpgradeFirewallFailure { param([scriptblock]$Action); try { & $Action } catch { return $_.Exception.Message }; return '' }
Describe 'Upgrade installer firewall baseline' {
    BeforeEach {
        $go=[IO.File]::ReadAllText((Join-Path $repoRoot 'cmd/installer-verifier/main_windows.go'))
        $match=[regex]::Match($go,'(?s)const firewallLifecycleScript = `(.*?)`\r?\n\r?\nfunc')
        $support=$match.Groups[1].Value.Split(@("if(`$mode -eq 'install'){"),[StringSplitOptions]::None)[0]
        . ([scriptblock]::Create($support))
        $source=[IO.File]::ReadAllText((Join-Path $repoRoot 'cmd/installer-verifier/upgrade_snapshot.ps1'))
        . ([scriptblock]::Create(($source -replace '(?m)^Invoke-UpgradeSnapshot -Mode \$args\[0\].*$', '')))
        $script:rules=@{}
        function Get-NetFirewallRule { param($Name,$PolicyStore,$ErrorAction); if($Name){return $script:rules[$Name]}; return @($script:rules.Values) }
        function Get-NetFirewallApplicationFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process {$InputObject.App} }
        function Get-NetFirewallPortFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process {$InputObject.Port} }
        function Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process {$InputObject.Address} }
        function Get-NetFirewallServiceFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process {$InputObject.ServiceFilter} }
        function Get-NetFirewallInterfaceFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process {$InputObject.InterfaceFilter} }
        function Get-NetFirewallSecurityFilter { param([Parameter(ValueFromPipeline=$true)]$InputObject); process {$InputObject.SecurityFilter} }
        function New-NetFirewallRule {
            param($Name,$DisplayName,$Group,$Direction,$Action,$Program,$Protocol,$Profile,$Enabled,$PolicyStore)
            $script:rules[$Name]=[pscustomobject]@{Name=$Name;DisplayName=$DisplayName;Group=$Group;Direction=$Direction;Action=$Action;Profile=$Profile;Enabled=[string]$Enabled;
                App=[pscustomobject]@{Program=$Program;Package='Any'};Port=[pscustomobject]@{Protocol=$Protocol;LocalPort='Any';RemotePort='Any'};
                Address=[pscustomobject]@{LocalAddress='Any';RemoteAddress='Any'};ServiceFilter=[pscustomobject]@{Service='Any'};
                InterfaceFilter=[pscustomobject]@{InterfaceType='Any';InterfaceAlias='Any'};
                SecurityFilter=[pscustomobject]@{Authentication='NotRequired';Encryption='NotRequired';LocalUser='Any';RemoteUser='Any';RemoteMachine='Any';OverrideBlockRules='False'}}
        }
        function Set-NetFirewallRule { param($Name,$Enabled,$PolicyStore,$ErrorAction); $script:rules[$Name].Enabled=[string]$Enabled }
        function Remove-NetFirewallRule { param($Name,$PolicyStore,$ErrorAction); [void]$script:rules.Remove($Name) }
        $script:oldJournal=[pscustomobject]@{schema_version=2;product_id='RegenBioOverseasAccess';owned_rules=@($definitions);current_operation=$null}
        function Read-FirewallJournal { return $script:oldJournal }
        foreach($definition in $definitions[0..1]) { New-NetFirewallRule -Name $definition.name -DisplayName $definition.display_name -Group $group -Direction Outbound -Action Allow -Program $definition.program -Protocol $definition.protocol -Profile Any -Enabled True }
        $script:rules[$definitions[1].name].Enabled='False'
    }
    It 'captures full identity including enabled and absent states and restores only the prior baseline' {
        $baseline=Get-UpgradeFirewallBaseline
        $baseline.rules.Count | Should Be 3
        $script:rules.Clear()
        Restore-UpgradeFirewallBaseline -Baseline $baseline -CurrentJournal $script:oldJournal
        $script:rules.Count | Should Be 2
        $script:rules[$definitions[1].name].Enabled | Should Be 'False'
        $script:rules.ContainsKey($definitions[2].name) | Should Be $false
    }
    It 'refuses same-name foreign semantic drift before backup and rollback deletion' {
        $baseline=Get-UpgradeFirewallBaseline
        $script:rules[$definitions[0].name].App.Program='C:\foreign.exe'
        (Get-UpgradeFirewallFailure { Get-UpgradeFirewallBaseline }) | Should Match 'exactly match'
        (Get-UpgradeFirewallFailure { Restore-UpgradeFirewallBaseline -Baseline $baseline -CurrentJournal $script:oldJournal }) | Should Match 'exactly match'
        $script:rules[$definitions[0].name].App.Program | Should Be 'C:\foreign.exe'
    }
}
