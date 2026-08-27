$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptRoot = Join-Path $repoRoot 'scripts\windows'
$scriptPaths = @{
    Snapshot = Join-Path $scriptRoot 'snapshot.ps1'
    Apply = Join-Path $scriptRoot 'apply-poc.ps1'
    Rollback = Join-Path $scriptRoot 'rollback-poc.ps1'
}

function Get-ScriptText([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ''
    }

    return Get-Content -LiteralPath $Path -Raw
}

Describe 'Windows PoC networking script safety' {
    It 'provides all three networking scripts' {
        (Test-Path -LiteralPath $scriptPaths.Snapshot -PathType Leaf) | Should Be $true
        (Test-Path -LiteralPath $scriptPaths.Apply -PathType Leaf) | Should Be $true
        (Test-Path -LiteralPath $scriptPaths.Rollback -PathType Leaf) | Should Be $true
    }

    It 'keeps every script syntactically valid' {
        foreach ($path in $scriptPaths.Values) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                $false | Should Be $true
                continue
            }

            $tokens = $null
            $parseErrors = $null
            [void] [System.Management.Automation.Language.Parser]::ParseFile(
                $path,
                [ref] $tokens,
                [ref] $parseErrors
            )
            $parseErrors.Count | Should Be 0
        }
    }

    It 'uses ShouldProcess for every script that can write or mutate state' {
        foreach ($path in $scriptPaths.Values) {
            (Get-ScriptText $path) | Should Match 'SupportsShouldProcess\s*=\s*\$true'
        }
    }

    It 'rejects empty interface aliases and keeps the aliases distinct' {
        $text = Get-ScriptText $scriptPaths.Apply
        $text | Should Match '(?s)ValidateNotNullOrEmpty\(\).*?\$WireGuardInterface'
        $text | Should Match '(?s)ValidateNotNullOrEmpty\(\).*?\$TelecomInterface'
        $text | Should Match '(?s)ValidateNotNullOrEmpty\(\).*?\$EmployeeInterface'
        $text | Should Match '\$aliases\.Count\s+-ne\s+3'
    }

    It 'validates each configured interface with Get-NetAdapter and terminating errors' {
        $text = Get-ScriptText $scriptPaths.Apply
        $text | Should Match 'Get-NetAdapter\s+-Name\s+\$WireGuardInterface\s+-ErrorAction\s+Stop'
        $text | Should Match 'Get-NetAdapter\s+-Name\s+\$TelecomInterface\s+-ErrorAction\s+Stop'
        $text | Should Match 'Get-NetAdapter\s+-Name\s+\$EmployeeInterface\s+-ErrorAction\s+Stop'
    }

    It 'requires absolute snapshot targets and validates snapshot contents before mutation' {
        $applyText = Get-ScriptText $scriptPaths.Apply
        $rollbackText = Get-ScriptText $scriptPaths.Rollback
        $snapshotText = Get-ScriptText $scriptPaths.Snapshot

        $applyText | Should Match '\[System\.IO\.Path\]::IsPathRooted\(\$SnapshotPath\)'
        $rollbackText | Should Match '\[System\.IO\.Path\]::IsPathRooted\(\$SnapshotPath\)'
        $snapshotText | Should Match '\[System\.IO\.Path\]::IsPathRooted\(\$ArtifactsDirectory\)'
        $applyText | Should Match 'Assert-PocSnapshot'
        $rollbackText | Should Match 'Assert-PocSnapshot'
        $rollbackText | Should Match 'required interface index'
    }

    It 'captures the required pre-change state in a create-new snapshot' {
        $text = Get-ScriptText $scriptPaths.Snapshot
        foreach ($cmdlet in @(
            'Get-NetIPInterface',
            'Get-NetRoute',
            'Get-NetNat',
            'Get-NetFirewallRule',
            'Get-NetFirewallAddressFilter',
            'Get-NetAdapter'
        )) {
            $text | Should Match $cmdlet
        }
        $text | Should Match 'FileMode\]::CreateNew'
        $text | Should Match 'poc-networking-\{0\:yyyyMMdd-HHmmss-fffffff\}\.json'
    }

    It 'normalizes saved forwarding state instead of relying on CIM enum JSON encoding' {
        $snapshotText = Get-ScriptText $scriptPaths.Snapshot
        $applyText = Get-ScriptText $scriptPaths.Apply
        $rollbackText = Get-ScriptText $scriptPaths.Rollback

        $snapshotText | Should Match 'Forwarding\s*=\s*\$wireGuardIPv4\.Forwarding\.ToString\(\)'
        $snapshotText | Should Match 'Forwarding\s*=\s*\$telecomIPv4\.Forwarding\.ToString\(\)'
        $applyText | Should Match '\$entry\.Forwarding\s+-notin\s+@\(''Enabled'',\s*''Disabled''\)'
        $rollbackText | Should Match '\$entry\.Forwarding\s+-notin\s+@\(''Enabled'',\s*''Disabled''\)'
    }

    It 'enables forwarding only on the WireGuard and telecom interfaces' {
        $text = Get-ScriptText $scriptPaths.Apply
        $text | Should Match 'Set-NetIPInterface\s+-InterfaceIndex\s+\$wireGuardAdapter\.ifIndex\s+-Forwarding\s+Enabled'
        $text | Should Match 'Set-NetIPInterface\s+-InterfaceIndex\s+\$telecomAdapter\.ifIndex\s+-Forwarding\s+Enabled'
        $text | Should Not Match 'Set-NetIPInterface\s+-InterfaceIndex\s+\$employeeAdapter\.ifIndex\s+-Forwarding\s+Enabled'
    }

    It 'creates only the exactly named owned NAT' {
        $text = Get-ScriptText $scriptPaths.Apply
        $text | Should Match 'New-NetNat\s+-Name\s+OverseasPocNat\s+-InternalIPInterfaceAddressPrefix\s+\$WireGuardSubnet'
        $text | Should Not Match 'New-NetNat\s+-Name\s+\$'
    }

    It 'uses interface-scoped allow and fail-closed employee-interface block rules' {
        $text = Get-ScriptText $scriptPaths.Apply
        $text | Should Match '(?s)New-NetFirewallRule.*?-Group\s+''Overseas Gateway PoC''.*?-Direction\s+Inbound.*?-Action\s+Allow.*?-InterfaceAlias\s+\$WireGuardInterface.*?-RemoteAddress\s+\$WireGuardSubnet'
        $text | Should Match '(?s)New-NetFirewallRule.*?-Group\s+''Overseas Gateway PoC''.*?-Direction\s+Outbound.*?-Action\s+Allow.*?-InterfaceAlias\s+\$TelecomInterface.*?-LocalAddress\s+\$WireGuardSubnet'
        $text | Should Match '(?s)New-NetFirewallRule.*?-Group\s+''Overseas Gateway PoC''.*?-Direction\s+Outbound.*?-Action\s+Block.*?-InterfaceAlias\s+\$EmployeeInterface.*?-LocalAddress\s+\$WireGuardSubnet'
        $text | Should Match 'Block rules take precedence'
        $text | Should Not Match '(?i)priority\s*[-=]\s*\d+'
    }

    It 'rollback only removes firewall rules in the owned group' {
        $text = Get-ScriptText $scriptPaths.Rollback
        $text | Should Match 'Get-NetFirewallRule\s+-Group\s+''Overseas Gateway PoC''\s+-ErrorAction\s+SilentlyContinue'
        $text | Should Match 'Remove-NetFirewallRule'
        $text | Should Not Match 'Get-NetFirewallRule\s+(?!-Group\s+''Overseas Gateway PoC'')[^\r\n]*\|\s*Remove-NetFirewallRule'
    }

    It 'rollback only removes the owned NAT' {
        $text = Get-ScriptText $scriptPaths.Rollback
        $text | Should Match 'Remove-NetNat\s+-Name\s+OverseasPocNat'
        $text | Should Not Match 'Remove-NetNat\s*(\r?\n|$)'
    }

    It 'rollback restores forwarding from the validated snapshot' {
        $text = Get-ScriptText $scriptPaths.Rollback
        $text | Should Match 'Set-NetIPInterface\s+-InterfaceIndex\s+\$entry\.InterfaceIndex\s+-Forwarding\s+\$entry\.Forwarding'
        $text | Should Match '\$requiredInterfaceIndexes'
    }

    It 'never disables all Windows Firewall profiles' {
        foreach ($path in $scriptPaths.Values) {
            $text = Get-ScriptText $path
            $text | Should Not Match 'Set-NetFirewallProfile[^\r\n]*-Enabled\s+(False|Disabled|0)'
            $text | Should Not Match 'netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off'
        }
    }

    It 'guards every mutating networking cmdlet with ShouldProcess' {
        $applyText = Get-ScriptText $scriptPaths.Apply
        $rollbackText = Get-ScriptText $scriptPaths.Rollback
        $applyText | Should Match '(?s)ShouldProcess\(.*?Set-NetIPInterface'
        $applyText | Should Match '(?s)ShouldProcess\(.*?New-NetNat'
        $applyText | Should Match '(?s)ShouldProcess\(.*?New-NetFirewallRule'
        $rollbackText | Should Match '(?s)ShouldProcess\(.*?Remove-NetFirewallRule'
        $rollbackText | Should Match '(?s)ShouldProcess\(.*?Remove-NetNat'
        $rollbackText | Should Match '(?s)ShouldProcess\(.*?Set-NetIPInterface'
    }
}
