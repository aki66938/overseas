$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$snapshotScript = Join-Path $repoRoot 'cmd/installer-verifier/upgrade_snapshot.ps1'
function Get-SnapshotFailure { param([scriptblock]$Action); try { & $Action } catch { return $_.Exception.Message }; return '' }
Describe 'Protected MSI upgrade snapshot' {
    BeforeEach {
        if (Test-Path -LiteralPath $snapshotScript) {
            $source = [IO.File]::ReadAllText($snapshotScript)
            . ([scriptblock]::Create(($source -replace '(?m)^Invoke-UpgradeSnapshot -Mode \$args\[0\].*$', '')))
        }
        # File/DPAPI boundary tests use an empty isolated firewall store. The
        # firewall semantic adapter is tested separately, never against host rules.
        function Get-UpgradeFirewallBaseline { return [pscustomobject]@{journal_present=$false;rules=@()} }
        function Restore-UpgradeFirewallBaseline { }
        function Read-FirewallJournal { return $null }
        $data = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $snapshot = Join-Path (Join-Path $TestDrive ('snapshot-' + [guid]::NewGuid().ToString('N'))) 'active'
        [void][IO.Directory]::CreateDirectory($data)
        Set-SnapshotDirectoryProtection $data
        [IO.File]::WriteAllBytes((Join-Path $data 'credential.bin'), [byte[]](1,2,3,4,5))
        [IO.File]::WriteAllText((Join-Path $data 'sing-box.json'), '{"password":"synthetic-snapshot-secret"}')
        [IO.File]::WriteAllText((Join-Path $data 'runtime-owned.json'), '{"schema_version":2,"finalized":["credential.bin","sing-box.json"],"intents":[]}')
        $before = @{}
        foreach ($name in @('credential.bin','sing-box.json','runtime-owned.json')) { $before[$name] = (Get-FileHash (Join-Path $data $name)).Hash }
    }
    It 'keeps only DPAPI wrapped backups and restores exact bytes after old cleanup' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        foreach ($file in @(Get-ChildItem $snapshot -File)) {
            ([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($file.FullName)).Contains('synthetic-snapshot-secret')) | Should Be $false
        }
        foreach ($name in @($before.Keys)) { [IO.File]::Delete((Join-Path $data $name)) }
        Invoke-UpgradeSnapshot -Mode Restore -DataRoot $data -SnapshotRoot $snapshot
        foreach ($name in @($before.Keys)) { (Get-FileHash (Join-Path $data $name)).Hash | Should Be $before[$name] }
        Invoke-UpgradeSnapshot -Mode Commit -DataRoot $data -SnapshotRoot $snapshot
        (Test-Path $snapshot) | Should Be $false
    }
    It 'refuses unowned source data and stale transactions without overwriting anything' {
        [IO.File]::Delete((Join-Path $data 'runtime-owned.json'))
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'ownership'
        (Test-Path $snapshot) | Should Be $false
        [void][IO.Directory]::CreateDirectory($snapshot)
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'existing|stale'
    }
    It 'refuses corrupt backup before restoring any file and retains recovery evidence' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        $blob = @(Get-ChildItem $snapshot -Filter '*.blob')[0]
        [IO.File]::WriteAllBytes($blob.FullName, [byte[]](9,9,9))
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Rollback -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'integrity'
        foreach ($name in @($before.Keys)) { (Get-FileHash (Join-Path $data $name)).Hash | Should Be $before[$name] }
        (Test-Path $snapshot) | Should Be $true
    }
    It 'rejects reparse source parents and does not remove foreign snapshot content' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        [IO.File]::WriteAllText((Join-Path $snapshot 'foreign.txt'), 'untouched')
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Commit -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'foreign|inventory'
        [IO.File]::ReadAllText((Join-Path $snapshot 'foreign.txt')) | Should Be 'untouched'
    }

    It 'rolls back a backup write failure without changing source files or leaving a usable stale snapshot' {
        $originalWriter = (Get-Command Write-SnapshotBytes).ScriptBlock
        Mock Write-SnapshotBytes {
            param($Path,$Bytes)
            if ($Path.EndsWith('sing-box.json.blob')) { throw 'injected backup failure' }
            & $originalWriter $Path $Bytes
        }
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'injected backup failure'
        foreach ($name in @($before.Keys)) { (Get-FileHash (Join-Path $data $name)).Hash | Should Be $before[$name] }
        (Test-Path $snapshot) | Should Be $false
    }

    It 'can roll back a failed phase two restoration using the retained protected snapshot' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        foreach ($name in @($before.Keys)) { [IO.File]::Delete((Join-Path $data $name)) }
        $record = Get-Content (Join-Path $snapshot 'journal.json') -Raw | ConvertFrom-Json
        $temporary = Join-Path $data ('sing-box.json.upgrade-' + $record.transaction_id + '.tmp')
        [IO.File]::WriteAllText($temporary, 'synthetic collision')
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Restore -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'Interrupted upgrade restore'
        [IO.File]::Delete($temporary)
        Invoke-UpgradeSnapshot -Mode Rollback -DataRoot $data -SnapshotRoot $snapshot
        foreach ($name in @($before.Keys)) { (Get-FileHash (Join-Path $data $name)).Hash | Should Be $before[$name] }
        (Test-Path $snapshot) | Should Be $false
    }

    It 'protects the snapshot parent against directory substitution and rejects a reparse data root' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        (Get-Acl -LiteralPath (Split-Path -Parent $snapshot)).AreAccessRulesProtected | Should Be $true
        Invoke-UpgradeSnapshot -Mode Commit -DataRoot $data -SnapshotRoot $snapshot
        $junction = Join-Path $TestDrive ('junction-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Junction -Path $junction -Target $data | Out-Null
        try { (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Backup -DataRoot $junction -SnapshotRoot $snapshot }) | Should Match 'reparse' }
        finally { [IO.Directory]::Delete($junction) }
    }

    It 'removes only a validated phase two firewall journal when the original baseline had none' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        $firewallJournal = Join-Path $data 'msi-firewall-owned.json'
        [IO.File]::WriteAllText($firewallJournal, 'synthetic validated phase two journal')
        function Read-FirewallJournal { return [pscustomobject]@{schema_version=2;product_id='RegenBioOverseasAccess'} }
        Invoke-UpgradeSnapshot -Mode Rollback -DataRoot $data -SnapshotRoot $snapshot
        (Test-Path $firewallJournal) | Should Be $false
        foreach ($name in @($before.Keys)) { (Get-FileHash (Join-Path $data $name)).Hash | Should Be $before[$name] }
    }

    It 'refuses a user-writable source directory before trusting its ownership journal' {
        $acl = Get-Acl -LiteralPath $data
        $sid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'Modify','ContainerInherit,ObjectInherit','None','Allow')))
        Set-Acl -LiteralPath $data -AclObject $acl
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'ACL'
        (Test-Path $snapshot) | Should Be $false
    }
}
