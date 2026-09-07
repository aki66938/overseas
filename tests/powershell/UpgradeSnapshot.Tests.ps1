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

    It 'automatically rolls back a phase two ACL failure after temporary file creation' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        foreach ($name in @($before.Keys)) { [IO.File]::Delete((Join-Path $data $name)) }
        $script:failRestoreAcl = $true
        Mock Set-Acl { throw 'injected restore ACL failure' } -ParameterFilter { $script:failRestoreAcl -and $LiteralPath -like '*sing-box.json.upgrade-*.tmp' }
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Restore -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'injected restore ACL failure'
        $script:failRestoreAcl = $false
        Invoke-UpgradeSnapshot -Mode Rollback -DataRoot $data -SnapshotRoot $snapshot
        foreach ($name in @($before.Keys)) { (Get-FileHash (Join-Path $data $name)).Hash | Should Be $before[$name] }
        @(Get-ChildItem -LiteralPath $data -Filter '*.tmp').Count | Should Be 0
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

    It 'automatically recovers a partial restore write and a publication failure without manual deletion' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        $script:failRestoreWrite = $true
        Mock Write-SnapshotRestoreContent { param($Stream,$Bytes); $Stream.Write($Bytes,0,1); $Stream.Flush($true); throw 'injected partial restore write' } -ParameterFilter { $script:failRestoreWrite }
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Restore -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'injected partial restore write'
        $script:failRestoreWrite = $false
        $script:failPublish = $true
        Mock Publish-SnapshotRestoreFile { throw 'injected publication failure' } -ParameterFilter { $script:failPublish }
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Restore -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'injected publication failure'
        $script:failPublish = $false
        Invoke-UpgradeSnapshot -Mode Rollback -DataRoot $data -SnapshotRoot $snapshot
        foreach ($name in @($before.Keys)) { (Get-FileHash (Join-Path $data $name)).Hash | Should Be $before[$name] }
        @(Get-ChildItem -LiteralPath $data -Filter '*.tmp').Count | Should Be 0
    }

    It 'recovers an abandoned partial restore reservation from its persisted native file identity' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        $record = Read-UpgradeSnapshot $snapshot $data
        $reservation = New-SnapshotRestoreReservation $snapshot $data $record $record.files[0]
        $reservation.stream.WriteByte(42); $reservation.stream.Flush($true); $reservation.stream.Dispose()
        # Simulate a new invocation without any in-memory ownership state.
        $reservation = $null
        Invoke-UpgradeSnapshot -Mode Rollback -DataRoot $data -SnapshotRoot $snapshot
        foreach ($name in @($before.Keys)) { (Get-FileHash (Join-Path $data $name)).Hash | Should Be $before[$name] }
        @(Get-ChildItem -LiteralPath $data -Filter '*.tmp').Count | Should Be 0
    }

    It 'preserves a foreign replacement of an owned restore temporary file' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        $record = Read-UpgradeSnapshot $snapshot $data
        $reservation = New-SnapshotRestoreReservation $snapshot $data $record $record.files[0]
        $reservation.stream.Dispose()
        $original = $reservation.path + '.original'
        [IO.File]::Move($reservation.path,$original)
        [IO.File]::WriteAllText($reservation.path,'foreign collision')
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Rollback -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'Foreign replacement'
        [IO.File]::ReadAllText($reservation.path) | Should Be 'foreign collision'
        foreach ($name in @($before.Keys)) { (Get-FileHash (Join-Path $data $name)).Hash | Should Be $before[$name] }
    }

    It 'resumes committed cleanup after a blob deletion failure through automatic maintenance' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        $script:failCleanupDelete = $true
        Mock Remove-Item { throw 'injected cleanup deletion failure' } -ParameterFilter { $script:failCleanupDelete -and $LiteralPath -like '*credential.bin.blob' }
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Commit -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'injected cleanup deletion failure'
        (Test-Path (Join-Path $snapshot 'runtime-owned.json.blob')) | Should Be $false
        (Test-Path ($snapshot + '.cleanup.json')) | Should Be $true
        (Get-Content ($snapshot + '.cleanup.json') -Raw | ConvertFrom-Json).state | Should Be 'cleanup-pending'
        $script:failCleanupDelete = $false
        Invoke-UpgradeSnapshot -Mode Maintenance -DataRoot $data -SnapshotRoot $snapshot
        (Test-Path $snapshot) | Should Be $false
        (Test-Path ($snapshot + '.cleanup.json')) | Should Be $false
        foreach ($name in @($before.Keys)) { (Get-FileHash (Join-Path $data $name)).Hash | Should Be $before[$name] }
    }

    It 'retries completed rollback cleanup and preserves foreign content during pending cleanup' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        $script:failCleanupDelete = $true
        Mock Remove-Item { throw 'injected cleanup deletion failure' } -ParameterFilter { $script:failCleanupDelete -and $LiteralPath -like '*credential.bin.blob' }
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Rollback -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'injected cleanup deletion failure'
        [IO.File]::WriteAllText((Join-Path $snapshot 'foreign.txt'),'untouched')
        $script:failCleanupDelete = $false
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Maintenance -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'Foreign'
        [IO.File]::ReadAllText((Join-Path $snapshot 'foreign.txt')) | Should Be 'untouched'
        # Remove only this test-created collision to permit testing a legitimate retry.
        [IO.File]::Delete((Join-Path $snapshot 'foreign.txt'))
        Invoke-UpgradeSnapshot -Mode Rollback -DataRoot $data -SnapshotRoot $snapshot
        (Test-Path ($snapshot + '.cleanup.json')) | Should Be $false
        foreach ($name in @($before.Keys)) { (Get-FileHash (Join-Path $data $name)).Hash | Should Be $before[$name] }
    }

    It 'retains cleanup ownership even when the final empty directory deletion fails' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        $script:failDirectoryDelete = $true
        Mock Remove-Item { throw 'injected final directory deletion failure' } -ParameterFilter { $script:failDirectoryDelete -and $LiteralPath -eq $snapshot }
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Commit -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'injected final directory deletion failure'
        @(Get-ChildItem -LiteralPath $snapshot -Force).Count | Should Be 0
        (Test-Path ($snapshot + '.cleanup.json')) | Should Be $true
        $script:failDirectoryDelete = $false
        Invoke-UpgradeSnapshot -Mode Maintenance -DataRoot $data -SnapshotRoot $snapshot
        (Test-Path $snapshot) | Should Be $false
    }

    It 'automatically finishes pending committed cleanup before taking a new upgrade snapshot' {
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        $oldId = (Read-UpgradeSnapshot $snapshot $data).transaction_id
        $script:failCleanupDelete = $true
        Mock Remove-Item { throw 'injected cleanup deletion failure' } -ParameterFilter { $script:failCleanupDelete -and $LiteralPath -like '*credential.bin.blob' }
        (Get-SnapshotFailure { Invoke-UpgradeSnapshot -Mode Commit -DataRoot $data -SnapshotRoot $snapshot }) | Should Match 'injected cleanup deletion failure'
        $script:failCleanupDelete = $false
        Invoke-UpgradeSnapshot -Mode Backup -DataRoot $data -SnapshotRoot $snapshot
        (Read-UpgradeSnapshot $snapshot $data).transaction_id | Should Not Be $oldId
        (Test-Path ($snapshot + '.cleanup.json')) | Should Be $false
        Invoke-UpgradeSnapshot -Mode Rollback -DataRoot $data -SnapshotRoot $snapshot
    }

    It 'refuses a junction before changing the external directory ACL' {
        $external = Join-Path $TestDrive ('external-' + [guid]::NewGuid().ToString('N'))
        $junction = Join-Path $TestDrive ('acl-link-' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($external)
        $beforeAcl = (Get-Acl -LiteralPath $external).Sddl
        New-Item -ItemType Junction -Path $junction -Target $external | Out-Null
        try {
            (Get-SnapshotFailure { Set-SnapshotDirectoryProtection $junction }) | Should Match 'reparse'
            (Get-Acl -LiteralPath $external).Sddl | Should Be $beforeAcl
        }
        finally { [IO.Directory]::Delete($junction) }
    }

    It 'checks a junction before invoking any directory ACL mutation' {
        $external = Join-Path $TestDrive ('external-' + [guid]::NewGuid().ToString('N'))
        $junction = Join-Path $TestDrive ('acl-link-' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($external)
        New-Item -ItemType Junction -Path $junction -Target $external | Out-Null
        Mock Set-Acl { throw 'ACL mutation reached before validation' } -ParameterFilter { $LiteralPath -eq $junction }
        try { (Get-SnapshotFailure { Set-SnapshotDirectoryProtection $junction }) | Should Match 'reparse' }
        finally { [IO.Directory]::Delete($junction) }
    }

    It 'refuses an ordinary file without changing its ACL or contents' {
        $file = Join-Path $TestDrive ('ordinary-' + [guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($file,'foreign file')
        $beforeAcl = (Get-Acl -LiteralPath $file).Sddl
        (Get-SnapshotFailure { Set-SnapshotDirectoryProtection $file }) | Should Match 'directory'
        (Get-Acl -LiteralPath $file).Sddl | Should Be $beforeAcl
        [IO.File]::ReadAllText($file) | Should Be 'foreign file'
    }

    It 'rejects an already existing directory instead of claiming it during atomic creation' {
        $foreign = Join-Path $TestDrive ('precreated-' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($foreign)
        $beforeAcl = (Get-Acl -LiteralPath $foreign).Sddl
        (Get-SnapshotFailure { Set-SnapshotDirectoryProtection $foreign -CreateNew }) | Should Not Be ''
        (Get-Acl -LiteralPath $foreign).Sddl | Should Be $beforeAcl
        $created = Join-Path $TestDrive ('atomic-' + [guid]::NewGuid().ToString('N'))
        Set-SnapshotDirectoryProtection $created -CreateNew
        Assert-SnapshotDirectoryProtection $created
    }

    It 'holds ancestors against rename and rejects a late junction before handle-bound ACL mutation' {
        $parent = Join-Path $TestDrive ('locked-parent-' + [guid]::NewGuid().ToString('N'))
        $target = Join-Path $parent 'target'
        $external = Join-Path $TestDrive ('late-external-' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($parent)
        [void][IO.Directory]::CreateDirectory($external)
        $beforeAcl = (Get-Acl -LiteralPath $external).Sddl
        $guard = New-Object RegenBioUpgradeDirectoryGuard($target)
        try {
            (Get-SnapshotFailure { [IO.Directory]::Move($parent,$parent + '-moved') }) | Should Not Be ''
            New-Item -ItemType Junction -Path $target -Target $external | Out-Null
            $acl = New-Object Security.AccessControl.DirectorySecurity
            $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
            (Get-SnapshotFailure { $guard.Protect($acl.GetSecurityDescriptorBinaryForm(),$false) }) | Should Match 'reparse'
            (Get-Acl -LiteralPath $external).Sddl | Should Be $beforeAcl
        }
        finally { $guard.Dispose(); if (Test-Path -LiteralPath $target) { [IO.Directory]::Delete($target) } }
        [IO.Directory]::Move($parent,$parent + '-moved')
        (Test-Path ($parent + '-moved')) | Should Be $true
    }
}
