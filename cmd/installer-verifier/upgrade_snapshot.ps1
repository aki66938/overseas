$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Add-Type -AssemblyName System.Security
if (-not ('RegenBioUpgradeFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class RegenBioUpgradeFileIdentity {
    [StructLayout(LayoutKind.Sequential)] private struct Information {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh,
            WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Information info);
    public static string Read(SafeFileHandle handle) {
        Information info;
        if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return info.Volume.ToString("x8") + info.IndexHigh.ToString("x8") + info.IndexLow.ToString("x8");
    }
}
'@
}

function Get-UpgradeFirewallBaseline {
    $value = Read-FirewallJournal
    if ($null -ne $value -and $null -ne $value.current_operation -and $value.current_operation.state -ne 'committed') { throw 'Unfinished installer firewall ownership blocks upgrade.' }
    $entries = @()
    foreach ($definition in $definitions) {
        $exact = Get-ExactFirewallRule $definition -AllowDisabled
        if ($null -ne $exact -and ($null -eq $value -or -not (Test-JournalOwnsDefinition $value $definition))) { throw 'Installer firewall ownership proof is absent.' }
        $entries += [ordered]@{definition=$definition;present=($null -ne $exact);enabled=$(if ($null -ne $exact) { [string]$exact.Enabled } else { 'False' })}
    }
    return [pscustomobject]@{journal_present=($null -ne $value);rules=@($entries)}
}

function Restore-UpgradeFirewallBaseline($Baseline,$CurrentJournal) {
    if (@($Baseline.rules).Count -ne $definitions.Count) { throw 'Firewall snapshot inventory is invalid.' }
    $seen = @{}
    # Validate all identities and current rules before creating/removing any.
    foreach ($entry in @($Baseline.rules)) {
        $definition = Get-Definition ([string]$entry.definition.name)
        if ($seen.ContainsKey($definition.name) -or -not (Test-SameDefinition $entry.definition $definition) -or $entry.enabled -notin @('True','False') -or $entry.present -isnot [bool]) { throw 'Firewall snapshot definition is invalid.' }
        $seen[$definition.name] = $true
        $exact = Get-ExactFirewallRule $definition -AllowDisabled
        if ($null -ne $exact -and -not $entry.present -and ($null -eq $CurrentJournal -or -not (Test-JournalOwnsDefinition $CurrentJournal $definition))) { throw 'Unowned firewall rule prevents baseline recovery.' }
    }
    foreach ($entry in @($Baseline.rules)) {
        $definition = Get-Definition ([string]$entry.definition.name)
        $exact = Get-ExactFirewallRule $definition -AllowDisabled
        if ($entry.present) {
            if ($null -eq $exact) {
                New-NetFirewallRule -Name $definition.name -DisplayName $definition.display_name -Group $group -Direction Outbound -Action Allow -Program $definition.program -Protocol $definition.protocol -Profile Any -Enabled $entry.enabled -PolicyStore PersistentStore | Out-Null
            }
            elseif ([string]$exact.Enabled -ne $entry.enabled) { Set-NetFirewallRule -Name $definition.name -Enabled $entry.enabled -PolicyStore PersistentStore -ErrorAction Stop | Out-Null }
            $verified = Get-ExactFirewallRule $definition -AllowDisabled
            if ($null -eq $verified -or [string]$verified.Enabled -ne $entry.enabled) { throw 'Installer firewall baseline restoration failed.' }
        }
        elseif ($null -ne $exact) {
            Remove-NetFirewallRule -Name $definition.name -PolicyStore PersistentStore -ErrorAction Stop
            if ($null -ne (Get-ExactFirewallRule $definition -AllowDisabled)) { throw 'Installer firewall absence could not be proven.' }
        }
    }
}

function Assert-SnapshotOrdinaryPath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Upgrade snapshot path crosses a reparse point.' }
        }
        $current = Split-Path -Parent $current
    }
}

function Get-SnapshotHash([byte[]]$Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Write-SnapshotBytes([string]$Path, [byte[]]$Bytes) {
    Assert-SnapshotOrdinaryPath $Path
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Read-SnapshotRestoreReservations([string]$SnapshotRoot,$Record) {
    $reservations = @()
    foreach ($item in @(Get-ChildItem -LiteralPath $SnapshotRoot -Filter 'restore-*.json' -Force)) {
        Assert-SnapshotOrdinaryPath $item.FullName
        if ($item.PSIsContainer -or $item.Name -cnotmatch '^restore-[a-f0-9]{32}\.json$' -or $item.Length -gt 4096) { throw 'Invalid restore reservation inventory.' }
        $value = Get-Content -LiteralPath $item.FullName -Raw | ConvertFrom-Json
        if ($value.transaction_id -cne $Record.transaction_id -or $value.identity -cnotmatch '^[a-f0-9]{24}$' -or
            @($Record.files | Where-Object { $_.name -ceq $value.name }).Count -ne 1 -or
            $value.token -cne $item.Name.Substring(8,32)) { throw 'Invalid restore reservation ownership.' }
        $reservations += $value
    }
    return $reservations
}

function Remove-SnapshotRestoreReservation([string]$SnapshotRoot,[string]$DataRoot,$Reservation) {
    $temporary = Join-Path $DataRoot ($Reservation.name + '.upgrade-' + $Reservation.transaction_id + '-' + $Reservation.token + '.tmp')
    Assert-SnapshotOrdinaryPath $temporary
    if (Test-Path -LiteralPath $temporary) {
        $stream = New-Object IO.FileStream($temporary,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
        try {
            if ([RegenBioUpgradeFileIdentity]::Read($stream.SafeFileHandle) -cne $Reservation.identity) { throw 'Foreign replacement of a restore temporary file.' }
        }
        finally { $stream.Dispose() }
        [IO.File]::Delete($temporary)
    }
    [IO.File]::Delete((Join-Path $SnapshotRoot ('restore-' + $Reservation.token + '.json')))
}

function New-SnapshotRestoreReservation([string]$SnapshotRoot,[string]$DataRoot,$Record,$File) {
    $token = [guid]::NewGuid().ToString('N')
    $temporary = Join-Path $DataRoot ($File.name + '.upgrade-' + $Record.transaction_id + '-' + $token + '.tmp')
    Assert-SnapshotOrdinaryPath $temporary
    $stream = New-Object IO.FileStream($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $markerStream = $null
    $markerPath = Join-Path $SnapshotRoot ('restore-' + $token + '.json')
    try {
        $reservation = [pscustomobject]@{transaction_id=$Record.transaction_id;token=$token;name=$File.name;identity=[RegenBioUpgradeFileIdentity]::Read($stream.SafeFileHandle)}
        # Persist the exclusive CreateNew file identity BEFORE writing plaintext.
        # A crash after this point leaves enough evidence for another process to
        # delete only this file, even if its write never completed.
        $markerStream = New-Object IO.FileStream($markerPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $markerBytes = [Text.Encoding]::UTF8.GetBytes(($reservation | ConvertTo-Json -Compress))
        $markerStream.Write($markerBytes,0,$markerBytes.Length); $markerStream.Flush($true); $markerStream.Dispose()
    }
    catch {
        $stream.Dispose(); [IO.File]::Delete($temporary)
        if ($null -ne $markerStream) { $markerStream.Dispose(); [IO.File]::Delete($markerPath) }
        throw
    }
    return [pscustomobject]@{stream=$stream;path=$temporary;reservation=$reservation}
}

function Write-SnapshotRestoreContent($Stream,[byte[]]$Bytes) {
    $Stream.Write($Bytes,0,$Bytes.Length)
    $Stream.Flush($true)
}

function Publish-SnapshotRestoreFile([string]$Temporary,[string]$Target) {
    if (Test-Path -LiteralPath $Target) { [IO.File]::Replace($Temporary,$Target,[Management.Automation.Language.NullString]::Value) }
    else { [IO.File]::Move($Temporary,$Target) }
}

function Set-SnapshotDirectoryProtection([string]$Path) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-SnapshotDirectoryProtection $Path
}

function Assert-SnapshotDirectoryProtection([string]$Path) {
    Assert-SnapshotOrdinaryPath $Path
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Upgrade snapshot ACL owner is not administrative.' }
    if (-not $acl.AreAccessRulesProtected) { throw 'Upgrade snapshot ACL is not protected.' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Upgrade snapshot ACL grants foreign access.' }
    }
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        if (@($rules | Where-Object { $_.IdentityReference.Value -eq $sid -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl }).Count -ne 1) { throw 'Upgrade snapshot administrative ACL is incomplete.' }
    }
}

function Get-UpgradeOwnedRuntimeFiles([string]$DataRoot) {
    $ledgerPath = Join-Path $DataRoot 'runtime-owned.json'
    foreach ($name in @('credential.bin','sing-box.json','runtime-owned.json')) { Assert-SnapshotOrdinaryPath (Join-Path $DataRoot $name) }
    if (-not (Test-Path -LiteralPath $ledgerPath -PathType Leaf)) {
        foreach ($name in @('credential.bin','sing-box.json')) {
            if (Test-Path -LiteralPath (Join-Path $DataRoot $name)) { throw 'Runtime ownership proof is absent.' }
        }
        return @()
    }
    $ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
    if ($ledger.schema_version -ne 2 -or $ledger.PSObject.Properties.Name -notcontains 'finalized' -or
        $ledger.PSObject.Properties.Name -notcontains 'intents' -or @($ledger.intents).Count -ne 0) { throw 'Runtime ownership journal is incomplete or unsupported.' }
    $owned = @($ledger.finalized)
    if (@($owned | Sort-Object -Unique).Count -ne $owned.Count -or @($owned | Where-Object { $_ -cnotin @('credential.bin','sing-box.json') }).Count) { throw 'Runtime ownership journal names are invalid.' }
    foreach ($name in @('credential.bin','sing-box.json')) {
        if ((Test-Path -LiteralPath (Join-Path $DataRoot $name)) -and $owned -cnotcontains $name) { throw 'Runtime ownership proof does not cover an existing file.' }
    }
    $result = @('runtime-owned.json')
    foreach ($name in $owned) {
        if (Test-Path -LiteralPath (Join-Path $DataRoot $name) -PathType Leaf) { $result += $name }
        elseif (Test-Path -LiteralPath (Join-Path $DataRoot $name)) { throw 'Runtime owned file is not ordinary.' }
    }
    return $result
}

function Read-UpgradeSnapshot([string]$SnapshotRoot, [string]$DataRoot) {
    Assert-SnapshotDirectoryProtection $SnapshotRoot
    $journalPath = Join-Path $SnapshotRoot 'journal.json'
    Assert-SnapshotOrdinaryPath $journalPath
    if (-not (Test-Path -LiteralPath $journalPath -PathType Leaf)) { throw 'Incomplete upgrade snapshot; manual recovery inspection is required.' }
    $record = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
    if ($record.schema_version -ne 1 -or $record.product -cne 'RegenBioOverseasAccess' -or
        $record.transaction_id -cnotmatch '^[a-f0-9]{32}$' -or [string]$record.data_root -cne [IO.Path]::GetFullPath($DataRoot)) { throw 'Upgrade snapshot journal integrity is invalid.' }
    $names = @{}; $inventory = @('journal.json')
    foreach ($file in @($record.files)) {
        if ([string]$file.name -cnotin @('credential.bin','sing-box.json','runtime-owned.json','msi-firewall-owned.json') -or $names.ContainsKey([string]$file.name) -or
            [string]$file.sha256 -cnotmatch '^[a-f0-9]{64}$' -or [string]$file.wrapped_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$file.blob -cne ([string]$file.name + '.blob')) { throw 'Upgrade snapshot file integrity metadata is invalid.' }
        $names[[string]$file.name] = $true
        $blob = Join-Path $SnapshotRoot $file.blob
        Assert-SnapshotOrdinaryPath $blob
        if (-not (Test-Path -LiteralPath $blob -PathType Leaf) -or (Get-Item -LiteralPath $blob).Length -gt 16777216 -or
            (Get-SnapshotHash ([IO.File]::ReadAllBytes($blob))) -cne $file.wrapped_sha256) { throw 'Upgrade snapshot blob integrity mismatch.' }
        $inventory += [string]$file.blob
    }
    $actual = @(Get-ChildItem -LiteralPath $SnapshotRoot -Force | ForEach-Object { $_.Name })
    foreach ($reservation in @(Read-SnapshotRestoreReservations $SnapshotRoot $record)) { $inventory += 'restore-' + $reservation.token + '.json' }
    if (Compare-Object @($inventory | Sort-Object) @($actual | Sort-Object)) { throw 'Upgrade snapshot contains foreign inventory.' }
    return $record
}

function Complete-SnapshotCleanup([string]$SnapshotRoot,[string]$DataRoot,[string]$Mode) {
    $receiptPath = $SnapshotRoot + '.cleanup.json'
    Assert-SnapshotDirectoryProtection (Split-Path -Parent $SnapshotRoot)
    Assert-SnapshotOrdinaryPath $receiptPath
    if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf) -or (Get-Item -LiteralPath $receiptPath).Length -gt 65536) { throw 'Invalid pending snapshot cleanup receipt.' }
    $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    if ($receipt.schema_version -ne 1 -or $receipt.product -cne 'RegenBioOverseasAccess' -or
        $receipt.transaction_id -cnotmatch '^[a-f0-9]{32}$' -or $receipt.data_root -cne [IO.Path]::GetFullPath($DataRoot) -or
        $receipt.kind -cnotin @('committed','rolled-back') -or $receipt.state -cne 'cleanup-pending' -or $receipt.journal_sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid pending snapshot cleanup ownership.' }
    if ($Mode -eq 'Rollback' -and $receipt.kind -ne 'rolled-back') { throw 'Commit cleanup already started; rollback payload is no longer complete.' }
    $expected = @{'journal.json'=[string]$receipt.journal_sha256}
    $ordered = @()
    foreach ($file in @($receipt.files)) {
        if ($file.name -cnotin @('credential.bin','sing-box.json','runtime-owned.json','msi-firewall-owned.json') -or
            $file.blob -cne ($file.name + '.blob') -or $expected.ContainsKey([string]$file.blob) -or
            $file.wrapped_sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid pending snapshot cleanup inventory.' }
        $expected[[string]$file.blob] = [string]$file.wrapped_sha256
        $ordered += [string]$file.blob
    }
    if (Test-Path -LiteralPath $SnapshotRoot) {
        Assert-SnapshotDirectoryProtection $SnapshotRoot
        # Missing owned files are expected after an interrupted cleanup. Prove
        # every remaining file and reject any foreign content BEFORE deleting.
        foreach ($item in @(Get-ChildItem -LiteralPath $SnapshotRoot -Force)) {
            Assert-SnapshotOrdinaryPath $item.FullName
            if ($item.PSIsContainer -or -not $expected.ContainsKey($item.Name) -or $item.Length -gt 16777216 -or
                (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected[$item.Name]) { throw 'Foreign or corrupt pending snapshot cleanup content.' }
        }
        foreach ($name in @($ordered) + @('journal.json')) {
            $path = Join-Path $SnapshotRoot $name
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
        }
        if (@(Get-ChildItem -LiteralPath $SnapshotRoot -Force).Count) { throw 'Foreign snapshot content prevents cleanup.' }
        Remove-Item -LiteralPath $SnapshotRoot -Force -ErrorAction Stop
    }
    # The receipt lives in the protected parent, so even a directory-delete
    # failure after the last blob/journal deletion remains safely retryable.
    Remove-Item -LiteralPath $receiptPath -Force -ErrorAction Stop
}

function Remove-UpgradeSnapshot([string]$SnapshotRoot,$Record,[string]$Kind) {
    $receiptPath = $SnapshotRoot + '.cleanup.json'
    $temporary = $receiptPath + '.new'
    Assert-SnapshotOrdinaryPath $receiptPath
    Assert-SnapshotOrdinaryPath $temporary
    if (Test-Path -LiteralPath $receiptPath) { throw 'Pending snapshot cleanup must be resumed first.' }
    $receipt = [ordered]@{schema_version=1;product='RegenBioOverseasAccess';transaction_id=$Record.transaction_id;data_root=$Record.data_root;kind=$Kind;state='cleanup-pending';files=@($Record.files);journal_sha256=(Get-FileHash -LiteralPath (Join-Path $SnapshotRoot 'journal.json') -Algorithm SHA256).Hash.ToLowerInvariant()}
    $stream = New-Object IO.FileStream($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($receipt | ConvertTo-Json -Depth 8))
        $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true); $stream.Dispose()
        [IO.File]::Move($temporary,$receiptPath)
    }
    finally { $stream.Dispose(); if (Test-Path -LiteralPath $temporary) { [IO.File]::Delete($temporary) } }
    # This durable transition is only allowed after all rollback-capable work or
    # after successful baseline rollback. It never occurs during phase two.
    Complete-SnapshotCleanup $SnapshotRoot $Record.data_root $(if ($Kind -eq 'rolled-back') { 'Rollback' } else { 'Commit' })
}

function Invoke-UpgradeSnapshot {
    param([ValidateSet('Backup','Restore','Rollback','Commit','Maintenance')][string]$Mode, [string]$DataRoot, [string]$SnapshotRoot)
    Assert-SnapshotOrdinaryPath $DataRoot
    Assert-SnapshotOrdinaryPath $SnapshotRoot
    if (Test-Path -LiteralPath ($SnapshotRoot + '.cleanup.json')) {
        if ($Mode -eq 'Restore') { throw 'Snapshot is already in terminal cleanup and cannot restore phase two.' }
        Complete-SnapshotCleanup $SnapshotRoot $DataRoot $Mode
        if ($Mode -ne 'Backup') { return }
    }
    if ($Mode -eq 'Maintenance') {
        if (Test-Path -LiteralPath $SnapshotRoot) { throw 'Unfinished upgrade recovery blocks maintenance; no runtime resources were removed.' }
        return
    }
    if (-not (Test-Path -LiteralPath $SnapshotRoot) -and $Mode -in @('Rollback','Commit')) { return }
    Assert-SnapshotDirectoryProtection $DataRoot
    if ($Mode -eq 'Backup') {
        if (Test-Path -LiteralPath $SnapshotRoot) { throw 'An existing or stale upgrade snapshot requires recovery before retry.' }
        $owned = @(Get-UpgradeOwnedRuntimeFiles $DataRoot)
        $firewall = Get-UpgradeFirewallBaseline
        if ($firewall.journal_present) { $owned += 'msi-firewall-owned.json' }
        $parent = Split-Path -Parent $SnapshotRoot
        if (-not (Test-Path -LiteralPath $parent)) {
            [void][IO.Directory]::CreateDirectory($parent)
            Set-SnapshotDirectoryProtection $parent
        }
        else { Assert-SnapshotDirectoryProtection $parent }
        $transaction = [guid]::NewGuid().ToString('N')
        $entropy = [Text.Encoding]::UTF8.GetBytes($transaction)
        $created = @()
        [void][IO.Directory]::CreateDirectory($SnapshotRoot)
        try {
            Set-SnapshotDirectoryProtection $SnapshotRoot
            if (@(Get-ChildItem -LiteralPath $SnapshotRoot -Force).Count) { throw 'Foreign snapshot content appeared before backup.' }
            $records = @()
            foreach ($name in $owned) {
                $path = Join-Path $DataRoot $name
                Assert-SnapshotOrdinaryPath $path
                if ((Get-Item -LiteralPath $path).Length -gt 8388608) { throw 'Runtime file exceeds bounded upgrade snapshot size.' }
                $bytes = [IO.File]::ReadAllBytes($path)
                # Never decrypt credential.bin. Wrap opaque bytes; this also protects
                # legacy rendered configs containing secrets from plaintext backup.
                $wrapped = [Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
                $blob = $name + '.blob'
                Write-SnapshotBytes (Join-Path $SnapshotRoot $blob) $wrapped
                $created += $blob
                $records += [ordered]@{name=$name;blob=$blob;sha256=(Get-SnapshotHash $bytes);wrapped_sha256=(Get-SnapshotHash $wrapped);sddl=(Get-Acl -LiteralPath $path).Sddl}
                [Array]::Clear($bytes, 0, $bytes.Length)
            }
            $record = [ordered]@{schema_version=1;product='RegenBioOverseasAccess';transaction_id=$transaction;data_root=[IO.Path]::GetFullPath($DataRoot);files=@($records);firewall=$firewall}
            Write-SnapshotBytes (Join-Path $SnapshotRoot 'journal.json') ([Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Depth 6)))
            [void](Read-UpgradeSnapshot $SnapshotRoot $DataRoot)
        }
        catch {
            # Before a durable journal, no original file was changed. Remove only
            # successful exact writes, retaining any unrecognized/interrupted data.
            if (-not (Test-Path -LiteralPath (Join-Path $SnapshotRoot 'journal.json'))) {
                foreach ($name in $created) { Assert-SnapshotOrdinaryPath (Join-Path $SnapshotRoot $name); [IO.File]::Delete((Join-Path $SnapshotRoot $name)) }
                if (@(Get-ChildItem -LiteralPath $SnapshotRoot -Force).Count -eq 0) { [IO.Directory]::Delete($SnapshotRoot) }
            }
            throw
        }
        return
    }
    if (-not (Test-Path -LiteralPath $SnapshotRoot)) {
        if ($Mode -in @('Rollback','Commit')) { return }
        throw 'Upgrade snapshot is absent before restoration.'
    }
    Assert-SnapshotDirectoryProtection (Split-Path -Parent $SnapshotRoot)
    $record = Read-UpgradeSnapshot $SnapshotRoot $DataRoot
    foreach ($reservation in @(Read-SnapshotRestoreReservations $SnapshotRoot $record)) { Remove-SnapshotRestoreReservation $SnapshotRoot $DataRoot $reservation }
    if ($Mode -eq 'Commit') { Remove-UpgradeSnapshot $SnapshotRoot $record 'committed'; return }
    $decoded = @{}
    $currentFirewallJournal = Read-FirewallJournal
    try {
        # Prove every DPAPI envelope before publishing any restored file.
        foreach ($file in @($record.files)) {
            $bytes = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path $SnapshotRoot $file.blob)), [Text.Encoding]::UTF8.GetBytes($record.transaction_id), [Security.Cryptography.DataProtectionScope]::LocalMachine)
            if ((Get-SnapshotHash $bytes) -cne $file.sha256) { throw 'Upgrade snapshot plaintext integrity mismatch.' }
            $decoded[[string]$file.name] = $bytes
        }
        try { $currentOwned = @(Get-UpgradeOwnedRuntimeFiles $DataRoot) }
        catch {
            # An interrupted phase-two restore may have published data before
            # its last-write ledger. Only exact bytes proven by this protected
            # snapshot are recoverable through this path; mismatches stay put.
            if (Test-Path -LiteralPath (Join-Path $DataRoot 'runtime-owned.json')) { throw }
            $currentOwned = @()
            foreach ($name in @('credential.bin','sing-box.json')) {
                $path = Join-Path $DataRoot $name
                Assert-SnapshotOrdinaryPath $path
                if (Test-Path -LiteralPath $path) {
                    if (-not $decoded.ContainsKey($name) -or -not (Test-Path -LiteralPath $path -PathType Leaf) -or
                        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne (Get-SnapshotHash $decoded[$name])) { throw 'Unowned runtime content prevents interrupted restore recovery.' }
                    $currentOwned += $name
                }
            }
        }
        foreach ($name in $currentOwned) {
            if (-not $decoded.ContainsKey($name)) { [IO.File]::Delete((Join-Path $DataRoot $name)) }
        }
        # The ownership ledger is published last, after its exact files exist.
        foreach ($file in @($record.files | Sort-Object @{Expression={ $_.name -eq 'runtime-owned.json' }}, name)) {
            $target = Join-Path $DataRoot $file.name
            Assert-SnapshotOrdinaryPath $target
            $reservation = New-SnapshotRestoreReservation $SnapshotRoot $DataRoot $record $file
            try {
                try { Write-SnapshotRestoreContent $reservation.stream $decoded[[string]$file.name] }
                finally { $reservation.stream.Dispose() }
                $acl = New-Object Security.AccessControl.FileSecurity
                $acl.SetSecurityDescriptorSddlForm([string]$file.sddl)
                Set-Acl -LiteralPath $reservation.path -AclObject $acl
                Publish-SnapshotRestoreFile $reservation.path $target
                if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256) { throw 'Restored runtime hash mismatch.' }
            }
            finally { Remove-SnapshotRestoreReservation $SnapshotRoot $DataRoot $reservation.reservation }
        }
        if ($Mode -eq 'Rollback') {
            Restore-UpgradeFirewallBaseline -Baseline $record.firewall -CurrentJournal $currentFirewallJournal
            if (-not $decoded.ContainsKey('msi-firewall-owned.json')) {
                $firewallJournalPath = Join-Path $DataRoot 'msi-firewall-owned.json'
                Assert-SnapshotOrdinaryPath $firewallJournalPath
                if (Test-Path -LiteralPath $firewallJournalPath) {
                    if ($null -eq $currentFirewallJournal) { throw 'Unowned firewall journal prevents baseline recovery.' }
                    [IO.File]::Delete($firewallJournalPath)
                }
            }
        }
    }
    finally { foreach ($bytes in $decoded.Values) { [Array]::Clear($bytes, 0, $bytes.Length) } }
    if ($Mode -eq 'Rollback') { Remove-UpgradeSnapshot $SnapshotRoot $record 'rolled-back' }
}

Invoke-UpgradeSnapshot -Mode $args[0] -DataRoot 'C:\ProgramData\RegenBio\OverseasAccess' -SnapshotRoot 'C:\ProgramData\RegenBio\InstallerTransactions\UpgradeSnapshot'
