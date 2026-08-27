# Windows forwarding PoC operator runbook

This runbook is the controlled proof only. It does not create a control plane or
an end-user client. Run it from an elevated PowerShell session on the Windows
VM, during the approved maintenance window, and test only the operator-approved
HTTPS target and IPs covered by the telecom/operator whitelist.

## Stop/go prerequisites

Do not start unless all of the following are present:

- written operator approval, including the exact operator-approved HTTPS target
  and permitted destination IPs;
- VM console access that remains available if networking is disrupted;
- a recovery snapshot location under artifacts and enough protected storage to
  copy it elsewhere;
- current telecom PIN holder availability. The PIN stays with that holder and is
  never entered into, read by, stored in, or automated by these scripts;
- an approved maintenance window and an operator available to manually
  disconnect/reconnect the telecom client; and
- one pre-existing WireGuard test interface/address and its exact configured
  subnet route. The inventory command requires that route on the selected
  interface. Only its test subnet may be NATed; employee and management subnets
  remain directly routed.

Stop immediately and roll back where applicable if a snapshot fails, an alias
is ambiguous or resolves to a different index, the WireGuard subnet overlaps an
existing route/address or CGNAT use, NAT creation fails, the employee default
route/internal routes change, the no-leak check detects a reconnect or success,
or rollback verification fails. Do not retry an apply against an uncertain
network state.

## Build and review the fixed inputs

From the repository root, run the repeatable local checks. make test uses
Pester's detailed output when that option is supported and falls back to the
Pester 3 verbose form available on older Windows hosts.

~~~powershell
make test
make build
Test-Path .\bin\poc-probe.exe
~~~

Create the untracked runtime configuration once, then edit it only with the
approved aliases, target, timeout, telecom_route_prefixes, and internal CIDRs.
Never use the sample hostname as an actual test target.

~~~powershell
if (-not (Test-Path -LiteralPath .\configs\poc.yaml -PathType Leaf)) {
    Copy-Item .\configs\poc.example.yaml .\configs\poc.yaml
}
notepad .\configs\poc.yaml
.\bin\poc-probe.exe preflight --config .\configs\poc.yaml
Get-Content -LiteralPath .\configs\poc.yaml -Raw
~~~

The commands below deliberately use one immutable run ID for every evidence
file. The binary computes the config_digest from the full validated config;
the verdict rejects evidence with another run ID or digest. Do not reuse an
artifact filename: the binary and no-leak script both use create-new semantics.

~~~powershell
$ArtifactsPath = [System.IO.Path]::GetFullPath('.\artifacts')
$ConfigPath = [System.IO.Path]::GetFullPath('.\configs\poc.yaml')
$RunId = 'poc-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$InventoryBeforePath = Join-Path $ArtifactsPath 'inventory-before.json'
$ProbeUpPath = Join-Path $ArtifactsPath 'probe-telecom-up.json'
$ProbeDownPath = Join-Path $ArtifactsPath 'probe-telecom-down.json'
$DownMonitorPath = Join-Path $ArtifactsPath 'probe-telecom-down-monitor.json'
$InventoryAfterPath = Join-Path $ArtifactsPath 'inventory-after.json'
$VerdictPath = Join-Path $ArtifactsPath 'verdict.json'

$ConfigMetadata = & .\bin\poc-probe.exe describe-config --config $ConfigPath | ConvertFrom-Json
$ConfigDigest = $ConfigMetadata.config_digest
$TelecomRoutePrefixes = @($ConfigMetadata.telecom_route_prefixes)
$ConfigMetadata
~~~

Record the output of describe-config in the change ticket. In particular,
confirm that telecom_route_prefixes are exactly the approved external/default
prefixes presently installed by the telecom client; this is the route set the
no-leak monitor watches. The command intentionally exposes only the telecom
interface, telecom_route_prefixes, and config_digest; it is not an apply input.

Set these parameters exactly to the reviewed values in poc.yaml; PowerShell
does not parse YAML for the transaction scripts, so this explicit copy is a
mandatory second-person check. The example values below are documentation
values, not discovered VM aliases.

~~~powershell
$WireGuardInterface = 'wg-overseas-poc'
$TelecomInterface = 'Telecom-Client'
$EmployeeInterface = 'Ethernet'
$WireGuardSubnet = '100.127.77.0/24'
$InternalCidrs = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
~~~

Before continuing, verify each alias once and stop if an alias returns zero or
multiple adapters, or the three interface indices are not distinct.

~~~powershell
Get-NetAdapter -Name $WireGuardInterface, $TelecomInterface, $EmployeeInterface | Select-Object Name, ifIndex, Status
~~~

The WireGuard subnet example is 100.127.77.0/24. It must be absent from every
internal route/address, every telecom/operator route, and current CGNAT use
before apply. 100.64.0.0/10 is CGNAT; using any part of it is forbidden when
another interface or route already uses CGNAT. The following read-only check is
the same overlap guard used by apply. It permits only the already configured
test address/route on the selected WireGuard interface.

~~~powershell
. .\scripts\windows\poc-networking-common.ps1
$WireGuardAdapter = Get-NetAdapter -Name $WireGuardInterface -ErrorAction Stop
Assert-PocWireGuardSubnetAvailable -WireGuardSubnet $WireGuardSubnet -InternalCidrs $InternalCidrs -WireGuardInterfaceIndex ([int] $WireGuardAdapter.ifIndex) -IPAddresses @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop) -Routes @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Sort-Object InterfaceIndex, DestinationPrefix | Format-Table -AutoSize
~~~

Any thrown error is a stop condition. Do not choose another subnet during this
window without renewed written approval and a new reviewed config.

## Snapshot, preview, and controlled apply

Capture the snapshot before any network mutation. snapshot.ps1 emits the actual
absolute timestamped filename on success. Save that exact output into
$SnapshotPath; do not type a literal artifacts\<selected-snapshot>.json.
The file is an integrity envelope with SchemaVersion = 2, PayloadBase64, and
PayloadSha256; apply verifies the payload hash, machine, snapshot interfaces,
employee default route, and (by default) a maximum age of 240 minutes. Copy the
returned file to the approved recovery location before apply.

~~~powershell
$SnapshotPath = & .\scripts\windows\snapshot.ps1 -WireGuardInterface $WireGuardInterface -TelecomInterface $TelecomInterface -EmployeeInterface $EmployeeInterface -ArtifactsDirectory $ArtifactsPath -Confirm:$false
if ([string]::IsNullOrWhiteSpace($SnapshotPath) -or -not (Test-Path -LiteralPath $SnapshotPath -PathType Leaf)) {
    throw 'Snapshot failed; stop before applying any PoC networking change.'
}
Copy-Item -LiteralPath $SnapshotPath -Destination '<operator-approved-recovery-location>' -ErrorAction Stop
~~~

First preview the exact transaction. -WhatIf runs validations but does not
create rules/NAT or change forwarding. It is not evidence that the eventual
mutation succeeded.

~~~powershell
.\scripts\windows\apply-poc.ps1 -SnapshotPath $SnapshotPath -WireGuardInterface $WireGuardInterface -TelecomInterface $TelecomInterface -EmployeeInterface $EmployeeInterface -WireGuardSubnet $WireGuardSubnet -InternalCidrs $InternalCidrs -WhatIf
~~~

With the operator at the console, capture the baseline evidence and apply once.
The apply transaction creates exactly OverseasPocNat, three owned firewall rules
in Overseas Gateway PoC, and IPv4 forwarding only on the WireGuard and telecom
indices. If any transactional step fails, its script compensates by removing
PoC state and restoring saved forwarding; the employee public-internet block is
deliberately retained if safe compensation cannot be verified.

~~~powershell
.\bin\poc-probe.exe inventory --config $ConfigPath --run-id $RunId --out $InventoryBeforePath
.\scripts\windows\apply-poc.ps1 -SnapshotPath $SnapshotPath -WireGuardInterface $WireGuardInterface -TelecomInterface $TelecomInterface -EmployeeInterface $EmployeeInterface -WireGuardSubnet $WireGuardSubnet -InternalCidrs $InternalCidrs -Confirm:$false
~~~

If apply reports an error, stop traffic testing. Preserve its error and use the
rollback procedure below only after confirming console access; do not attempt a
second apply.

## Connectivity and fail-closed evidence

With the telecom client connected and one WireGuard test peer active, produce
the up-state evidence. A healthy result means validated TLS and a 2xx HTTPS
response for every approved target. Confirm the observed public path separately
with operator-supplied telecom-line evidence.

~~~powershell
.\bin\poc-probe.exe probe --config $ConfigPath --run-id $RunId --out $ProbeUpPath
~~~

Hash the exact compiled native binary immediately before the no-leak step. The
no-leak script refuses wrappers/non-PE executables, holds a deny-write lock
across both binary calls, and verifies this caller-supplied PocProbeSha256.
It asks the operator to manually disconnect then reconnect the telecom client;
it neither handles nor requests the telecom PIN. It writes both the down probe
and continuous route/interface monitor evidence with the same run ID and
config_digest.

~~~powershell
$PocProbeSha256 = (Get-FileHash -LiteralPath .\bin\poc-probe.exe -Algorithm SHA256 -ErrorAction Stop).Hash
.\scripts\windows\assert-no-leak.ps1 -ConfigPath $ConfigPath -RunId $RunId -OutputPath $ProbeDownPath -MonitorOutputPath $DownMonitorPath -PocProbePath ([System.IO.Path]::GetFullPath('.\bin\poc-probe.exe')) -PocProbeSha256 $PocProbeSha256
~~~

Stop and proceed to rollback if any configured telecom route remains after
manual disconnection, the telecom path reconnects while the probe runs, any
approved target succeeds while telecom is disconnected, the native probe exits
nonzero, or the telecom route/interface does not return after manual reconnect.

## Roll back, compare, and decide

Rollback accepts the actual selected snapshot path, validates its envelope and
transaction ownership, removes only OverseasPocNat and the three exact owned
rules, restores only the two saved forwarding settings, and then verifies those
resources are absent/restored. A snapshot can be used for recovery even if it is
older than the apply age limit. Rollback verification failed is a hard stop:
keep console access and escalate; do not declare normal networking restored.

~~~powershell
.\scripts\windows\rollback-poc.ps1 -SnapshotPath $SnapshotPath -Confirm:$false
.\bin\poc-probe.exe inventory --config $ConfigPath --run-id $RunId --out $InventoryAfterPath
.\bin\poc-probe.exe verdict --config $ConfigPath --run-id $RunId --artifacts $ArtifactsPath --out $VerdictPath
Get-Content -LiteralPath $VerdictPath -Raw | ConvertFrom-Json
~~~

The verdict consumes exactly these fixed filenames in $ArtifactsPath:
inventory-before.json, probe-telecom-up.json, probe-telecom-down.json,
probe-telecom-down-monitor.json, and inventory-after.json. It fails on state
drift, a down-state leak, or telecom reconnection, and is inconclusive for
missing, stale, malformed, wrong-run, or wrong-digest evidence.

Only PASS permits a separate plan for subsequent work. FAIL_LEAK,
FAIL_NO_FORWARD, FAIL_STATE_DRIFT, FAIL_TELECOM_RECONNECTED, or any
INCONCLUSIVE_* result stops the PoC gate. Do not commit configs/poc.yaml or raw
artifacts; both are intentionally ignored.
