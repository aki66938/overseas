# sing-box PoC deployment and physical-host acceptance runbook

## Status and safety boundary

This is an operator procedure, not permission to perform a deployment from a
development workstation. The developer workstation is not the designated host.
Run it only on the authorized disposable physical Windows host and only after
the Task 10 code prerequisites have been implemented and independently reviewed.
The current prerequisite ledger is `.superpowers/sdd/task-10-brief.md`.

OVERSEAS_ACCESS_INTEGRATION=1 must never be set by this runbook. It neither
sets that variable nor changes routes, DNS, firewall, services, adapters,
installer state, or runtime configuration while being read or statically tested.
The authorised physical-host operator performs each expressly approved action.

Known server facts to verify, rather than overwrite, are:

- VM address/prefix: `172.20.9.15/22`; default gateway: `172.20.10.1`.
- Expected interface index: interface index 4.
- SSH host: `DESKTOP-1BVR2H6`.
- Telecom upstream: `127.0.0.1:8080` (VM loopback only).
- Employee CIDR and server port are `172.20.8.0/22` and `18443`.

All Internet TCP must use the tested tunnel. Corporate traffic, including the
node, AD, corporate DNS, EC, and `172.20.8.0/22`, remains direct. Internet UDP
and UDP/443 must remain rejected. Loss of the telecom upstream, server, tunnel,
policy, or binary must fail closed; it must never select an ordinary Internet
gateway. TCP 8080 must never be reachable from the physical client.

## Required external inputs — stop if any is missing

- The actual SSH SHA256 host key fingerprint, supplied through an independently
  verified channel; do not accept a fingerprint displayed only by this session.
- Corporate signer thumbprint and signed artifacts, including the exact
  corporate fixture-manifest signer allowlist and corporate executable
  signer allowlists; the corporate-signed MSI; detached signatures for the
  fixture and release payload manifests; and pinned server bundle/config hashes.
- Signed fixture contract values for every corporate CIDR, corporate DNS
  resolver, and internal suffix; signed release payload entries for every file,
  destination, SHA-256, and Authenticode requirement; and exact generated
  client, server, and action-config hashes.
- Exact public-data/public-health/corporate/fake-control/fake-data endpoints and
  distinct identities, plus the production server listener endpoint and a
  future RFC3339 credential expiration bound by the action config.
- Credential supplied pipe-only to the manifest-pinned provisioner. Do not place
  it in argv, a file, logs, evidence, source control, or an MSI property.
- Physical disposable host identity/token and authorization to use it. It must
  be a new host, not a developer workstation or previously accepted host.
- A new empty baseline directory on ACL-protected evidence storage.
- Operator stop/go approval before every mutation group, plus a maintenance
  window, VM-console recovery owner, and telecom PIN-holder availability. The
  PIN itself is never requested, read, written, or distributed here.

Use a UTC run ID and preserve only sanitized evidence:

```powershell
$RunId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$EvidenceRoot = 'D:\RegenBio-Evidence\sing-box-poc'
$ArtifactsPath = Join-Path $EvidenceRoot $RunId
$BaselineDirectory = Join-Path $ArtifactsPath 'baseline'
if (Test-Path -LiteralPath $ArtifactsPath) { throw "Run directory already exists: $ArtifactsPath" }
New-Item -ItemType Directory -Path $BaselineDirectory -ErrorAction Stop | Out-Null
if (@(Get-ChildItem -LiteralPath $BaselineDirectory -Force).Count -ne 0) { throw 'Baseline directory must be new and empty.' }
```

Record the operator, approval reference, exact target names, UTC timestamps,
binary/config/manifest hashes, exit codes, route/DNS/firewall snapshots, nonce
receipt, leak receipt, and redacted logs. Do not collect credentials, PINs,
private keys, raw employee identifiers, page content, or full URLs.

## Common guard convention

Every native invocation below captures `$?` and `$LASTEXITCODE` on the next two
lines and aborts on either launch or exit failure. Do not combine native commands
in a pipeline, command substitution, or `cmd /c`; doing so breaks that guarantee.
If an additional native command is needed, copy the same four-line pattern and
give it a unique prefix. PowerShell cmdlets use `-ErrorAction Stop` and must be
included in the evidence rather than silently ignored.

Use this PowerShell-only collector before each real mutation group; it records
the physical-host inventory without changing the protected network state:

```powershell
function Save-PhysicalInventory {
    param([Parameter(Mandatory = $true)][string] $Path)
    [ordered]@{
        captured_utc = [datetime]::UtcNow.ToString('o')
        adapters = Get-NetAdapter -ErrorAction Stop
        routes = Get-NetRoute -ErrorAction Stop
        dns = Get-DnsClientServerAddress -ErrorAction Stop
        listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop
        services = Get-Service -ErrorAction Stop
        firewall = Get-NetFirewallRule -ErrorAction Stop
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}
```

## 1. Pin the SSH host key and inspect VM facts (read-only)

The actual SSH SHA256 host key fingerprint is a required external input. Replace
only the placeholder below with the value approved out-of-band; never paste an
SSH private key. Compare the `ssh-keygen` output exactly before pinning the
scanned key. A mismatch is a hard stop.

```powershell
$VmSshHost = 'DESKTOP-1BVR2H6'
$VmSshTarget = 'Administrator@DESKTOP-1BVR2H6'
$KnownHostsPath = Join-Path $ArtifactsPath 'known_hosts'
$ScannedHostKeyPath = Join-Path $ArtifactsPath 'vm-ed25519.pub'
$ActualHostKeyFingerprint = '<SHA256-FINGERPRINT-SUPPLIED-OUT-OF-BAND>'
& ssh-keyscan.exe -t ed25519 $VmSshHost > $ScannedHostKeyPath
$SshKeyscanSucceeded = $?
$SshKeyscanExitCode = $LASTEXITCODE
if (-not $SshKeyscanSucceeded -or $SshKeyscanExitCode -ne 0) { throw '& ssh-keyscan.exe -t ed25519 $VmSshHost > $ScannedHostKeyPath failed to launch or exited with code $SshKeyscanExitCode.' }
& ssh-keygen.exe -lf $ScannedHostKeyPath -E sha256
$SshKeygenSucceeded = $?
$SshKeygenExitCode = $LASTEXITCODE
if (-not $SshKeygenSucceeded -or $SshKeygenExitCode -ne 0) { throw '& ssh-keygen.exe -lf $ScannedHostKeyPath -E sha256 failed to launch or exited with code $SshKeygenExitCode.' }
Read-Host 'Compare the displayed fingerprint to $ActualHostKeyFingerprint; type the approved fingerprint to continue' | ForEach-Object { if ($_ -cne $ActualHostKeyFingerprint) { throw 'SSH host-key fingerprint mismatch.' } }
Copy-Item -LiteralPath $ScannedHostKeyPath -Destination $KnownHostsPath -ErrorAction Stop
```

The following remote commands are fixed read-only evidence commands. Do not
substitute an IP address or disable `StrictHostKeyChecking`.

```powershell
$VmFactsPath = Join-Path $BaselineDirectory 'vm-facts.json'
$VmBaselinePath = Join-Path $BaselineDirectory 'baseline-vm.json'
$TelecomConnectPath = Join-Path $BaselineDirectory 'telecom-connect.json'
$VmFactsCommand = 'powershell.exe -NoProfile -Command "Get-ComputerInfo | Select-Object CsName,WindowsProductName,WindowsVersion,OsBuildNumber | ConvertTo-Json -Compress"'
$VmBaselineCommand = 'powershell.exe -NoProfile -Command "[ordered]@{ adapters=Get-NetAdapter; routes=Get-NetRoute; dns=Get-DnsClientServerAddress; listeners=Get-NetTCPConnection -State Listen; services=Get-Service; processes=Get-Process; firewall=Get-NetFirewallRule; sing_box=(Get-Command sing-box.exe -ErrorAction SilentlyContinue); direct_google=(Test-NetConnection -ComputerName www.google.com -Port 443 -InformationLevel Detailed) } | ConvertTo-Json -Depth 6"'
$TelecomConnectCommand = 'powershell.exe -NoProfile -Command "curl.exe --proxy http://127.0.0.1:8080 --connect-timeout 15 https://www.google.com/generate_204 -o NUL; `$CurlSucceeded = `$?; `$CurlExitCode = `$LASTEXITCODE; if (-not `$CurlSucceeded -or `$CurlExitCode -ne 0) { exit `$CurlExitCode }"'
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmFactsCommand > $VmFactsPath
$VmFactsSucceeded = $?
$VmFactsExitCode = $LASTEXITCODE
if (-not $VmFactsSucceeded -or $VmFactsExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmFactsCommand > $VmFactsPath failed to launch or exited with code $VmFactsExitCode.' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmBaselineCommand > $VmBaselinePath
$VmBaselineSucceeded = $?
$VmBaselineExitCode = $LASTEXITCODE
if (-not $VmBaselineSucceeded -or $VmBaselineExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmBaselineCommand > $VmBaselinePath failed to launch or exited with code $VmBaselineExitCode.' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $TelecomConnectCommand > $TelecomConnectPath
$TelecomConnectSucceeded = $?
$TelecomConnectExitCode = $LASTEXITCODE
if (-not $TelecomConnectSucceeded -or $TelecomConnectExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $TelecomConnectCommand > $TelecomConnectPath failed to launch or exited with code $TelecomConnectExitCode.' }
```

Review and sign the facts: OS, adapter, interface index 4, routes, DNS,
listeners, services/processes, firewall, sing-box absence/presence, owner of
port 8080, direct Google failure (without the telecom proxy), and CONNECT-through
8080 success. If direct Google succeeds, TCP 8080 is non-loopback, the owner is
unexpected, or the CONNECT check fails, stop and preserve evidence.

## 2. Server dry run and zero-drift proof

Copy only the corporate-signed server release to a VM staging directory with
ACLs restricted to Administrators/SYSTEM. Generate the server configuration and
one-time secret through the reviewed release process; no credential appears in
this runbook or local history. Supply the real signed values only on the VM.

```powershell
$ServerWhatIfPath = Join-Path $ArtifactsPath 'server-whatif.json'
$ServerInstallPath = Join-Path $ArtifactsPath 'server-install.json'
$ServerStatusPath = Join-Path $ArtifactsPath 'server-status.json'
$ServerRollbackPath = Join-Path $ArtifactsPath 'server-rollback.json'
$ServerWhatIfCommand = "powershell.exe -NoProfile -File 'C:\Staging\OverseasAccessServer\install-server.ps1' -Mode Install -BundlePath 'C:\Staging\OverseasAccessServer\bundle' -ConfigPath 'C:\Staging\OverseasAccessServer\server.json' -ExpectedSingBoxSha256 '<SIGNED-SHA256>' -ExpectedConfigSha256 '<SIGNED-SHA256>' -ExpectedServerServiceSha256 '<SIGNED-SHA256>' -EmployeeCIDR '172.20.8.0/22' -ServerPort 18443 -EvidencePath 'C:\Staging\OverseasAccessServer\evidence.json' -WhatIf"
$ServerInstallCommand = "powershell.exe -NoProfile -File 'C:\Staging\OverseasAccessServer\install-server.ps1' -Mode Install -BundlePath 'C:\Staging\OverseasAccessServer\bundle' -ConfigPath 'C:\Staging\OverseasAccessServer\server.json' -ExpectedSingBoxSha256 '<SIGNED-SHA256>' -ExpectedConfigSha256 '<SIGNED-SHA256>' -ExpectedServerServiceSha256 '<SIGNED-SHA256>' -EmployeeCIDR '172.20.8.0/22' -ServerPort 18443 -EvidencePath 'C:\Staging\OverseasAccessServer\evidence.json'"
$ServerStatusCommand = "powershell.exe -NoProfile -File 'C:\Staging\OverseasAccessServer\install-server.ps1' -Mode Status -EvidencePath 'C:\Staging\OverseasAccessServer\evidence.json'"
$ServerRollbackCommand = "powershell.exe -NoProfile -File 'C:\Staging\OverseasAccessServer\install-server.ps1' -Mode Rollback -EvidencePath 'C:\Staging\OverseasAccessServer\evidence.json'"
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerWhatIfCommand > $ServerWhatIfPath
$ServerWhatIfSucceeded = $?
$ServerWhatIfExitCode = $LASTEXITCODE
if (-not $ServerWhatIfSucceeded -or $ServerWhatIfExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerWhatIfCommand > $ServerWhatIfPath failed to launch or exited with code $ServerWhatIfExitCode.' }
```

Capture the same VM inventory again, compare it to `baseline-vm.json`, and
record zero changes after WhatIf. Any difference is a FAIL; do not install.

## 3. STOP/GO — server install

Before this real mutation group, record a fresh VM inventory in the evidence
directory and obtain written operator stop/go approval. The telecom PIN session
must be active, the server release must be corporate-signed, all hashes must
match the detached manifest, and the code-prerequisite ledger must be closed.

```powershell
$VmPreInstallPath = Join-Path $ArtifactsPath 'server-preinstall-inventory.json'
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmBaselineCommand > $VmPreInstallPath
$VmPreInstallSucceeded = $?
$VmPreInstallExitCode = $LASTEXITCODE
if (-not $VmPreInstallSucceeded -or $VmPreInstallExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmBaselineCommand > $VmPreInstallPath failed to launch or exited with code $VmPreInstallExitCode.' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerInstallCommand > $ServerInstallPath
$ServerInstallSucceeded = $?
$ServerInstallExitCode = $LASTEXITCODE
if (-not $ServerInstallSucceeded -or $ServerInstallExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerInstallCommand > $ServerInstallPath failed to launch or exited with code $ServerInstallExitCode.' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerStatusCommand > $ServerStatusPath
$ServerStatusSucceeded = $?
$ServerStatusExitCode = $LASTEXITCODE
if (-not $ServerStatusSucceeded -or $ServerStatusExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerStatusCommand > $ServerStatusPath failed to launch or exited with code $ServerStatusExitCode.' }
```

Exact server rollback command: `deploy\server\install-server.ps1 -Mode Rollback`
(executed remotely through the guarded `$ServerRollbackCommand` below). Do not
manually remove a service, route, firewall rule, or directory.

## 4. STOP/GO — standard-client activation

Take `baseline-physical.json` before any mutation. The physical host must use a
standard upstream sing-box client first. Its temporary configuration is generated
from the approved server manifest and one-time secret; it contains no corporate
client MSI artifacts. The standard-client gate PASS is required before custom MSI
and must be recorded before proceeding.

```powershell
$PhysicalBaselinePath = Join-Path $BaselineDirectory 'baseline-physical.json'
Save-PhysicalInventory -Path $PhysicalBaselinePath
$StandardClientConfigPath = 'C:\Staging\standard-client.json'
$StandardSingBoxPath = 'C:\Staging\sing-box.exe'
& $StandardSingBoxPath run -c $StandardClientConfigPath
$StandardClientSucceeded = $?
$StandardClientExitCode = $LASTEXITCODE
if (-not $StandardClientSucceeded -or $StandardClientExitCode -ne 0) { throw '& $StandardSingBoxPath run -c $StandardClientConfigPath failed to launch or exited with code $StandardClientExitCode.' }
```

The operator must prove an approved HTTPS target succeeds, corporate access
continues, and direct access to VM:8080 failure is observed. Stop the server
service and then the telecom process under the approved VM recovery procedure;
each must produce service stop leak failure and telecom-process stop leak failure
(no ordinary Internet receipt), followed by recovery after restart. Capture
`standard-client.json`, timestamps, config/binary hashes, nonce receipt, and
leak receipt. If any check fails, run the rollback section immediately.

## 5. STOP/GO — custom-MSI install

Remove the standard sing-box configuration before the MSI gate. Confirm it
is absent and inventory the physical host again. Verify the MSI and every
detached manifest with `Get-AuthenticodeSignature` and exact hashes, and require
the signer thumbprint to equal `$CorporateSignerThumbprint`; the MSI must be
externally corporate-signed, not merely locally trusted.

```powershell
$MsiPreInstallInventoryPath = Join-Path $ArtifactsPath 'msi-preinstall-inventory.json'
Save-PhysicalInventory -Path $MsiPreInstallInventoryPath
$CorporateSignedMsiPath = 'C:\Staging\OverseasAccessSetup.msi'
$CorporateSignerThumbprint = '<CORPORATE-SIGNER-THUMBPRINT-SUPPLIED-OUT-OF-BAND>'
$MsiSignature = Get-AuthenticodeSignature -FilePath $CorporateSignedMsiPath -ErrorAction Stop
if ($MsiSignature.Status -ne 'Valid' -or $MsiSignature.SignerCertificate.Thumbprint -cne $CorporateSignerThumbprint) { throw 'MSI signature or corporate signer thumbprint is invalid.' }
$MsiInstallLogPath = Join-Path $ArtifactsPath 'msi-install.log'
& msiexec.exe /i $CorporateSignedMsiPath /qn /norestart /l*v $MsiInstallLogPath
$MsiInstallSucceeded = $?
$MsiInstallExitCode = $LASTEXITCODE
if (-not $MsiInstallSucceeded -or $MsiInstallExitCode -ne 0) { throw '& msiexec.exe /i $CorporateSignedMsiPath /qn /norestart /l*v $MsiInstallLogPath failed to launch or exited with code $MsiInstallExitCode.' }
```

The credential is supplied pipe-only by the reviewed manifest-pinned provisioner;
this contract must be present before installation. Never use a command line,
response file, temporary file, registry entry, evidence field, or log for it.
Click the shipped UI's enable/disable toggle only after a clean baseline and
inventory are recorded. Verify enable/disable for browser, Git, HTTPS, corporate
DNS, AD, and EC; retain exact probe targets, route/DNS/firewall snapshots, and
redacted logs. A required Git probe example follows the same native guard.

```powershell
$ApprovedGitProbeRepository = 'https://<OPERATOR-APPROVED-REDACTED-GIT-ENDPOINT>/'
$GitProbePath = Join-Path $ArtifactsPath 'git-probe.txt'
& git.exe ls-remote $ApprovedGitProbeRepository > $GitProbePath
$GitProbeSucceeded = $?
$GitProbeExitCode = $LASTEXITCODE
if (-not $GitProbeSucceeded -or $GitProbeExitCode -ne 0) { throw '& git.exe ls-remote $ApprovedGitProbeRepository > $GitProbePath failed to launch or exited with code $GitProbeExitCode.' }
```

## 6. STOP/GO — lifecycle and uninstall

Before each injected failure, capture inventory and approve the specific action.
Test service/core/UI termination, node loss, telecom loss, reboot, user disable,
and 20 clean enable/disable cycles. A successful check requires a fail-closed
result while unavailable, recovery only after the dependency returns, and no
ordinary-exit fallback. Use the operator-recorded PIDs only after confirming the
image path and hash match the signed manifest.

```powershell
$LifecycleInventoryPath = Join-Path $ArtifactsPath 'lifecycle-precheck-inventory.json'
Save-PhysicalInventory -Path $LifecycleInventoryPath
& taskkill.exe /PID $AgentProcessId /T /F
$AgentKillSucceeded = $?
$AgentKillExitCode = $LASTEXITCODE
if (-not $AgentKillSucceeded -or $AgentKillExitCode -ne 0) { throw '& taskkill.exe /PID $AgentProcessId /T /F failed to launch or exited with code $AgentKillExitCode.' }
& taskkill.exe /PID $CoreProcessId /T /F
$CoreKillSucceeded = $?
$CoreKillExitCode = $LASTEXITCODE
if (-not $CoreKillSucceeded -or $CoreKillExitCode -ne 0) { throw '& taskkill.exe /PID $CoreProcessId /T /F failed to launch or exited with code $CoreKillExitCode.' }
& taskkill.exe /PID $UiProcessId /T /F
$UiKillSucceeded = $?
$UiKillExitCode = $LASTEXITCODE
if (-not $UiKillSucceeded -or $UiKillExitCode -ne 0) { throw '& taskkill.exe /PID $UiProcessId /T /F failed to launch or exited with code $UiKillExitCode.' }
& shutdown.exe /r /t 0 /f
$RebootSucceeded = $?
$RebootExitCode = $LASTEXITCODE
if (-not $RebootSucceeded -or $RebootExitCode -ne 0) { throw '& shutdown.exe /r /t 0 /f failed to launch or exited with code $RebootExitCode.' }
```

After return from reboot, continue only after a new stop/go approval and
inventory. For cycles 1 through 20, use the UI toggle, prove the complete
probe matrix in both states, wait for the action-local snapshots, and record
the per-cycle nonce/leak receipts in `lifecycle-20-cycles.json`. Any missing
receipt, timeout, drift, fallback, or failed restore is FAIL.

Before uninstall, save `custom-client.json`, invoke a controlled disable, and
record the final managed resources. The exact custom-client rollback/uninstall
command is `msiexec.exe /x $CorporateSignedMsiPath /qn /norestart`:

```powershell
$MsiUninstallLogPath = Join-Path $ArtifactsPath 'msi-uninstall.log'
& msiexec.exe /x $CorporateSignedMsiPath /qn /norestart /l*v $MsiUninstallLogPath
$MsiUninstallSucceeded = $?
$MsiUninstallExitCode = $LASTEXITCODE
if (-not $MsiUninstallSucceeded -or $MsiUninstallExitCode -ne 0) { throw '& msiexec.exe /x $CorporateSignedMsiPath /qn /norestart /l*v $MsiUninstallLogPath failed to launch or exited with code $MsiUninstallExitCode.' }
```

## 7. STOP/GO — rollback

Any mandatory failure invokes server rollback before a new attempt. Inventory
the VM immediately before and after the action; preserve the rollback evidence
and compare it to the original VM baseline. The guarded exact action is:

```powershell
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerRollbackCommand > $ServerRollbackPath
$ServerRollbackSucceeded = $?
$ServerRollbackExitCode = $LASTEXITCODE
if (-not $ServerRollbackSucceeded -or $ServerRollbackExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerRollbackCommand > $ServerRollbackPath failed to launch or exited with code $ServerRollbackExitCode.' }
```

Then uninstall the custom client (if present), remove only the operator-created
standard-client configuration, and compare the final physical inventory to
`baseline-physical.json`. Exact final-state restoration requires original routes,
DNS, firewall, services, adapters, installer state, and runtime configuration.
If rollback cannot be proven, declare FAIL, preserve evidence, and escalate to
the VM-console recovery owner; do not attempt manual cleanup.

## 8. Evidence bundle and verdict

Before signing a verdict, place these sanitized files in `$ArtifactsPath`:
`baseline-vm.json`, `baseline-physical.json`, `server-whatif.json`,
`server-install.json`, `server-status.json`, `server-rollback.json`,
`standard-client.json`, `custom-client.json`, `lifecycle-20-cycles.json`, and
`verdict.json`. Hash every signed artifact and emitted evidence file with
`Get-FileHash`; use `Compress-Archive` only after a redaction review and store
the archive outside Git. Runtime artifacts belong under the already ignored
`artifacts/sing-box-poc/<UTC-run-id>/` path.

PASS requires one full workday, all required probes, all fail-closed cases, 20
clean cycles, no direct 8080 access, no ordinary-exit fallback, and exact final-
state restoration. Any mandatory failure is FAIL and triggers the rollback above.
Never label a partial test PASS.
