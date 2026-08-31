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
  destination, SHA-256, source commit, and Authenticode signer requirement; and
  exact generated client, server, action-config, credential-source, and remote
  attestation hashes.
- Exact public-data/public-health/corporate/fake-control/fake-data endpoints and
  distinct identities, plus the production server listener endpoint and a
  future RFC3339 credential expiration bound by the action config.
- Remote attestation captured from VM101 over pinned SSH host-key
  custody. It must bind the exact server-service path/hash, sing-box path/hash,
  config path/hash, listener PID/path/hash, parent-child PID chain, and
  `172.20.9.15:18443` listener ownership. Do not install the server locally on
  the physical client.
- Credential supplied pipe-only to the manifest-pinned provisioner. Do not place
  it in argv, a file, logs, evidence, source control, an MSI property, or an
  environment variable. The only allowed runtime sing-box client config is the product-owned ACL-protected runtime file required by sing-box, and uninstall must remove it.
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
        processes = Get-Process -ErrorAction Stop
        firewall = Get-NetFirewallRule -ErrorAction Stop
        registry = Get-Item 'HKLM:\Software' -ErrorAction Stop | Select-Object Name
        scheduled_tasks = Get-ScheduledTask -ErrorAction Stop | Select-Object TaskName,TaskPath,State
        server_owned_state = Get-ChildItem -LiteralPath 'C:\ProgramData\RegenBio' -Force -ErrorAction SilentlyContinue | Select-Object FullName,Name,Length,LastWriteTimeUtc
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}

function Compare-CanonicalStateSnapshots {
    param(
        [Parameter(Mandatory = $true)][string] $BeforePath,
        [Parameter(Mandatory = $true)][string] $AfterPath,
        [Parameter(Mandatory = $true)][string] $Label
    )
    $before = Get-Content -LiteralPath $BeforePath -Raw -ErrorAction Stop | ConvertFrom-Json
    $after = Get-Content -LiteralPath $AfterPath -Raw -ErrorAction Stop | ConvertFrom-Json
    $beforeCanonical = ($before | ConvertTo-Json -Compress -Depth 8)
    $afterCanonical = ($after | ConvertTo-Json -Compress -Depth 8)
    if ($beforeCanonical -cne $afterCanonical) { throw "$Label drift detected." }
}

function Capture-ManagedProcess {
    param(
        [string] $ServiceName,
        [string] $ParentServiceName,
        [Parameter(Mandatory = $true)][string] $ExpectedPath,
        [Parameter(Mandatory = $true)][string] $ExpectedSha256
    )
    if (($ServiceName -and $ParentServiceName) -or (-not $ServiceName -and -not $ParentServiceName -and [string]::IsNullOrWhiteSpace($ExpectedPath))) { throw 'Process capture mode is invalid.' }
    $service = $null
    $parentPid = 0
    if ($ServiceName) {
        $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        if ($null -eq $service -or [int] $service.ProcessId -le 0) { throw "$ServiceName is not running." }
        $candidates = @(Get-CimInstance Win32_Process -Filter "ProcessId=$([int] $service.ProcessId)" -ErrorAction Stop)
    }
    elseif ($ParentServiceName) {
        $service = Get-CimInstance Win32_Service -Filter "Name='$ParentServiceName'" -ErrorAction Stop
        if ($null -eq $service -or [int] $service.ProcessId -le 0) { throw "$ParentServiceName is not running." }
        $parentPid = [int] $service.ProcessId
        $candidates = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            [int] $_.ParentProcessId -eq $parentPid -and [string]::Equals([string] $_.ExecutablePath, $ExpectedPath, [StringComparison]::OrdinalIgnoreCase)
        })
    }
    else {
        $candidates = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            [string]::Equals([string] $_.ExecutablePath, $ExpectedPath, [StringComparison]::OrdinalIgnoreCase)
        })
    }
    if ($candidates.Count -ne 1) { throw "Expected exactly one managed process at $ExpectedPath; found $($candidates.Count)." }
    $candidate = $candidates[0]
    if (-not [string]::Equals([string] $candidate.ExecutablePath, $ExpectedPath, [StringComparison]::OrdinalIgnoreCase)) { throw 'Managed process path mismatch.' }
    $hash = (Get-FileHash -LiteralPath $candidate.ExecutablePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($hash -cne $ExpectedSha256) { throw 'Managed process hash mismatch.' }
    [ordered]@{
        captured_utc = [datetime]::UtcNow.ToString('o')
        service = $(if ($null -ne $service) { [string] $service.Name } else { '' })
        pid = [int] $candidate.ProcessId
        parent_pid = [int] $candidate.ParentProcessId
        image_sha256 = $hash
        image_path = [string] $candidate.ExecutablePath
    }
}
```

## 1. Pin the SSH host key and inspect VM facts (read-only)

The exact Ed25519 known-host public-key line and its SSH SHA256 fingerprint are
two independently approved external inputs. Replace only the placeholders below;
never paste an SSH private key or construct trust from a live key scan. The file
must contain that sole key, and its independently derived fingerprint must match
exactly. Any ambiguity is a hard stop.

```powershell
$VmSshHost = 'DESKTOP-1BVR2H6'
$VmSshTarget = 'Administrator@DESKTOP-1BVR2H6'
$KnownHostsPath = Join-Path $ArtifactsPath 'known_hosts'
$ApprovedVmEd25519KnownHostLine = '<INDEPENDENTLY-APPROVED-DESKTOP-1BVR2H6-ED25519-KNOWN-HOST-LINE>'
$ActualHostKeyFingerprint = '<SHA256-FINGERPRINT-SUPPLIED-OUT-OF-BAND>'
if ($ActualHostKeyFingerprint -cnotmatch '^SHA256:[A-Za-z0-9+/]{43}$') { throw 'Approved SSH fingerprint is not an exact Ed25519 SHA256 fingerprint.' }
$ApprovedKnownHostParts = @($ApprovedVmEd25519KnownHostLine.Split([char[]] @(' '), [StringSplitOptions]::RemoveEmptyEntries))
if ($ApprovedVmEd25519KnownHostLine -cnotmatch '^DESKTOP-1BVR2H6 ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' -or $ApprovedKnownHostParts.Count -ne 3 -or $ApprovedKnownHostParts[0] -cne 'DESKTOP-1BVR2H6' -or $ApprovedKnownHostParts[1] -cne 'ssh-ed25519') { throw 'Approved known-host line is not exactly one DESKTOP-1BVR2H6 Ed25519 entry.' }
try { $ApprovedKnownHostKeyBlob = [Convert]::FromBase64String($ApprovedKnownHostParts[2]) } catch { throw 'Approved Ed25519 known-host key is not valid base64.' }
if ($ApprovedKnownHostKeyBlob.Count -eq 0) { throw 'Approved Ed25519 known-host key is empty.' }
$KnownHostsStream = [IO.File]::Open($KnownHostsPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $KnownHostsBytes = (New-Object Text.UTF8Encoding($false)).GetBytes($ApprovedVmEd25519KnownHostLine + [Environment]::NewLine)
    $KnownHostsStream.Write($KnownHostsBytes, 0, $KnownHostsBytes.Length)
    $KnownHostsStream.Flush($true)
}
finally { $KnownHostsStream.Dispose() }
$KnownHostsItem = Get-Item -LiteralPath $KnownHostsPath -Force -ErrorAction Stop
if (($KnownHostsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $KnownHostsItem.PSIsContainer) { throw 'Pinned known_hosts is not one ordinary file.' }
$PinnedKnownHostLines = @(Get-Content -LiteralPath $KnownHostsPath -ErrorAction Stop)
if ($PinnedKnownHostLines.Count -ne 1 -or $PinnedKnownHostLines[0] -cne $ApprovedVmEd25519KnownHostLine) { throw 'Pinned known_hosts does not contain exactly the approved entry.' }
$PinnedKnownHostsFingerprintLines = @(& ssh-keygen.exe -lf $KnownHostsPath -E sha256)
$PinnedKnownHostsFingerprintSucceeded = $?
$PinnedKnownHostsFingerprintExitCode = $LASTEXITCODE
if (-not $PinnedKnownHostsFingerprintSucceeded -or $PinnedKnownHostsFingerprintExitCode -ne 0) { throw '$PinnedKnownHostsFingerprintLines = @(& ssh-keygen.exe -lf $KnownHostsPath -E sha256) failed to launch or exited with code $PinnedKnownHostsFingerprintExitCode.' }
if ($PinnedKnownHostsFingerprintLines.Count -ne 1) { throw 'Pinned known_hosts did not produce exactly one fingerprint line.' }
$PinnedKnownHostsFingerprintMatches = @([regex]::Matches($PinnedKnownHostsFingerprintLines[0], 'SHA256:[A-Za-z0-9+/]{43}'))
if ($PinnedKnownHostsFingerprintMatches.Count -ne 1) { throw 'Pinned known_hosts did not produce exactly one SHA256 fingerprint.' }
$PinnedKnownHostsFingerprint = $PinnedKnownHostsFingerprintMatches[0].Value
if ($PinnedKnownHostsFingerprint -cne $ActualHostKeyFingerprint) { throw 'Pinned known_hosts fingerprint differs from the approved fingerprint.' }
```

The following remote commands are fixed read-only evidence commands. Do not
substitute an IP address or disable `StrictHostKeyChecking`.

```powershell
$VmFactsPath = Join-Path $BaselineDirectory 'vm-facts.json'
$VmBaselinePath = Join-Path $BaselineDirectory 'baseline-vm.json'
$TelecomConnectPath = Join-Path $BaselineDirectory 'telecom-connect.json'
$VmFactsCommand = 'powershell.exe -NoProfile -Command "Get-ComputerInfo | Select-Object CsName,WindowsProductName,WindowsVersion,OsBuildNumber | ConvertTo-Json -Compress"'
$VmBaselineCommand = 'powershell.exe -NoProfile -Command "[ordered]@{ adapters=Get-NetAdapter; routes=Get-NetRoute; dns=Get-DnsClientServerAddress; listeners=Get-NetTCPConnection -State Listen; services=Get-Service; processes=Get-Process; firewall=Get-NetFirewallRule; sing_box=(Get-Command sing-box.exe -ErrorAction SilentlyContinue); direct_google=(Test-NetConnection -ComputerName www.google.com -Port 443 -InformationLevel Detailed) } | ConvertTo-Json -Depth 6"'
$VmCanonicalStateCommand = 'powershell.exe -NoProfile -Command "$ErrorActionPreference=''Stop'';$roots=@(''C:\Program Files\RegenBio\OverseasAccessServer'',''C:\ProgramData\RegenBio\OverseasAccessServer'',''C:\Staging\OverseasAccessServer'');function H([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()};$filesystem=@(foreach($root in $roots){if(Test-Path -LiteralPath $root){Get-ChildItem -LiteralPath $root -Recurse -Force|Sort-Object FullName|ForEach-Object{[ordered]@{path=$_.FullName;kind=$(if($_.PSIsContainer){''directory''}else{''file''});length=$(if($_.PSIsContainer){0}else{$_.Length});sha256=$(if($_.PSIsContainer){''''}else{H $_.FullName})}}}else{[ordered]@{path=$root;kind=''absent'';length=0;sha256=''''}}});$registry=@(foreach($key in @(''HKLM:\SYSTEM\CurrentControlSet\Services\RegenBioOverseasAccessServer'',''HKLM:\SOFTWARE\RegenBio\OverseasAccessServer'')){if(Test-Path -LiteralPath $key){$value=Get-ItemProperty -LiteralPath $key;[ordered]@{path=$key;values=@($value.PSObject.Properties|Where-Object{$_.Name-notlike''PS*''}|Sort-Object Name|ForEach-Object{[ordered]@{name=$_.Name;value=[string]$_.Value}})}}else{[ordered]@{path=$key;values=@()}}});$scheduled_tasks=@(Get-ScheduledTask|Where-Object{$_.TaskName-like''*RegenBio*''-or$_.TaskPath-like''*RegenBio*''}|Sort-Object TaskPath,TaskName|Select-Object TaskPath,TaskName);$server_service=@(Get-CimInstance Win32_Service -Filter ""Name=''RegenBioOverseasAccessServer''""|Select-Object Name,State,StartMode,PathName);function A($v){return @($v|ForEach-Object{[string]$_}|Sort-Object)};$firewallNames=@(''RegenBioOverseasAccess-AllowEmployee-In'',''RegenBioOverseasAccess-Block8080-Remote'',''RegenBioOverseasAccess-BlockManagement-Employee'');$server_firewall=@(foreach($name in $firewallNames){$rules=@(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction SilentlyContinue);if($rules.Count-eq 0){[ordered]@{name=$name;present=$false;rule=$null;application=@();port=@();address=@();service=@();interface=@();interface_type=@();security=@()}}elseif($rules.Count-eq 1){$rule=$rules[0];$ruleDefinition=[ordered]@{Name=[string]$rule.Name;DisplayName=[string]$rule.DisplayName;Description=[string]$rule.Description;DisplayGroup=[string]$rule.DisplayGroup;Group=[string]$rule.Group;Enabled=[string]$rule.Enabled;Profile=(A $rule.Profile);Platform=(A $rule.Platform);Direction=[string]$rule.Direction;Action=[string]$rule.Action;EdgeTraversalPolicy=[string]$rule.EdgeTraversalPolicy;LooseSourceMapping=[string]$rule.LooseSourceMapping;LocalOnlyMapping=[string]$rule.LocalOnlyMapping;Owner=[string]$rule.Owner;PolicyStoreSourceType=[string]$rule.PolicyStoreSourceType;PolicyStoreSource=[string]$rule.PolicyStoreSource;RemoteDynamicKeywordAddresses=(A $rule.RemoteDynamicKeywordAddresses);PolicyAppId=[string]$rule.PolicyAppId};$application=@($rule|Get-NetFirewallApplicationFilter|ForEach-Object{[ordered]@{Program=[string]$_.Program;Package=[string]$_.Package}}|Sort-Object Program,Package);$port=@($rule|Get-NetFirewallPortFilter|ForEach-Object{[ordered]@{Protocol=[string]$_.Protocol;LocalPort=(A $_.LocalPort);RemotePort=(A $_.RemotePort);IcmpType=(A $_.IcmpType);DynamicTarget=[string]$_.DynamicTarget}}|Sort-Object Protocol,DynamicTarget);$address=@($rule|Get-NetFirewallAddressFilter|ForEach-Object{[ordered]@{LocalAddress=(A $_.LocalAddress);RemoteAddress=(A $_.RemoteAddress)}}|Sort-Object {$_.LocalAddress-join'',''},{$_.RemoteAddress-join'',''});$service=@($rule|Get-NetFirewallServiceFilter|ForEach-Object{[ordered]@{Service=(A $_.Service)}}|Sort-Object {$_.Service-join'',''});$interface=@($rule|Get-NetFirewallInterfaceFilter|ForEach-Object{[ordered]@{InterfaceAlias=(A $_.InterfaceAlias)}}|Sort-Object {$_.InterfaceAlias-join'',''});$interfaceType=@($rule|Get-NetFirewallInterfaceTypeFilter|ForEach-Object{[ordered]@{InterfaceType=(A $_.InterfaceType)}}|Sort-Object {$_.InterfaceType-join'',''});$security=@($rule|Get-NetFirewallSecurityFilter|ForEach-Object{[ordered]@{Authentication=(A $_.Authentication);Encryption=(A $_.Encryption);OverrideBlockRules=[string]$_.OverrideBlockRules;LocalUser=(A $_.LocalUser);RemoteUser=(A $_.RemoteUser);RemoteMachine=(A $_.RemoteMachine);RemoteMachineAuthorizedList=(A $_.RemoteMachineAuthorizedList);RemoteMachineExceptions=(A $_.RemoteMachineExceptions);RemoteUserAuthorizedList=(A $_.RemoteUserAuthorizedList);RemoteUserExceptions=(A $_.RemoteUserExceptions)}}|Sort-Object {$_|ConvertTo-Json -Compress -Depth 4});[ordered]@{name=$name;present=$true;rule=$ruleDefinition;application=$application;port=$port;address=$address;service=$service;interface=$interface;interface_type=$interfaceType;security=$security}}else{throw ''ambiguous server firewall rule $name''}});$server_owned_state=@($filesystem|Where-Object{$_.path-like''*.fixture-owner.json''-or$_.path-like''*runtime-manifest.json''-or$_.path-like''*evidence.json''});[ordered]@{filesystem=$filesystem;registry=$registry;scheduled_tasks=$scheduled_tasks;server_service=$server_service;server_firewall=$server_firewall;server_owned_state=$server_owned_state}|ConvertTo-Json -Compress -Depth 10"'
$TelecomConnectCommand = 'powershell.exe -NoProfile -Command "curl.exe --proxy http://127.0.0.1:8080 --connect-timeout 15 https://www.google.com/generate_204 -o NUL; `$CurlSucceeded = `$?; `$CurlExitCode = `$LASTEXITCODE; if (-not `$CurlSucceeded -or `$CurlExitCode -ne 0) { exit `$CurlExitCode }"'
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmFactsCommand > $VmFactsPath
$VmFactsSucceeded = $?
$VmFactsExitCode = $LASTEXITCODE
if (-not $VmFactsSucceeded -or $VmFactsExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmFactsCommand > $VmFactsPath failed to launch or exited with code $VmFactsExitCode.' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmBaselineCommand > $VmBaselinePath
$VmBaselineSucceeded = $?
$VmBaselineExitCode = $LASTEXITCODE
if (-not $VmBaselineSucceeded -or $VmBaselineExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmBaselineCommand > $VmBaselinePath failed to launch or exited with code $VmBaselineExitCode.' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $TelecomConnectCommand > $TelecomConnectPath
$TelecomConnectSucceeded = $?
$TelecomConnectExitCode = $LASTEXITCODE
if (-not $TelecomConnectSucceeded -or $TelecomConnectExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $TelecomConnectCommand > $TelecomConnectPath failed to launch or exited with code $TelecomConnectExitCode.' }
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
$VmWhatIfBeforePath = Join-Path $ArtifactsPath 'server-whatif-before.json'
$ServerWhatIfPath = Join-Path $ArtifactsPath 'server-whatif.json'
$VmWhatIfAfterPath = Join-Path $ArtifactsPath 'server-whatif-after.json'
$ServerInstallPath = Join-Path $ArtifactsPath 'server-install.json'
$ServerStatusPath = Join-Path $ArtifactsPath 'server-status.json'
$ServerRollbackPath = Join-Path $ArtifactsPath 'server-rollback.json'
$ServerAttestationPath = Join-Path $ArtifactsPath 'server-attestation.json'
$ServerAttestationRunNonce = $RunId
$ServerWhatIfCommand = "powershell.exe -NoProfile -File 'C:\Staging\OverseasAccessServer\install-server.ps1' -Mode Install -BundlePath 'C:\Staging\OverseasAccessServer\bundle' -ConfigPath 'C:\Staging\OverseasAccessServer\server.json' -ExpectedSingBoxSha256 '<SIGNED-SHA256>' -ExpectedConfigSha256 '<SIGNED-SHA256>' -ExpectedServerServiceSha256 '<SIGNED-SHA256>' -EmployeeCIDR '172.20.8.0/22' -ServerPort 18443 -EvidencePath 'C:\Staging\OverseasAccessServer\evidence.json' -WhatIf"
$ServerInstallCommand = "powershell.exe -NoProfile -File 'C:\Staging\OverseasAccessServer\install-server.ps1' -Mode Install -BundlePath 'C:\Staging\OverseasAccessServer\bundle' -ConfigPath 'C:\Staging\OverseasAccessServer\server.json' -ExpectedSingBoxSha256 '<SIGNED-SHA256>' -ExpectedConfigSha256 '<SIGNED-SHA256>' -ExpectedServerServiceSha256 '<SIGNED-SHA256>' -EmployeeCIDR '172.20.8.0/22' -ServerPort 18443 -EvidencePath 'C:\Staging\OverseasAccessServer\evidence.json'"
$ServerStatusCommand = "powershell.exe -NoProfile -File 'C:\Staging\OverseasAccessServer\install-server.ps1' -Mode Status -EvidencePath 'C:\Staging\OverseasAccessServer\evidence.json'"
$ServerRollbackCommand = "powershell.exe -NoProfile -File 'C:\Staging\OverseasAccessServer\install-server.ps1' -Mode Rollback -EvidencePath 'C:\Staging\OverseasAccessServer\evidence.json'"
$ServerAttestationScript = @'
$ErrorActionPreference = 'Stop'
$servicePath = 'C:\Program Files\RegenBio\OverseasAccessServer\overseas-server-service.exe'
$corePath = 'C:\Program Files\RegenBio\OverseasAccessServer\sing-box.exe'
$configPath = 'C:\ProgramData\RegenBio\OverseasAccessServer\config.json'
if ($env:COMPUTERNAME -cne 'DESKTOP-1BVR2H6') { throw 'host mismatch' }
$service = Get-CimInstance Win32_Service -Filter "Name='RegenBioOverseasAccessServer'"
if ($null -eq $service -or [int] $service.ProcessId -le 0 -or -not [string]::Equals(([string] $service.PathName).Trim('"'), $servicePath, [StringComparison]::OrdinalIgnoreCase)) { throw 'service mismatch' }
$cores = @(Get-CimInstance Win32_Process | Where-Object { [string]::Equals([string] $_.ExecutablePath, $corePath, [StringComparison]::OrdinalIgnoreCase) })
if ($cores.Count -ne 1) { throw 'core mismatch' }
$core = $cores[0]
$listeners = @(Get-NetTCPConnection -State Listen -LocalAddress 172.20.9.15 -LocalPort 18443)
if ($listeners.Count -ne 1 -or [int] $listeners[0].OwningProcess -ne [int] $core.ProcessId -or [int] $core.ParentProcessId -ne [int] $service.ProcessId) { throw 'listener chain mismatch' }
[ordered]@{
    schema_version = 1
    host_identity = [string] $env:COMPUTERNAME
    host_key_fingerprint = '__HOST_KEY_FINGERPRINT__'
    run_nonce = '__RUN_NONCE__'
    observed_at = [datetime]::UtcNow.ToString('o')
    listener_endpoint = '172.20.9.15:18443'
    service_name = 'RegenBioOverseasAccessServer'
    service_path = $servicePath
    service_sha256 = (Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant()
    service_pid = [int] $service.ProcessId
    core_path = $corePath
    core_sha256 = (Get-FileHash -LiteralPath $corePath -Algorithm SHA256).Hash.ToLowerInvariant()
    core_pid = [int] $core.ProcessId
    core_parent_pid = [int] $core.ParentProcessId
    config_path = $configPath
    config_sha256 = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    listener_pid = [int] $listeners[0].OwningProcess
    listener_image_path = $corePath
    listener_image_sha256 = (Get-FileHash -LiteralPath $corePath -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Compress
'@
$ServerAttestationScript = $ServerAttestationScript.Replace('__HOST_KEY_FINGERPRINT__', $ActualHostKeyFingerprint).Replace('__RUN_NONCE__', $ServerAttestationRunNonce)
$ServerAttestationEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ServerAttestationScript))
$ServerAttestationCommand = "powershell.exe -NoProfile -EncodedCommand $ServerAttestationEncoded"
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmCanonicalStateCommand > $VmWhatIfBeforePath
$VmWhatIfBeforeSucceeded = $?
$VmWhatIfBeforeExitCode = $LASTEXITCODE
if (-not $VmWhatIfBeforeSucceeded -or $VmWhatIfBeforeExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmCanonicalStateCommand > $VmWhatIfBeforePath failed to launch or exited with code $VmWhatIfBeforeExitCode.' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerWhatIfCommand > $ServerWhatIfPath
$ServerWhatIfSucceeded = $?
$ServerWhatIfExitCode = $LASTEXITCODE
if (-not $ServerWhatIfSucceeded -or $ServerWhatIfExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerWhatIfCommand > $ServerWhatIfPath failed to launch or exited with code $ServerWhatIfExitCode.' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmCanonicalStateCommand > $VmWhatIfAfterPath
$VmWhatIfAfterSucceeded = $?
$VmWhatIfAfterExitCode = $LASTEXITCODE
if (-not $VmWhatIfAfterSucceeded -or $VmWhatIfAfterExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmCanonicalStateCommand > $VmWhatIfAfterPath failed to launch or exited with code $VmWhatIfAfterExitCode.' }
Compare-CanonicalStateSnapshots -BeforePath $VmWhatIfBeforePath -AfterPath $VmWhatIfAfterPath -Label 'server-WhatIf filesystem registry scheduled tasks server-owned state'
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
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmBaselineCommand > $VmPreInstallPath
$VmPreInstallSucceeded = $?
$VmPreInstallExitCode = $LASTEXITCODE
if (-not $VmPreInstallSucceeded -or $VmPreInstallExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $VmBaselineCommand > $VmPreInstallPath failed to launch or exited with code $VmPreInstallExitCode.' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerInstallCommand > $ServerInstallPath
$ServerInstallSucceeded = $?
$ServerInstallExitCode = $LASTEXITCODE
if (-not $ServerInstallSucceeded -or $ServerInstallExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerInstallCommand > $ServerInstallPath failed to launch or exited with code $ServerInstallExitCode.' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerStatusCommand > $ServerStatusPath
$ServerStatusSucceeded = $?
$ServerStatusExitCode = $LASTEXITCODE
if (-not $ServerStatusSucceeded -or $ServerStatusExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerStatusCommand > $ServerStatusPath failed to launch or exited with code $ServerStatusExitCode.' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerAttestationCommand > $ServerAttestationPath
$ServerAttestationSucceeded = $?
$ServerAttestationExitCode = $LASTEXITCODE
if (-not $ServerAttestationSucceeded -or $ServerAttestationExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerAttestationCommand > $ServerAttestationPath failed to launch or exited with code $ServerAttestationExitCode.' }
$ServerAttestationValue = Get-Content -LiteralPath $ServerAttestationPath -Raw -ErrorAction Stop | ConvertFrom-Json
$ServerAttestationFields = @('schema_version','host_identity','host_key_fingerprint','run_nonce','observed_at','listener_endpoint','service_name','service_path','service_sha256','service_pid','core_path','core_sha256','core_pid','core_parent_pid','config_path','config_sha256','listener_pid','listener_image_path','listener_image_sha256')
if (@($ServerAttestationValue.PSObject.Properties.Name).Count -ne $ServerAttestationFields.Count -or (Compare-Object -ReferenceObject ($ServerAttestationFields | Sort-Object) -DifferenceObject ($ServerAttestationValue.PSObject.Properties.Name | Sort-Object))) { throw 'Remote attestation is not the exact strict flat schema.' }
if ($ServerAttestationValue.host_identity -cne 'DESKTOP-1BVR2H6' -or $ServerAttestationValue.host_key_fingerprint -cne $ActualHostKeyFingerprint -or $ServerAttestationValue.run_nonce -cne $ServerAttestationRunNonce) { throw 'Remote attestation host/fingerprint/run binding mismatch.' }
$ServerAttestationObserved = [datetime]::Parse([string] $ServerAttestationValue.observed_at).ToUniversalTime()
if ($ServerAttestationObserved -gt [datetime]::UtcNow.AddMinutes(5) -or $ServerAttestationObserved -lt [datetime]::UtcNow.AddMinutes(-15)) { throw 'Remote attestation is not fresh.' }
if ([string] $ServerAttestationValue.listener_image_path -cne [string] $ServerAttestationValue.core_path -or [int] $ServerAttestationValue.listener_pid -ne [int] $ServerAttestationValue.core_pid -or [int] $ServerAttestationValue.core_parent_pid -ne [int] $ServerAttestationValue.service_pid) { throw 'Remote attestation PID/image chain mismatch.' }
$CapturedServerAttestationSha256 = (Get-FileHash -LiteralPath $ServerAttestationPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
```

Generate the strict signed action configuration only after this capture. Its
`server_attestation_sha256`, `server_host_key_fingerprint`, and
`server_attestation_run_nonce` fields must exactly equal
`$CapturedServerAttestationSha256`, `$ActualHostKeyFingerprint`, and
`$ServerAttestationRunNonce`. The authenticated SSH channel is therefore tied
to the same pinned Ed25519 known_hosts key whose fingerprint is embedded in the
flat artifact; copied or stale JSON from another run is refused.

Exact server rollback command: `deploy\server\install-server.ps1 -Mode Rollback`
(executed remotely through the guarded `$ServerRollbackCommand` below). Do not
manually remove a service, route, firewall rule, or directory.

## 4. STOP/GO — standard-client activation

Take `baseline-physical.json` before any mutation. The physical host must use a
standard upstream sing-box client first. Its signed staged template is
credentialless; the one-time secret exists only in memory and the complete
configuration is streamed to sing-box standard input. It contains no corporate
client MSI artifacts. The standard-client gate PASS is required before custom MSI
and must be recorded before proceeding.

```powershell
$PhysicalBaselinePath = Join-Path $BaselineDirectory 'baseline-physical.json'
Save-PhysicalInventory -Path $PhysicalBaselinePath
$StandardClientTemplatePath = 'C:\Staging\standard-client-template.json'
$StandardSingBoxPath = 'C:\Staging\sing-box.exe'
$StandardSingBoxSha256 = '<SIGNED-SHA256>'
$StandardClientTemplateSha256 = '<SIGNED-SHA256>'
$StandardSignerThumbprint = '<CORPORATE-SIGNER-THUMBPRINT-SUPPLIED-OUT-OF-BAND>'
if ((Get-FileHash -LiteralPath $StandardSingBoxPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $StandardSingBoxSha256) { throw 'standard sing-box hash mismatch.' }
if ((Get-FileHash -LiteralPath $StandardClientTemplatePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $StandardClientTemplateSha256) { throw 'standard client template hash mismatch.' }
$StandardSignature = Get-AuthenticodeSignature -FilePath $StandardSingBoxPath -ErrorAction Stop
if ($StandardSignature.Status -ne 'Valid' -or $StandardSignature.SignerCertificate.Thumbprint -cne $StandardSignerThumbprint) { throw 'standard sing-box signer mismatch.' }
$StandardVersionText = & $StandardSingBoxPath version
$StandardVersionSucceeded = $?
$StandardVersionExitCode = $LASTEXITCODE
if (-not $StandardVersionSucceeded -or $StandardVersionExitCode -ne 0) { throw '$StandardVersionText = & $StandardSingBoxPath version failed to launch or exited with code $StandardVersionExitCode.' }
if (($StandardVersionText -join "`n") -notmatch '(?m)^sing-box version 1\.13\.19$') { throw 'standard client is not pinned sing-box version 1.13.19.' }

function Test-SingBoxStdinConfigSupport {
    param([Parameter(Mandatory = $true)][string] $Executable)
    $probeInfo = New-Object Diagnostics.ProcessStartInfo
    $probeInfo.FileName = $Executable
    $probeInfo.Arguments = 'check -c stdin'
    $probeInfo.UseShellExecute = $false
    $probeInfo.CreateNoWindow = $true
    $probeInfo.RedirectStandardInput = $true
    $probe = New-Object Diagnostics.Process
    $probe.StartInfo = $probeInfo
    try {
        if (-not $probe.Start()) { throw 'sing-box stdin support probe did not start.' }
        $probe.StandardInput.Write('{"log":{"disabled":true},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}')
        $probe.StandardInput.Close()
        if (-not $probe.WaitForExit(10000)) { $probe.Kill(); throw 'sing-box stdin support probe timed out.' }
        if ($probe.ExitCode -ne 0) { throw 'pinned sing-box does not accept -c stdin.' }
    }
    finally { $probe.Dispose() }
}
Test-SingBoxStdinConfigSupport -Executable $StandardSingBoxPath

$StandardTemplate = Get-Content -LiteralPath $StandardClientTemplatePath -Raw -ErrorAction Stop | ConvertFrom-Json
$StandardInbound = @($StandardTemplate.inbounds | Where-Object { $_.type -eq 'tun' -and $_.interface_name -ceq 'RegenBioStandardAcceptance' })
if ($StandardInbound.Count -ne 1) { throw 'standard-client template must define exactly one expected TUN interface.' }
$StandardTunnel = @($StandardTemplate.outbounds | Where-Object { $_.type -eq 'shadowsocks' -and $_.tag -eq 'tunnel' })
if ($StandardTunnel.Count -ne 1 -or ($StandardTunnel[0].PSObject.Properties.Name -contains 'password' -and -not [string]::IsNullOrEmpty([string] $StandardTunnel[0].password))) { throw 'standard-client template is not credentialless.' }
$StandardSecret = Read-Host 'Enter the one-time standard-client secret; it is never written to disk' -AsSecureString
$StandardBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($StandardSecret)
$StandardClientProcess = $null
$StandardRuntimeJson = $null
try {
    $StandardPlaintext = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($StandardBstr)
    $StandardTunnel[0] | Add-Member -NotePropertyName password -NotePropertyValue $StandardPlaintext -Force
    $StandardRuntimeJson = $StandardTemplate | ConvertTo-Json -Compress -Depth 12
    $StandardPlaintext = $null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($StandardBstr)
    $StandardBstr = [IntPtr]::Zero
    $StandardStartInfo = New-Object Diagnostics.ProcessStartInfo
    $StandardStartInfo.FileName = $StandardSingBoxPath
    $StandardStartInfo.Arguments = 'run -c stdin'
    $StandardStartInfo.UseShellExecute = $false
    $StandardStartInfo.CreateNoWindow = $true
    $StandardStartInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $StandardStartInfo.RedirectStandardInput = $true
    $StandardClientProcess = New-Object Diagnostics.Process
    $StandardClientProcess.StartInfo = $StandardStartInfo
    if (-not $StandardClientProcess.Start()) { throw 'standard client failed to start.' }
    $StandardClientProcess.StandardInput.Write($StandardRuntimeJson)
    $StandardClientProcess.StandardInput.Close()
    $StandardRuntimeJson = $null
    $readyDeadline = [datetime]::UtcNow.AddSeconds(30)
    do {
        $StandardClientProcess.Refresh()
        if ($StandardClientProcess.HasExited) { throw 'standard client exited before readiness.' }
        $StandardAdapter = Get-NetAdapter -Name 'RegenBioStandardAcceptance' -ErrorAction SilentlyContinue
        if ($null -ne $StandardAdapter -and $StandardAdapter.Status -eq 'Up') { break }
        Start-Sleep -Milliseconds 250
    } while ([datetime]::UtcNow -lt $readyDeadline)
    if ($null -eq $StandardAdapter -or $StandardAdapter.Status -ne 'Up') { throw 'standard client readiness timed out.' }

    # Run the approved HTTPS/corporate/direct-8080 and dependency-loss probe matrix here.
}
finally {
    if ($StandardBstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($StandardBstr) }
    $StandardTunnel[0].password = $null
    $StandardTemplate = $null
    $StandardPlaintext = $null
    $StandardRuntimeJson = $null
    $StandardSecret = $null
    if ($null -ne $StandardClientProcess) {
        $StandardClientProcess.Refresh()
        if (-not $StandardClientProcess.HasExited) { $StandardClientProcess.Kill() }
        $StandardClientProcess.WaitForExit()
        if (-not $StandardClientProcess.HasExited) { throw 'standard client cleanup failed.' }
        $StandardClientProcess.Dispose()
    }
}
```

The operator must prove an approved HTTPS target succeeds, corporate access
continues, and direct access to VM:8080 failure is observed. Stop the server
service and then the telecom process under the approved VM recovery procedure;
each must produce service stop leak failure and telecom-process stop leak failure
(no ordinary Internet receipt), followed by recovery after restart. Capture only
`standard-client-evidence.json`, timestamps, template/binary hashes, nonce receipt, and leak receipt—never the in-memory runtime JSON or secret.

If any check fails, run the rollback section immediately.

## 5. STOP/GO — custom-MSI install

Confirm the standard sing-box process is gone and inventory the physical host
again. Verify the MSI and every
detached manifest with `Get-AuthenticodeSignature`, detached CMS verification,
exact source commit, and exact hashes before `msiexec`. The MSI must be
externally corporate-signed, not merely locally trusted.

```powershell
$MsiPreInstallInventoryPath = Join-Path $ArtifactsPath 'msi-preinstall-inventory.json'
Save-PhysicalInventory -Path $MsiPreInstallInventoryPath
$CorporateSignedMsiPath = 'C:\Staging\OverseasAccessSetup.msi'
$ReleaseBundlePath = 'C:\Staging\OverseasAccessClient\bundle'
$FixtureManifestPath = 'C:\Staging\fixture-manifest.json'
$FixtureManifestSignaturePath = 'C:\Staging\fixture-manifest.json.p7s'
$ReleaseArtifactManifestPath = Join-Path $ReleaseBundlePath 'artifact-manifest.json'
$ReleaseArtifactManifestSignaturePath = Join-Path $ReleaseBundlePath 'artifact-manifest.json.p7s'
$StagedVerifierPath = 'C:\Staging\Task10Verifier\installer-verifier.exe'
$ActionHelperPath = 'C:\Staging\fixture-action.exe'
$ActionConfigPath = 'C:\Staging\action-config.json'
$VerifierEvidencePath = Join-Path $ArtifactsPath 'installer-verifier.json'
$CorporateSignerThumbprint = '<CORPORATE-SIGNER-THUMBPRINT-SUPPLIED-OUT-OF-BAND>'
$MsiSignerThumbprint = $CorporateSignerThumbprint
$FixtureManifestSignerThumbprint = '<FIXTURE-MANIFEST-SIGNER-THUMBPRINT>'
$ReleaseManifestSignerThumbprint = '<RELEASE-MANIFEST-SIGNER-THUMBPRINT>'
$VerifierSignerThumbprint = '<STAGED-VERIFIER-SIGNER-THUMBPRINT>'
$ExpectedStagedVerifierSha256 = '<EXTERNALLY-PINNED-VERIFIER-SHA256>'
$ExpectedMsiSha256 = '<EXTERNALLY-PINNED-MSI-SHA256>'
$ExpectedFixtureManifestSha256 = '<EXTERNALLY-PINNED-FIXTURE-MANIFEST-SHA256>'
$ExpectedReleaseManifestSha256 = '<EXTERNALLY-PINNED-ARTIFACT-MANIFEST-SHA256>'
$ExpectedSourceCommit = '<SIGNED-SOURCE-COMMIT>'
$ExpectedActionConfigSha256 = '<SIGNED-OR-INDEPENDENTLY-APPROVED-ACTION-CONFIG-SHA256>'
$ExpectedClientConfigSha256 = '<SIGNED-OR-INDEPENDENTLY-APPROVED-CLIENT-CONFIG-SHA256>'
$ExpectedCredentialSourceSha256 = '<SIGNED-OR-INDEPENDENTLY-APPROVED-CREDENTIAL-SOURCE-SHA256>'
$ExpectedServerAttestationSha256 = '<SIGNED-OR-INDEPENDENTLY-APPROVED-SERVER-ATTESTATION-SHA256>'
$DirectProvisioningExpectedHashes = @($ExpectedActionConfigSha256, $ExpectedClientConfigSha256, $ExpectedCredentialSourceSha256, $ExpectedServerAttestationSha256)
if (@($DirectProvisioningExpectedHashes | Where-Object { $_ -cnotmatch '^[a-f0-9]{64}$' }).Count -ne 0) { throw 'Direct provisioning expected hashes are absent or malformed.' }
if ((Get-FileHash -LiteralPath $StagedVerifierPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $ExpectedStagedVerifierSha256) { throw 'clean-host staged verifier hash mismatch.' }
$StagedVerifierSignature = Get-AuthenticodeSignature -FilePath $StagedVerifierPath -ErrorAction Stop
if ($StagedVerifierSignature.Status -ne 'Valid' -or $StagedVerifierSignature.SignerCertificate.Thumbprint -cne $VerifierSignerThumbprint) { throw 'clean-host staged verifier signature mismatch.' }
& $StagedVerifierPath verify-bundle --bundle $ReleaseBundlePath --msi $CorporateSignedMsiPath --fixture-manifest $FixtureManifestPath --fixture-signature $FixtureManifestSignaturePath --release-manifest $ReleaseArtifactManifestPath --release-signature $ReleaseArtifactManifestSignaturePath --expected-commit $ExpectedSourceCommit --expected-msi-sha256 $ExpectedMsiSha256 --expected-fixture-sha256 $ExpectedFixtureManifestSha256 --expected-release-sha256 $ExpectedReleaseManifestSha256 --fixture-signer $FixtureManifestSignerThumbprint --release-signer $ReleaseManifestSignerThumbprint --msi-signer $MsiSignerThumbprint --evidence $VerifierEvidencePath
$InstallerVerifierSucceeded = $?
$InstallerVerifierExitCode = $LASTEXITCODE
if (-not $InstallerVerifierSucceeded -or $InstallerVerifierExitCode -ne 0) { throw '& $StagedVerifierPath verify-bundle --bundle $ReleaseBundlePath --msi $CorporateSignedMsiPath --fixture-manifest $FixtureManifestPath --fixture-signature $FixtureManifestSignaturePath --release-manifest $ReleaseArtifactManifestPath --release-signature $ReleaseArtifactManifestSignaturePath --expected-commit $ExpectedSourceCommit --expected-msi-sha256 $ExpectedMsiSha256 --expected-fixture-sha256 $ExpectedFixtureManifestSha256 --expected-release-sha256 $ExpectedReleaseManifestSha256 --fixture-signer $FixtureManifestSignerThumbprint --release-signer $ReleaseManifestSignerThumbprint --msi-signer $MsiSignerThumbprint --evidence $VerifierEvidencePath failed to launch or exited with code $InstallerVerifierExitCode.' }
$MsiInstallLogPath = Join-Path $ArtifactsPath 'msi-install.log'
& msiexec.exe /i $CorporateSignedMsiPath /qn /norestart /l*v $MsiInstallLogPath
$MsiInstallSucceeded = $?
$MsiInstallExitCode = $LASTEXITCODE
if (-not $MsiInstallSucceeded -or $MsiInstallExitCode -ne 0) { throw '& msiexec.exe /i $CorporateSignedMsiPath /qn /norestart /l*v $MsiInstallLogPath failed to launch or exited with code $MsiInstallExitCode.' }
if ((Get-Service -Name 'RegenBioOverseasAccessAgent' -ErrorAction Stop).Status -ne 'Stopped') { throw 'Install must leave the agent stopped before provisioning.' }
$env:OVERSEAS_ACCESS_FIXTURE_ACTION_CONFIG = $ActionConfigPath
try {
& $ActionHelperPath provision-credential --expected-action-config-sha256 $ExpectedActionConfigSha256 --expected-client-config-sha256 $ExpectedClientConfigSha256 --expected-credential-source-sha256 $ExpectedCredentialSourceSha256 --expected-server-attestation-sha256 $ExpectedServerAttestationSha256
$CredentialProvisioningSucceeded = $?
$CredentialProvisioningExitCode = $LASTEXITCODE
if (-not $CredentialProvisioningSucceeded -or $CredentialProvisioningExitCode -ne 0) { throw '& $ActionHelperPath provision-credential --expected-action-config-sha256 $ExpectedActionConfigSha256 --expected-client-config-sha256 $ExpectedClientConfigSha256 --expected-credential-source-sha256 $ExpectedCredentialSourceSha256 --expected-server-attestation-sha256 $ExpectedServerAttestationSha256 failed to launch or exited with code $CredentialProvisioningExitCode.' }
}
finally { Remove-Item Env:OVERSEAS_ACCESS_FIXTURE_ACTION_CONFIG -ErrorAction SilentlyContinue }
if (-not (Test-Path -LiteralPath 'C:\ProgramData\RegenBio\OverseasAccess\credential.bin' -PathType Leaf)) { throw 'credential.bin was not created.' }
Start-Service -Name 'RegenBioOverseasAccessAgent' -ErrorAction Stop
if ((Get-Service -Name 'RegenBioOverseasAccessAgent' -ErrorAction Stop).Status -ne 'Running') { throw 'Agent service did not reach Running after provisioning.' }
```

Never use a command line, response file, temporary file, registry entry,
evidence field, or log for the credential. The source stdout is connected directly to provisioner stdin by the Go helper.
The four expected hashes must come from the already verified signed fixture/release contract or independently approved operator ledger; never compute them from the action config, generated client config, credential source, or attestation being verified.
The signed method, endpoint, and expiry are
passed as non-secret fixed arguments to both processes; only the secret-bearing
document traverses the anonymous pipe. Click the shipped UI's enable/disable
toggle only after a clean baseline and inventory are recorded. Verify
enable/disable for browser, Git, HTTPS, corporate DNS, AD, and EC; retain exact
probe targets, route/DNS/firewall snapshots, and redacted logs. A required Git
probe example follows the same native guard.

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
Never accept preset PID variables. Before each individual fault, run a fresh
`Capture-ManagedProcess`, bind the PID to the exact path/hash/service, record the
evidence, perform only that one mutation, probe, and restore before the next
fault. A successful check requires a fail-closed result while unavailable,
recovery only after the dependency returns, and no ordinary-exit fallback.

### STOP/GO — agent fault

```powershell
$AgentFaultInventoryPath = Join-Path $ArtifactsPath 'agent-fault-inventory.json'
Save-PhysicalInventory -Path $AgentFaultInventoryPath
$AgentCapture = Capture-ManagedProcess -ServiceName 'RegenBioOverseasAccessAgent' -ExpectedPath 'C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe' -ExpectedSha256 '<SIGNED-SHA256>'
$AgentCapture | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $ArtifactsPath 'agent-capture.json') -Encoding UTF8 -ErrorAction Stop
& taskkill.exe /PID $AgentCapture.pid /T /F
$AgentKillSucceeded = $?
$AgentKillExitCode = $LASTEXITCODE
if (-not $AgentKillSucceeded -or $AgentKillExitCode -ne 0) { throw '& taskkill.exe /PID $AgentCapture.pid /T /F failed to launch or exited with code $AgentKillExitCode.' }
```

Probe, confirm fail-closed, then restore the service and re-run the probe matrix
before moving to the next fault.

### STOP/GO — core fault

```powershell
$CoreFaultInventoryPath = Join-Path $ArtifactsPath 'core-fault-inventory.json'
Save-PhysicalInventory -Path $CoreFaultInventoryPath
$CoreCapture = Capture-ManagedProcess -ParentServiceName 'RegenBioOverseasAccessAgent' -ExpectedPath 'C:\Program Files\RegenBio\OverseasAccess\sing-box.exe' -ExpectedSha256 '<SIGNED-SHA256>'
$CoreCapture | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $ArtifactsPath 'core-capture.json') -Encoding UTF8 -ErrorAction Stop
& taskkill.exe /PID $CoreCapture.pid /T /F
$CoreKillSucceeded = $?
$CoreKillExitCode = $LASTEXITCODE
if (-not $CoreKillSucceeded -or $CoreKillExitCode -ne 0) { throw '& taskkill.exe /PID $CoreCapture.pid /T /F failed to launch or exited with code $CoreKillExitCode.' }
```

Probe, confirm fail-closed, then restore the service and re-run the probe matrix
before moving to the next fault.

### STOP/GO — UI fault

```powershell
$UiFaultInventoryPath = Join-Path $ArtifactsPath 'ui-fault-inventory.json'
Save-PhysicalInventory -Path $UiFaultInventoryPath
$UiCapture = Capture-ManagedProcess -ExpectedPath 'C:\Program Files\RegenBio\OverseasAccess\overseas-client.exe' -ExpectedSha256 '<SIGNED-SHA256>'
$UiCapture | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $ArtifactsPath 'ui-capture.json') -Encoding UTF8 -ErrorAction Stop
& taskkill.exe /PID $UiCapture.pid /T /F
$UiKillSucceeded = $?
$UiKillExitCode = $LASTEXITCODE
if (-not $UiKillSucceeded -or $UiKillExitCode -ne 0) { throw '& taskkill.exe /PID $UiCapture.pid /T /F failed to launch or exited with code $UiKillExitCode.' }
```

Probe, confirm fail-closed, then restore the service and re-run the probe matrix
before moving to the next fault.

### STOP/GO — node loss and telecom loss

Use the approved VM stop/start and telecom stop/start procedures one at a time.
Capture inventory immediately before and after each mutation. Required outcomes:
node loss, telecom loss, service stop leak failure, telecom-process stop leak
failure, no direct access to VM:8080 failure bypass, and recovery only after the
dependency returns.

### STOP/GO — forced reboot

Forced reboot is its own approved section. Capture inventory first, perform only
the reboot, then obtain a new stop/go approval before any subsequent fault or
probe.

```powershell
$RebootInventoryPath = Join-Path $ArtifactsPath 'forced-reboot-inventory.json'
Save-PhysicalInventory -Path $RebootInventoryPath
& shutdown.exe /r /t 0 /f
$RebootSucceeded = $?
$RebootExitCode = $LASTEXITCODE
if (-not $RebootSucceeded -or $RebootExitCode -ne 0) { throw '& shutdown.exe /r /t 0 /f failed to launch or exited with code $RebootExitCode.' }
```

After return from reboot, continue only after a new stop/go approval and
inventory. Run 20 clean enable/disable cycles. For cycles 1 through 20, use
the UI toggle, prove the complete probe matrix in both states, wait for the
action-local snapshots, and record the per-cycle nonce/leak receipts in
`lifecycle-20-cycles.json`. Any missing receipt, timeout, drift, fallback, or
failed restore is FAIL.

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
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerRollbackCommand > $ServerRollbackPath
$ServerRollbackSucceeded = $?
$ServerRollbackExitCode = $LASTEXITCODE
if (-not $ServerRollbackSucceeded -or $ServerRollbackExitCode -ne 0) { throw '& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=$KnownHostsPath $VmSshTarget $ServerRollbackCommand > $ServerRollbackPath failed to launch or exited with code $ServerRollbackExitCode.' }
```

Then uninstall the custom client (if present), confirm the standard-client
process handle has exited, and compare the final physical inventory to
`baseline-physical.json`. Exact final-state restoration requires original routes,
DNS, firewall, services, adapters, installer state, and runtime configuration.
If rollback cannot be proven, declare FAIL, preserve evidence, and escalate to
the VM-console recovery owner; do not attempt manual cleanup.

## 8. Evidence bundle and verdict

Before signing a verdict, place these sanitized files in `$ArtifactsPath`:
`baseline-vm.json`, `baseline-physical.json`, `server-whatif.json`,
`server-install.json`, `server-status.json`, `server-rollback.json`,
`server-attestation.json`, `standard-client-evidence.json`, `custom-client.json`,
`lifecycle-20-cycles.json`, `installer-verifier.json`, and `verdict.json`.
Hash every signed artifact and emitted evidence file with `Get-FileHash`; use
`Compress-Archive` only after a redaction review and store the archive outside
Git. Runtime artifacts belong under the already ignored
`artifacts/sing-box-poc/<UTC-run-id>/` path.

PASS requires one full workday, all required probes, all fail-closed cases, 20
clean cycles, no direct 8080 access, no ordinary-exit fallback, exact final-
state restoration, and zero changes after WhatIf. Any mandatory failure is FAIL
and triggers the rollback above. Never label a partial test PASS.
