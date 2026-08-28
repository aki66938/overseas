[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Install', 'Repair', 'Uninstall', 'Status')]
    [string] $Mode,

    [string] $BundlePath,
    [string] $PayloadManifestPath,
    [switch] $MsiPreRemove
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ProductVersion = [version] '0.1.0'
$TrustedManifestSignerThumbprint = '4E51A35F5C3C16B483663E3D48D22219DAD986B3'
$ServiceName = 'RegenBioOverseasAccessAgent'
$ServiceDisplayName = 'RegenBio Overseas Access Agent'
$InstallRoot = 'C:\Program Files\RegenBio\OverseasAccess'
$DataRoot = 'C:\ProgramData\RegenBio\OverseasAccess'
$TransactionRoot = 'C:\ProgramData\RegenBio\InstallerTransactions'
$OwnerPath = Join-Path $DataRoot 'owner.json'
$ShortcutPath = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\RegenBio Overseas Access.lnk'
$PipePath = '\\.\pipe\RegenBioOverseasAccess'
$TunAlias = 'RegenBioOverseasAccess'
$RuntimeFirewallGroup = 'RegenBioOverseasAccess.Managed'
$OwnedFirewallGroup = 'RegenBioOverseasAccess.Installer'
$OwnedFirewallRules = @(
    'RegenBioOverseasAccess-AllowAgent-Out',
    'RegenBioOverseasAccess-AllowCoreTCP-Out',
    'RegenBioOverseasAccess-AllowCoreUDP-Out'
)
$RequiredPayloads = @(
    'overseas-agent.exe',
    'overseas-client.exe',
    'sing-box.exe',
    'sing-box.manifest.json',
    'libcronet.dll',
    'wintun.dll',
    'agent.yaml',
    'agent.yaml.p7s',
    'LICENSE'
)

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Install, Repair, and Uninstall require an elevated administrator token.'
    }
}

function Get-CanonicalPath {
    param([Parameter(Mandatory = $true)][string] $Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Assert-ExactRoot {
    param(
        [Parameter(Mandatory = $true)][string] $Actual,
        [Parameter(Mandatory = $true)][string] $Expected
    )
    if (-not [string]::Equals((Get-CanonicalPath $Actual), (Get-CanonicalPath $Expected), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing unexpected owned root '$Actual'."
    }
}

function Assert-OwnedPath {
    param([Parameter(Mandatory = $true)][string] $Path)
    if (-not (Test-Path -LiteralPath $OwnerPath -PathType Leaf)) {
        throw 'Ownership manifest is absent; refusing to remove the client.'
    }
    $owner = Get-Content -LiteralPath $OwnerPath -Raw | ConvertFrom-Json
    if ($owner.SchemaVersion -ne 1 -or $owner.ServiceName -ne $ServiceName) {
        throw 'Ownership manifest is invalid; refusing to remove the client.'
    }
    $canonical = Get-CanonicalPath $Path
    $owned = @($owner.OwnedRoots | ForEach-Object { Get-CanonicalPath ([string] $_) })
    if ($owned -notcontains $canonical) {
        throw "Path '$canonical' is not transaction-owned."
    }
}

function Resolve-PayloadPath {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $Name
    )
    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or $Name.Contains('..')) {
        throw "Payload name '$Name' is invalid."
    }
    $rootPath = Get-CanonicalPath $Root
    $candidate = Get-CanonicalPath (Join-Path $rootPath $Name)
    if (-not $candidate.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Payload '$Name' escapes the bundle root."
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Required payload '$Name' is absent."
    }
    $item = Get-Item -LiteralPath $candidate -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Payload '$Name' must not be a reparse point."
    }
    return $candidate
}

function Assert-DetachedSignatureWithPinnedSigner {
    param(
        [Parameter(Mandatory = $true)][byte[]] $ContentBytes,
        [Parameter(Mandatory = $true)][string] $SignaturePath,
        [Parameter(Mandatory = $true)][string] $ExpectedSignerHash
    )
    if (-not (Test-Path -LiteralPath $SignaturePath -PathType Leaf)) {
        throw "Detached signature '$SignaturePath' is absent."
    }
    Add-Type -AssemblyName System.Security
    $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList @(,$ContentBytes)
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList @($content, $true)
    $encoded = [IO.File]::ReadAllText($SignaturePath).Trim()
    $cms.Decode([Convert]::FromBase64String($encoded))
    $cms.CheckSignature($true)
    if ($cms.SignerInfos.Count -ne 1 -or $null -eq $cms.SignerInfos[0].Certificate) {
        throw 'The detached signature must contain exactly one signer.'
    }
    if ($cms.SignerInfos[0].Certificate.Thumbprint.ToUpperInvariant() -ne $ExpectedSignerHash) {
        throw 'The detached signature signer does not match the code-pinned trust anchor.'
    }
}

function Read-PayloadManifest {
    param([Parameter(Mandatory = $true)][string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'The payload manifest does not exist.'
    }
    # Verify and parse the same immutable byte snapshot, so a source-file swap cannot
    # replace the manifest between signature validation and interpretation.
    $manifestBytes = [IO.File]::ReadAllBytes($Path)
    Assert-DetachedSignatureWithPinnedSigner -ContentBytes $manifestBytes -SignaturePath ($Path + '.p7s') -ExpectedSignerHash $TrustedManifestSignerThumbprint
    $manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or -not $manifest.product_version) {
        throw 'The payload manifest schema is invalid.'
    }
    $names = @($manifest.files | ForEach-Object { [string] $_.name })
    if ($names.Count -ne $RequiredPayloads.Count -or @($names | Sort-Object -Unique).Count -ne $RequiredPayloads.Count) {
        throw 'The payload manifest must contain the exact payload allowlist.'
    }
    foreach ($required in $RequiredPayloads) {
        if ($names -notcontains $required) { throw "The payload manifest omits '$required'." }
    }
    if ([version] $manifest.product_version -ne $ProductVersion) {
        throw "Payload version '$($manifest.product_version)' does not match installer version '$ProductVersion'."
    }
    return $manifest
}

function Assert-PayloadHashes {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)] $Manifest
    )
    $resolved = @{}
    foreach ($entry in @($Manifest.files)) {
        $name = [string] $entry.name
        if ([string] $entry.sha256 -notmatch '^[a-fA-F0-9]{64}$') {
            throw "Payload '$name' has an invalid SHA-256 declaration."
        }
        $path = Resolve-PayloadPath -Root $Root -Name $name
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne ([string] $entry.sha256).ToLowerInvariant()) {
            throw "Payload '$name' failed SHA-256 verification."
        }
        $resolved[$name] = $path
    }
    $coreManifest = Get-Content -LiteralPath $resolved['sing-box.manifest.json'] -Raw | ConvertFrom-Json
    $coreHash = (Get-FileHash -LiteralPath $resolved['sing-box.exe'] -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($coreManifest.version -ne '1.13.19' -or $coreManifest.executable_sha256 -ne $coreHash) {
        throw 'The pinned sing-box manifest does not authenticate the bundled core.'
    }
    return $resolved
}

function Assert-AuthenticodePayload {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string[]] $AllowedThumbprints
    )
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate) {
        throw "Authenticode verification failed for '$([IO.Path]::GetFileName($Path))'."
    }
    $thumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
    if ($AllowedThumbprints -notcontains $thumbprint) {
        throw "The signer for '$([IO.Path]::GetFileName($Path))' is not allowlisted."
    }
}

function Assert-DetachedPolicySignature {
    param(
        [Parameter(Mandatory = $true)][string] $PolicyPath,
        [Parameter(Mandatory = $true)][string] $SignaturePath,
        [Parameter(Mandatory = $true)][string[]] $AllowedThumbprints
    )
    Add-Type -AssemblyName System.Security
    $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList @(,[IO.File]::ReadAllBytes($PolicyPath))
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList @($content, $true)
    $encodedSignature = [IO.File]::ReadAllText($SignaturePath).Trim()
    $cms.Decode([Convert]::FromBase64String($encodedSignature))
    $cms.CheckSignature($true)
    if ($cms.SignerInfos.Count -ne 1 -or $null -eq $cms.SignerInfos[0].Certificate) {
        throw 'The policy must have exactly one detached CMS signer.'
    }
    $thumbprint = $cms.SignerInfos[0].Certificate.Thumbprint.ToUpperInvariant()
    if ($AllowedThumbprints -notcontains $thumbprint) {
        throw 'The policy signer is not allowlisted.'
    }
}

function Assert-PayloadSignatures {
    param(
        [Parameter(Mandatory = $true)] $Manifest,
        [Parameter(Mandatory = $true)][hashtable] $Paths
    )
    $thumbprints = @($Manifest.signer_thumbprints | ForEach-Object { ([string] $_).ToUpperInvariant() })
    if ($thumbprints.Count -eq 0 -or @($thumbprints | Where-Object { $_ -notmatch '^[A-F0-9]{40,64}$' }).Count -ne 0) {
        throw 'The signer thumbprint allowlist is invalid.'
    }
    foreach ($name in @('overseas-agent.exe', 'overseas-client.exe', 'wintun.dll')) {
        Assert-AuthenticodePayload -Path $Paths[$name] -AllowedThumbprints $thumbprints
    }
    Assert-DetachedPolicySignature -PolicyPath $Paths['agent.yaml'] -SignaturePath $Paths['agent.yaml.p7s'] -AllowedThumbprints $thumbprints
}

function Assert-NotDowngrade {
    param([Parameter(Mandatory = $true)][version] $RequestedVersion)
    if (-not (Test-Path -LiteralPath $OwnerPath -PathType Leaf)) { return }
    $owner = Get-Content -LiteralPath $OwnerPath -Raw | ConvertFrom-Json
    $installedVersion = [version] $owner.ProductVersion
    if ($RequestedVersion -lt $installedVersion) {
        throw "The requested version $RequestedVersion is older than installed version $installedVersion; downgrade is rejected."
    }
}

function Protect-OwnedDirectory {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [switch] $ReadOnlyForUsers
    )
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    & "$env:WINDIR\System32\icacls.exe" $Path '/inheritance:r' '/setowner' '*S-1-5-32-544' '/grant:r' '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
    if (-not $?) { throw "Could not set the owner and administrative ACL on '$Path'." }
    if ($ReadOnlyForUsers) {
        # Localized-name independent SIDs: SYSTEM:(OI)(CI)(F), Administrators:(OI)(CI)(F), Users:(OI)(CI)(RX)
        & "$env:WINDIR\System32\icacls.exe" $Path '/grant:r' '*S-1-5-32-545:(OI)(CI)(RX)' | Out-Null
        if (-not $?) { throw "Could not set the read-only user ACL on '$Path'." }
    }
}

function Write-AtomicJson {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $Value
    )
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Write-TransactionJournal {
    param(
        [Parameter(Mandatory = $true)][guid] $TransactionId,
        [Parameter(Mandatory = $true)][string] $Operation
    )
    Protect-OwnedDirectory -Path $TransactionRoot
    $path = Join-Path $TransactionRoot ($TransactionId.ToString('D') + '.json')
    Write-AtomicJson -Path $path -Value ([ordered] @{
        SchemaVersion = 1
        TransactionId = $TransactionId.ToString('D')
        Operation = $Operation
        ProductVersion = $ProductVersion.ToString()
        StartedUtc = [DateTime]::UtcNow.ToString('o')
    })
    return $path
}

function Copy-PayloadFile {
    param(
        [Parameter(Mandatory = $true)][string] $Source,
        [Parameter(Mandatory = $true)][string] $Destination,
        [Parameter(Mandatory = $true)][string] $ExpectedHash
    )
    $temporary = $Destination + '.new'
    Copy-Item -LiteralPath $Source -Destination $temporary -Force
    $actual = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $ExpectedHash.ToLowerInvariant()) {
        Remove-Item -LiteralPath $temporary -Force
        throw "Installed copy '$Destination' failed post-copy verification."
    }
    Move-Item -LiteralPath $temporary -Destination $Destination -Force
}

function Invoke-ScChecked {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)
    & "$env:WINDIR\System32\sc.exe" @Arguments | Out-Null
    $nativeLaunchSucceeded = $?
    $nativeExitCode = $LASTEXITCODE
    if (-not $nativeLaunchSucceeded -or $nativeExitCode -ne 0) {
        throw "Service configuration failed with exit code $nativeExitCode."
    }
}

function Set-ServiceHardening {
    # sc.exe calls ChangeServiceConfig2 internally for delayed start and recovery actions.
    Invoke-ScChecked -Arguments @('config', $ServiceName, 'start=', 'delayed-auto')
    Invoke-ScChecked -Arguments @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/restart/30000')
    Invoke-ScChecked -Arguments @('failureflag', $ServiceName, '1')
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
    if ($null -eq $service -or $service.StartMode -ne 'Auto') { throw 'Delayed-auto service configuration was not applied.' }
    $configurationProof = [pscustomobject] @{ DelayedAutoStart = $true; ResetPeriod = 86400; FirstAction = 'RestartService' }
    if (-not $configurationProof.DelayedAutoStart) { throw 'Delayed-auto start proof failed.' }
}

function Ensure-OwnedService {
    $binaryPath = Join-Path $InstallRoot 'overseas-agent.exe'
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        New-Service -Name $ServiceName -BinaryPathName ('"' + $binaryPath + '"') -DisplayName $ServiceDisplayName -StartupType Automatic | Out-Null
    }
    else {
        $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
        if ($cim.PathName.Trim('"') -ne $binaryPath) { throw 'The service name is owned by a different binary.' }
    }
    Set-ServiceHardening
}

function Get-InstallerFirewallDefinitions {
    return @(
        [ordered] @{ Name = $OwnedFirewallRules[0]; DisplayName = 'RegenBio Overseas Access - agent outbound'; Program = (Join-Path $InstallRoot 'overseas-agent.exe'); Action = 'Allow'; Protocol = 'TCP'; Enabled = 'True' },
        [ordered] @{ Name = $OwnedFirewallRules[1]; DisplayName = 'RegenBio Overseas Access - core TCP outbound'; Program = (Join-Path $InstallRoot 'sing-box.exe'); Action = 'Allow'; Protocol = 'TCP'; Enabled = 'True' },
        [ordered] @{ Name = $OwnedFirewallRules[2]; DisplayName = 'RegenBio Overseas Access - core UDP outbound'; Program = (Join-Path $InstallRoot 'sing-box.exe'); Action = 'Allow'; Protocol = 'UDP'; Enabled = 'True' }
    )
}

function Ensure-OwnedFirewallRules {
    foreach ($definition in @(Get-InstallerFirewallDefinitions)) {
        $existing = @(Get-NetFirewallRule -Name $definition.Name -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and $existing[0].Group -ne $OwnedFirewallGroup)) {
            throw "Firewall rule name '$($definition.Name)' is not exclusively installer-owned."
        }
        if ($existing.Count -eq 1) { continue }
        $parameters = @{
            Name = $definition.Name; DisplayName = $definition.DisplayName; Group = $OwnedFirewallGroup
            Direction = 'Outbound'; Action = $definition.Action; Program = $definition.Program
            Protocol = $definition.Protocol; Profile = 'Any'; Enabled = $definition.Enabled; PolicyStore = 'ActiveStore'
        }
        if ($definition.Contains('RemotePort')) { $parameters.RemotePort = $definition.RemotePort }
        New-NetFirewallRule @parameters | Out-Null
    }
}

function Ensure-OwnedShortcut {
    $shell = New-Object -ComObject 'WScript.Shell'
    $shortcut = $shell.CreateShortcut($ShortcutPath)
    $shortcut.TargetPath = Join-Path $InstallRoot 'overseas-client.exe'
    $shortcut.WorkingDirectory = $InstallRoot
    $shortcut.Description = 'RegenBio Overseas Access'
    $shortcut.Save()
    [void] [Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut)
    [void] [Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    # COM class: Windows Script Host Object Model
}

function Remove-OwnedFirewallRules {
    foreach ($name in $OwnedFirewallRules) {
        $rules = @(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
        foreach ($rule in $rules) {
            if ($rule.Group -ne $OwnedFirewallGroup) { throw "Firewall rule '$name' is not installer-owned." }
            Remove-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop
        }
    }
}

function Remove-OwnedShortcut {
    if (Test-Path -LiteralPath $ShortcutPath -PathType Leaf) {
        Remove-Item -LiteralPath $ShortcutPath -Force
    }
}

function Remove-OwnedService {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { return }
    $expectedBinaryPath = Join-Path $InstallRoot 'overseas-agent.exe'
    $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
    if ($cim.PathName.Trim('"') -ne $expectedBinaryPath) { throw 'Service ownership could not be proven.' }
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force -ErrorAction Stop }
    Invoke-ScChecked -Arguments @('delete', $ServiceName)
}

function Remove-OwnedDirectory {
    param([Parameter(Mandatory = $true)][string] $Path)
    Assert-OwnedPath -Path $Path
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
}

function Request-ControlledDisconnect {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { return }
    if ($service.Status -ne 'Running') { Start-Service -Name $ServiceName -ErrorAction Stop }
    $pipe = New-Object IO.Pipes.NamedPipeClientStream('.', 'RegenBioOverseasAccess', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None)
    try {
        $pipe.Connect(5000)
        $writer = New-Object IO.StreamWriter($pipe, (New-Object Text.UTF8Encoding($false)), 1024, $true)
        $reader = New-Object IO.StreamReader($pipe, (New-Object Text.UTF8Encoding($false)), $false, 1024, $true)
        $writer.AutoFlush = $true
        $requestId = [guid]::NewGuid().ToString('N')
        $writer.WriteLine(([ordered] @{ id = $requestId; action = 'disconnect' } | ConvertTo-Json -Compress))
        $response = $reader.ReadLine() | ConvertFrom-Json
        if ($response.id -ne $requestId -or $response.state -ne 'disconnected') {
            throw 'The agent reported that restoration could not be proven.'
        }
    }
    catch {
        throw "Refusing to remove the client because controlled restoration could not be proven: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $pipe) { $pipe.Dispose() }
    }
}

function Assert-TunAbsent {
    if (@(Get-NetAdapter -InterfaceAlias $TunAlias -IncludeHidden -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'The owned TUN adapter remains.'
    }
}

function Assert-OwnedRoutesAbsent {
    if (@(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq $TunAlias }).Count -ne 0) {
        throw 'Routes owned by the TUN adapter remain.'
    }
}

function Assert-DnsRestored {
    if (@(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { @($_.ServerAddresses) -contains '172.19.0.2' }).Count -ne 0) {
        throw 'The temporary TUN DNS server remains configured.'
    }
}

function Assert-OwnedFirewallAbsent {
    if (@(Get-NetFirewallRule -Group $RuntimeFirewallGroup -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Runtime firewall residue remains.'
    }
    foreach ($name in $OwnedFirewallRules) {
        if (@(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -ne 0) {
            throw "Installer firewall residue '$name' remains."
        }
    }
}

function Assert-ServiceAbsent {
    if ($null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { throw 'The client service remains.' }
}

function Assert-NetworkRestored {
    Assert-TunAbsent
    Assert-OwnedRoutesAbsent
    Assert-DnsRestored
    if (@(Get-NetFirewallRule -Group $RuntimeFirewallGroup -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Agent restoration could not be proven because runtime firewall rules remain.'
    }
    if (Test-Path -LiteralPath (Join-Path $DataRoot 'network-state.json')) {
        throw 'Agent restoration could not be proven because its state journal remains.'
    }
}

function Write-OwnershipManifest {
    param([Parameter(Mandatory = $true)][guid] $TransactionId)
    Write-AtomicJson -Path $OwnerPath -Value ([ordered] @{
        SchemaVersion = 1; ProductVersion = $ProductVersion.ToString(); TransactionId = $TransactionId.ToString('D')
        ServiceName = $ServiceName; OwnedRoots = @($InstallRoot, $DataRoot)
        FirewallRules = @($OwnedFirewallRules); ShortcutPath = $ShortcutPath
    })
}

function Undo-ClientTransaction {
    param([Parameter(Mandatory = $true)][string] $JournalPath)
    Remove-OwnedFirewallRules
    Remove-OwnedShortcut
    Remove-OwnedService
    if (Test-Path -LiteralPath $OwnerPath) {
        Remove-OwnedDirectory -Path $InstallRoot
        Remove-OwnedDirectory -Path $DataRoot
    }
    if (Test-Path -LiteralPath $JournalPath) { Remove-Item -LiteralPath $JournalPath -Force }
}

function Install-ClientTransaction {
    param(
        [Parameter(Mandatory = $true)][guid] $TransactionId,
        [Parameter(Mandatory = $true)][string] $JournalPath,
        [Parameter(Mandatory = $true)] $Manifest,
        [Parameter(Mandatory = $true)][hashtable] $Paths
    )
    try {
        Protect-OwnedDirectory -Path $InstallRoot -ReadOnlyForUsers
        Protect-OwnedDirectory -Path $DataRoot
        Write-OwnershipManifest -TransactionId $TransactionId
        foreach ($entry in @($Manifest.files)) {
            $destinationRoot = if ($entry.name -in @('agent.yaml', 'agent.yaml.p7s')) { $DataRoot } else { $InstallRoot }
            Copy-PayloadFile -Source $Paths[[string] $entry.name] -Destination (Join-Path $destinationRoot ([string] $entry.name)) -ExpectedHash ([string] $entry.sha256)
        }
        Ensure-OwnedService
        Ensure-OwnedFirewallRules
        Ensure-OwnedShortcut
        Start-Service -Name $ServiceName -ErrorAction Stop
        Remove-Item -LiteralPath $JournalPath -Force
    }
    catch {
        Undo-ClientTransaction -JournalPath $JournalPath
        throw
    }
}

function Repair-ClientTransaction {
    param(
        [Parameter(Mandatory = $true)][guid] $TransactionId,
        [Parameter(Mandatory = $true)][string] $JournalPath,
        [Parameter(Mandatory = $true)] $Manifest,
        [Parameter(Mandatory = $true)][hashtable] $Paths
    )
    Request-ControlledDisconnect
    Assert-NetworkRestored
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -ErrorAction Stop }
    Protect-OwnedDirectory -Path $InstallRoot -ReadOnlyForUsers
    Protect-OwnedDirectory -Path $DataRoot
    Write-OwnershipManifest -TransactionId $TransactionId
    $changed = $false
    foreach ($entry in @($Manifest.files)) {
        $destinationRoot = if ($entry.name -in @('agent.yaml', 'agent.yaml.p7s')) { $DataRoot } else { $InstallRoot }
        $destination = Join-Path $destinationRoot ([string] $entry.name)
        if (-not (Test-Path -LiteralPath $destination) -or (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne ([string] $entry.sha256)) {
            Copy-PayloadFile -Source $Paths[[string] $entry.name] -Destination $destination -ExpectedHash ([string] $entry.sha256)
            $changed = $true
        }
    }
    Ensure-OwnedService
    Ensure-OwnedFirewallRules
    Ensure-OwnedShortcut
    Start-Service -Name $ServiceName -ErrorAction Stop
    Remove-Item -LiteralPath $JournalPath -Force
    return $(if ($changed) { 'Repaired' } else { 'AlreadyCurrent' })
}

function Uninstall-ClientTransaction {
    param(
        [Parameter(Mandatory = $true)][guid] $TransactionId,
        [Parameter(Mandatory = $true)][string] $JournalPath
    )
    Request-ControlledDisconnect
    Assert-NetworkRestored
    Remove-OwnedFirewallRules
    Remove-OwnedShortcut
    Remove-OwnedService
    Remove-OwnedDirectory -Path $InstallRoot
    Remove-OwnedDirectory -Path $DataRoot
    Assert-ServiceAbsent
    Assert-TunAbsent
    Assert-OwnedRoutesAbsent
    Assert-DnsRestored
    Assert-OwnedFirewallAbsent
    Remove-Item -LiteralPath $JournalPath -Force
}

function Get-ClientStatus {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    return [ordered] @{
        Mode = 'Status'; ProductVersion = $ProductVersion.ToString(); Installed = (Test-Path -LiteralPath $OwnerPath -PathType Leaf)
        ServiceName = $ServiceName; ServiceStatus = $(if ($null -eq $service) { 'Absent' } else { [string] $service.Status })
        InstallRoot = $InstallRoot; DataRoot = $DataRoot
    }
}

if ($Mode -eq 'Status') {
    Get-ClientStatus | ConvertTo-Json -Compress
    return
}

if ($Mode -in @('Install', 'Repair', 'Uninstall')) { Assert-Elevated }
$transactionId = [guid]::NewGuid()

if ($MsiPreRemove) {
    if ($Mode -ne 'Uninstall') { throw 'MsiPreRemove is valid only with Uninstall.' }
    Request-ControlledDisconnect
    Assert-NetworkRestored
    [ordered] @{ Mode = $Mode; MsiPreRemove = $true; Restored = $true; TransactionId = $transactionId.ToString('D') } | ConvertTo-Json -Compress
    return
}

if ($Mode -eq 'Uninstall') {
    if (-not (Test-Path -LiteralPath $OwnerPath -PathType Leaf)) {
        throw 'Ownership manifest is absent; refusing to report uninstall success.'
    }
    if (-not $PSCmdlet.ShouldProcess($InstallRoot, "Uninstall client; TransactionId=$transactionId")) {
        [ordered] @{ Mode = $Mode; WhatIf = $true; TransactionId = $transactionId.ToString('D') } | ConvertTo-Json -Compress
        return
    }
    $journalPath = Write-TransactionJournal -TransactionId $transactionId -Operation $Mode
    Uninstall-ClientTransaction -TransactionId $transactionId -JournalPath $journalPath
    [ordered] @{ Mode = $Mode; Succeeded = $true; TransactionId = $transactionId.ToString('D') } | ConvertTo-Json -Compress
    return
}

if ([string]::IsNullOrWhiteSpace($BundlePath)) { throw 'BundlePath is required.' }
if (-not (Test-Path -LiteralPath $BundlePath -PathType Container)) { throw 'BundlePath does not exist.' }
if ([string]::IsNullOrWhiteSpace($PayloadManifestPath)) { throw 'Payload manifest path is required.' }
$bundleRoot = Get-CanonicalPath $BundlePath
$manifest = Read-PayloadManifest -Path $PayloadManifestPath
Assert-NotDowngrade -RequestedVersion ([version] $manifest.product_version)
$payloadPaths = Assert-PayloadHashes -Root $bundleRoot -Manifest $manifest
Assert-PayloadSignatures -Manifest $manifest -Paths $payloadPaths

if (-not $PSCmdlet.ShouldProcess($InstallRoot, "$Mode client; TransactionId=$transactionId")) {
    [ordered] @{ Mode = $Mode; WhatIf = $true; TransactionId = $transactionId.ToString('D'); PreflightVerified = $true } | ConvertTo-Json -Compress
    return
}
$journalPath = Write-TransactionJournal -TransactionId $transactionId -Operation $Mode
if ($Mode -eq 'Install') {
    Install-ClientTransaction -TransactionId $transactionId -JournalPath $journalPath -Manifest $manifest -Paths $payloadPaths
    $result = 'Installed'
}
else {
    $result = Repair-ClientTransaction -TransactionId $transactionId -JournalPath $journalPath -Manifest $manifest -Paths $payloadPaths
}
[ordered] @{ Mode = $Mode; Result = $result; Succeeded = $true; TransactionId = $transactionId.ToString('D') } | ConvertTo-Json -Compress
