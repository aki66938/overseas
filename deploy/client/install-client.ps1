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

$ProductVersion = [version] '0.1.6'
$TrustedManifestSignerThumbprint = '0000000000000000000000000000000000000000' # INSPECT_ONLY_REFUSES_INSTALL; release recipe replaces this copy.
$ServiceName = 'RegenBioOverseasAccessAgent'
$ServiceDisplayName = 'RegenBio Overseas Access Agent'
$InstallRoot = 'C:\Program Files\RegenBio\OverseasAccess'
$DataRoot = 'C:\ProgramData\RegenBio\OverseasAccess'
$LogRoot = Join-Path $DataRoot 'logs'
$TransactionRoot = 'C:\ProgramData\RegenBio\InstallerTransactions'
$RootOwnerFileName = '.regenbio-overseas-access.owner.json'
$InstallOwnerPath = Join-Path $InstallRoot $RootOwnerFileName
$DataOwnerPath = Join-Path $DataRoot $RootOwnerFileName
$OwnerPath = $DataOwnerPath
$RuntimeOwnershipPath = Join-Path $DataRoot 'runtime-owned.json'
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
    'installer-verifier.exe',
    'install-client.ps1',
    'sing-box.exe',
    'sing-box.manifest.json',
    'libcronet.dll',
    'wintun.dll',
    'agent.yaml',
    'agent.yaml.p7s',
    'client-sbom.json',
    'SHA256SUMS',
    'sing-box-LICENSE.txt',
    'wintun-LICENSE.txt',
    'RegenBio-OverseasAccess-PoC-Root.cer',
    'Telecom-GoMITM-Root.cer'
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
    $canonical = Get-CanonicalPath $Path
    if ($canonical -notin @((Get-CanonicalPath $InstallRoot), (Get-CanonicalPath $DataRoot)) -or -not (Test-ValidRootMarker -Root $canonical)) {
        throw "Path '$canonical' is not transaction-owned."
    }
}

function Test-JournalOwnsResource {
    param(
        [string] $JournalPath,
        [Parameter(Mandatory = $true)][string] $Resource
    )
    if ([string]::IsNullOrWhiteSpace($JournalPath) -or -not (Test-Path -LiteralPath $JournalPath -PathType Leaf)) { return $false }
    try {
        $journal = Get-Content -LiteralPath $JournalPath -Raw | ConvertFrom-Json
        if ($journal.SchemaVersion -ne 2 -or $journal.Operation -ne 'Install') { return $false }
        return [string]::Equals([string] $journal.PendingResource, $Resource, [StringComparison]::OrdinalIgnoreCase) -or
            @($journal.CreatedResources | Where-Object { [string]::Equals([string] $_, $Resource, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 1
    }
    catch { return $false }
}

function Test-UninstallJournalOwnsRootDeletion {
    param(
        [string] $JournalPath,
        [Parameter(Mandatory = $true)][string] $Root
    )
    if ([string]::IsNullOrWhiteSpace($JournalPath) -or -not (Test-Path -LiteralPath $JournalPath -PathType Leaf)) { return $false }
    try {
        $journal = Get-Content -LiteralPath $JournalPath -Raw | ConvertFrom-Json
        return $journal.SchemaVersion -eq 2 -and $journal.Operation -eq 'Uninstall' -and
            [string]::Equals([string] $journal.PendingResource, $Root, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Assert-InstallCollisions {
    param([string] $JournalPath)
    foreach ($root in @('C:\Program Files\RegenBio\OverseasAccess', 'C:\ProgramData\RegenBio\OverseasAccess')) {
        if ((Test-Path -LiteralPath $root) -and -not (Test-ValidRootMarker -Root $root) -and
            -not (Test-JournalOwnsResource -JournalPath $JournalPath -Resource $root)) {
            throw "Refusing pre-existing unowned root '$root'."
        }
    }
    if (Test-Path -LiteralPath 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\RegenBio Overseas Access.lnk') {
        if (-not (Test-JournalOwnsResource -JournalPath $JournalPath -Resource $ShortcutPath) -or -not (Test-OwnedShortcut)) {
            throw 'Refusing a pre-existing unowned shortcut.'
        }
    }
    $existingService = Get-Service -Name 'RegenBioOverseasAccessAgent' -ErrorAction SilentlyContinue
    if ($null -ne $existingService) {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
        if (-not (Test-JournalOwnsResource -JournalPath $JournalPath -Resource $ServiceName) -or
            $service.PathName.Trim('"') -ne (Join-Path $InstallRoot 'overseas-agent.exe')) {
            throw 'Refusing a pre-existing service name.'
        }
    }
    foreach ($name in @('RegenBioOverseasAccess-AllowAgent-Out', 'RegenBioOverseasAccess-AllowCoreTCP-Out', 'RegenBioOverseasAccess-AllowCoreUDP-Out')) {
        $rules = @(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
        if ($rules.Count -ne 0) {
            if (-not (Test-JournalOwnsResource -JournalPath $JournalPath -Resource $OwnedFirewallGroup) -or
                $rules.Count -ne 1 -or $rules[0].Group -ne $OwnedFirewallGroup) {
                throw "Refusing a pre-existing firewall rule '$name'."
            }
        }
    }
}

function Assert-RemoveOwnership {
    param([string] $JournalPath)
    $resuming = $false
    if (-not [string]::IsNullOrWhiteSpace($JournalPath) -and (Test-Path -LiteralPath $JournalPath -PathType Leaf)) {
        $journal = Get-Content -LiteralPath $JournalPath -Raw | ConvertFrom-Json
        $resuming = $journal.SchemaVersion -eq 2 -and $journal.Operation -eq 'Uninstall'
        if (-not $resuming) { throw 'The uninstall resume journal is invalid.' }
    }
    foreach ($root in @($InstallRoot, $DataRoot)) {
        if (Test-Path -LiteralPath $root -PathType Container) {
            if (-not (Test-ValidRootMarker -Root $root) -and -not (Test-UninstallJournalOwnsRootDeletion -JournalPath $JournalPath -Root $root)) {
                throw "Uninstall requires a valid ownership marker for '$root'."
            }
        }
        elseif (-not $resuming) { throw "Owned root '$root' is absent; refusing uninstall success." }
    }
    if ((Test-Path -LiteralPath $ShortcutPath -PathType Leaf) -and -not (Test-OwnedShortcut)) {
        throw 'The shortcut is not installer-owned.'
    }
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $existingService) {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
        if ($service.PathName.Trim('"') -ne (Join-Path $InstallRoot 'overseas-agent.exe')) { throw 'The service is not installer-owned.' }
    }
    foreach ($name in $OwnedFirewallRules) {
        $rules = @(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
        if ($rules.Count -gt 1 -or ($rules.Count -eq 1 -and $rules[0].Group -ne $OwnedFirewallGroup)) {
            throw "Firewall rule '$name' is not installer-owned."
        }
    }
}

function Test-ValidRootMarker {
    param([Parameter(Mandatory = $true)][string] $Root)
    $markerPath = Join-Path $Root $RootOwnerFileName
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { return $false }
    try {
        $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
        return $marker.SchemaVersion -eq 2 -and $marker.ProductId -eq 'RegenBioOverseasAccess' -and
            [string]::Equals((Get-CanonicalPath ([string] $marker.Root)), (Get-CanonicalPath $Root), [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Write-RootOwnershipMarker {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][guid] $TransactionId,
        [string[]] $OwnedFiles = @()
    )
    Assert-ExactRoot -Actual $Root -Expected $(if ($Root -eq $InstallRoot) { $InstallRoot } else { $DataRoot })
    Write-AtomicJson -Path (Join-Path $Root $RootOwnerFileName) -Value ([ordered] @{
        SchemaVersion = 2; ProductId = 'RegenBioOverseasAccess'; Root = $Root
        TransactionId = $TransactionId.ToString('D'); ProductVersion = $ProductVersion.ToString()
        OwnedFiles = @($OwnedFiles)
    })
}

function Remove-RootOwnershipMarker {
    param([Parameter(Mandatory = $true)][string] $Root)
    if (-not (Test-ValidRootMarker -Root $Root)) { throw "Ownership marker for '$Root' is absent or invalid." }
    Remove-Item -LiteralPath (Join-Path $Root $RootOwnerFileName) -Force
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
    # The raw .NET exception is locale-dependent and must not leak into journals.
    $manifestBytes = $null
    try { $manifestBytes = [IO.File]::ReadAllBytes($Path) } catch { throw 'The payload manifest could not be read.' }
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
    foreach ($name in @('overseas-agent.exe', 'overseas-client.exe', 'installer-verifier.exe', 'wintun.dll')) {
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
        SchemaVersion = 2
        TransactionId = $TransactionId.ToString('D')
        Operation = $Operation
        Phase = 'Prepared'
        PendingResource = $null
        CreatedResources = @()
        ProductVersion = $ProductVersion.ToString()
        StartedUtc = [DateTime]::UtcNow.ToString('o')
    })
    return $path
}

function Write-TransactionPhase {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Phase,
        [string] $PendingResource,
        [string] $CompletedResource
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Transaction journal is absent.' }
    $journal = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($journal.SchemaVersion -ne 2 -or [string] $journal.TransactionId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'Transaction journal is invalid.' }
    $created = @($journal.CreatedResources)
    if (-not [string]::IsNullOrWhiteSpace($CompletedResource) -and $created -notcontains $CompletedResource) { $created += $CompletedResource }
    Write-AtomicJson -Path $Path -Value ([ordered] @{
        SchemaVersion = 2; TransactionId = [string] $journal.TransactionId; Operation = [string] $journal.Operation
        Phase = $Phase; PendingResource = $PendingResource; CreatedResources = @($created)
        ProductVersion = [string] $journal.ProductVersion; StartedUtc = [string] $journal.StartedUtc
        UpdatedUtc = [DateTime]::UtcNow.ToString('o')
    })
}

function Get-ResumableJournal {
    param([Parameter(Mandatory = $true)][string] $Operation)
    if (-not (Test-Path -LiteralPath $TransactionRoot -PathType Container)) { return $null }
    $matches = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $TransactionRoot -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
        try {
            $journal = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            if ($journal.SchemaVersion -eq 2 -and $journal.Operation -eq $Operation) { $matches += $file.FullName }
        }
        catch { throw "Invalid transaction journal '$($file.FullName)' blocks lifecycle changes." }
    }
    if ($matches.Count -gt 1) { throw "Multiple unfinished $Operation transactions require operator review." }
    return $(if ($matches.Count -eq 1) { $matches[0] } else { $null })
}

function Resume-ClientTransaction {
    param([Parameter(Mandatory = $true)][string] $JournalPath)
    if (-not (Test-Path -LiteralPath $JournalPath -PathType Leaf)) { throw 'Resume journal is absent.' }
    return Get-Content -LiteralPath $JournalPath -Raw | ConvertFrom-Json
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

function Test-OwnedShortcut {
    if (-not (Test-Path -LiteralPath $ShortcutPath -PathType Leaf)) { return $false }

    $shell = $null
    $shortcut = $null
    try {
        $shell = New-Object -ComObject 'WScript.Shell'
        $shortcut = $shell.CreateShortcut($ShortcutPath)
        return [string]::Equals((Get-CanonicalPath $shortcut.TargetPath), (Join-Path $InstallRoot 'overseas-client.exe'), [System.StringComparison]::OrdinalIgnoreCase)
    }
    finally {
        if ($null -ne $shortcut) { [void] [Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) }
        if ($null -ne $shell) { [void] [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
    }
}

function Ensure-OwnedShortcut {
    if ((Test-Path -LiteralPath $ShortcutPath -PathType Leaf) -and -not (Test-OwnedShortcut)) {
        throw 'Refusing to overwrite a shortcut that is not installer-owned.'
    }
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
        if (-not (Test-OwnedShortcut)) {
            throw 'Refusing to remove a shortcut that is not installer-owned.'
        }
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

function Clear-OwnedSensitiveRuntimeFiles {
    if (-not [IO.File]::Exists($RuntimeOwnershipPath)) {
        foreach ($expected in @('sing-box.json')) {
            if ([IO.File]::Exists((Join-Path $DataRoot $expected))) {
                throw "Sensitive runtime file '$expected' exists without an ownership ledger."
            }
        }
        return
    }
    $ledger = Get-Content -LiteralPath $RuntimeOwnershipPath -Raw | ConvertFrom-Json
    if ($ledger.schema_version -ne 2) { throw 'Runtime ownership ledger is invalid.' }
    $supported = @('sing-box.json')
    $ownedTargets = @($ledger.finalized)
    $ownedPaths = @($ledger.finalized)
    foreach ($intent in @($ledger.intents)) {
        $target = [string] $intent.target
        if ($target -notin $supported -or [string] $intent.phase -notin @('prepared', 'temporary-written', 'publishing', 'published')) {
            throw 'Runtime ownership ledger contains an invalid intent.'
        }
        $ownedTargets += $target
        $ownedPaths += $target
        foreach ($entry in @(@('temporary', 'publish'), @('backup', 'backup'), @('replaced', 'replaced'))) {
            $name = [string] $intent.($entry[0])
            $pattern = '^\.' + [regex]::Escape($target) + '\.' + $entry[1] + '-[a-f0-9]{32}\.tmp$'
            if ([IO.Path]::GetFileName($name) -ne $name -or $name -notmatch $pattern) {
                throw 'Runtime ownership ledger contains a foreign transient path.'
            }
            $ownedPaths += $name
        }
    }
    foreach ($name in @($ledger.finalized)) {
        if ([string] $name -notin $supported) { throw 'Runtime ownership ledger contains a foreign finalized path.' }
    }
    foreach ($expected in @('sing-box.json')) {
        if ([IO.File]::Exists((Join-Path $DataRoot $expected)) -and $ownedTargets -notcontains $expected) {
            throw "Sensitive runtime file '$expected' is not ownership-proven."
        }
    }
    foreach ($name in @($ownedPaths | Select-Object -Unique)) {
        $path = Join-Path $DataRoot $name
        if ([IO.File]::Exists($path)) {
            $length = (Get-Item -LiteralPath $path).Length
            [IO.File]::WriteAllBytes($path, (New-Object byte[] $length))
            [IO.File]::Delete($path)
        }
        elseif ([IO.Directory]::Exists($path)) { throw "Sensitive runtime path '$name' is not a regular file." }
        if ([IO.File]::Exists($path) -or [IO.Directory]::Exists($path)) { throw "Sensitive runtime residue '$name' remains." }
    }
    foreach ($expected in @('sing-box.json')) {
        if ([IO.File]::Exists((Join-Path $DataRoot $expected)) -or [IO.Directory]::Exists((Join-Path $DataRoot $expected))) { throw "Sensitive runtime residue '$expected' remains." }
    }
    [IO.File]::Delete($RuntimeOwnershipPath)
    if ([IO.File]::Exists($RuntimeOwnershipPath) -or [IO.Directory]::Exists($RuntimeOwnershipPath)) { throw 'Runtime ownership ledger residue remains.' }
}

function Remove-OwnedTraceDirectory {
    $expected = Join-Path $DataRoot 'logs'
    if (-not [string]::Equals((Get-CanonicalPath $LogRoot), (Get-CanonicalPath $expected), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Trace directory is outside the owned data root.'
    }
    if (-not (Test-Path -LiteralPath $LogRoot)) { return }
    if (-not (Test-Path -LiteralPath $LogRoot -PathType Container)) { throw 'Owned trace path is not a directory.' }
    foreach ($entry in @(Get-ChildItem -LiteralPath $LogRoot -Force)) {
        if (-not $entry.PSIsContainer -and $entry.Name -match '^trace-\d{8}T\d{6}\.\d{9}Z(?:-\d{2})?-g\d+\.jsonl$') {
            Remove-Item -LiteralPath $entry.FullName -Force
            continue
        }
        throw "Owned trace directory contains foreign entry '$($entry.Name)'."
    }
    Remove-Item -LiteralPath $LogRoot -Force
}

function Remove-OwnedDirectory {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [switch] $MarkerRemoved
    )
    Assert-ExactRoot -Actual $Path -Expected $(if ($Path -eq $InstallRoot) { $InstallRoot } else { $DataRoot })
    if (-not $MarkerRemoved) { Assert-OwnedPath -Path $Path }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    if (@(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) {
        throw "Owned root '$Path' contains foreign or unremoved content; refusing directory removal."
    }
    Remove-Item -LiteralPath $Path -Force
}

function Remove-OwnedRoot {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $JournalPath
    )
    Assert-ExactRoot -Actual $Root -Expected $(if ($Root -eq $InstallRoot) { $InstallRoot } else { $DataRoot })
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        Write-TransactionPhase -Path $JournalPath -Phase 'RootDeletionProven' -CompletedResource $Root
        return
    }
    $hasMarker = Test-ValidRootMarker -Root $Root
    if ($hasMarker) {
        Remove-OwnedPayloadFiles -Root $Root
        $foreign = @(Get-ChildItem -LiteralPath $Root -Force | Where-Object { $_.Name -ne $RootOwnerFileName })
        if ($foreign.Count -ne 0) {
            throw "Owned root '$Root' contains foreign or unremoved content; ownership proof retained."
        }
        Write-TransactionPhase -Path $JournalPath -Phase 'DeletingRoot' -PendingResource $Root
        Remove-RootOwnershipMarker -Root $Root
    }
    elseif (-not (Test-UninstallJournalOwnsRootDeletion -JournalPath $JournalPath -Root $Root) -and
        -not (Test-JournalOwnsResource -JournalPath $JournalPath -Resource $Root)) {
        throw "Root deletion for '$Root' lacks durable ownership proof."
    }
    if (@(Get-ChildItem -LiteralPath $Root -Force).Count -ne 0) {
        throw "Owned root '$Root' contains foreign or unremoved content; refusing directory removal."
    }
    Remove-Item -LiteralPath $Root -Force
    if (Test-Path -LiteralPath $Root) { throw "Owned root '$Root' deletion could not be proven." }
    Write-TransactionPhase -Path $JournalPath -Phase 'RootDeletionProven' -CompletedResource $Root
}

function Remove-OwnedPayloadFiles {
    param([Parameter(Mandatory = $true)][string] $Root)
    if (-not (Test-ValidRootMarker -Root $Root)) { throw "Ownership marker for '$Root' is invalid." }
    $marker = Get-Content -LiteralPath (Join-Path $Root $RootOwnerFileName) -Raw | ConvertFrom-Json
    foreach ($name in @($marker.OwnedFiles)) {
        if ([string] $name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or ([string] $name).Contains('..')) { throw 'Owned file name is invalid.' }
        $path = Join-Path $Root ([string] $name)
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
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
    $groupRules = @(Get-NetFirewallRule -Group $RuntimeFirewallGroup -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    $enabledRules = @($groupRules | Where-Object { [string]$_.Enabled -eq 'True' })
    if ($enabledRules.Count -ne 0) {
        throw 'Agent restoration could not be proven because runtime firewall rules remain.'
    }
    if (Test-Path -LiteralPath (Join-Path $DataRoot 'network-state.json')) {
        throw 'Agent restoration could not be proven because its state journal remains.'
    }
}

function Remove-PreparedFirewallPool {
    $preparedPath = Join-Path $DataRoot 'prepared-network.json'
    $ledger = $null
    if (Test-Path -LiteralPath $preparedPath -PathType Leaf) {
        try { $ledger = Get-Content -LiteralPath $preparedPath -Raw | ConvertFrom-Json } catch { throw 'Prepared firewall ledger is unreadable.' }
    }
    $rules = @(Get-NetFirewallRule -Group $RuntimeFirewallGroup -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    if ($rules.Count -eq 0) {
        if ($null -ne $ledger) { Remove-Item -LiteralPath $preparedPath -Force -ErrorAction Stop }
        return
    }
    $enabled = @($rules | Where-Object { [string]$_.Enabled -eq 'True' })
    if ($enabled.Count -ne 0) { throw 'Refusing to uninstall while prepared firewall rules remain enabled.' }
    if ($null -eq $ledger) { throw 'Refusing to remove unlabelled product-group firewall rules.' }
    $ownedNames = @($ledger.rules | ForEach-Object { [string]$_.name } | Sort-Object -Unique)
    if ($ownedNames.Count -eq 0) { throw 'Prepared firewall ledger lists no owned rules.' }
    $unknown = @($rules | Where-Object { $ownedNames -notcontains [string]$_.Name })
    if ($unknown.Count -ne 0) { throw 'Refusing to remove unknown product-group firewall rules.' }
    foreach ($name in $ownedNames) {
        $match = @(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
        foreach ($rule in $match) {
            if ([string]$rule.Group -ne $RuntimeFirewallGroup) { throw "Firewall rule '$name' is not product-owned." }
            Remove-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop
        }
    }
    if (@(Get-NetFirewallRule -Group $RuntimeFirewallGroup -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Prepared firewall pool removal could not be proven.'
    }
    Remove-Item -LiteralPath $preparedPath -Force -ErrorAction Stop
}

function Write-OwnershipManifest {
    param(
        [Parameter(Mandatory = $true)][guid] $TransactionId,
        [Parameter(Mandatory = $true)] $Manifest
    )
    $installFiles = @($Manifest.files | Where-Object { $_.name -notin @('agent.yaml', 'agent.yaml.p7s', 'artifact-manifest.json', 'artifact-manifest.json.p7s', 'client-sbom.json', 'SHA256SUMS') } | ForEach-Object { [string] $_.name })
    $dataFiles = @($Manifest.files | Where-Object { $_.name -in @('agent.yaml', 'agent.yaml.p7s', 'artifact-manifest.json', 'artifact-manifest.json.p7s', 'client-sbom.json', 'SHA256SUMS') } | ForEach-Object { [string] $_.name })
    Write-RootOwnershipMarker -Root $InstallRoot -TransactionId $TransactionId -OwnedFiles $installFiles
    Write-RootOwnershipMarker -Root $DataRoot -TransactionId $TransactionId -OwnedFiles $dataFiles
}

function Undo-ClientTransaction {
    param([Parameter(Mandatory = $true)][string] $JournalPath)
    try {
        Write-TransactionPhase -Path $JournalPath -Phase 'Compensating' -PendingResource 'FirewallRules'
        Remove-PreparedFirewallPool
        Remove-OwnedFirewallRules
        Remove-OwnedShortcut
        Remove-OwnedService
        Clear-OwnedSensitiveRuntimeFiles
        Remove-OwnedTraceDirectory
        foreach ($root in @($InstallRoot, $DataRoot)) {
            if (Test-Path -LiteralPath $root -PathType Container) { Remove-OwnedRoot -Root $root -JournalPath $JournalPath }
        }
        Write-TransactionPhase -Path $JournalPath -Phase 'Compensated'
        Remove-Item -LiteralPath $JournalPath -Force
    }
    catch {
        Write-TransactionPhase -Path $JournalPath -Phase 'CompensationIncomplete'
        throw
    }
}

function Install-ClientTransaction {
    param(
        [Parameter(Mandatory = $true)][guid] $TransactionId,
        [Parameter(Mandatory = $true)][string] $JournalPath,
        [Parameter(Mandatory = $true)] $Manifest,
        [Parameter(Mandatory = $true)][hashtable] $Paths
    )
    try {
        Write-TransactionPhase -Path $JournalPath -Phase 'CreatingInstallRoot' -PendingResource $InstallRoot
        Protect-OwnedDirectory -Path $InstallRoot -ReadOnlyForUsers
        Write-RootOwnershipMarker -Root $InstallRoot -TransactionId $TransactionId
        Write-TransactionPhase -Path $JournalPath -Phase 'CreatingDataRoot' -PendingResource $DataRoot -CompletedResource $InstallRoot
        Protect-OwnedDirectory -Path $DataRoot
        Write-RootOwnershipMarker -Root $DataRoot -TransactionId $TransactionId
        Protect-OwnedDirectory -Path $LogRoot
        Write-TransactionPhase -Path $JournalPath -Phase 'CopyingPayloads' -CompletedResource $DataRoot
        foreach ($entry in @($Manifest.files)) {
            $destinationRoot = if ($entry.name -in @('agent.yaml', 'agent.yaml.p7s', 'artifact-manifest.json', 'artifact-manifest.json.p7s', 'client-sbom.json', 'SHA256SUMS')) { $DataRoot } else { $InstallRoot }
            $destination = Join-Path $destinationRoot ([string] $entry.name)
            Write-TransactionPhase -Path $JournalPath -Phase 'CopyingPayloads' -PendingResource $destination
            Copy-PayloadFile -Source $Paths[[string] $entry.name] -Destination $destination -ExpectedHash ([string] $entry.sha256)
            Write-TransactionPhase -Path $JournalPath -Phase 'CopyingPayloads' -CompletedResource $destination
        }
        Write-OwnershipManifest -TransactionId $TransactionId -Manifest $Manifest
        Write-TransactionPhase -Path $JournalPath -Phase 'CreatingService' -PendingResource $ServiceName
        Ensure-OwnedService
        Write-TransactionPhase -Path $JournalPath -Phase 'CreatingFirewall' -PendingResource $OwnedFirewallGroup -CompletedResource $ServiceName
        Ensure-OwnedFirewallRules
        Write-TransactionPhase -Path $JournalPath -Phase 'CreatingShortcut' -PendingResource $ShortcutPath -CompletedResource $OwnedFirewallGroup
        Ensure-OwnedShortcut
        Write-TransactionPhase -Path $JournalPath -Phase 'Completed' -CompletedResource $ShortcutPath
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
    $changed = $false
    try {
        $resume = Resume-ClientTransaction -JournalPath $JournalPath
        Write-TransactionPhase -Path $JournalPath -Phase 'RepairDisconnect'
        Request-ControlledDisconnect
        Assert-NetworkRestored
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -ErrorAction Stop }
        Protect-OwnedDirectory -Path $InstallRoot -ReadOnlyForUsers
        Protect-OwnedDirectory -Path $DataRoot
        Protect-OwnedDirectory -Path $LogRoot
        Write-TransactionPhase -Path $JournalPath -Phase 'RepairPayloads'
        foreach ($entry in @($Manifest.files)) {
            $destinationRoot = if ($entry.name -in @('agent.yaml', 'agent.yaml.p7s', 'artifact-manifest.json', 'artifact-manifest.json.p7s', 'client-sbom.json', 'SHA256SUMS')) { $DataRoot } else { $InstallRoot }
            $destination = Join-Path $destinationRoot ([string] $entry.name)
            if (-not (Test-Path -LiteralPath $destination) -or (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne ([string] $entry.sha256)) {
                Write-TransactionPhase -Path $JournalPath -Phase 'RepairPayloads' -PendingResource $destination
                Copy-PayloadFile -Source $Paths[[string] $entry.name] -Destination $destination -ExpectedHash ([string] $entry.sha256)
                Write-TransactionPhase -Path $JournalPath -Phase 'RepairPayloads' -CompletedResource $destination
                $changed = $true
            }
        }
        Write-OwnershipManifest -TransactionId $TransactionId -Manifest $Manifest
        Ensure-OwnedService
        Ensure-OwnedFirewallRules
        Ensure-OwnedShortcut
        Write-TransactionPhase -Path $JournalPath -Phase 'Completed'
        Remove-Item -LiteralPath $JournalPath -Force
        return $(if ($changed) { 'Repaired' } else { 'AlreadyCurrent' })
    }
    catch {
        Write-TransactionPhase -Path $JournalPath -Phase 'RepairIncomplete'
        throw
    }
}

function Uninstall-ClientTransaction {
    param(
        [Parameter(Mandatory = $true)][guid] $TransactionId,
        [Parameter(Mandatory = $true)][string] $JournalPath
    )
    try {
        $resume = Resume-ClientTransaction -JournalPath $JournalPath
        Write-TransactionPhase -Path $JournalPath -Phase 'UninstallDisconnect'
        Request-ControlledDisconnect
        Assert-NetworkRestored
        Remove-PreparedFirewallPool
        Write-TransactionPhase -Path $JournalPath -Phase 'UninstallResources'
        Remove-OwnedFirewallRules
        Remove-OwnedShortcut
        Remove-OwnedService
        Write-TransactionPhase -Path $JournalPath -Phase 'SensitiveCleanup' -PendingResource $RuntimeOwnershipPath
        Clear-OwnedSensitiveRuntimeFiles
        Remove-OwnedTraceDirectory
        Assert-ServiceAbsent
        Assert-TunAbsent
        Assert-OwnedRoutesAbsent
        Assert-DnsRestored
        Assert-OwnedFirewallAbsent
        if (Test-Path -LiteralPath $ShortcutPath) { throw 'Owned shortcut residue remains.' }
        Write-TransactionPhase -Path $JournalPath -Phase 'ResidueProven'
        foreach ($root in @($InstallRoot, $DataRoot)) {
            Remove-OwnedRoot -Root $root -JournalPath $JournalPath
        }
        Write-TransactionPhase -Path $JournalPath -Phase 'Completed'
        Remove-Item -LiteralPath $JournalPath -Force
    }
    catch {
        $pendingRoot = $null
        if (Test-Path -LiteralPath $JournalPath -PathType Leaf) {
            try {
                $failureJournal = Get-Content -LiteralPath $JournalPath -Raw | ConvertFrom-Json
                if ($failureJournal.Operation -eq 'Uninstall' -and $failureJournal.Phase -eq 'DeletingRoot' -and
                    [string] $failureJournal.PendingResource -in @($InstallRoot, $DataRoot)) {
                    $pendingRoot = [string] $failureJournal.PendingResource
                }
            }
            catch { $pendingRoot = $null }
        }
        if ($null -ne $pendingRoot) {
            Write-TransactionPhase -Path $JournalPath -Phase 'RootDeletionIncomplete' -PendingResource $pendingRoot
        }
        else {
            Write-TransactionPhase -Path $JournalPath -Phase 'SensitiveCleanupIncomplete'
        }
        throw
    }
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
    $resumePath = Get-ResumableJournal -Operation $Mode
    Assert-RemoveOwnership -JournalPath $resumePath
    if (-not $PSCmdlet.ShouldProcess($InstallRoot, "Uninstall client; TransactionId=$transactionId")) {
        [ordered] @{ Mode = $Mode; WhatIf = $true; TransactionId = $transactionId.ToString('D') } | ConvertTo-Json -Compress
        return
    }
    $journalPath = if ($null -ne $resumePath) { $resumePath } else { Write-TransactionJournal -TransactionId $transactionId -Operation $Mode }
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
$resumePath = Get-ResumableJournal -Operation $Mode
if ($Mode -eq 'Install') {
    Assert-InstallCollisions -JournalPath $resumePath
}
else {
    foreach ($root in @($InstallRoot, $DataRoot)) {
        if (-not (Test-ValidRootMarker -Root $root)) { throw "Repair requires a valid ownership marker for '$root'." }
    }
}

if (-not $PSCmdlet.ShouldProcess($InstallRoot, "$Mode client; TransactionId=$transactionId")) {
    [ordered] @{ Mode = $Mode; WhatIf = $true; TransactionId = $transactionId.ToString('D'); PreflightVerified = $true } | ConvertTo-Json -Compress
    return
}
$journalPath = if ($null -ne $resumePath) { $resumePath } else { Write-TransactionJournal -TransactionId $transactionId -Operation $Mode }
if ($Mode -eq 'Install') {
    Install-ClientTransaction -TransactionId $transactionId -JournalPath $journalPath -Manifest $manifest -Paths $payloadPaths
    $result = 'Installed'
}
else {
    $result = Repair-ClientTransaction -TransactionId $transactionId -JournalPath $journalPath -Manifest $manifest -Paths $payloadPaths
}
[ordered] @{ Mode = $Mode; Result = $result; Succeeded = $true; TransactionId = $transactionId.ToString('D') } | ConvertTo-Json -Compress
