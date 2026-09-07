[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $MsiPath,
    [Parameter(Mandatory = $true)][string] $StagingPath,
    [string] $OutputDirectory = 'build/msi-inspect'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
. (Join-Path $PSScriptRoot 'client-payload-tools.ps1')
$workspace = Get-ClientWorkspace -Repository $repo
$lock = Get-Content -LiteralPath (Join-Path $repo 'deploy\client\build-lock.json') -Raw | ConvertFrom-Json
function Resolve-VerifiedTool([string] $RelativePath, [string] $ExpectedHash) {
    $path = [IO.Path]::GetFullPath((Join-Path $workspace $RelativePath))
    if (-not $path.StartsWith($workspace + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedHash) {
        throw 'MSI inspection tool is outside the lock or mismatched.'
    }
    return $path
}
$WixPath = Resolve-VerifiedTool $lock.wix.executable_path $lock.wix.executable_sha256
$DtfPath = Resolve-VerifiedTool $lock.wix.dtf_path $lock.wix.dtf_sha256
if ((& $WixPath --version) -notmatch ('^' + [regex]::Escape($lock.wix.version) + '\+')) { throw 'Locked WiX version is mismatched.' }
$output = [IO.Path]::GetFullPath((Join-Path $repo $OutputDirectory))
if (-not $output.StartsWith($repo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe inspection directory.' }
if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Recurse -Force }
New-Item -ItemType Directory -Path $output | Out-Null
& $WixPath msi decompile -x (Join-Path $output 'files') -o (Join-Path $output 'decompiled.wxs') $MsiPath
if (-not $? -or $LASTEXITCODE -ne 0) { throw 'MSI decompilation failed.' }

$map = [ordered] @{
    AgentExe='overseas-agent.exe'; ClientExe='overseas-client.exe'
    InstallerVerifierFile='installer-verifier.exe'; InstallerHarnessFile='install-client.ps1'
    SingBoxExe='sing-box.exe'; CoreManifest='sing-box.manifest.json'; CronetRuntime='libcronet.dll'; TunDriver='wintun.dll'
    SingBoxLicense='sing-box-LICENSE.txt'; WintunLicense='wintun-LICENSE.txt'; PocRootCert='RegenBio-OverseasAccess-PoC-Root.cer'; TelecomMitmCert='Telecom-GoMITM-Root.cer'; AgentPolicy='agent.yaml'; AgentPolicySignature='agent.yaml.p7s'
    ArtifactManifest='artifact-manifest.json'; ArtifactManifestSignature='artifact-manifest.json.p7s'; ClientSbom='client-sbom.json'; PayloadChecksums='SHA256SUMS'
}
$manifest = Get-Content -LiteralPath (Join-Path $StagingPath 'artifact-manifest.json') -Raw | ConvertFrom-Json
$names = @{}
foreach ($entry in @($manifest.files)) {
    $name = [string]$entry.name
    if ($names.ContainsKey($name)) { throw 'Duplicate Windows name in MSI manifest.' }
    $names[$name] = $true
    if (@($map.Values) -cnotcontains $name) {
        if ($name -cnotmatch '^(flutter_windows\.dll|[A-Za-z0-9_]+_plugin\.dll|native_assets\.json|data/(app\.so|icudtl\.dat|flutter_assets/[A-Za-z0-9_][A-Za-z0-9_./-]*))$' -or $name.Contains('..') -or $name.Contains('//')) { throw 'MSI Flutter payload allowlist mismatch.' }
        $map[(Get-FlutterPayloadId $name)] = $name
    }
}
$extracted = Get-ChildItem -LiteralPath (Join-Path $output 'files\File') -File
if (Compare-Object @($map.Keys | Sort-Object) @($extracted.Name | Sort-Object)) { throw 'MSI file-table allowlist mismatch.' }
$trustRootNames = @('artifact-manifest.json','artifact-manifest.json.p7s')
$coveredNames = @($manifest.files | ForEach-Object { [string] $_.name }) + $trustRootNames
$payloadNames = @($map.Values)
if (Compare-Object @($coveredNames | Sort-Object -Unique) @($payloadNames | Sort-Object -Unique)) { throw 'Signed trust-root coverage does not exactly match MSI payloads.' }
foreach ($id in $map.Keys) {
    $source = Join-Path $StagingPath $map[$id]
    $packaged = Join-Path $output ('files\File\' + $id)
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $packaged -Algorithm SHA256).Hash) { throw "Extracted payload mismatch: $id" }
}
foreach ($entry in @($manifest.files)) {
    $source = Join-Path $StagingPath ([string] $entry.name)
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne ([string] $entry.sha256).ToLowerInvariant()) { throw "Source manifest mismatch: $($entry.name)" }
    if ($entry.authenticode_required -eq $true) {
        $signature = Get-AuthenticodeSignature -LiteralPath $source
        if ($signature.Status -ne 'Valid' -or @($entry.authenticode_thumbprints) -notcontains $signature.SignerCertificate.Thumbprint.ToLowerInvariant()) { throw "Authenticode mismatch: $($entry.name)" }
    }
}
if ($manifest.mode -eq 'release') {
    Add-Type -AssemblyName System.Security
    $bytes = [IO.File]::ReadAllBytes((Join-Path $StagingPath 'artifact-manifest.json'))
    $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList @(,$bytes)
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList @($content,$true)
    $cms.Decode([Convert]::FromBase64String([IO.File]::ReadAllText((Join-Path $StagingPath 'artifact-manifest.json.p7s')).Trim()))
    $cms.CheckSignature($true)
}
else {
    if ([IO.File]::ReadAllText((Join-Path $StagingPath 'artifact-manifest.json.p7s')) -ne 'INSPECT-ONLY-NOT-SIGNED') { throw 'Inspect-only signature sentinel mismatch.' }
    if ((Get-AuthenticodeSignature -LiteralPath $MsiPath).Status -ne 'NotSigned') { throw 'Inspect-only MSI unexpectedly signed.' }
}

$forbiddenName = '(?i)credential\.bin|\.pfx$|\.pem$|\.key$'
$binaryForbiddenContent = '(?i)BEGIN (RSA |EC )?PRIVATE KEY'
$textForbiddenContent = '(?i)cleartextcredential|bearer\s+[a-z0-9._-]+|password\s*[:=]\s*[^"R\s]'
$textExtensions = @('.ps1', '.md', '.yaml', '.json', '.p7s', '.txt')
foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $output 'files') -Recurse -File)) {
    if ($file.Name -match $forbiddenName) { throw "Secret-bearing filename in MSI: $($file.Name)" }
    $text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($file.FullName))
    if ($text -match $binaryForbiddenContent) { throw "Private-key content in MSI: $($file.Name)" }
    if (($textExtensions -contains $file.Extension -or $file.Name -eq 'SHA256SUMS') -and $text -match $textForbiddenContent) {
        throw "Secret-like text content in MSI: $($file.Name)"
    }
}

Add-Type -Path $DtfPath
$database = [WixToolset.Dtf.WindowsInstaller.Database]::new((Resolve-Path $MsiPath).Path, [WixToolset.Dtf.WindowsInstaller.DatabaseOpenMode]::ReadOnly)
function Get-MsiTableRows([string] $Table) {
    $rows = @()
    $view = $database.OpenView("SELECT * FROM ``$Table``"); $view.Execute()
    while ($record = $view.Fetch()) {
        $values = for ($index = 1; $index -le $record.FieldCount; $index++) { try { $record.GetString($index) } catch { '<binary>' } }
        $rows += ,@($values)
        $record.Dispose()
    }
    $view.Dispose()
    return $rows
}
$sequence = @{}
$directories = @{}; foreach ($row in @(Get-MsiTableRows 'Directory')) { $directories[[string]$row[0]]=$row }
$components = @{}; foreach ($row in @(Get-MsiTableRows 'Component')) { $components[[string]$row[0]]=$row }
$manifestEntries = @{}; foreach ($entry in @($manifest.files)) { $manifestEntries[[string]$entry.name]=$entry }
foreach ($row in @(Get-MsiTableRows 'File')) {
    $id=[string]$row[0]
    if (-not $map.Contains($id) -or -not $components.ContainsKey([string]$row[1])) { throw 'Unlisted MSI payload component.' }
    $actual=Resolve-MsiPayloadDestination -DirectoryId ([string]$components[[string]$row[1]][2]) -FileName ([string]$row[2]) -Directories $directories
    $expectedName=[string]$map[$id]
    $expectedDestination=if ($trustRootNames -contains $expectedName) { 'program-data' } else { [string]$manifestEntries[$expectedName].destination }
    if ($actual.name -cne $expectedName -or $actual.destination -cne $expectedDestination) { throw 'MSI payload destination differs from the signed manifest.' }
}
foreach ($row in @(Get-MsiTableRows 'InstallExecuteSequence')) { $sequence[[string] $row[0]] = [int] $row[2] }
if ($sequence.VerifyPackageTrust -ge $sequence.InstallInitialize) { throw 'VerifyPackageTrust must precede InstallInitialize.' }
if ($sequence.MsiSafeRemove -ge $sequence.StopServices) { throw 'MsiSafeRemove must precede StopServices.' }
if ($sequence.VerifyInstalledPayload -ge $sequence.InstallServices -or $sequence.VerifyInstalledPayload -le $sequence.InstallFiles) { throw 'VerifyInstalledPayload must follow InstallFiles and precede InstallServices.' }
if ($sequence.InstallSharedRoot -le $sequence.VerifyInstalledPayload -or $sequence.InstallSharedRoot -ge $sequence.InstallServices) { throw 'Shared trust must follow verified payload and precede service installation.' }
if ($sequence.RemoveClientFirewall -le $sequence.StopServices -or $sequence.CleanupOwnedRuntime -le $sequence.RemoveClientFirewall) { throw 'Uninstall firewall and runtime cleanup ordering is unsafe.' }
if ($sequence.PrepareClientUpgrade -ge $sequence.StopServices -or $sequence.BackupUpgradeSnapshot -le $sequence.StopServices -or $sequence.BackupUpgradeSnapshot -ge $sequence.InstallFiles) { throw 'Upgrade preparation/snapshot ordering is unsafe.' }
if ($sequence.RollbackUpgradeSnapshot -le $sequence.StopServices -or $sequence.RollbackUpgradeSnapshot -ge $sequence.BackupUpgradeSnapshot) { throw 'Snapshot rollback must precede backup and follow StopServices.' }
if ($sequence.RemoveExistingProducts -ne ($sequence.InstallExecute + 1)) { throw 'Old removal must immediately follow the first transaction flush.' }
if ($sequence.RestoreUpgradeSnapshot -le $sequence.RemoveExistingProducts -or $sequence.InstallClientFirewall -le $sequence.RestoreUpgradeSnapshot -or $sequence.StartServices -le $sequence.InstallClientFirewall -or $sequence.InstallExecuteAgain -le $sequence.StartServices -or $sequence.InstallExecuteAgain -ge $sequence.InstallFinalize) { throw 'Second-phase restoration/start/flush ordering is unsafe.' }
$aclRows = @(Get-MsiTableRows 'MsiLockPermissionsEx')
$expectedSddl = @('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)', 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
foreach ($sddl in $expectedSddl) { if (@($aclRows | Where-Object { $_[3] -eq $sddl }).Count -ne 1) { throw "Required ACL row is absent: $sddl" } }
$propertyRows = @(Get-MsiTableRows 'Property')
$productVersions = @($propertyRows | Where-Object { $_[0] -eq 'ProductVersion' } | ForEach-Object { [string] $_[1] })
if ($productVersions.Count -ne 1 -or $productVersions[0] -ne [string] $manifest.product_version) { throw 'MSI and manifest product versions differ.' }
$expectedUpgradeCode = 'A4D8477C-7F2D-46E6-9B5C-65BE7E8474E1'
$upgradeRows = @(Get-MsiTableRows 'Upgrade')
$relatedUpgradeRows = @($upgradeRows | Where-Object { ([string] $_[0]).Trim('{}').ToUpperInvariant() -eq $expectedUpgradeCode })
if ($upgradeRows.Count -eq 0 -or $relatedUpgradeRows.Count -ne $upgradeRows.Count) { throw 'MSI Upgrade table does not use the authoritative UpgradeCode.' }
$trustMode = @($propertyRows | Where-Object { $_[0] -eq 'PACKAGE_TRUST_MODE' } | ForEach-Object { $_[1] })
if ($trustMode.Count -ne 1 -or $trustMode[0] -notin @('INSPECT_ONLY_REFUSES_INSTALL','RELEASE_SIGNED')) { throw 'Package trust mode is invalid.' }
$customActions = @(Get-MsiTableRows 'CustomAction')
$tables = @(Get-MsiTableRows '_Tables' | ForEach-Object { [string]$_[0] })
if ($tables -contains 'Wix4Certificate' -or @($customActions | Where-Object { $_[3] -match 'InstallCertificates|UninstallCertificates' }).Count) { throw 'Shared company trust must not have an IIS uninstall action.' }
$sharedRootActions = @($customActions | Where-Object { $_[0] -eq 'InstallSharedRoot' -and $_[1] -eq '3074' -and $_[2] -eq 'InstallerVerifierBinary' -and $_[3] -eq 'shared-root-install' })
if ($sharedRootActions.Count -ne 1) { throw 'Pinned install-only company root action is absent.' }
$legacyTrustComponent = @(Get-MsiTableRows 'Component' | Where-Object { $_[0] -eq 'TelecomMitmRootTrust' -and ([string]$_[1]).Trim('{}') -eq 'A6A99D6F-B4F9-43C4-91F4-3E1E167DF063' })
if ($legacyTrustComponent.Count -ne 1 -or ([int]$legacyTrustComponent[0][3] -band 16)) { throw 'Legacy trust component identity must remain non-permanent.' }
$packageTrustActions = @($customActions | Where-Object { $_[0] -eq 'VerifyPackageTrust' -and $_[1] -eq '2' -and $_[2] -eq 'InstallerVerifierBinary' })
$payloadDataActions = @($customActions | Where-Object { $_[1] -eq '51' -and $_[2] -eq 'VerifyInstalledPayload' })
if ($packageTrustActions.Count -ne 1 -or $payloadDataActions.Count -ne 0) { throw 'First-party trust custom actions are invalid.' }
$packageThumbprintMatch = [regex]::Match([string] $packageTrustActions[0][3], '--thumbprint\s+"([A-Fa-f0-9]{40})"')
if (-not $packageThumbprintMatch.Success) { throw 'Embedded corporate trust anchor is absent.' }
$embeddedCorporateThumbprint = $packageThumbprintMatch.Groups[1].Value.ToUpperInvariant()
$expectedPayloadCommand = 'payload --program-files "C:\Program Files\RegenBio\OverseasAccess" --program-data "C:\ProgramData\RegenBio\OverseasAccess" --manifest "C:\ProgramData\RegenBio\OverseasAccess\artifact-manifest.json" --signature "C:\ProgramData\RegenBio\OverseasAccess\artifact-manifest.json.p7s" --thumbprint "' + $embeddedCorporateThumbprint + '"'
$payloadTrustActions = @($customActions | Where-Object { $_[0] -eq 'VerifyInstalledPayload' -and $_[1] -eq '3074' -and $_[2] -eq 'InstallerVerifierBinary' -and $_[3] -ceq $expectedPayloadCommand })
if ($payloadTrustActions.Count -ne 1) { throw 'First-party payload trust custom action is invalid.' }
$firewallCommands = @{
    RollbackClientFirewall = 'firewall-rollback'
    InstallClientFirewall = 'firewall-install'
    RemoveClientFirewall = 'firewall-uninstall'
}
foreach ($action in $firewallCommands.Keys) {
    $rows = @($customActions | Where-Object { $_[0] -eq $action -and $_[2] -eq 'InstallerVerifierBinary' -and $_[3] -eq $firewallCommands[$action] })
    if ($rows.Count -ne 1) { throw "Raw firewall custom action '$action' is invalid." }
}
if ($manifest.mode -eq 'release') {
    if ($trustMode[0] -ne 'RELEASE_SIGNED' -or $embeddedCorporateThumbprint -eq ('0' * 40)) { throw 'Release trust metadata is invalid.' }
    $msiSignature = Get-AuthenticodeSignature -LiteralPath $MsiPath
    if ($msiSignature.Status -ne 'Valid' -or $null -eq $msiSignature.SignerCertificate -or $msiSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $embeddedCorporateThumbprint) {
        throw 'Release MSI signature does not match its embedded trust anchor.'
    }
    if ($cms.SignerInfos.Count -ne 1 -or $null -eq $cms.SignerInfos[0].Certificate -or
        $cms.SignerInfos[0].Certificate.Thumbprint.ToUpperInvariant() -ne $embeddedCorporateThumbprint) {
        throw 'Release manifest signer does not match the embedded trust anchor.'
    }
}
elseif ($trustMode[0] -ne 'INSPECT_ONLY_REFUSES_INSTALL' -or $embeddedCorporateThumbprint -ne ('0' * 40)) {
    throw 'Inspect-only MSI does not contain the fail-closed trust sentinel.'
}
foreach ($table in @('ServiceInstall','ServiceControl','RemoveFile','Upgrade')) { [void] @(Get-MsiTableRows $table) }
$database.Dispose()
$database = $null
$msiSignature = $null
[GC]::Collect()
[GC]::WaitForPendingFinalizers()
[ordered] @{ msi_sha256 = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash; payload_count = $map.Count; mode = $manifest.mode; source_commit = $manifest.source_commit } | ConvertTo-Json -Compress
