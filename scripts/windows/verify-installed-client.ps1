[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [version] $ExpectedVersion,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string] $ExpectedSourceCommit,

    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string] $ExpectedRootThumbprint = '7903068AAA22CA51185706C23611E6B5EEEF2729'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$displayName = 'RegenBio Overseas Access'
$installRoot = 'C:\Program Files\RegenBio\OverseasAccess'
$dataRoot = 'C:\ProgramData\RegenBio\OverseasAccess'
$manifestPath = Join-Path $dataRoot 'artifact-manifest.json'

$matchingRegistrations = @(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object {
        $property = $_.PSObject.Properties['DisplayName']
        $null -ne $property -and [string] $property.Value -eq $displayName
    })
if ($matchingRegistrations.Count -ne 1) {
    throw "Expected exactly one installed '$displayName' registration; found $($matchingRegistrations.Count)."
}
if ([version] $matchingRegistrations[0].DisplayVersion -ne $ExpectedVersion) {
    throw "DisplayVersion '$($matchingRegistrations[0].DisplayVersion)' does not match '$ExpectedVersion'."
}
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Installed artifact-manifest.json is absent.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([version] $manifest.product_version -ne $ExpectedVersion) { throw 'Installed manifest version does not match.' }
if (-not [string]::Equals([string] $manifest.source_commit, $ExpectedSourceCommit, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Installed manifest source commit does not match.'
}
$roots = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object {
    [string]::Equals([string] $_.Thumbprint, $ExpectedRootThumbprint, [StringComparison]::OrdinalIgnoreCase)
})
if ($roots.Count -ne 1) { throw 'Expected telecom MITM root is absent or ambiguous.' }
$service = Get-CimInstance Win32_Service -Filter "Name='RegenBioOverseasAccessAgent'"
$expectedServicePath = Join-Path $installRoot 'overseas-agent.exe'
if ($null -eq $service -or -not [string]::Equals(([string] $service.PathName).Trim('"'), $expectedServicePath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Installed service path does not match the owned agent binary.'
}

[ordered] @{
    product_version = $ExpectedVersion.ToString()
    source_commit = ([string] $manifest.source_commit).ToLowerInvariant()
    registration_count = $matchingRegistrations.Count
    root_thumbprint = $roots[0].Thumbprint
    service_path = $expectedServicePath
} | ConvertTo-Json -Compress
