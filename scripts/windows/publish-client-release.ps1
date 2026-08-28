[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $SigningCertificateThumbprint,
    [Parameter(Mandatory = $true)][string] $WixPath,
    [Parameter(Mandatory = $true)][string] $UtilExtensionPath,
    [Parameter(Mandatory = $true)][string] $DtfPath,
    [string] $SignToolPath = 'signtool.exe',
    [string] $FinalMsiPath = 'dist/OverseasAccessSetup-RELEASE_SIGNED.msi'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$final = [IO.Path]::GetFullPath((Join-Path $repo $FinalMsiPath))
if (-not $final.StartsWith($repo + [IO.Path]::DirectorySeparatorChar) -or [IO.Path]::GetFileName($final) -notmatch 'RELEASE_SIGNED') { throw 'Unsafe release output path.' }
if (Test-Path -LiteralPath $final) { throw 'Final release artifact already exists.' }
$id = [guid]::NewGuid().ToString('N')
$temporaryRoot = Join-Path $repo ('build\release-' + $id)
$payloadRelative = 'build/release-' + $id + '/payload'
$payload = Join-Path $repo $payloadRelative
$temporaryMsi = Join-Path $temporaryRoot 'candidate.msi'
try {
    & (Join-Path $PSScriptRoot 'build-client-artifacts.ps1') -Mode Release -OutputDirectory $payloadRelative -SigningCertificateThumbprint $SigningCertificateThumbprint -SignToolPath $SignToolPath
    if ($LASTEXITCODE -ne 0) { throw 'Release payload build failed.' }
    & $WixPath build (Join-Path $repo 'deploy\client\Product.wxs') (Join-Path $repo 'deploy\client\Files.wxs') -d CorporateSigningThumbprint=$SigningCertificateThumbprint -d PackageTrustMode=RELEASE_SIGNED -bindpath $payload -arch x64 -ext $UtilExtensionPath -intermediateFolder (Join-Path $temporaryRoot 'wixobj') -pdbtype none -out $temporaryMsi
    if ($LASTEXITCODE -ne 0) { throw 'wix release build failed.' }
    & $SignToolPath sign /fd SHA256 /sha1 $SigningCertificateThumbprint $temporaryMsi | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'signtool release signing failed.' }
    & (Join-Path $PSScriptRoot 'inspect-client-msi.ps1') -MsiPath $temporaryMsi -StagingPath $payload -WixPath $WixPath -DtfPath $DtfPath -OutputDirectory ('build/release-' + $id + '/inspect')
    if ($LASTEXITCODE -ne 0) { throw 'Release inspection failed.' }
    Move-Item -LiteralPath $temporaryMsi -Destination $final
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}
