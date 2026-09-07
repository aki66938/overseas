$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Get-SharedRoots {
    $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        return @($store.Certificates | Where-Object { $_.Thumbprint -ceq '7903068AAA22CA51185706C23611E6B5EEEF2729' })
    }
    finally { $store.Close() }
}

function Add-SharedRoot($Certificate) {
    $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($Certificate)
    }
    finally { $store.Close() }
}

function Ensure-SharedRoot([string]$CertificatePath) {
    # The corporate root is persistent shared trust. No uninstall or rollback
    # operation removes it, regardless of the historical product registry marker.
    $bytes = [IO.File]::ReadAllBytes($CertificatePath)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
    if ($hash -cne '0D344A6F39FD4252C96F0E5606E2F4E7205CB2E59C44603C542AA8C132A711F8') { throw 'Company root file differs from the pinned certificate.' }
    $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes)
    try {
        if ($certificate.Thumbprint -cne '7903068AAA22CA51185706C23611E6B5EEEF2729' -or $certificate.HasPrivateKey) { throw 'Company root identity differs from the pinned certificate.' }
        $existing = @(Get-SharedRoots)
        if ($existing.Count -gt 1) { throw 'Company root store identity is ambiguous.' }
        if ($existing.Count -eq 0) { Add-SharedRoot $certificate }
        $verified = @(Get-SharedRoots)
        if ($verified.Count -ne 1 -or [Convert]::ToBase64String($verified[0].RawData) -cne [Convert]::ToBase64String($certificate.RawData)) { throw 'Company shared root publication could not be verified.' }
    }
    finally { $certificate.Dispose() }
}

Ensure-SharedRoot -CertificatePath 'C:\Program Files\RegenBio\OverseasAccess\Telecom-GoMITM-Root.cer'
