$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repo 'scripts/windows/client-payload-tools.ps1')

Describe 'Client timestamp endpoint policy' {
    It 'accepts the documented DigiCert RFC3161 endpoint' {
        Assert-ClientTimestampUrl 'http://timestamp.digicert.com'
    }
    It 'retains HTTPS endpoint support' {
        Assert-ClientTimestampUrl 'https://timestamp.digicert.com'
    }
    It 'rejects arbitrary cleartext endpoints and URL confusion' {
        foreach ($url in @('', 'http://example.com', 'http://timestamp.digicert.com.evil.test', 'http://timestamp.digicert.com@evil.test', 'http://timestamp.digicert.com/path', 'http://timestamp.digicert.com?x=1', 'file:///tmp/a', "https://example.com`n")) {
            $rejected = $false
            try { Assert-ClientTimestampUrl $url } catch { $rejected = $true }
            $rejected | Should Be $true
        }
    }
}
