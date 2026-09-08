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

Describe 'Bounded Authenticode signing retries' {
    BeforeEach {
        $script:signCalls = 0
        $script:failures = 0
        function Test-SignTool {
            $script:signCalls++
            $global:LASTEXITCODE = 0
            if ($script:signCalls -le $script:failures) { $global:LASTEXITCODE = 1 }
        }
        Mock Start-Sleep {}
    }
    It 'does not retry a successful signature' {
        Invoke-ClientAuthenticodeSign -SignToolPath Test-SignTool -Path candidate.exe -Thumbprint ('A' * 40) -TimestampUrl http://timestamp.digicert.com
        $script:signCalls | Should Be 1
        Assert-MockCalled Start-Sleep -Times 0 -Exactly -Scope It
    }
    It 'retries transient failures with a finite delay' {
        $script:failures = 2
        Invoke-ClientAuthenticodeSign -SignToolPath Test-SignTool -Path candidate.exe -Thumbprint ('A' * 40) -TimestampUrl http://timestamp.digicert.com
        $script:signCalls | Should Be 3
        Assert-MockCalled Start-Sleep -Times 2 -Exactly -Scope It -ParameterFilter { $Seconds -eq 2 }
    }
    It 'fails closed after three unsuccessful attempts' {
        $script:failures = 100
        { Invoke-ClientAuthenticodeSign -SignToolPath Test-SignTool -Path candidate.exe -Thumbprint ('A' * 40) -TimestampUrl http://timestamp.digicert.com } | Should Throw
        $script:signCalls | Should Be 3
        Assert-MockCalled Start-Sleep -Times 2 -Exactly -Scope It
    }
    It 'does not accept a missing signer with a stale successful exit code' {
        $global:LASTEXITCODE = 0
        { Invoke-ClientAuthenticodeSign -SignToolPath 'RegenBio-Nonexistent-Signer-20260908' -Path candidate.exe -Thumbprint ('A' * 40) -TimestampUrl http://timestamp.digicert.com } | Should Throw
    }
}
