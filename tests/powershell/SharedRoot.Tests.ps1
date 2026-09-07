$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$sourcePath = Join-Path $repoRoot 'cmd/installer-verifier/shared_root.ps1'
function Get-SharedRootFailure { param([scriptblock]$Action); try { & $Action } catch { return $_.Exception.Message }; return '' }
Describe 'Company shared root install-only ownership' {
    BeforeEach {
        if (Test-Path $sourcePath) { . ([scriptblock]::Create(([IO.File]::ReadAllText($sourcePath) -replace '(?m)^Ensure-SharedRoot -CertificatePath.*$', ''))) }
        $certificatePath = Join-Path $repoRoot 'deploy/client/Telecom-GoMITM-Root.cer'
        $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($certificatePath)
    }
    It 'validates an already installed root without importing or removing it' {
        function Get-SharedRoots { return @($certificate) }
        function Add-SharedRoot { throw 'unexpected import' }
        (Get-SharedRootFailure { Ensure-SharedRoot -CertificatePath $certificatePath }) | Should Be ''
    }
    It 'imports only the pinned missing root and verifies publication' {
        $script:sharedRoots = @(); $script:importCount = 0
        function Get-SharedRoots { return $script:sharedRoots }
        function Add-SharedRoot { param($Certificate); $script:sharedRoots = @($Certificate); $script:importCount++ }
        Ensure-SharedRoot -CertificatePath $certificatePath
        $script:importCount | Should Be 1
    }
    It 'rejects wrong certificate bytes and a failed import' {
        function Get-SharedRoots { return @() }
        function Add-SharedRoot { throw 'injected import failure' }
        (Get-SharedRootFailure { Ensure-SharedRoot -CertificatePath (Join-Path $repoRoot 'deploy/client/RegenBio-OverseasAccess-PoC-Root.cer') }) | Should Match 'pinned'
        (Get-SharedRootFailure { Ensure-SharedRoot -CertificatePath $certificatePath }) | Should Match 'injected import failure'
    }
}
