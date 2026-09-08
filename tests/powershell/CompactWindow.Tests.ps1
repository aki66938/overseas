$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Describe 'Compact B native content dimensions' {
    It 'starts with the approved compact client area' {
        $source = Get-Content (Join-Path $repoRoot 'apps/regen_access/windows/runner/main.cpp') -Raw
        $source | Should Match 'Win32Window::Size size\(480, 224\)'
    }
    It 'checks the same dimensions in the owned-window smoke test' {
        $source = Get-Content (Join-Path $repoRoot 'apps/regen_access/windows/runner/tests/smoke-owned-window.ps1') -Raw
        $source | Should Match '\$width - 480'
        $source | Should Match '\$height - 224'
    }
}
