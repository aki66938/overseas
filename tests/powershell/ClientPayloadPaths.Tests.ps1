$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$installerPath = Join-Path $repoRoot 'deploy/client/install-client.ps1'
function Get-PayloadFailure {
    param([scriptblock] $Action)
    try { & $Action } catch { return $_.Exception.Message }
    return ''
}

Describe 'Nested Flutter payload ownership' {
    BeforeEach {
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($installerPath, [ref]$tokens, [ref]$errors)
        foreach ($name in @('Get-CanonicalPath','Resolve-OwnedPayloadPath','Resolve-PayloadPath','Assert-PayloadInventory','Copy-PayloadFile','Remove-OwnedPayloadFiles')) {
            $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
            if ($null -ne $definition) { . ([scriptblock]::Create($definition.Extent.Text)) }
        }
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory((Join-Path $root 'data/flutter_assets/fonts'))
        [IO.File]::WriteAllText((Join-Path $root 'data/flutter_assets/fonts/font.otf'), 'font')
    }

    It 'resolves nested payloads below the owned root' {
        (Resolve-PayloadPath -Root $root -Name 'data/flutter_assets/fonts/font.otf') | Should Be (Join-Path $root 'data\flutter_assets\fonts\font.otf')
    }

    It 'rejects ambiguous and escaping Windows relative names before touching disk' {
        foreach ($name in @('../foreign','data/../foreign','/rooted','C:\rooted','data\\font','data//font','data/font:stream','data/font.','data/font ','data/CON','data/NUL.txt','data/COM1.log','data/./font')) {
            (Get-PayloadFailure { Resolve-OwnedPayloadPath -Root $root -Name $name }) | Should Match 'invalid'
        }
    }

    It 'rejects junctions in any parent of a payload' {
        $outside = Join-Path $TestDrive ('outside-' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($outside)
        [IO.File]::WriteAllText((Join-Path $outside 'foreign.txt'), 'untouched')
        $junction = Join-Path $root 'escape'
        New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
        try {
            (Get-PayloadFailure { Resolve-PayloadPath -Root $root -Name 'escape/foreign.txt' }) | Should Match 'reparse'
        }
        finally { [IO.Directory]::Delete($junction) }
    }

    It 'removes only owned nested files and empty parent directories preserving foreign files' {
        $RootOwnerFileName = '.owner.json'
        function Test-ValidRootMarker { return $true }
        [IO.File]::WriteAllText((Join-Path $root $RootOwnerFileName), '{"OwnedFiles":["data/flutter_assets/fonts/font.otf"]}')
        [IO.File]::WriteAllText((Join-Path $root 'data/foreign.txt'), 'untouched')
        Remove-OwnedPayloadFiles -Root $root
        (Test-Path -LiteralPath (Join-Path $root 'data/flutter_assets')) | Should Be $false
        [IO.File]::ReadAllText((Join-Path $root 'data/foreign.txt')) | Should Be 'untouched'
    }

    It 'requires the base allowlist plus signed manifest Flutter files without Windows duplicates' {
        $RequiredPayloads = @('overseas-client.exe','agent.yaml')
        $manifest = [pscustomobject]@{ files=@(
            [pscustomobject]@{name='overseas-client.exe';destination='program-files'},
            [pscustomobject]@{name='agent.yaml';destination='program-data'},
            [pscustomobject]@{name='flutter_windows.dll';destination='program-files'},
            [pscustomobject]@{name='data/flutter_assets/fonts/font.otf';destination='program-files'}
        ) }
        (Get-PayloadFailure { Assert-PayloadInventory -Manifest $manifest -Root $root }) | Should Be ''
        $manifest.files += [pscustomobject]@{name='FLUTTER_WINDOWS.DLL';destination='program-files'}
        (Get-PayloadFailure { Assert-PayloadInventory -Manifest $manifest -Root $root }) | Should Match 'duplicate'
    }

    It 'rejects unknown payloads or redirected destinations in a manifest' {
        $RequiredPayloads = @('overseas-client.exe')
        foreach ($extra in @(@{name='foreign.exe';destination='program-files'},@{name='data/icudtl.dat';destination='program-data'})) {
            $manifest = [pscustomobject]@{files=@([pscustomobject]@{name='overseas-client.exe';destination='program-files'},[pscustomobject]$extra)}
            (Get-PayloadFailure { Assert-PayloadInventory -Manifest $manifest -Root $root }) | Should Match 'allowlist|destination'
        }
    }

    It 'copies a nested file into protected owned ancestry and verifies its hash' {
        $InstallRoot = $root
        $DataRoot = Join-Path $TestDrive 'program-data'
        $source = Join-Path $root 'data/flutter_assets/fonts/font.otf'
        $destination = Join-Path $root 'data/flutter_assets/new/font.otf'
        Copy-PayloadFile -Source $source -Destination $destination -ExpectedHash (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        [IO.File]::ReadAllText($destination) | Should Be 'font'
    }
}
