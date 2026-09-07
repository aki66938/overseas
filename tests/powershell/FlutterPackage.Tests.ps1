$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$toolsPath = Join-Path $repoRoot 'scripts/windows/client-payload-tools.ps1'
function Get-FlutterFailure { param([scriptblock]$Action); try { & $Action } catch { return $_.Exception.Message }; return '' }
Describe 'Flutter Windows package inventory' {
    BeforeEach {
        if (Test-Path -LiteralPath $toolsPath) { . $toolsPath }
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory((Join-Path $root 'data/flutter_assets/fonts'))
        foreach ($name in @('regen_access.exe','flutter_windows.dll','native_assets.json','data/app.so','data/icudtl.dat','data/flutter_assets/fonts/font.otf')) {
            [IO.File]::WriteAllText((Join-Path $root $name), $name)
        }
    }
    It 'inventories every Flutter file with a canonical relative name' {
        $inventory = @(Get-FlutterPayloadInventory -Root $root)
        $inventory.Count | Should Be 6
        @($inventory | Where-Object { $_.Name -ceq 'data/flutter_assets/fonts/font.otf' }).Count | Should Be 1
    }
    It 'rejects foreign executables and runtime junctions' {
        [IO.File]::WriteAllText((Join-Path $root 'foreign.exe'), 'foreign')
        (Get-FlutterFailure { Get-FlutterPayloadInventory -Root $root }) | Should Match 'allowlist'
        [IO.File]::Delete((Join-Path $root 'foreign.exe'))
        $junction = Join-Path $root 'data/escape'
        New-Item -ItemType Junction -Path $junction -Target $TestDrive | Out-Null
        try { (Get-FlutterFailure { Get-FlutterPayloadInventory -Root $root }) | Should Match 'reparse' }
        finally { [IO.Directory]::Delete($junction) }
    }
    It 'emits stable one-file components with exact nested destinations' {
        $inventory = @(Get-FlutterPayloadInventory -Root $root)
        $output = Join-Path $TestDrive 'FlutterFiles.wxs'
        Write-FlutterWixFragment -Inventory $inventory -Path $output
        [xml]$xml = [IO.File]::ReadAllText($output)
        $files = @($xml.SelectNodes('//*[local-name()="File"]'))
        $files.Count | Should Be 5
        @($files | Where-Object { $_.Source -eq 'data/flutter_assets/fonts/font.otf' }).Count | Should Be 1
        @($files | Where-Object { $_.Source -eq 'regen_access.exe' }).Count | Should Be 0
        $first = [IO.File]::ReadAllText($output)
        Write-FlutterWixFragment -Inventory $inventory -Path $output
        [IO.File]::ReadAllText($output) | Should Be $first
    }
    It 'builds Flutter with the authoritative package version and uses its payload in MSI recipes' {
        $builder = Get-Content (Join-Path $repoRoot 'scripts/windows/build-client-artifacts.ps1') -Raw
        $publisher = Get-Content (Join-Path $repoRoot 'scripts/windows/publish-client-release.ps1') -Raw
        $builder | Should Match 'FlutterRuntimeDirectory'
        $builder | Should Match 'Get-FlutterPayloadInventory'
        $publisher | Should Match 'flutter.*build|flutterExecutable'
        $publisher | Should Match '--build-name'
        $publisher | Should Not Match "'\./cmd/overseas-client'"
    }
}
