# Pure inventory and WiX authoring helpers. No installation or trust-store work.
function Assert-ClientTimestampUrl {
    param([string]$Url)
    # SignTool rejects HTTPS with the pinned SDK. DigiCert documents this
    # RFC3161 HTTP endpoint; authenticity comes from the signed TSA response.
    # Do not generalize this exception to arbitrary cleartext servers.
    if ($Url -cne 'http://timestamp.digicert.com' -and $Url -notmatch '\Ahttps://[^\s]+\z') {
        throw 'Release requires HTTPS or the fixed DigiCert RFC3161 endpoint.'
    }
}

function Resolve-MsiPayloadDestination {
    param([string]$DirectoryId,[string]$FileName,[hashtable]$Directories)
    $parts = @($FileName.Split('|')[-1]); $seen = @{}
    while ($DirectoryId -notin @('INSTALLFOLDER','DATAFOLDER')) {
        if (-not $Directories.ContainsKey($DirectoryId) -or $seen.ContainsKey($DirectoryId)) { throw 'Invalid MSI payload directory ancestry.' }
        $seen[$DirectoryId]=$true
        $row=$Directories[$DirectoryId]
        $segment=([string]$row[2]).Split(':')[0].Split('|')[-1]
        if ($segment -ne '.') { $parts=@($segment)+$parts }
        $DirectoryId=[string]$row[1]
    }
    foreach ($segment in $parts) {
        if ($segment -cnotmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]*$' -or $segment.Contains('..') -or $segment.EndsWith('.') -or $segment -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') { throw 'Invalid MSI payload directory name.' }
    }
    return [pscustomobject]@{name=($parts -join '/');destination=$(if ($DirectoryId -eq 'INSTALLFOLDER') {'program-files'} else {'program-data'})}
}

function Get-ClientWorkspace {
    param([string]$Repository)
    $candidate = [IO.Path]::GetFullPath($Repository)
    while ($candidate) {
        if (Test-Path -LiteralPath (Join-Path $candidate '.tools') -PathType Container) { return $candidate }
        $candidate = Split-Path -Parent $candidate
    }
    throw 'Locked workspace tool directory was not found.'
}

function Get-FlutterPayloadId {
    param([string]$Name)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return 'Flutter_' + ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Name.ToLowerInvariant())))).Replace('-', '').Substring(0, 24) }
    finally { $hash.Dispose() }
}

function Invoke-LockedFlutterBuild {
    param([string]$Repository, [version]$ProductVersion)
    $workspace = Get-ClientWorkspace -Repository $Repository
    $toolchain = Get-Content -LiteralPath (Join-Path $Repository 'deploy/toolchains.json') -Raw | ConvertFrom-Json
    $flutterExecutable = Join-Path $workspace ('.tools/flutter-' + $toolchain.flutter.version + '/bin/flutter.bat')
    $version = (& $flutterExecutable --version --machine | Out-String) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $version.frameworkVersion -ne $toolchain.flutter.version -or
        $version.frameworkRevision -ne $toolchain.flutter.commit -or $version.engineRevision -ne $toolchain.flutter.engine_commit -or
        $version.dartSdkVersion -notlike ($toolchain.flutter.dart_version + '*')) { throw 'Flutter toolchain differs from deploy/toolchains.json.' }
    Push-Location (Join-Path $Repository 'apps/regen_access')
    try {
        & $flutterExecutable pub get --enforce-lockfile
        if ($LASTEXITCODE -ne 0) { throw 'Locked Flutter dependency resolution failed.' }
        & $flutterExecutable build windows --release --no-pub --build-name $ProductVersion.ToString() --build-number 0
        if ($LASTEXITCODE -ne 0) { throw 'Flutter Windows release build failed.' }
    }
    finally { Pop-Location }
    return (Join-Path $Repository 'apps/regen_access/build/windows/x64/runner/Release')
}

function Get-FlutterPayloadInventory {
    param([Parameter(Mandatory = $true)][string]$Root)
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $current = $rootPath
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Flutter root crosses a reparse point.' }
        $current = Split-Path -Parent $current
    }
    $pending = New-Object 'Collections.Generic.Stack[string]'
    $pending.Push($rootPath)
    $files = @(); $names = @{}
    while ($pending.Count) {
        foreach ($item in @(Get-ChildItem -LiteralPath $pending.Pop() -Force)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Flutter payload contains a reparse point.' }
            $name = $item.FullName.Substring($rootPath.Length + 1).Replace('\', '/')
            if ($name -cnotmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$') { throw 'Invalid Flutter payload name.' }
            foreach ($segment in @($name -split '/')) {
                if ($segment.EndsWith('.') -or $segment.Contains('..') -or $segment -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') { throw 'Invalid Flutter payload name.' }
            }
            if ($item.PSIsContainer) { $pending.Push($item.FullName); continue }
            if ($names.ContainsKey($name)) { throw 'Duplicate Windows Flutter payload name.' }
            $names[$name] = $true
            if ($name -cnotmatch '^(regen_access\.exe|flutter_windows\.dll|[A-Za-z0-9_]+_plugin\.dll|native_assets\.json|data/(app\.so|icudtl\.dat|flutter_assets/.+))$') { throw "Flutter payload '$name' is outside the allowlist." }
            $files += [pscustomobject]@{ Name=$name; FullName=$item.FullName; Id=(Get-FlutterPayloadId $name) }
        }
    }
    foreach ($required in @('regen_access.exe','flutter_windows.dll','data/app.so','data/icudtl.dat')) {
        if (-not $names.ContainsKey($required)) { throw "Flutter payload '$required' is missing." }
    }
    return @($files | Sort-Object Name)
}

function Write-FlutterWixFragment {
    param([Parameter(Mandatory = $true)][object[]]$Inventory, [Parameter(Mandatory = $true)][string]$Path)
    $directories = @{ ''='INSTALLFOLDER' }
    $lines = New-Object 'Collections.Generic.List[string]'
    $lines.Add('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Fragment>')
    foreach ($file in @($Inventory | Where-Object { $_.Name -cne 'regen_access.exe' } | Sort-Object Name)) {
        $parts = $file.Name -split '/'; $parent = ''
        for ($index=0; $index -lt $parts.Length-1; $index++) {
            $directory = ($parts[0..$index] -join '/')
            if (-not $directories.ContainsKey($directory)) {
                $id = Get-FlutterPayloadId ('directory/' + $directory)
                $lines.Add('<DirectoryRef Id="' + $directories[$parent] + '"><Directory Id="' + $id + '" Name="' + $parts[$index] + '" /></DirectoryRef>')
                $directories[$directory] = $id
            }
            $parent = $directory
        }
    }
    $lines.Add('<ComponentGroup Id="FlutterFiles">')
    foreach ($file in @($Inventory | Where-Object { $_.Name -cne 'regen_access.exe' } | Sort-Object Name)) {
        $parent = if ($file.Name.Contains('/')) { $file.Name.Substring(0,$file.Name.LastIndexOf('/')) } else { '' }
        $id = Get-FlutterPayloadId $file.Name
        $lines.Add('<Component Id="' + $id + 'Component" Directory="' + $directories[$parent] + '" Guid="*" Bitness="always64"><File Id="' + $id + '" Source="' + $file.Name + '" KeyPath="yes" Checksum="yes" /></Component>')
    }
    $lines.Add('</ComponentGroup></Fragment></Wix>')
    [IO.File]::WriteAllLines($Path, $lines, (New-Object Text.UTF8Encoding($false)))
}
