[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('ManifestNativeMethods' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class ManifestNativeMethods
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr FindResource(IntPtr hModule, IntPtr lpName, IntPtr lpType);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr FindResource(IntPtr hModule, string lpName, IntPtr lpType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LockResource(IntPtr hResData);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);
}
'@
}

$resolved = Resolve-Path -LiteralPath $Path
$module = [ManifestNativeMethods]::LoadLibraryEx($resolved.Path, [IntPtr]::Zero, 0x00000002)
if ($module -eq [IntPtr]::Zero) {
    throw "LoadLibraryEx failed for '$($resolved.Path)'. Win32=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

try {
    $resourceInfo = [ManifestNativeMethods]::FindResource($module, '#1', [IntPtr] 24)
    if ($resourceInfo -eq [IntPtr]::Zero) {
        throw "RT_MANIFEST resource #1 not found in '$($resolved.Path)'."
    }

    $size = [ManifestNativeMethods]::SizeofResource($module, $resourceInfo)
    if ($size -le 0) {
        throw "RT_MANIFEST resource #1 in '$($resolved.Path)' has invalid size $size."
    }

    $resourceHandle = [ManifestNativeMethods]::LoadResource($module, $resourceInfo)
    if ($resourceHandle -eq [IntPtr]::Zero) {
        throw "LoadResource failed for '$($resolved.Path)'. Win32=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    $resourcePointer = [ManifestNativeMethods]::LockResource($resourceHandle)
    if ($resourcePointer -eq [IntPtr]::Zero) {
        throw "LockResource failed for '$($resolved.Path)'."
    }

    $bytes = New-Object byte[] $size
    [Runtime.InteropServices.Marshal]::Copy($resourcePointer, $bytes, 0, $size)
    $manifestText = [System.Text.Encoding]::UTF8.GetString($bytes).Trim([char] 0, [char] 0xFEFF)
    [xml] $manifest = $manifestText

    $ns = New-Object System.Xml.XmlNamespaceManager($manifest.NameTable)
    $ns.AddNamespace('asmv1', 'urn:schemas-microsoft-com:asm.v1')
    $ns.AddNamespace('asmv3', 'urn:schemas-microsoft-com:asm.v3')

    $commonControls = $manifest.SelectSingleNode('//asmv1:dependency/asmv1:dependentAssembly/asmv1:assemblyIdentity[@name="Microsoft.Windows.Common-Controls"]', $ns)
    if ($null -eq $commonControls) {
        throw "Common Controls dependency missing from RT_MANIFEST resource #1."
    }

    if ($commonControls.GetAttribute('type') -ne 'win32' -or
        $commonControls.GetAttribute('version') -ne '6.0.0.0' -or
        $commonControls.GetAttribute('processorArchitecture') -ne '*' -or
        $commonControls.GetAttribute('publicKeyToken') -ne '6595b64144ccf1df' -or
        $commonControls.GetAttribute('language') -ne '*') {
        throw "Common Controls dependency attributes do not match the expected v6 declaration."
    }

    $executionLevel = $manifest.SelectSingleNode('//asmv3:requestedExecutionLevel', $ns)
    if ($null -eq $executionLevel -or $executionLevel.GetAttribute('level') -ne 'asInvoker') {
        throw "requestedExecutionLevel=asInvoker missing from RT_MANIFEST resource #1."
    }

    Write-Output 'MANIFEST_OK: Microsoft.Windows.Common-Controls 6.0.0.0 embedded'
}
finally {
    [void] [ManifestNativeMethods]::FreeLibrary($module)
}
