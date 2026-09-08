param([Parameter(Mandatory=$true)][string]$Executable, [int]$ExistingOwnedPid = 0)
$ErrorActionPreference = 'Stop'
$appPath = (Resolve-Path -LiteralPath $Executable).Path
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RegenOwnedWindow {
  public delegate bool EnumProc(IntPtr window, IntPtr data);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc callback, IntPtr data);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr window);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr window);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr window, uint message, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr window, int state);
  [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr window);
  [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr window, int index);
  [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr window, out Rect rect);
  [StructLayout(LayoutKind.Sequential)] public struct TitlebarInfo {
    public uint Size; public Rect Bounds;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst=6)] public uint[] State;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst=6)] public Rect[] Buttons;
  }
  [DllImport("user32.dll", EntryPoint="SendMessageW")] public static extern IntPtr Titlebar(IntPtr w, uint m, IntPtr p, ref TitlebarInfo info);
  [DllImport("user32.dll", EntryPoint="SendMessageW")] public static extern IntPtr Send(IntPtr w, uint m, IntPtr p, IntPtr l);
  [StructLayout(LayoutKind.Sequential)] public struct Point { public int X, Y; }
  [DllImport("user32.dll")] public static extern bool ScreenToClient(IntPtr window, ref Point point);
  public static TitlebarInfo Caption(IntPtr w) {
    var info = new TitlebarInfo { Size = (uint)Marshal.SizeOf(typeof(TitlebarInfo)), State = new uint[6], Buttons = new Rect[6] };
    Titlebar(w, 0x33f, IntPtr.Zero, ref info); return info;
  }
  public static void ClickCaption(IntPtr w, int index) {
    var rect = Caption(w).Buttons[index];
    var point = new Point { X = (rect.Left + rect.Right) / 2, Y = (rect.Top + rect.Bottom) / 2 };
    var screen = new IntPtr((point.X & 0xffff) | (point.Y << 16));
    var expected = index == 5 ? 20 : 8;
    if (Send(w, 0x84, IntPtr.Zero, screen).ToInt32() != expected) throw new Exception("Caption hit region mismatch");
    Send(w, 0xa1, new IntPtr(expected), screen);
    ScreenToClient(w, ref point);
    Send(w, 0x202, IntPtr.Zero, new IntPtr((point.X & 0xffff) | (point.Y << 16)));
  }
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr window, System.Text.StringBuilder name, int count);
  public static IntPtr Find(uint ownedPid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((w, _) => { uint p; GetWindowThreadProcessId(w, out p); var name = new System.Text.StringBuilder(256); GetClassName(w, name, 256); if (p == ownedPid && name.ToString() == "RegenBioOverseasAccessFlutterWindow") { found = w; return false; } return true; }, IntPtr.Zero);
    return found;
  }
}
'@
# Run only the owned release executable. No connect/disconnect/menu action is sent.
if ($ExistingOwnedPid) {
  $owned = Get-Process -Id $ExistingOwnedPid
  if ($owned.Path -ne $appPath) { throw 'Owned PID does not match the exact test executable' }
} else {
  $owned = Start-Process -FilePath $appPath -WorkingDirectory (Split-Path $appPath) -PassThru -WindowStyle Hidden
}
try {
  $window = [IntPtr]::Zero
  for ($attempt = 0; $attempt -lt 100 -and $window -eq [IntPtr]::Zero; $attempt++) {
    Start-Sleep -Milliseconds 100
    $window = [RegenOwnedWindow]::Find($owned.Id)
  }
  if ($window -eq [IntPtr]::Zero) { throw 'Owned GUI failed to show (or another instance already exists).' }
  # STARTUPINFO SW_HIDE overrides the application's first ShowWindow call.
  [void][RegenOwnedWindow]::ShowWindow($window, 5)
  Start-Sleep -Milliseconds 500
  $dpi = [RegenOwnedWindow]::GetDpiForWindow($window)
  $rect = New-Object RegenOwnedWindow+Rect
  [void][RegenOwnedWindow]::GetClientRect($window, [ref]$rect)
  $width = ($rect.Right - $rect.Left) * 96 / $dpi
  $height = ($rect.Bottom - $rect.Top) * 96 / $dpi
  if ([Math]::Abs($width - 480) -gt 1 -or [Math]::Abs($height - 224) -gt 1) { throw "Unexpected logical client dimensions $width x $height" }
  $style = [RegenOwnedWindow]::GetWindowLong($window, -16)
  $caption = [RegenOwnedWindow]::Caption($window)
  Write-Output "Native caption states: min=$($caption.State[2]), max=$($caption.State[3]), close=$($caption.State[5]); maximize bounds=$($caption.Buttons[3].Left),$($caption.Buttons[3].Right)"
  if (($caption.State[3] -band 0x8000) -eq 0 -or $caption.Buttons[3].Right -ne $caption.Buttons[3].Left) { throw 'Maximize caption slot remains visible' }
  if ($caption.State[2] -ne 0 -or $caption.State[5] -ne 0) { throw 'Minimize or close unavailable' }
  if (($style -band 0x00010000) -ne 0 -or ($style -band 0x00040000) -ne 0) { throw 'Maximize or resize style enabled' }
  [RegenOwnedWindow]::ClickCaption($window, 5)
  Start-Sleep -Milliseconds 200
  if ([RegenOwnedWindow]::IsWindowVisible($window)) { throw 'Close did not hide' }
  $second = Start-Process -FilePath $appPath -WorkingDirectory (Split-Path $appPath) -PassThru -WindowStyle Hidden
  if (!$second.WaitForExit(5000) -or $second.ExitCode -ne 0) { throw 'Duplicate instance failed to hand off' }
  Start-Sleep -Milliseconds 200
  if (![RegenOwnedWindow]::IsWindowVisible($window)) { throw 'Duplicate launch did not restore existing window' }
  [RegenOwnedWindow]::ClickCaption($window, 2)
  Start-Sleep -Milliseconds 200
  if (![RegenOwnedWindow]::IsIconic($window)) { throw 'Minimize did not enter iconic state' }
  # Synthetic single tray select; does not touch Explorer or its processes.
  [void][RegenOwnedWindow]::PostMessage($window, 0x8020, [IntPtr]::Zero, [IntPtr]0x400)
  Start-Sleep -Milliseconds 200
  if ([RegenOwnedWindow]::IsIconic($window)) { throw 'Single tray select did not restore' }
  Write-Output "PASS: owned release client $width x $height logical at DPI $dpi; no maximize slot; caption close/hide; duplicate activation; caption minimize; single select restore."
} finally {
  if ($window -ne [IntPtr]::Zero -and !$owned.HasExited) {
    [void][RegenOwnedWindow]::PostMessage($window, 0x8021, [IntPtr]::Zero, [IntPtr]::Zero)
    if (!$owned.WaitForExit(5000)) { throw 'Owned GUI did not exit within 5 seconds' }
    Write-Output 'PASS: GUI exit and process shutdown; no lifecycle command sent.'
  }
}
