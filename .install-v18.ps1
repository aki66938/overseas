$msi = 'C:\Users\Eleme\codex_workspace\overseas-access-gateway\.worktrees\windows-forwarding-poc\dist\OverseasAccessSetup-v18-RELEASE_SIGNED.msi'
$log = 'C:\Users\Eleme\codex_workspace\overseas-access-gateway\.worktrees\windows-forwarding-poc\build\v18-install.log'
$p = Start-Process -FilePath msiexec.exe -ArgumentList @('/i', $msi, '/qn', '/l*v', $log) -Wait -PassThru
Write-Output ("msiexec exit: " + $p.ExitCode)
