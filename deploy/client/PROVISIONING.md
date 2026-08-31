# Direct HTTP TUN PoC acceptance

This build does not require or accept a tunnel credential. Its signed schema-2
policy sends the TUN's overseas TCP traffic to the approved telecom HTTP
CONNECT endpoint `172.20.9.15:8080`.

Installation must leave `RegenBioOverseasAccessAgent` stopped. It must not
change Windows system proxy, WinHTTP proxy, or FlClash state. Verify from an
elevated PowerShell prompt:

```powershell
Get-Service RegenBioOverseasAccessAgent
Get-NetAdapter -InterfaceAlias RegenBioOverseasAccess -IncludeHidden -ErrorAction SilentlyContinue
Get-NetRoute -ErrorAction Stop | Where-Object InterfaceAlias -eq RegenBioOverseasAccess
```

The service must report `Stopped`; the adapter and route commands must return
nothing before the live test.

## User-owned live test

Codex prepares and installs the build but does not close FlClash or start the
TUN. The user performs these steps:

1. Open an elevated PowerShell prompt and run the provided recovery command.
2. Close FlClash and confirm its system/TUN proxy is inactive.
3. Start the RegenBio client from the Start menu and click Connect once.
4. Test approved overseas sites from applications with no application proxy.
5. Click Disconnect and confirm the client reports Disconnected.
6. Restart FlClash only after the RegenBio client is disconnected.

If connectivity is lost, wait for the recovery command to stop the RegenBio
service and restore the captured network state. The recovery script must not
start, stop, or reconfigure FlClash.
