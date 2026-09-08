# Windows pilot refresh — 2026-09-08

Target: 172.20.20.200 only. User approved replacing the app components using the existing PoC signing identity. No OS, DNS, or unrelated software changes.

## Preflight

- SSH 22 works; former debug port 2222 refuses connections.
- Installed registration: 0.1.7; agent running at the owned Program Files path.
- New GUI runs separately from the user's Downloads directory.
- SSH token includes NETWORK; direct named-pipe status reads are denied by the intentional network-token DACL. This is not evidence of a desktop-session ACL failure.
- Existing PoC signing root and corporate proxy root are present. No trust-store changes performed.
- Agent SHA256: F1CB51AEBF0CD2CDB751328F3B2EA1342B4D51343500E9E7B64B08EF06EFADBF.

## Build preparation

- Isolated local clone under workspace outputs/windows-pilot-20260908/source, initially a554dbf. Linux supervisor drafts remain untouched in the development worktree.
- Initial full Windows Go suite passed; ClientInstall Pester 49/49 passed.
- Flutter-generated files had identical Git blob hashes but dirty index state after LF generation. Build-clone-only core.autocrlf=false and scoped index refresh restored a clean tree without source changes.
- SDK 10.0.26100.0 SignTool rejects both https://timestamp.digicert.com and its trailing-slash variant as Invalid Timestamp URL.
- Disposable copied EXE signed successfully using http://timestamp.digicert.com; SignTool verify /pa /tw /v returned 0, zero warnings, and a valid DigiCert RFC3161 timestamp chain.
- Official endpoint reference: https://knowledge.digicert.com/solution/troubleshooting-timestamping-problems . The narrow HTTP exception does not disable TSA signature verification or permit arbitrary cleartext endpoints.

No pilot upgrade has occurred at this checkpoint. Package build, signature/payload validation, upgrade/rollback evidence, and real GUI/connection tests remain pending.

## First pilot attempt and correction

- f3b1074 produced signed 0.1.8 MSI SHA256 90FF3B48DFC63EE4A9054173F8E6213EE4A88C2CA5031284D273411F7D185246. Package trust verifier and SignTool /pa /tw both passed.
- Existing app files and configuration backed up on target under C:\ProgramData\RegenBio\PilotBackup-20260908 with SYSTEM/Administrators-only ACL. Old MSI also retained in the test download directory. No private keys exported.
- Upgrade returned 1603 at BackupUpgradeSnapshot. Windows Installer rolled back; registration remained 0.1.7 and service resumed (PID 5020). No manual file replacement or firewall alteration used.
- Read-only function-level reproduction: ACL and runtime ownership checks passed; firewall failed because InterfaceType was read from Get-NetFirewallInterfaceFilter, whose actual Win10 object contains InterfaceAlias only. Get-NetFirewallInterfaceTypeFilter supplies InterfaceType.
- Corrected test fixtures to mirror the real separate filter objects: RED 0/3 reproduced PropertyNotFoundException. Fix uses the correct cmdlet, rejects missing/ambiguous filters, and retains exact semantic checks.
- Corrected read-only checks on target: acl OK, runtime OK, firewall OK. Full PowerShell suite 198/198; Go installer verifier and contracts passed. Updated candidate will use version 0.1.9 to distinguish it from the failed 0.1.8 artifact.

## Successful 0.1.9 pilot upgrade

- Source f4aec859a3e23ec4618e0525d6424ba784ed735e; MSI SHA256 C5638BC3773D82D2454AE0142883D266563667B073C2B05F885704CCA45752EE. Full signed package inspection: 30 payload files. SignTool /pa /tw and package trust gate passed. Flutter 76/76 passed.
- Target MSI exit 0. Agent Running (PID 10332); installed verification reports version 0.1.9, exact source commit, one registration, expected shared root and service path.
- Installed verifier `payload` exit 0: installed manifest, signatures and payload hashes validated.
- Temporary SYSTEM scheduled task made one read-only APIv1 status request (no connection action). Result: version 1, matching request ID, state idle, quality unknown, generation 1. Task exited 0 and was removed.
- Upgrade snapshot absent, cleanup receipt absent. Protected manual backup remains intentionally for recovery. Do not manually copy it into the live installation.
- Start Menu entry: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\RegenBio Overseas Access.lnk . New GUI: C:\Program Files\RegenBio\OverseasAccess\overseas-client.exe . The earlier Downloads/regen_access.exe is not the installed entry point.
- Real browser connectivity, live probe results, GUI interactions and long-duration stability remain to be tested. Do not infer those from successful installation or the SYSTEM API probe.
