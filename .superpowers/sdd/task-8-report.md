# Task 8 Report — Transactional Client Install and MSI

> Second re-review update: commits `ecd68b80980a2018f58798602cd33d9e28824860` and `3367ec61c541b316bfa290826c157aace624a07f` close runtime residue, CustomActionData, firewall sequencing, trust-envelope coverage, enforced tool locks, corrected Wintun license metadata, and atomic release publication.

- Final full Pester: `99 passed, 0 failed` in Windows PowerShell 5.1 and PowerShell 7.
- Final `go test -count=1 ./...` and `go vet ./...`: passed.
- Final inspect-only MSI: `dist/OverseasAccessSetup-review2.msi`, SHA-256 `DCB2C66C6C811A7BC45BFCD79BFBFB739D4E7B9C57AF53F6C33045B3B4CC946B`, source commit `3367ec61c541b316bfa290826c157aace624a07f`.
- Signed-envelope coverage: 16 hashed non-root payloads plus the explicit `artifact-manifest.json` / `artifact-manifest.json.p7s` trust-root pair equals all 18 MSI payloads exactly.
- Raw order: `VerifyInstalledPayload=5797`, `RollbackClientFirewall=5798`, `InstallClientFirewall=5799`, `InstallServices=5800`; cleanup is `1901`, after `StopServices=1900`.
- Deferred verifier target is exactly `[CustomActionData]`; type-51 `SetVerifyInstalledPayload` carries the validated fixed arguments.
- Atomic release refusal test with no signer: exit `1`, final artifact absent, temporary release directory count `0`.
- Corporate-signed production release and disposable-host lifecycle validation remain external release blockers.

---

> Review remediation update (2026-08-29): this section supersedes the original implementation evidence retained below.

Final HEAD: `6c333f961562c9a70b213be6392e749b508f7559`  
Remediation commits: `f2b7bdf`, `032c295`, `6c333f9`

## Review remediation outcome

The review findings were remediated with fail-closed package and payload trust gates, controlled upgrade disconnect, exact resource ownership, resumable lifecycle journals, a stdin-only machine credential provisioner, separate official Wintun attribution, and a locked artifact/SBOM/checksum pipeline. No installer lifecycle action was executed on the live workstation.

The default artifact is deliberately inspect-only: its embedded corporate thumbprint is all zeroes, its manifest signature is `INSPECT-ONLY-NOT-SIGNED`, the MSI is unsigned, and the embedded verifier rejects it before `InstallInitialize`. A release requires an out-of-repository corporate certificate with a private key; no private key was generated or committed.

### Final verification

- Windows PowerShell 5.1 full Pester: `96 passed, 0 failed`.
- PowerShell 7 full Pester: `96 passed, 0 failed`.
- Focused client installer Pester: `28 passed, 0 failed` in each runtime.
- `go test -count=1 ./...`: all packages passed.
- `go vet ./...`: exit 0.
- Windows amd64 agent, UI, credential provisioner, and installer verifier builds: exit 0.
- Inspect-only package verifier: generic refusal, exit `1`.
- Release build without signing input: exit `1`; requested output remained absent.

### Final MSI evidence

- Path: `dist/OverseasAccessSetup.msi`
- SHA-256: `8694415097B23181DEE3049F22D56013EECEB222AC5547DF5255480A80B6837B`
- Artifact source commit: `6c333f961562c9a70b213be6392e749b508f7559`
- Extracted allowlist: exactly `18` payloads; all bytes matched staging.
- Signature status: `NotSigned`, required for inspect-only mode.
- Ordering: `VerifyPackageTrust=1499`, `InstallInitialize=1500`, `RemoveExistingProducts=1501`, `MsiSafeRemove=1899`, `StopServices=1900`, `InstallFiles=4000`, `VerifyInstalledPayload=5799`, `InstallServices=5800`.
- `MsiSafeRemove` condition is exactly `REMOVE~="ALL"`; package gate covers install, repair, and upgrade.
- `InstallerVerifierBinary` is present; service-control event is `162` (no automatic install-time start).

The inspector decompiled/extracted the MSI, compared every allowlisted payload byte, validated required hashes/signatures, recursively secret-scanned the extraction, inspected raw tables/ACLs, and tied release-mode MSI/CMS/payload signatures to one embedded corporate thumbprint. WiX emitted expected extension-table and ACL decompile reconstruction warnings; direct raw-table reads proved those rows.

### Remaining release blockers

1. No corporate signing certificate was available. A production release artifact cannot be produced or verified; the inspect-only MSI intentionally refuses installation.
2. No privileged live install/repair/upgrade/uninstall was run. These destructive lifecycle tests remain required on a disposable Windows integration host with a corporate-signed artifact.
3. `go generate ./cmd/overseas-client` attempted a Go-proxy lookup for the pinned `rsrc` generator and timed out. The existing generated resource was present and all Windows binaries built; the release environment should pre-seed or vendor the generator for offline regeneration.
4. GNU Make was unavailable. Equivalent tracked commands used the hash-verified local WiX 4.0.6 restore without global changes.

---

## Original implementation report (pre-review)

Date: 2026-08-29  
Base: `a061e75`  
Implementation commit: `64be410`

## Outcome

Implemented the Windows development lifecycle harness and a WiX v4 per-machine x64 MSI for the RegenBio overseas-access client. No installer or MSI was executed against the live workstation; validation was limited to static tests, `-WhatIf`, package build/decompile/extraction, signature/hash checks, and raw MSI database inspection.

The harness provides `Install`, `Repair`, `Uninstall`, and `Status`, performs an elevation gate, authenticates a code-pinned detached-CMS payload manifest, hashes every allowlisted payload, validates Authenticode/CMS signatures before persistent mutation, rejects downgrade, writes restrictive ACLs, configures delayed automatic service startup/recovery, creates only exact firewall/shortcut resources, journals transactions, and refuses uninstall success unless the agent completes controlled disconnect and network-restoration proof.

The MSI uses native WiX files, service, service-control, ACL, shortcut, firewall, and upgrade mechanisms. Its only deferred no-impersonate custom action is a checked pre-remove restoration gate immediately before `StopServices`.

## TDD evidence

- Initial RED: focused Pester failed before installer/WiX sources existed (13+ failures).
- Security RED: added checks for a signed manifest trust anchor, rollback order, and the deferred MSI uninstall gate; observed 4 focused failures before implementation.
- TOCTOU RED: required signature verification and JSON parsing to use the same manifest byte snapshot; observed 1 focused failure before replacing the second file read.
- Final GREEN, Windows PowerShell 5.1: `16 passed, 0 failed`.
- Final GREEN, PowerShell 7.6: `16 passed, 0 failed`.
- Full PowerShell suite: `84 passed, 0 failed`.
- `go test ./...`: passed all packages.
- `go vet ./...`: exit 0, no findings.
- Windows agent/UI builds and the native probe build completed successfully with portable Go 1.27.0.

## Package/toolchain evidence

GNU Make was not available, so the exact Makefile target commands were executed directly. WiX was restored locally under `C:\Users\Eleme\codex_workspace\.tools\wix4.0.6`; no global install or destructive global change was made.

- WiX: `4.0.6+73c89738`
- `WixToolset.Sdk.4.0.6.nupkg`: `029C37C6490A810F61BCD375DD661ACE04C328640A9DADAEF1E7149BC14FF0F6`
- `WixToolset.Util.wixext.4.0.6.nupkg`: `541168D58C299DD8D62E92EA1877489756CFA73A27FD6EC855CD6341C8447562`
- `WixToolset.Firewall.wixext.4.0.6.nupkg`: `1A852369FB9C5EA9AA83D29AC40C9BF4D2564B5E516955E28643D6471DE56239`
- Official Wintun 0.14.1 archive: `07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51`
- Wintun DLL Authenticode: Valid; signer thumbprint `DF98E075A012ED8C86FBCF14854B8F9555CB3D45`
- Pinned sing-box 1.13.19 archive: `E011A4DEF2F5E2B143ED54ADB2B1A20A6BE407806AB4442F3667F1DD817A2C8D`
- Final inspected MSI: `dist/OverseasAccessSetup-final.msi`
- Final inspected MSI SHA-256: `AF434D248765A3C4D1871D4233B8927543241E14C18E9DFCAB2F0BF2302D0544`

## MSI inspection

The MSI built successfully, decompiled, and extracted. Extracted payload hashes exactly matched staging. The file-table payload allowlist was exactly:

`AgentExe, AgentPolicy, AgentPolicySignature, ClientExe, CoreManifest, CronetRuntime, InstallerHarnessFile, SingBoxExe, ThirdPartyLicense, TunDriver`

No credential-bearing filename, private-key marker, `.pfx`, `.pem`, or `.key` was present. The embedded policy CMS signature verified to pinned thumbprint `4E51A35F5C3C16B483663E3D48D22219DAD986B3`.

Raw MSI tables confirmed:

- Program Files SDDL: `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)`
- ProgramData SDDL: `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`
- `InstallInitialize=1500`, `RemoveExistingProducts=1501`
- `MsiSafeRemove=1899`, immediately before `StopServices=1900`
- deferred custom action type `3073` (deferred, no impersonation, checked return)
- native service install/control, delayed-autostart registry value, recovery config, upgrade detection, and downgrade detection rows

WiX decompilation emitted expected warnings for extension-owned custom tables and an `MsiLockPermissionsEx` foreign-key reconstruction limitation. Direct raw-table reads proved both ACL rows and their correct directory identifiers, so these warnings do not indicate missing MSI rows.

## Release gates / concerns

1. The MSI is intentionally **unsigned** because no RegenBio corporate code-signing key was available. `Get-AuthenticodeSignature` reports `NotSigned`. It must not be distributed or installed until the release pipeline signs it and verifies the resulting signature. This is also necessary to give the MSI container itself a production trust boundary.
2. The committed policy signature and code-pinned certificate are PoC artifacts. The ephemeral private key was not persisted or committed. Production must replace the trust anchor and re-sign policy/payload manifests using the controlled corporate signer.
3. WiX v4.0.6 does not produce byte-identical MSI files from identical inputs because it regenerates PackageCode and summary timestamps. Inputs, source GUIDs, versions, dependencies, and payload hashes are pinned, but bit-for-bit MSI reproducibility is an upstream WiX limitation.
4. No privileged live install/uninstall was run. A disposable Windows integration host must validate SCM recovery behavior, ActiveStore firewall behavior, TUN/route/DNS restoration, upgrade, repair, rollback under injected failure, and uninstall refusal before production use.
5. The checked-in Makefile uses version-pinned WiX extension references but assumes `wix` and GNU Make are supplied by the build environment. This workstation used the verified local WiX restore and direct equivalent commands.

---

## Third-wave transaction hardening (2026-08-29)

Base: `3367ec61c541b316bfa290826c157aace624a07f`  
Implementation commits: `492e0ca7046922a63ade570e8132ac68303b8211`, `f8f54b839f67f196a1d8d0e4318f3c2b0a0049e0`

### Outcome

The third-wave review requirements are implemented without privileged live mutation:

- MSI firewall install, rollback, and uninstall are distinct raw custom actions. An ACL-protected write-ahead journal records exact definitions and `intended`, `created`, or proven-product-owned `preexisting` dispositions. Exact matching covers application/package, protocol, local/remote ports, local/remote addresses, service, interface type/alias, direction, action, profile, enablement, group, display name, and unique name. Rollback removes only names durably proven absent-before/current-created even if their definition later drifts; uninstall removes only exact product-owned rules.
- Runtime ownership schema v2 contains structured intents with target, temporary, backup, replaced, and phase fields. All possible sensitive paths are durable before bytes are written. Publication uses same-directory atomic replacement, preserves intents through transient wipe, compensates/restores on failure, and serializes credential/config transactions with one global Windows mutex held on a locked OS thread. Cleanup validates and securely removes canonical and every recorded transient path before deleting the ledger; ledger absence succeeds only when both canonical sensitive files are absent.
- Root deletion retains the ownership marker and journal while foreign content exists. After marker removal, `RootDeletionIncomplete` retains the exact pending root until absence is proven, so a later uninstall can resume safely.
- Go 1.27.0, WiX 4.0.6, Util/Firewall extensions, and DTF paths/hashes are bound by `build-lock.json`. Make invokes Go/WiX only through the verified wrapper; the wrapper owns extension arguments; the inspector independently resolves and hashes WiX/DTF. The publisher uses `git -C $repo`, rebuilds all four first-party binaries into its temporary release tree with the verified Go executable, and signs only those outputs.
- Artifact/release parent creation validates every segment under the repository and rejects reparse points/non-directories before creation or replacement. Final directory/MSI publication is a same-volume atomic move after a clean-checkout proof.
- All Wintun GPL claims were removed. Attribution is only `Wintun Prebuilt Binaries License`.

### TDD and failure-injection evidence

- Initial RED: runtime-owner tests did not compile because structured intent/publication APIs were absent; focused client Pester had seven failures covering the six outstanding groups.
- Reviewer RED: a persistent post-publish secure-compensation failure lost ownership proof before correction.
- Behavioral firewall test executes the extracted production lifecycle script against isolated mocked state: foreign exact pre-existing rejection, fresh install, idempotent repair, repair rollback preservation, uninstall, injected second-rule creation failure, and compensating rollback. It performs no live firewall call.
- Runtime tests inject writer, finalization, canonical wipe, and backup wipe failures. Windows subprocess tests terminate at temporary-written, published, and finalized boundaries and prove every surviving pathname is present in the structured intent.
- Follow-up review found that DPAPI's legacy atomic helper nested another `.credential-*.tmp` under the journaled publisher path. The provisioner now uses `StoreMachineExact`, which applies the protected ACL and `CREATE_NEW` directly to the already-journaled pathname. A subprocess exits immediately after DPAPI ciphertext flush and proves that this exact journaled path is the only residue.
- Firewall exactness also validates `Get-NetFirewallSecurityFilter` defaults: authentication, encryption, local/remote user, remote machine, and override-block state. The behavioral lifecycle test mutates authentication to `Required` and proves uninstall rejects the drift before removal.
- A two-process barrier test proves credential/config publication serialization. It exposed and fixed Windows mutex thread affinity and `ERROR_ALREADY_EXISTS` handling.
- A behavioral harness test injects root deletion failure after the deletion journal is durable and proves `RootDeletionIncomplete` retains the exact root. Another test creates canonical/temp/backup/replaced sensitive residue and proves cleanup removes all of it before the ledger.

### Final verification

- Focused client Pester: `40 passed, 0 failed` in PowerShell 7; the same tests are included in both full runs.
- Windows PowerShell 5.1 full Pester: `108 passed, 0 failed`.
- PowerShell 7 full Pester: `108 passed, 0 failed`.
- `go test -count=1 ./...`: all packages passed, including subprocess crash and concurrency tests.
- `go vet ./...`: exit 0.
- Locked Windows amd64 builds: agent, GUI client, credential provisioner, and installer verifier all exit 0.
- PowerShell parsing: installer harness, artifact builder, release publisher, locked wrapper, and MSI inspector all parse successfully.
- `git diff --check`: no errors (Git emitted only configured LF-to-CRLF conversion notices).
- Wintun/GPL paired search outside the negative test: no match.

### Locked release tools

- Go executable SHA-256: `7D828191BA32519A9C9361789AB647486236ED45C660889196C7770A8FF1985C`; exact version output is Go `1.27.0` for `windows/amd64`.
- WiX executable SHA-256: `DD46C03852E0360D711B150C2E01162AC098C556E12D55ADF592C607FCC0F0D7`; exact version is `4.0.6+73c89738`.
- Util extension SHA-256: `AC1A603904DC8DEBE1D263322C53B058B7156CEF115F00DE29A3E33C56218816`.
- Firewall extension SHA-256: `11684D6FB73269A745CD7B0D93D5894C45BEAB3CFE829D98BE24EB4B38BAE2E6`.
- DTF SHA-256: `CDD7F34DDA1180F21205543C8EE836C5BE66060D94441172366BCE078E1CDB87`.

### Inspect-only MSI and raw-table evidence

- Path: `dist/OverseasAccessSetup.msi`
- SHA-256: `D5A12BFD5A96AE9FF50BC7A558232DE75E3FEC2AAE5E90A3956D4A75FC28CC4A`
- Source commit in artifact manifest: `f8f54b839f67f196a1d8d0e4318f3c2b0a0049e0`
- Extracted allowlist: exactly 18 payloads; source/extracted bytes and signed-envelope coverage matched.
- Raw ordering: `VerifyPackageTrust=1499`, `InstallInitialize=1500`, `RemoveExistingProducts=1501`, `StopServices=1900`, `RemoveClientFirewall=1901`, `CleanupOwnedRuntime=1902`, `VerifyInstalledPayload=5797`, `RollbackClientFirewall=5798`, `InstallClientFirewall=5799`, `InstallServices=5800`.
- Raw commands: rollback=`firewall-rollback` type 3330; install=`firewall-install` type 3074; uninstall=`firewall-uninstall` type 3074; runtime cleanup=`runtime-cleanup` type 3074; installed-payload verifier target is exactly `[CustomActionData]`.
- WiX decompile emitted the expected custom-table and ACL relationship reconstruction warnings. Direct read-only DTF table inspection proved the raw sequence/custom-action rows.
- Release refusal: exit 1 because no verified Microsoft `signtool.exe` was available; the requested signed final artifact remained absent and release temporary-directory count was zero.

### Remaining external release concerns

1. No corporate certificate/private key and no verified Microsoft signing tool were available, so a corporate-signed production artifact was intentionally not produced.
2. No live install/repair/upgrade/rollback/uninstall or firewall/service mutation was run. Those destructive scenarios remain for a disposable Windows integration host using a corporate-signed artifact.
3. GNU Make was unavailable; the exact tracked target commands were executed directly through the locked wrapper.

---

## Final firewall rollback ownership proof (2026-08-29)

Implementation commit: `5d9550d1f7d2f6a7c5672ade988d5d7d2e24c384`

The final review identified a valid ownership race: an `intended` journal entry with an earlier `absent_before` observation is not sufficient authority to delete by name during rollback. Another process can create or replace that name between the observation, the failed creation attempt, and rollback.

Rollback now calls the same complete `Get-ExactFirewallRule` validator immediately before every possible deletion. This validates unique name plus display name, group, direction, action, enablement, profile, application/package, protocol and ports, local/remote addresses, service, interface type/alias, and all security-filter fields. A missing rule is durably marked `resolved`; an exact rule is removed and absence is proven; a mismatch or ambiguous name fails closed while preserving both the rule and transaction journal. Per-entry `pending`/`resolved` state makes interrupted compensation resumable without weakening ownership proof.

Strict TDD evidence:

- RED: the PowerShell 7 mocked lifecycle suite reported `39 passed, 1 failed`; rollback did not throw and deleted a foreign same-name rule created during an injected `New-NetFirewallRule` failure.
- GREEN race test: a foreign process publishes the second rule name between absence proof and injected create failure; rollback rejects the mismatch, preserves the foreign rule, and retains `current_operation`.
- GREEN drift/replacement test: the first newly created rule is replaced or mutated before rollback; rollback durably resolves the independently missing second rule, then rejects the changed first rule and preserves it and the journal.
- Windows PowerShell 5.1 full Pester: `108 passed, 0 failed`.
- PowerShell 7 full Pester: `108 passed, 0 failed`.
- `go test -count=1 ./...`: all packages passed.
- `go vet ./...`: exit 0.
- No live or privileged firewall mutation was performed; the behavioral tests execute the extracted production lifecycle script with isolated mocks.

---

# Task 8 implementation evidence

## 2026-09-07 — first implementation slice (candidate, not accepted release)

Read task-8-brief/context/preflight first, TDD skill and implementer template.
No developer-machine installed product/service, remote host, certificate store, private key,
or production network mutations performed. No release signing performed.

Implemented so far: bounded asynchronous restoration response (95s total / 64KiB),
legacy disconnected/prepared and version-one idle validation, request/error checks;
stopped services require independent real residue proof and are not started by old removal.
Nested owned paths reject traversal, ADS, DOS names, alternate separators, trailing
dots/spaces, duplicate Windows names and reparse ancestry. Cleanup removes only listed
files and empty ancestors; foreign content remains. The embedded installed verifier now
resolves nested paths and rejects duplicate names. Flutter inventory emits stable one-file
WiX components, preserving overseas-client.exe and its existing GUID; candidate version
0.1.8 is bound to native Flutter PE resources, manifest and MSI. Flutter toolchain checked
against deploy/toolchains.json. Release recipe builds Flutter, signs its DLLs and exe, keeps
upstream Wintun signer, and requires explicit HTTPS timestamp service. These are recipe
changes only; short-lived signing identity remains unqualified for formal release.

TDD commands (cwd `.worktrees/cross-platform`):

```powershell
Import-Module 'C:/Program Files/WindowsPowerShell/Modules/Pester/3.4.0/Pester.psd1'
Invoke-Pester tests/powershell/ClientUpgrade.Tests.ps1 -EnableExit
Invoke-Pester tests/powershell/ClientPayloadPaths.Tests.ps1 -EnableExit
Invoke-Pester tests/powershell/FlutterPackage.Tests.ps1 -EnableExit
& C:/Users/Eleme/codex_workspace/.tools/go1.27.0/go/bin/go.exe test ./cmd/installer-verifier -run TestInstalledVerifierResolvesNestedPayloadWithoutWindowsAliases -count=1
& C:/Users/Eleme/codex_workspace/.tools/go1.27.0/go/bin/go.exe test ./cmd/installer-verifier -run TestRunPreparesUpgradeAndPropagatesRestorationFailure -count=1
```

RED: restoration 0/4 (helpers absent), path ownership 0/4 (flat-path rejection and
no nested cleanup), extended inventory 4/6 (missing manifest helper), nested copy 6/7
(missing destination parent), Flutter 0/4 (missing inventory/authoring and legacy build),
stopped service 6/7 (unwanted Start-Service), Go nested resolver undefined constant,
Go prepare-upgrade returned exit2 with zero dispatch. GREEN: restoration7/7,
paths7/7, Flutter4/4, both focused Go tests pass. Pester3 Should Throw is unreliable on
PS7 here; tests use the repository's explicit try/catch failure-message pattern.

Full regression before this slice: PS7 Pester161/161, PS5.1 Pester161/161.
PS7 command: `Import-Module .../Pester/3.4.0/Pester.psd1; Invoke-Pester tests/powershell -PassThru -Quiet`
PS5.1: `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -Command "Import-Module 'C:/Program Files/WindowsPowerShell/Modules/Pester/3.4.0/Pester.psd1'; Invoke-Pester tests/powershell -EnableExit"`
Go: explicit go1.27.0 `test ./cmd/installer-verifier -count=1` PASS 11.383s;
signed-MSI input integration test retains its existing absent-input skip.
Flutter: `CI=true; . ./scripts/windows/client-payload-tools.ps1; Invoke-LockedFlutterBuild -Repository (Get-Location).Path -ProductVersion 0.1.8`
PASS native Windows release build 28.8s, dependency lock enforced. Four informational
newer-dependency notices; no dependency upgrades. No GUI acceptance performed.

Upgrade architecture remains separate pending work: changing only the new harness does
not fix old cached MSI early removal. Parent's per-user dummy-MSI fixture established
shared component Action Null and two-flush built-in rollback semantics; it did not exercise
our service, IIS certificate action or runtime cleanup. Old runtime-cleanup destroys owned
credential.bin/sing-box.json without rollback, requiring protected ciphertext-only snapshot,
restore, rollback and commit cleanup. Parent approved that extension. Formal sequence and
certificate changes are intentionally not included in this first slice. Native actual
0.1.7 upgrade/rollback/uninstall/clean install gates remain pending.

Self-review: first slice is coherent for inspect-only packaging; no claim that normal
upgrade works yet. MSI extraction still to run after a clean scoped commit because the
builder requires a clean source tree. Additional full Go/platform checks follow final slice.

## 2026-09-07 — first review remediation

First-slice commits: `671dd83`, report append `8a0026c`. Review identified inherited
`SilentlyContinue` discovery as a false zero-residue proof and missing enforcement of
the embedded/harness synchronization comment. Both verified and corrected together.
Service and adapter/route/DNS/firewall discovery now enumerate with ErrorAction Stop;
selection filters ordinary empty results without interpreting query failure as absence.
Every embedded restoration function is compared byte-for-byte (newline normalized) with
its authoritative harness definition by the new mandatory Pester contract test.

RED: focused ClientUpgrade test **8/9** (injected enumeration error accepted).
After authoritative harness repair, **8/9** (synchronization contract caught stale embed).
After synchronizing the embed, **9/9 on both PowerShell7 and Windows PowerShell5.1**,
same explicit Import-Module and Invoke-Pester commands as above. These tests include
four individually injected discovery failures, absent/stopped-service behavior and a
real isolated asynchronous named-pipe timeout. No real product lifecycle actions.

First inspect attempt refused dirty tree because the appended report had not been
committed; guard was preserved. Next clean attempt discovered absent upstream archives.
Official GitHub sing-box archive fetched and SHA matched the lock. Official Wintun
download from this workstation timed out; parent fetched the same official archive via
test VM116 and verified the locked SHA both remotely and locally. No alternate version
or checksum change. MSI extraction still pending the next clean-source build.

## 2026-09-07 Task 8 second slice: protected migration candidate

Implemented two-flush upgrade sequencing: controlled disconnect before StopServices;
rollback snapshot queued after StopServices but before InstallFiles; backup before
replacement files; verified payload/shared-root import before InstallServices;
InstallExecute immediately followed by RemoveExistingProducts; snapshot restore,
new firewall and StartServices only afterward; InstallExecuteAgain before finalize.
Commit removes the exact protected backup. This is an implementation candidate,
not a claim that the signed product/native lifecycle gate passed.

Snapshot boundary: SYSTEM/Administrators-only directory and owner checks, reparse
ancestry refusal, bounded exact runtime ownership journal and file inventory,
random transaction entropy, LocalMachine DPAPI envelope for every backed-up file,
hashes and original ACL restoration. credential.bin is never decrypted; legacy
sing-box.json containing a synthetic secret was verified absent in backup plaintext.
Stale/incomplete/tampered/foreign snapshot contents refuse continuation and remain
for explicit recovery. Only exact successfully created files are cleaned on an
early backup failure. Runtime ledger is published last after restored file hashes.
Installer firewall baseline records all exact normalized definitions plus original
presence/enabled states; rollback restores only that baseline, never adds originally
absent rules or accepts foreign same-name semantic drift. New phase-two ownership
journal is removed on rollback only after validating it and proving the baseline.

Shared company trust is explicitly persistent and shared: no IIS Certificate row,
no uninstall/rollback certificate deletion, no Permanent component. Legacy shared
component GUID/keypath remains. Install-only adapter pins exact DER SHA256 and
thumbprint, verifies an existing match, imports only if absent, verifies afterward.
Abstract-store tests made no change to the workstation's actual certificate stores.

Focused RED/GREEN receipts (Pester 3.4.0 explicitly imported):
- Snapshot initial missing implementation RED 0/4 -> GREEN 4/4; backup failure,
  interrupted phase-two restoration, parent ACL and junction tests expanded to 7/7.
- Missing phase-two journal cleanup RED 7/8 -> GREEN 8/8.
- User-writable source ownership journal RED 8/9 -> GREEN 9/9.
- Terminal service/firewall enumeration failure RED 10/11 -> GREEN 11/11.
- Flutter DLL Authenticode coverage RED 7/8 -> GREEN 8/8.
- Firewall exact-state adapter 2/2; shared-root abstract store 3/3.
- Go bundle Flutter inventory test RED (old flat allowlist) -> GREEN; old static
  allowlist wording assertion subsequently updated to require the strengthened
  required-file, Windows duplicate, and safe-path boundaries.

Fresh full validation commands:
```powershell
Import-Module 'C:/Program Files/WindowsPowerShell/Modules/Pester/3.4.0/Pester.psd1'
$r = Invoke-Pester tests/powershell -PassThru -Quiet
# PowerShell 7: Passed=180 Failed=0
& 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe' -NoProfile -Command "Import-Module 'C:/Program Files/WindowsPowerShell/Modules/Pester/3.4.0/Pester.psd1'; Invoke-Pester tests/powershell -EnableExit"
# Windows PowerShell 5.1: Passed=180 Failed=0, exit 0, 21.84 seconds
& 'C:/Users/Eleme/codex_workspace/.tools/go1.27.0/go/bin/go.exe' test ./... -count=1
& 'C:/Users/Eleme/codex_workspace/.tools/go1.27.0/go/bin/go.exe' vet ./...
```
Go vet exit 0. Full Go tests were rerun after the final bundle contract edit;
its final receipt is recorded in the next append before packaging.

Self-review boundaries and remaining acceptance:
- Parent's isolated per-user MSI fixture proves shared component Action Null and
  the two-execute native MSI transaction ordering. Its embedded-cab phase-two
  deferred failure restored old file bytes BEFORE early RollbackOne read them.
  These are MSI built-in transaction observations, not proof of product custom
  action service/network/certificate rollback effects.
- Rollback network baseline is verified controlled-disconnected ordinary network;
  restoring prior service running state must NOT reconnect a former active tunnel.
- Native clean install, old 0.1.7 active/prepared/idle/missing service/duplicate
  registration upgrade, service running-state rollback, actual shared root retention,
  GUI click-through and final zero residue still require the parent's isolated pilot.
- Legacy disabled installer firewall rules may cause the immutable old strict
  uninstaller to refuse removal; the snapshot preserves disabled state on failure,
  but no claim that this native old-package edge case upgrades successfully.
- Signing identity and short-lived signing/timestamp/release acceptance remain
  pending user choice. No certificate issuance/private-key export, actual installed
  client operation, manual SCM deletion, permanent safety bypass or release occurred.

Final second-slice full Go test command above exited 0, all packages passed;
installer-verifier 14.454s. No signed-MSI integration inputs were supplied, so that
existing explicit native integration test remains skipped, not silently accepted.

## 2026-09-07 Native package authoring correction and extraction

The first WiX build found real schema errors WIX0072 (InstallExecute requires an
ordering attribute) and WIX0004 (StartServices does not accept After). Corrected
authoring to explicit InstallExecute Sequence=6500 and StartServices Sequence=6550;
all relative ordering remains checked against actual MSI tables by the inspector.
Default WiX ICE validation then passed without build warnings. An early extraction
attempt while the build still held its database failed WIX0223; after build exit 0,
extraction passed. No MSI installation was executed.

Added actual File -> Component -> Directory destination verification, with RED4/5
missing helper -> GREEN5/5 (nested long names, redirected ancestry, cycles). This
checks installed paths, not just matching extracted file IDs/hashes.
Full Pester at this point passed 181/181 in fresh PowerShell7 and WindowsPowerShell5.1
processes. Dot-sourcing the inspector before Pester exposed strict-mode fixture
leakage: the absent-service mock emitted a null object, not an empty enumeration;
that combined run was 180/181. Changed only the mock to return @(), reflecting the
real enumeration contract; strict-mode ClientUpgrade then passed11/11. No production
enumeration safety relaxation.

Commands (from repository root, using the locked wrapper):
```powershell
& 'C:/Users/Eleme/codex_workspace/.tools/go1.27.0/go/bin/go.exe' build -o bin/overseas-agent.exe ./cmd/overseas-agent
& 'C:/Users/Eleme/codex_workspace/.tools/go1.27.0/go/bin/go.exe' build -o bin/installer-verifier.exe ./cmd/installer-verifier
& ./scripts/windows/build-client-artifacts.ps1 -Mode Inspect -OutputDirectory build/task8-inspect -ProductVersion 0.1.8
& ./scripts/windows/invoke-locked-client-tool.ps1 -Tool Wix -ToolArguments @('build','deploy/client/Product.wxs','deploy/client/Files.wxs','build/task8-inspect.FlutterFiles.wxs','-d','ProductVersion=0.1.8','-bindpath','build/task8-inspect','-arch','x64','-intermediateFolder','build/task8-wixobj','-pdbtype','none','-out','dist/Task8-0.1.8-INSPECT_ONLY.msi')
& ./scripts/windows/inspect-client-msi.ps1 -MsiPath dist/Task8-0.1.8-INSPECT_ONLY.msi -StagingPath build/task8-inspect -OutputDirectory build/task8-msi-inspection
```
The exploratory package used payload7139605 plus corrected authoring; it is NOT a
source-aligned delivery. Clean-source rebuild after the correction commit follows.
Exploratory extraction passed30 files and exact trust sentinel/signature refusal.
Actual action sequence: Prepare1897, Stop1900, SnapshotRollback1901, Backup1902,
InstallFiles4000, Verify5798, SharedRoot5799, InstallServices5800, Execute6500,
RemoveExisting6501, Restore6502, FirewallRollback6503, FirewallInstall6504,
Start6550, Commit6551, ExecuteAgain6552, Finalize6600.

Decompilation warnings retained and investigated:
- WIX1060: Wix4ServiceConfig rendered as a custom table, an extension representation
  limitation of this decompile invocation, not an ICE compile failure.
- WIX1059 twice: decompiler misrepresents MsiLockPermissionsEx references and omits
  corresponding permission authoring. Read-only original database query confirms
  LockObject INSTALLFOLDER / Table CreateFolder / SDDL
  D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU), and DATAFOLDER /
  CreateFolder / D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA). CreateFolder contains matching
  INSTALLFOLDER→InstallFolderAcl and DATAFOLDER→DataFolderAcl rows. We do not rebuild
  from this lossy decompiled XML. Native application of ACLs remains a pilot gate.

### Exact-source inspect artifact receipt

Rebuilt both Go binaries and staged/built/extracted with the same commands above
from clean code commit **96751f5f05724886bdefe171f2133feeca0a23de**. All exited0;
WiX default validation passed. Final inspector: 30 payload files, mode inspect,
source_commit96751f5f05724886bdefe171f2133feeca0a23de,
MSI SHA256 **49AA52F2EDD5A5118A014B56C29D8B79F86CAB28F72E7B9281E81147CD36E57C**.
Artifact: `dist/Task8-0.1.8-INSPECT_ONLY.msi`; staging `build/task8-inspect`;
extraction `build/task8-msi-inspection`. The same three explained decompilation
warnings remain. All outputs are ignored local artifacts, not a formal release.

Executed only the read-only verifier gate:
```powershell
& ./bin/installer-verifier.exe package --msi ((Resolve-Path dist/Task8-0.1.8-INSPECT_ONLY.msi).Path) --thumbprint 0000000000000000000000000000000000000000
```
Expected fail-closed refusal confirmed exit1 (`installer trust verification failed`).
No msiexec product install/upgrade/uninstall was performed. Fresh full PowerShell7
under StrictMode2.0 also passed181/181 after the test mock correction. This receipt
is a documentation-only follow-up: it does not change the artifact's code provenance.
