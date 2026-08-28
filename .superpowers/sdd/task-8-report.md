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
Implementation commit: `492e0ca7046922a63ade570e8132ac68303b8211`

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
- SHA-256: `CE56DFA8A1C932C216E27B2E5968269441D0F9901FEDAE992A78A2BB3042AF8A`
- Source commit in artifact manifest: `492e0ca7046922a63ade570e8132ac68303b8211`
- Extracted allowlist: exactly 18 payloads; source/extracted bytes and signed-envelope coverage matched.
- Raw ordering: `VerifyPackageTrust=1499`, `InstallInitialize=1500`, `RemoveExistingProducts=1501`, `StopServices=1900`, `RemoveClientFirewall=1901`, `CleanupOwnedRuntime=1902`, `VerifyInstalledPayload=5797`, `RollbackClientFirewall=5798`, `InstallClientFirewall=5799`, `InstallServices=5800`.
- Raw commands: rollback=`firewall-rollback` type 3330; install=`firewall-install` type 3074; uninstall=`firewall-uninstall` type 3074; runtime cleanup=`runtime-cleanup` type 3074; installed-payload verifier target is exactly `[CustomActionData]`.
- WiX decompile emitted the expected custom-table and ACL relationship reconstruction warnings. Direct read-only DTF table inspection proved the raw sequence/custom-action rows.
- Release refusal: exit 1 because no verified Microsoft `signtool.exe` was available; the requested signed final artifact remained absent and release temporary-directory count was zero.

### Remaining external release concerns

1. No corporate certificate/private key and no verified Microsoft signing tool were available, so a corporate-signed production artifact was intentionally not produced.
2. No live install/repair/upgrade/rollback/uninstall or firewall/service mutation was run. Those destructive scenarios remain for a disposable Windows integration host using a corporate-signed artifact.
3. GNU Make was unavailable; the exact tracked target commands were executed directly through the locked wrapper.
