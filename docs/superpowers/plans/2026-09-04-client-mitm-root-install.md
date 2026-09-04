# Windows Client MITM Root Installation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a version 0.1.6 Windows MSI that transactionally installs the exact VM101 Telecom MITM CA into `LocalMachine\Root`, proves the MSI contains the certificate installation action, and preserves the current fast connection path.

**Architecture:** Add the pinned WiX IIS extension because its `Certificate` element provides MSI-managed install, rollback, upgrade, and uninstall behavior. Keep the CA as an immutable package binary, bind one vital machine-root certificate component to the existing Complete feature, and extend static MSI inspection to validate the resulting certificate table and action sequence. Do not let the runtime agent or PowerShell harness mutate the trust store.

**Tech Stack:** WiX Toolset 4.0.6, WixToolset.Iis.wixext 4.0.6, PowerShell/Pester, DTF MSI inspection, Go 1.27, Windows Installer.

## Global Constraints

- Only `Telecom-GoMITM-Root.cer` may be installed into `LocalMachine\Root`.
- `RegenBio-OverseasAccess-PoC-Root.cer` must not be installed into Root or TrustedPublisher.
- Certificate installation is vital and transactional; failure must fail and roll back MSI installation.
- Keep the current HTTP CONNECT policy at `172.20.9.15:8080` and do not modify UI or runtime routing behavior.
- Upgrade version from `0.1.0` to `0.1.6` consistently in MSI, manifest, and installer harness.
- Preserve the existing UpgradeCode and allow WiX to generate a new ProductCode for the new version.
- Do not accept disabled TLS validation as POC evidence.

---

### Task 1: Encode the Missing Certificate Contract as Failing Tests

**Files:**
- Modify: `tests/powershell/ClientInstall.Tests.ps1`

**Interfaces:**
- Consumes: `deploy/client/Files.wxs`, `deploy/client/Product.wxs`, `deploy/client/build-lock.json`, `scripts/windows/inspect-client-msi.ps1`.
- Produces: static assertions defining the exact certificate, store, dependency lock, MSI inspection, and version requirements.

- [ ] **Step 1: Add the failing source-contract test**

Add a Pester case that requires the IIS namespace and exactly one certificate declaration:

```powershell
It 'transactionally installs only the telecom MITM CA into the machine root store' {
    $files = Get-Content -LiteralPath $filesPath -Raw -Encoding UTF8
    $files | Should Match 'xmlns:iis="http://wixtoolset.org/schemas/v4/wxs/iis"'
    $files | Should Match '<iis:Certificate[^>]*Id="TelecomMitmRootTrust"[^>]*BinaryRef="TelecomMitmCertificateBinary"[^>]*Name="Go MITM Root CA"[^>]*StoreLocation="localMachine"[^>]*StoreName="root"[^>]*Vital="yes"'
    @([regex]::Matches($files, '<iis:Certificate\b')).Count | Should Be 1
    $files | Should Not Match 'RegenBio-OverseasAccess-PoC-Root\.cer[\s\S]{0,300}<iis:Certificate'
}
```

- [ ] **Step 2: Add failing dependency, inspection, and version tests**

Require `build-lock.json` to pin `iis_extension_path`, its DLL and NuGet hashes; require the verified tool wrapper to append the IIS extension; require `inspect-client-msi.ps1` to inspect `Certificate` and `Binary`; require `0.1.6` in `Product.wxs`, `install-client.ps1`, and the artifact manifest builder.

- [ ] **Step 3: Run the focused test and verify RED**

Run:

```powershell
Invoke-Pester tests/powershell/ClientInstall.Tests.ps1 -Output Detailed
```

Expected: FAIL specifically because the IIS certificate declaration, pinned IIS extension, MSI inspection assertion, and version `0.1.6` are absent.

- [ ] **Step 4: Commit the regression contract**

```powershell
git add tests/powershell/ClientInstall.Tests.ps1
git commit -m "test(installer): require transactional telecom root trust"
```

### Task 2: Pin and Wire the WiX IIS Extension

**Files:**
- Modify: `deploy/client/build-lock.json`
- Modify: `scripts/windows/invoke-locked-client-tool.ps1`
- Modify: `scripts/windows/build-client-artifacts.ps1`
- Modify: `scripts/windows/publish-client-release.ps1`

**Interfaces:**
- Consumes: locked WiX version `4.0.6` and the verified-tool wrapper.
- Produces: `$lock.wix.iis_extension_path`, `iis_extension_sha256`, and `iis_sha256`; all WiX build calls receive the verified IIS extension DLL.

- [ ] **Step 1: Acquire the exact WiX IIS extension package**

Download `WixToolset.Iis.wixext` version `4.0.6` from NuGet, retain the `.nupkg` under `C:\Users\Eleme\codex_workspace\.tools\wix4.0.6`, extract it beside the existing util/firewall extensions, and calculate SHA-256 for the package and `iis\wixext4\WixToolset.Iis.wixext.dll`.

- [ ] **Step 2: Add the hashes and paths to the lock**

Extend the WiX lock object with exact lowercase values:

```json
"iis_extension_path": ".tools/wix4.0.6/iis/wixext4/WixToolset.Iis.wixext.dll",
"iis_extension_sha256": "977d2b6930e3726fca21905ddcdc19ee2db0a9c035d0bd66315e9e3f6783d1c7",
"iis_sha256": "cbd4c4c2f2009794b9c22acb5acb0b2467467dc74041ccb7cc094a1254faa940"
```

- [ ] **Step 3: Verify and append the extension in every WiX build path**

Resolve the IIS DLL through the existing `Resolve-VerifiedTool`/`Assert-Hash` flow and append:

```powershell
'-ext', $iisExtension
```

next to the existing util and firewall extension arguments. Do not accept caller-supplied extension paths.

- [ ] **Step 4: Run the focused Pester test**

Run `Invoke-Pester tests/powershell/ClientInstall.Tests.ps1 -Output Detailed`.

Expected: dependency-lock assertions pass; certificate source and version assertions remain RED.

- [ ] **Step 5: Commit the pinned dependency**

```powershell
git add deploy/client/build-lock.json scripts/windows/invoke-locked-client-tool.ps1 scripts/windows/build-client-artifacts.ps1 scripts/windows/publish-client-release.ps1
git commit -m "build(installer): pin WiX IIS certificate extension"
```

### Task 3: Author the Transactional Root Certificate and Version 0.1.6

**Files:**
- Modify: `deploy/client/Files.wxs`
- Modify: `deploy/client/Product.wxs`
- Modify: `deploy/client/install-client.ps1`
- Modify: `scripts/windows/build-client-artifacts.ps1`

**Interfaces:**
- Consumes: `Telecom-GoMITM-Root.cer` and the pinned IIS extension.
- Produces: MSI component `TelecomMitmRootCertificate`, binary `TelecomMitmCertificateBinary`, certificate `TelecomMitmRootTrust`, and consistent product version `0.1.6`.

- [ ] **Step 1: Add the IIS namespace, binary, and certificate component**

Use this exact declaration in `Files.wxs`:

```xml
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"
     xmlns:util="http://wixtoolset.org/schemas/v4/wxs/util"
     xmlns:iis="http://wixtoolset.org/schemas/v4/wxs/iis">
  <Fragment>
    <Binary Id="TelecomMitmCertificateBinary" SourceFile="Telecom-GoMITM-Root.cer" />
    <ComponentGroup Id="ClientFiles" Directory="INSTALLFOLDER">
      <Component Id="TelecomMitmRootCertificate" Guid="A6A99D6F-B4F9-43C4-91F4-3E1E167DF063" Bitness="always64">
        <RegistryValue Root="HKLM" Key="Software\RegenBio\OverseasAccess" Name="TelecomMitmRootManaged" Type="integer" Value="1" KeyPath="yes" />
        <iis:Certificate Id="TelecomMitmRootTrust" BinaryRef="TelecomMitmCertificateBinary" Name="Go MITM Root CA" StoreLocation="localMachine" StoreName="root" Vital="yes" />
      </Component>
```

Keep the existing `.cer` file in `CoreRuntime` for manifest/hash evidence; do not attach an IIS Certificate element to the code-signing certificate.

- [ ] **Step 2: Update all product versions to 0.1.6**

Change `Product.wxs` package version, `$ProductVersion` in `install-client.ps1`, and `product_version` in `build-client-artifacts.ps1` from `0.1.0` to `0.1.6`.

- [ ] **Step 3: Remove the dead PowerShell trust-store mutation**

Delete `Import-PocRootCertificate` and its call from `install-client.ps1`. Certificate trust is owned exclusively by MSI; the harness must not import either certificate into Root or TrustedPublisher.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run `Invoke-Pester tests/powershell/ClientInstall.Tests.ps1 -Output Detailed`.

Expected: all ClientInstall tests PASS.

- [ ] **Step 5: Commit the behavior change**

```powershell
git add deploy/client/Files.wxs deploy/client/Product.wxs deploy/client/install-client.ps1 scripts/windows/build-client-artifacts.ps1
git commit -m "fix(installer): install telecom root transactionally"
```

### Task 4: Prove the Built MSI Contains Certificate Installation Semantics

**Files:**
- Modify: `scripts/windows/inspect-client-msi.ps1`
- Modify: `tests/powershell/ClientInstall.Tests.ps1`

**Interfaces:**
- Consumes: a built MSI and its signed staging directory.
- Produces: inspection failure unless exactly one machine-root Go MITM certificate row and required IIS custom actions exist.

- [ ] **Step 1: Extend MSI table inspection**

Read the IIS extension's certificate table from the built MSI, require exactly one row referencing `TelecomMitmCertificateBinary`, require store location/name values corresponding to LocalMachine/Root, and require the certificate action sequence to occur after `InstallFiles` and before `InstallServices`. Add `Binary` and the actual IIS certificate table name to the mandatory table list.

- [ ] **Step 2: Reject code-signing-root trust in the built package**

Assert that no certificate row references `PocRootCert` or a binary sourced from `RegenBio-OverseasAccess-PoC-Root.cer`.

- [ ] **Step 3: Run Pester and verify GREEN**

Run `Invoke-Pester tests/powershell/ClientInstall.Tests.ps1 -Output Detailed`.

Expected: all tests PASS.

- [ ] **Step 4: Commit MSI inspection**

```powershell
git add scripts/windows/inspect-client-msi.ps1 tests/powershell/ClientInstall.Tests.ps1
git commit -m "test(installer): inspect telecom certificate actions"
```

### Task 5: Build, Inspect, and Publish the 0.1.6 POC MSI

**Files:**
- Generated: `dist/OverseasAccessSetup-v0.1.6-poc.msi`
- Generated: `build/msi-inspect/decompiled.wxs`
- Modify: release/readme documentation only if the existing command names differ from the validated build.

**Interfaces:**
- Consumes: signing certificate thumbprint `6A9D8BC41086C6B764B8C7439E797671EF83C15E` and the clean committed source tree.
- Produces: signed MSI, SHA-256, MSI table evidence, and Git commit identifier.

- [ ] **Step 1: Run the complete automated suite before release**

Run:

```powershell
go test ./...
Invoke-Pester tests/powershell -Output Detailed
```

Expected: zero Go or Pester failures.

- [ ] **Step 2: Build inspect-only artifacts and MSI**

Run the existing locked `client-artifacts`, `client-msi`, and `client-msi-inspect` Make targets. Expected: the MSI builds with WiX 4.0.6 and inspection confirms the certificate table/action.

- [ ] **Step 3: Build the signed release MSI**

Use the existing publisher with signing thumbprint `6A9D8BC41086C6B764B8C7439E797671EF83C15E`, then copy the immutable result to `dist/OverseasAccessSetup-v0.1.6-poc.msi` without overwriting an existing file.

- [ ] **Step 4: Record artifact evidence**

Report the MSI SHA-256, Authenticode status, ProductVersion, ProductCode, UpgradeCode, Telecom CA SHA-256, certificate table row, and source commit.

- [ ] **Step 5: Commit any final source or documentation adjustments**

Do not commit generated MSI or internal runtime logs unless the repository's existing release policy explicitly tracks them.

### Task 6: Clean Windows 10 POC Gate

**Files:**
- Runtime evidence only; do not commit user browsing data or internal topology dumps.

**Interfaces:**
- Consumes: `OverseasAccessSetup-v0.1.6-poc.msi` on the clean Windows 10 test device.
- Produces: PASS/FAIL evidence for certificate installation, connection time, HTTPS browsing, stability, and uninstall cleanup.

- [ ] **Step 1: Capture the clean baseline**

Verify thumbprint `7903068AAA22CA51185706C23611E6B5EEEF2729` is absent from `Cert:\LocalMachine\Root` and the product is not installed.

- [ ] **Step 2: Install and verify trust**

Install with verbose MSI logging, require exit code 0, and verify exactly one matching certificate exists in `LocalMachine\Root`.

- [ ] **Step 3: Verify functionality without TLS bypasses**

Measure connect time and load Google, YouTube, and Pinterest in Chrome with no certificate-warning bypass. Confirm each site completes normal TLS validation and page loading.

- [ ] **Step 4: Verify stability**

Run repeated HTTPS probes and sustained browsing long enough to catch the previously observed disconnect behavior; record tunnel/service restart counts and failure timestamps.

- [ ] **Step 5: Verify uninstall cleanup**

Uninstall the MSI, confirm the product service/TUN/routes/DNS/firewall state are restored, and confirm the managed Telecom CA is removed.

- [ ] **Step 6: Record the gate decision**

Only a full PASS authorizes later UI or security-hardening work. Any certificate, routing, HTTPS, or stability failure returns to root-cause diagnosis without bundling unrelated changes.
