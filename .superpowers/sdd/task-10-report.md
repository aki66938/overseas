# Task 10 Report — Windows Physical-Host Gate Preparation

## Status

`DONE_WITH_CONCERNS` as of 2026-08-31.

Code readiness is green for the non-live Task 10 gate-preparation scope. The
live VM101 + disposable physical-host acceptance gate was not executed and
remains externally blocked. This report is a non-live code-and-runbook
readiness result only.

`OVERSEAS_ACCESS_INTEGRATION=1` was never set. No VM or workstation route, DNS,
firewall, adapter, service, installer, credential, or runtime state was
intentionally mutated during this remediation pass.

## What changed in this review-fix pass

1. Locked/generated client config is now treated as credentialless. Task 10 now
   rejects any plaintext tunnel password in the locked fixture config, extracts
   only non-secret provisioning metadata from that config, and keeps the secret
   path outside the rendered fixture config.
2. Fixture action setup now requires a genuinely clean baseline before
   `case-setup`, always uses `install` for that path, never silently switches to
   `repair`, provisions before agent start, and verifies that the physical
   client does not own a local server service/config/listener.
3. Local server staging on the physical client was removed from the Task 10
   harness path. Server identity is now consumed as a pinned remote attestation
   artifact bound to the expected VM101 SSH host-key fingerprint, service/core
   hashes, server config hash, PID chain, and `172.20.9.15:18443` listener.
4. Manifest handling is now identically strict on both sides of the install
   contract for the current reviewed 16 signed payload entries. Extra or missing
   entries are refused.
5. The runbook now documents the stronger non-live gate: explicit zero-drift
   WhatIf comparison, guarded remote attestation capture, hidden/background
   standard-client gate, guarded bundle/MSI verification before `msiexec`,
   explicit pipe-only provisioning, no preset PID variables, per-fault fresh PID
   capture, and a separate forced-reboot section.

## Code readiness

The following Task 10 review findings are now addressed in code and tests:

1. Credential source
   - `tests/integration/fixtureconfig` rejects locked client configs that carry
     a plaintext tunnel password.
   - Fixture action uses a pinned credential source path/hash plus the installed
     payload-pinned `credential-provisioner.exe`.
   - Provisioning input now flows through an anonymous pipe from the credential
     source process to the provisioner process; the secret is no longer derived
     from the locked config body.

2. Clean-host setup
   - `case-setup` now refuses any pre-existing MSI, owned roots, runtime files,
     services, processes, listeners, firewall rules, registry/ownership/
     recovery/transaction residue, or managed TUN adapter state in the supplied
     baseline snapshot.
   - `case-setup` no longer falls back to `repair`.

3. Remote topology
   - The fixture driver validates a pinned remote attestation artifact instead of
     accepting local server ownership on the physical client.
   - Snapshot validation now treats any local server service/process/config/
     listener presence on the physical client as residue.

4. Signed payload strictness
   - Payload manifest parsing now requires exactly the reviewed 16 signed
     entries; it no longer tolerates extras.

5. Runbook contract
   - `docs/sing-box-poc-runbook.md` and
     `tests/powershell/Runbook.Tests.ps1` were updated together so the static
     operator procedure matches the hardened non-live contract actually required
     by the review.

## Strict RED → GREEN record

Focused RED was observed first in the touched packages:

- `fixtureconfig`: missing credentialless-config rejection, missing attestation
  type/validation, and non-strict payload count handling.
- `fixtureaction`: stale test contract still expected password material from the
  locked config and still modeled local server staging during `case-setup`.
- `fixtureproto` / `fixturedriver`: still modeled local server identity on the
  physical client instead of remote attestation + local-server absence.
- Runbook tests: still allowed weaker MSI/provisioning/lifecycle/WhatIf wording.

Each slice was implemented only after the failing expectation existed, then
rerun to GREEN before moving on.

## Final non-live verification actually executed on 2026-08-31

- Locked full Go test:
  `scripts/windows/invoke-locked-client-tool.ps1 -Tool Go -ToolArguments @('test','-count=1','./...')`
  → PASS.
- Locked full Go vet:
  `scripts/windows/invoke-locked-client-tool.ps1 -Tool Go -ToolArguments @('vet','./...')`
  → PASS.
- Locked 20x repetition suite:
  `scripts/windows/invoke-locked-client-tool.ps1 -Tool Go -ToolArguments @('test','-count=20','./tests/integration/fixtureproto','./tests/integration/fixtureconfig','./tests/integration/fixtureaction','./tests/integration/fixturedriver','./internal/agent','./internal/supervisor')`
  → PASS.
- Windows PowerShell 5.1 Pester:
  `Invoke-Pester -Script tests/powershell -PassThru`
  → `113 passed, 0 failed, 0 skipped`.
- PowerShell 7 Pester:
  `Invoke-Pester -Script tests/powershell -PassThru`
  → `113 passed, 0 failed, 0 skipped`.
- Locked Windows amd64 builds:
  - `tests/integration/fixturedriver` → `bin/overseas-access-integration-driver.exe`
  - `tests/integration/fixtureserver` → `bin/fixture-sentinel.exe`
  - `tests/integration/fixtureaction` → `bin/fixture-action.exe`
  - `./cmd/overseas-agent` → `bin/overseas-agent.exe`
  - `./cmd/overseas-client` → `bin/overseas-client.exe`
  - `./cmd/credential-provisioner` → `bin/credential-provisioner.exe`
  - `./cmd/installer-verifier` → `bin/installer-verifier.exe`
  - `./cmd/overseas-server-service` → `bin/overseas-server-service.exe`
  → all 8 PASS.
- `git diff --check` → PASS, with only the repository’s LF→CRLF warning noise.
- PowerShell AST parse across repository `*.ps1` → `AST_OK`.
- Repository scans:
  - private-key marker scan → no matches.
  - bearer-token scan → no matches.
  - PIN assignment scan → no matches.
  - changed-file secret scan → clean.
  - full-tree password-assignment scan produced matches only in historical
    `.superpowers/sdd/review-*.diff` artifacts, earlier design notes/briefs, and
    intentional unit-test fixtures under `internal/singconfig/*_test.go`; no new
    live credential material was introduced by this Task 10 change set.

## Remaining concerns and external blockers

1. Live gate not executed
   - The VM101 server install/status/rollback flow, physical-host standard-client
     gate, custom MSI install, lifecycle faults, and 20 live repetitions remain
     unexecuted in this non-live pass.

2. External inputs still required
   - corporate-signed fixture manifest and detached signature;
   - corporate-signed release payload manifest and detached signature;
   - corporate signer thumbprint / executable signer allowlists;
   - corporate-signed MSI;
   - locked generated client/server/action configs and hashes;
   - pinned VM101 SSH Ed25519 SHA256 host-key fingerprint for
     `DESKTOP-1BVR2H6`;
   - pinned remote server attestation artifact for the actual live run;
   - authorized disposable physical Windows host identity/token;
   - new empty ACL-protected baseline evidence directory;
   - maintenance window, VM-console recovery owner, telecom PIN-holder
     availability, and written stop/go approvals.

3. Code-readiness boundary
   - Task 10 is ready for the live gate procedure, but it is not a live PASS.
     Any report that collapses non-live readiness into live acceptance would be
     incorrect.

## Final verdict

Task 10 non-live preparation is `DONE_WITH_CONCERNS`.

- Code readiness: PASS for the reviewed non-live scope.
- Live acceptance gate: still blocked by external inputs and by deliberate
  non-execution of VM/physical-host mutations.
