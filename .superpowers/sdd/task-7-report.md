# Task 7 Report — Transactional Server Deployment

## Status

Implemented and verified. No real service, firewall, listener, route, ACL, or network mutation was performed during development or tests.

Initial Task 7 commit: `c246c238432270afca904d5424ce7562be42e6cf` (`feat: add transactional sing-box server deployment`).
Review-fix commit: `a061e75a484599c590adccb15866f0dd6073c3e6` (`fix: harden server firewall and directory ownership`).

## TDD Evidence

- Baseline issue at `d0ec5b5`: both PowerShell engines passed 47/48; the sole failure was the legacy Makefile `.PHONY: test build` contract. Parent approved restoring that exact line within Task 7's Makefile scope. Focused RED then GREEN: 4/4 on both engines.
- Main RED: `ServerInstall.Tests.ps1` failed 0/8 on both Windows PowerShell 5.1/Pester 3.4 and PowerShell 7 because `install-server.ps1` and the Makefile target did not exist.
- Main GREEN: focused server suite passed 9/9 on both engines.
- Safety-refinement RED: ordering test failed because config publication preceded ProgramData ACL hardening and the transaction journal followed service start.
- Safety-refinement GREEN: focused server suite passed 10/10 on both engines after ordering ACL before config publication, rehashing installed files, and journaling before service start.
- Output-purity RED: a fake sing-box that wrote a success diagnostic polluted the function result and broke JSON evidence construction. GREEN suppresses native stdout/stderr while still capturing immediate launch and exit status; focused suite returned to 10/10 on both engines.
- Review-hardening RED: five new contracts failed for missing external write-ahead journaling, unsafe compensation ordering, broad server-port allow detection, rollback idempotency, and Make failure propagation. GREEN focused suite: 14/14 on both engines.
- SCM-compatibility RED: direct registration of sing-box 1.13.19 cannot satisfy Windows SCM `ServiceMain`; first-party host and range-aware firewall contracts failed. GREEN adds a minimal project-owned Go SCM host, focused Stop/Shutdown/readiness tests, an offline packaging step, and installer registration of only the pinned host.
- Packaging RED: the first-party host was neither copied into the bundle nor recorded in the bundle manifest. GREEN adds `package-server-service.ps1` and Make targets that copy and rehash the locally built host and atomically add `server_service_sha256` without network access.
- Behavioral-review GREEN adds executed refusal cases for unsupported OS, missing fixed VM IP, sing-box hash mismatch, non-loopback 8080 ownership, CONNECT failure, occupied TCP 18443, and range-based broad firewall exposure. The Go service suite also executes start-failure cleanup and unexpected-child-exit paths.

## Implemented Contracts

- Explicit `Install`, `Status`, and `Rollback` modes; no default mutating mode.
- Fixed VM `172.20.9.15`, approved employee CIDR `172.20.8.0/22`, sing-box TCP `18443`, loopback-only telecom proxy `127.0.0.1:8080`.
- Elevated/OS/VM/listener owner/actual HTTPS-over-proxy/hash/manifest/`sing-box check` gates before `ShouldProcess` and before persistent mutation.
- One `SupportsShouldProcess`; `-WhatIf` executes all preflight checks and makes zero persistent changes.
- Atomic create-new baseline evidence before system mutation, with services, listeners, routes, firewall rules and filters, 8080 owner, input hashes, config hash, and CONNECT result.
- External write-ahead journal is atomically published beside the explicit baseline before the first Program Files/ProgramData/service/firewall mutation; both owned roots carry transaction-ID owner markers.
- ACL-hardened Program Files binaries and ProgramData config/runtime-manifest paths, installed-file rehash, exact service and three exact firewall resources.
- Transaction-ID ownership descriptions, reverse compensation, rollback of exact owned resources only, immutable paths, literal-path removal only, and final staging cleanup.
- Compensation removes firewall rules in reverse order, then proves the service absent before deleting backing files. Rollback retains its external journal until exact absence is proven and returns `AlreadyRolledBack` on safe retries.
- Preflight rejects effective existing inbound allows that could expose TCP 18443 beyond `172.20.8.0/22`; baseline service inventory hashes rather than records service command lines.
- Preflight also rejects any existing TCP 18443 listener so the SCM host's loopback readiness probe cannot be satisfied by an unrelated process. The TCP 8080 block is scoped to local address `172.20.9.15`, so it blocks LAN access without matching the required `127.0.0.1:8080` telecom flow.
- Because sing-box 1.13.19 does not implement the Windows SCM control handler, the approved brief was necessarily expanded with `cmd/overseas-server-service`. This first-party host uses `golang.org/x/sys/windows/svc`, reads only fixed ProgramData config/manifest paths, delegates direct no-shell launch to the existing kill-on-close supervisor, invokes `coreverify.Verify` in the supervisor's immediate pre-launch boundary, reports `Running` only after local TCP 18443 readiness, and treats unproven Stop/Shutdown cleanup as a service failure.
- The offline packaging target builds `overseas-server-service.exe`, copies and rehashes it into the pinned sing-box bundle, and atomically records `server_service_sha256`. Install requires that manifest hash and a caller-explicit `ExpectedServerServiceSha256`, rehashes after installation, and registers SCM with the quoted service-host path only. Neither SCM argv nor sing-box argv contains secret material.
- Native `sing-box check` and `icacls.exe` calls immediately capture both `$?` and `$LASTEXITCODE`; config contents/secrets are never placed in argv or parameters.
- Both owned roots have inheritance removed, Administrators/SYSTEM-only access, and an explicit Administrators owner before binaries/configuration are published, matching `coreverify`'s runtime ownership requirements.

## Fresh Verification

- Windows PowerShell 5.1 / Pester 3.4 full suite: 68 passed, 0 failed.
- PowerShell 7 full suite: 68 passed, 0 failed.
- Portable Go 1.27.0: `go test ./...` passed.
- Portable Go 1.27.0: `go vet ./...` passed.
- Portable Go 1.27.0: `go build -trimpath ./cmd/overseas-server-service` passed.
- `git diff --check` passed.

## Concerns / Operational Boundaries

- Unit tests mock all Windows service/network/firewall commands; no live VM install or rollback was attempted by design.
- No live SCM integration, service install/start, firewall mutation, or rollback was attempted. The Go handler/supervisor lifecycle and PowerShell preflight/WhatIf paths are unit-tested with fakes/mocks, so a controlled VM rehearsal remains required before production use.
- High-risk preflight refusals execute behaviorally, but the PowerShell compensation/rollback ownership matrix is still primarily protected by static ordering/ownership contracts rather than a full injected-failure matrix. A controlled VM rehearsal should include partial install and repeated rollback checkpoints.
- Operators must run `package-server-service` after acquiring the pinned `bin/sing-box` bundle, then supply the resulting `server_service_sha256` explicitly to Install; the installer fails closed if either pin is missing or differs.
- The CONNECT proof uses a fixed HTTPS HEAD request through `127.0.0.1:8080`; controlled deployment still depends on that approved probe destination being reachable through the telecom session.
- Install intentionally refuses pre-existing exact service/firewall/install/data resources rather than guessing ownership. Operators must use the recorded transaction rollback or resolve the collision explicitly.

## Review Follow-up — 2026-08-29

- RED reproduced four failures: the management-rule helper was absent, CIM multi-value `LocalPort` arrays were missed, a broad multi-port allow reached `-WhatIf`, and the empty-unmarked directory bypass deleted a root whose owner marker was never published.
- `ManagementPorts` is now the real string array `@('22', '3389', '5985', '5986')`. A behavioral Pester test executes the production rule helper through the PS5.1/PS7 `New-NetFirewallRule` proxy and proves four distinct `LocalPort` values are received.
- `Test-PortSpecificationIncludes` now iterates `@($Specification)` and parses every element for exact ports, ranges, comma-separated entries, and `Any`. Behavioral preflight covers a CIM-style `@('443', '18443')` broad allow and refuses it.
- `AllowEmptyUnmarked` was removed from the function and every compensation/rollback caller. A partial-publication test proves an empty root created before `owner.json` remains untouched, while a correctly marked root with the exact transaction ID is removable.
- GREEN verification: focused server suite 20/20 in both PowerShell engines; full suites 68/68 in both; portable Go test/vet and the first-party server-service build passed; `git diff --check` passed.
## 2026-08-31 PoC telecom wildcard-listener compatibility

The operator explicitly accepted remote reachability of the telecom client's
TCP 8080 listener for this PoC. The server installer now accepts exactly one
listener on `127.0.0.1`, `::1`, `0.0.0.0`, or `::`, while retaining the live
PID, executable path, SHA-256, valid Authenticode signature, and successful
HTTPS CONNECT proofs. The product no longer creates, owns, reports, or rolls
back `RegenBioOverseasAccess-Block8080-Remote`; its canonical firewall set is
the employee-scoped TCP 18443 allow and management-port protection rules.

TDD evidence:

- RED: Windows PowerShell focused server suite produced 18 passed / 2 failed
  for the old fixed 8080 rule and loopback-only rejection.
- GREEN: focused server suite produced 20/20 under Windows PowerShell 5.1 and
  20/20 under PowerShell 7.
- Full regression: locked Go `test -count=1 ./...` and `vet ./...` passed;
  full Pester produced 115/115 under both Windows PowerShell 5.1 and
  PowerShell 7.

Accepted risk: an internal device may connect directly to VM101 TCP 8080 and
bypass the product's TCP 18443 authorization boundary. This exception is for
the PoC and requires a fresh production decision.

Live VM101 `-WhatIf` exposed two Windows PowerShell 5.1 compatibility gaps.
The installer now preloads discovery modules and runs its read-only input
verification with the global AllScope WhatIf preference disabled inside a
`try/finally`, restoring it before any mutation boundary. Listener discovery
reads the listener set and filters ports in memory, avoiding the VM build's
ObjectNotFound behavior for an unused `-LocalPort`. A packaged-app firewall
allow with a nonempty Package SID is no longer treated as applying to the
desktop sing-box executable. Real VM101 WhatIf then passed with no evidence,
service, listener, file, or firewall mutation. Fresh post-fix regression:
locked Go test/vet passed and both full Pester engines passed 117/117.
