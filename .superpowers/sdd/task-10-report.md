# Task 10 Report — Windows Physical-Host Gate Preparation

## Status

`DONE_WITH_CONCERNS`: all five carried code prerequisites and the non-live runbook contract are implemented and verified. The live VM/physical-host acceptance gate was deliberately not executed and therefore remains externally blocked. This report is a code-readiness result, not a physical-host PASS.

`OVERSEAS_ACCESS_INTEGRATION=1` was never set. No VM or workstation route, DNS, firewall, adapter, service, installer, credential, or runtime state was mutated.

## Code readiness

1. Protocol v4 derives the exact corporate CIDRs, corporate DNS resolvers, and internal suffixes from the detached-signed fixture manifest. Client direct routes reject unbounded/port/network escapes and any address outside the exact signed private allowlist. Direct DNS is exact, and suffix matching requires either equality or a `.` label boundary.
2. The release payload parser accepts the actual emitted release schema (`source_commit`, `mode`, destination, hashes, signer declarations, and Authenticode declarations), requires the complete core payload set, and safely includes every additional signed metadata entry. Clean-host setup starts the locally owned production server, installs, derives the credential document only from the locked client config, invokes the installed manifest-pinned provisioner with zero argv and an anonymous stdin pipe, zeroes the buffer, then starts the agent. Connect paths lock and revalidate the rendered runtime config.
3. Snapshot evidence derives every installed path/hash from the signed payload entries, inventories unexpected files recursively in both client roots, captures root presence and the dynamic network-state file, and requires exact setup hashes plus full payload/runtime/root absence at uninstall.
4. The local production server is installed only into fixed ACL-protected, run-marked roots. The action binds the exact service executable, core, server config, listener, and hashes. Snapshot validation requires one chain from SCM service PID to service image, child core PID/image, client-facing listener PID/image, and locked server-config hash. The production service readiness probe now derives its target from the locked server config rather than a hard-coded loopback address.
5. Integrated non-live refusal tests cover unrelated private CIDR/DNS values, suffix collisions, unbounded/direct-port escapes, real release-manifest metadata and unsafe/reserved entries, pipe-only provisioning order and rollback, missing/wrong/residual payload files, unexpected owned-root files, changed network/payload response bindings, and mismatched server parent/listener/config identity.

## Runbook readiness

`docs/sing-box-poc-runbook.md` records the fixed VM facts and the external input ledger, requires independently verified SSH host-key pinning, new empty baselines, server WhatIf with zero drift, stop/go before every mutation group, the standard-client gate before the corporate-signed MSI, lifecycle/leak probes, exact rollback, sanitized evidence, and a FAIL verdict for any mandatory failure. Every documented native invocation immediately captures both `$?` and `$LASTEXITCODE` and aborts on either failure. The legacy runbook tests were preserved byte-for-byte and the Task 10 contract tests were appended.

## Strict RED → GREEN evidence

Focused RED failures were observed before each implementation slice, including missing network/payload protocol fields, missing payload parser and credential document APIs, missing complete installed-file and production-server ownership checks, missing setup sequencing, the real release-manifest schema being rejected, the server readiness address being hard-coded, reserved runtime payload names being accepted, and direct routes with a port escape being accepted. Each focused package was green before the next slice.

## Final non-live verification

- rerun on 2026-08-31 with the locked toolchain;
- locked `go test -count=1 ./...`: PASS;
- locked `go vet ./...`: PASS;
- locked `go test -count=20 ./tests/integration/fixtureproto ./tests/integration/fixtureconfig ./tests/integration/fixtureaction ./tests/integration/fixturedriver ./internal/agent ./internal/supervisor`: PASS;
- Windows PowerShell 5.1 Pester: `113 passed, 0 failed, 0 skipped`;
- PowerShell 7 Pester: `113 passed, 0 failed, 0 skipped`;
- Windows amd64 builds through the locked Go wrapper: integration driver, sentinel, action helper, agent, UI, credential provisioner, installer verifier, and production server service all PASS;
- `git diff --check`: PASS, with only the repository's configured LF-to-CRLF warnings;
- explicit tracked-content scans for private-key markers, bearer-token patterns, and quoted `password`/`secret`/`pin` assignments: no matches in repository content; remaining `token`/`credential` matches are structural test/documentation vocabulary only.

The full Go/vet/repetition matrix was rerun after the last implementation change before commit. An additional `go generate ./cmd/overseas-client` probe on this workstation attempted a network deprecation lookup for `github.com/akavel/rsrc@v0.10.2` despite the checked-in `rsrc_windows_amd64.syso` and warm module cache; the required eight locked Windows binary builds still completed successfully and no Task 10 code change was required for that environment-specific generator behavior.

## Exact external inputs still required

- the corporate fixture-manifest signer allowlist and detached-signed fixture manifest containing exact `corporate_cidrs`, `corporate_dns`, `internal_suffixes`, and all artifact paths/hashes;
- a corporate-signed release payload manifest and detached signature, matching signed bundle, exact executable signer allowlists, and a corporate-signed custom MSI;
- locked generated client/server/action configs and exact hashes, including the production listener, distinct sentinel/fake identities and endpoints, and a future RFC3339 credential expiration;
- the real SSH Ed25519 SHA256 host-key fingerprint supplied out of band for `DESKTOP-1BVR2H6`;
- an explicitly authorized disposable physical Windows host identity/token, a new empty ACL-protected evidence baseline directory, maintenance window, VM-console recovery owner, telecom PIN-holder availability, and written stop/go approval.

The corporate signer and disposable physical host are external dependencies. Until those inputs exist and the authorized run preserves all scenario/repetition/zero-drift evidence, Task 10 must not be reported as live PASS.
