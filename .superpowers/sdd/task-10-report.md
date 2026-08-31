# Task 10 Report — Windows Physical-Host Gate Preparation

## Status

`DONE_WITH_CONCERNS` as of 2026-08-31.

The second-review false-pass gaps are closed for the non-live repository scope.
The live VM101 and disposable physical-host acceptance gate was not executed and
is not implied by this report. `OVERSEAS_ACCESS_INTEGRATION=1` was never set; no
VM, workstation, route, DNS, firewall, adapter, service, installer, credential,
or runtime state was intentionally mutated.

## Second-review fixes

1. Remote attestation now uses the exact strict flat Go schema and binds
   `DESKTOP-1BVR2H6`, a fresh observation, a per-run nonce, fixed service/core/
   config paths, listener PID/image identity, service→core PID parentage, and the
   fixture-manifest hashes. The Ed25519 OpenSSH fingerprint must decode as an
   exact 32-byte `SHA256:` value and is re-derived from the run-owned known_hosts
   file used by the pinned SSH invocation.
2. `installer-verifier.exe verify-bundle` is a real pre-install command. A clean-
   host staged verifier is pinned externally by SHA256 and Authenticode before it
   validates the MSI, fixture manifest/signature, release artifact manifest/
   signature, exact source commit, exact 16-file payload set, destinations,
   hashes, Authenticode requirements, signer allowlists, and exclusive sanitized
   evidence. The verifier contains no MSI execution.
3. Credential provisioning uses a real connected anonymous pipe: the pinned
   source process stdout is the installed provisioner's stdin. Both receive the
   same signed non-secret method/endpoint/expiry argument contract; the
   provisioner compares all three to the strict bounded JSON document before
   DPAPI storage. Neither process receives a parent stdin, inherited arbitrary
   environment, visible output, or a secret file/argv/environment/log channel.
4. The physical-client action helper's dead local production-server installer,
   owner marker, ACL/copy, verification, and removal implementation was deleted.
5. Managed-process evidence now captures the agent's exact SCM PID/image/hash,
   the core as the exact child image/hash of that agent, and the UI as its own
   unique exact image/path/hash instead of reusing the agent PID.
6. The standard-client gate pins sing-box `1.13.19`, proves `check -c stdin`
   support, validates a credentialless template and exact TUN interface, builds
   the runtime JSON only in memory, streams it through `run -c stdin`, waits on
   the exact adapter, and kills/waits/disposes the process in `finally`. The
   plaintext template property, plaintext string, secure-string BSTR, and runtime
   JSON references are cleared; no secret-bearing configuration is staged.
7. Server WhatIf compares executable before/after canonical snapshots of sorted
   filesystem hashes, registry values, scheduled-task identity, server service,
   firewall, and server-owned evidence/marker state. Volatile timestamps, process
   IDs, process inventories, and network probes are excluded from that equality
   surface.
8. The runbook invokes the pinned Go `provision-credential` helper after MSI and
   clears its non-secret action-config environment variable in `finally`.

## Strict RED → GREEN evidence

New failing tests were observed before each implementation slice: attestation
nonce/freshness/fixed paths/fingerprint; verifier routing and Windows crypto/
schema gates; provisioner contract mismatches and connected-pipe orchestration;
dead local-server symbol rejection; runbook attestation/WhatIf/verifier/stdin/
PID-capture requirements; exact standard TUN binding; and plaintext template
property cleanup. Each focused suite was rerun to green after its implementation.

## Fresh non-live verification executed on 2026-08-31

- Locked `go test -count=1 ./...`: PASS.
- Locked `go vet ./...`: PASS.
- Locked `go test -count=20` for fixtureproto, fixtureconfig, fixtureaction,
  fixturedriver, agent, and supervisor: PASS.
- Windows PowerShell 5.1 full Pester: `114 passed, 0 failed, 0 skipped`.
- PowerShell 7 full Pester: `114 passed, 0 failed, 0 skipped`.
- Locked Windows amd64 builds: all eight PASS (`fixturedriver`,
  `fixtureserver`, `fixtureaction`, `overseas-agent`, `overseas-client`,
  `credential-provisioner`, `installer-verifier`, and
  `overseas-server-service`).
- PowerShell AST parse: `AST_OK`, 28 repository `.ps1` files.
- Every fenced runbook PowerShell block parsed through the Pester contract.
- `git diff --check`: PASS (only repository LF→CRLF warning noise).
- Private-key marker, bearer-token, PIN-assignment, and changed-file secret-
  assignment scans: no matches.
- Complete scoped diff inspected; no live credential material or mutation output
  was introduced.

## Remaining external blockers

- Corporate-signed fixture manifest/signature, release artifact manifest/
  signature, MSI, verifier, and executable signer allowlists plus externally
  pinned hashes and exact source commit.
- Locked generated client/server/action configurations and signed contract
  values; the approved VM101 Ed25519 SHA256 host-key fingerprint.
- An authorized disposable physical Windows host, empty ACL-protected evidence
  directory, telecom PIN-holder availability, maintenance/recovery ownership,
  and written stop/go approvals.
- The actual server install/status/rollback, standard-client gate, custom MSI
  install, fault matrix, 20 live lifecycle repetitions, full-workday soak, and
  final zero-drift restoration evidence.

## Verdict

Repository code readiness is PASS for the reviewed non-live scope. Task 10
remains `DONE_WITH_CONCERNS` because the deliberately unexecuted live acceptance
gate is still required.
