# Task 9 Second-Review Hardening Design

## Goal

Make the privileged Windows integration harness prove that every installed and running component is the exact reviewed artifact, that generated client/server configuration can reach only the run-owned fake upstream, and that timeout/cancellation cannot leave a privileged process tree mutating the host. The development workstation remains non-live: only guard, unit, compile, build, vet, repetition, and Pester checks run here.

## Chosen architecture

Use a hybrid native/pinned design. A new in-repository `fixture-action.exe` implements fixed typed operations for all thirteen mutating actions. It uses Windows APIs for process, service, registry, listener, and ownership operations. It does not duplicate product installation logic: install, repair/reset, and uninstall invoke the reviewed MSI/installer through fixed operations, then independently verify the resulting state.

The only retained PowerShell boundary is the mature installer/state-capture path where replacing it would duplicate production logic. The fixture manifest binds the exact `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` path and SHA-256. No PATH resolution is allowed. The harness starts the outer driver suspended, assigns it to a kill-on-close Job Object, and resumes it. The driver applies the same containment to capture, PowerShell, installer, and action-helper process trees. A timeout closes the job and waits for tree quiescence before restoration proceeds.

Long-lived fixture processes never escape an action call. Fake CONNECT/data, control, and health endpoints are hosted by run-owned Windows services with unique run-bound service names. Their service configuration, PID, image path/hash, run identity, and listener ownership are evidence. `server-service` always denotes the production `overseas-server-service.exe`; fake upstream and sentinel roles remain separate artifacts with separate hashes.

## Trust and artifact binding

The protocol advances to version 3. The fixture configuration refers to one signed, deny-write/delete-locked artifact manifest. The driver derives role hashes from that locked manifest rather than trusting duplicated hashes in arbitrary configuration.

The fixture binding contains:

- manifest and generated-config hashes;
- agent, core, UI, production server-service, fixture driver, sentinel, lifecycle action-helper, pinned PowerShell, installer/MSI, and capture-script hashes;
- fake-upstream, public-sentinel, and corporate-sentinel identities;
- public data, public health, corporate, fake control, and fake CONNECT/data endpoints.

The harness independently holds/locks and verifies the driver, manifest, generated config, payload/installer, and action helper before privileged calls. The driver repeats validation before each action. Returned responses repeat the full binding, request nonce, run, scenario, and action. A mismatch is a fail-closed refusal.

## Configuration and listener proof

Before preflight succeeds, before any mutation, and immediately before a Connect-dependent operation, the driver parses the locked generated client and server configurations using shared semantic validation. Validation requires the sole external upstream to be the exact bound fake CONNECT/data endpoint. It rejects extra or fallback upstreams, wildcard/ambiguous targets, the telecom service, and `127.0.0.1:8080` explicitly.

Native listener inspection proves exclusive ownership: every bound fake data/control/health endpoint has exactly one listening socket, the owner PID belongs to the expected run-owned Windows service, and the owner image hash matches the sentinel binding. Public data and health remain paired under the same run-owned service/failure domain. A successful probe must carry the request nonce through the fake upstream; sentinel health and ownership are checked independently throughout failure windows.

## Lifecycle action helper

`fixture-action.exe` exposes only the thirteen protocol actions already accepted by the driver:

1. `case-setup`
2. `fake-upstream-start`
3. `fake-upstream-stop`
4. `core-crash`
5. `ui-start`
6. `ui-exit`
7. `agent-crash`
8. `agent-start`
9. `stage-machine-recovery`
10. `machine-recover`
11. `uninstall`
12. `case-cleanup`
13. `restore`

Requests use a strict JSON schema and inherit the driver request/binding. No free-form command or arbitrary executable path is accepted. Product lifecycle transitions call the pinned installer/MSI only through fixed argument templates. The helper then captures and asserts the action-specific post-state before returning. Cleanup cannot create evidence for an earlier action, and restoration consumes only the trusted baseline recreated/verified by the harness.

## Snapshot and evidence model

Snapshots retain adapters, routes, DNS, services, processes, and owned firewall rules and add:

- MSI product registration;
- installed file paths, presence, and SHA-256;
- credential/config presence and hashes without secret contents;
- owned registry records and definition hashes;
- runtime ownership ledger and owner-marker hashes;
- recovery and scheduled artifacts;
- installer transaction/journal artifacts;
- fixture service/process/listener records and residues.

Every present process or service in a bound role must have the expected image hash. Relevant installed files must match manifest hashes. Snapshot validation rejects missing role records, unknown/duplicate records, empty/trivial captures, unexpected present artifacts, and hash mismatches. Canonical state excludes ephemeral PIDs but includes artifact identity and ownership facts.

Uninstall evidence is captured before case cleanup. It requires the product service, processes, TUN, routes/DNS ownership, firewall rules, MSI registration, installed files, credential/config, registry ownership, runtime ledger, recovery/scheduled artifacts, transaction residue, and fixture-owned product residue to be absent. Case cleanup handles only run-owned fixture residue and cannot mask an uninstall failure.

## Failure, timeout, and restoration

Each privileged action has an independent context and Job Object. Cleanup and restore receive fresh independent budgets; restore is prioritized. Cancellation kills the complete process tree and waits for quiescence. Capture and verification helpers cannot resolve through PATH or outlive their caller. Final capture must exactly match the canonical trusted baseline or the run is poisoned and later cases stop.

## Test strategy

Strict RED to GREEN is organized in vertical slices:

1. Protocol v3 binding and snapshot schema reject omitted/wrong hashes and endpoint bindings.
2. Config semantic validation rejects the telecom/loopback endpoint, fallback upstreams, and listener ownership ambiguity.
3. Job containment tests prove outer driver, capture, installer, and helper descendants are terminated and quiescent on timeout.
4. Typed lifecycle helper tests prove all thirteen actions, fixed argument construction, post-state assertions, and persistent service ownership.
5. False-pass tests cover stale manifests, swapped artifacts, wrong running images, uninstall residue, config tamper, duplicate listeners, and cleanup masking.
6. Make target contract and Windows cross-builds include driver, sentinel, and lifecycle helper.

The final non-live gate runs repository Go tests, integration repetitions, `go vet`, Windows cross-builds, both Windows PowerShell 5.1 and PowerShell 7 Pester suites, and `git diff --check`. The live disposable-host run remains an explicit Task 10 acceptance gate and is never inferred from non-live success.

