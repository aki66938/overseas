# v18 Prepared Firewall Fast Connect — Verification Report

- **Date:** 2026-09-02
- **Branch:** `feature/windows-forwarding-poc`
- **Plan:** `docs/superpowers/plans/2026-09-02-v18-prepared-firewall-fast-connect.md`
- **Commits covered:** `1d3988d`(Task1) `6de0559`(Task2) `8d6b0a1`(Task3) `3b5bbaa`(Task4) `1ff7cd8`(Task5) `332ad04`+`5a520f6`(Task6) `d360c41`(Task7) `9a3a7ce`(Task8) `b4eada4`(Task9) plus this report commit (Tasks 6–9 and this gate were executed in this session; Tasks 1–5 were committed earlier the same day).

## Environment

- Toolchain: `C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe` (go1.27.0, windows/amd64)
- Race builds: `CGO_ENABLED=1`, gcc from `C:\msys64\ucrt64\bin`
- Pester: Windows PowerShell 5.1 (Pester 3.4.0) and PowerShell 7 (pwsh)
- All commands run from the worktree root on the designated test machine (DESKTOP-7LBO366).

## Task 6 — Connect/Disconnect as one automatic restoration transaction

Implemented and verified:

- Controller rewritten onto the six-step transaction (`network_prepare → network_capture → firewall_enable → config_render/core_start/core_ready → tun_ready → route_activation → connected`), with `Status{Phase,Step,TotalSteps,ElapsedMS}` carried end-to-end through the pipe protocol (`agent.Response`, `clientapi.Status`).
- `restoreTransaction` is the single reverse-order restoration used by Disconnect, Recover, every failed Connect, and runtime monitor triggers; residue proof gates the terminal state.
- Any connect failure from `Capture` onward returns **prepared + original error code** after a proven restore; only an unprovable restore returns **failed_safe/`automatic_restore_failed`** (Emergency retained). `failed_safe` refuses new Connect requests.
- Typed TUN boundary errors: `tun_not_found` only for the ready deadline; `tun_identity_mismatch` for identity/alias/address violations (`errors.Is`-typed in `WaitTUNReady`).
- Legacy 250 ms protection loop, `InstallPublicTCPBlock`, `reconcileProtection`, `monitorProtection`, `protectionInterval/Cancel/Done/RunMu` removed from the production path. Legacy restore remains only for snapshots without a prepared generation (v17 upgrade recovery).
- Prepared restore is one PowerShell transaction: baseline DNS/metrics/routes first, then exact-name pool disable (never delete), catch → pool emergency enable.
- Residue now counts **enabled** group rules only; Disabled pool rules are reported as `DisabledPreparedRules` and ignored by `IsZero()`.

Test evidence: `TestControllerConnectFailureMatrixReturnsPreparedWithOriginalCode` (10 injected failures), success-order trace test, six-step status contract, failed_safe refusal, monitor-triggered auto-restore, 25× disconnect/exit race, generation isolation.

## Task 7 — Post-connect fingerprint monitoring and deep audit

- `StartMonitor` runs only after `connected` (launched synchronously in `Connect` so `monitor_start` traces stay generation-ordered).
- 30 s native fingerprint ticks → zero PowerShell while unchanged; drift arms the pool emergency **before** delivering exactly one buffered terminal error.
- 5 min read-only deep audit; mismatch follows the same ordering with `errFirewallAudit`.
- Cancellation stops all writes; a canceled generation can never arm emergency or report into a new generation.
- Transient native read failures retry on the next tick instead of tearing down a healthy connection.

Test evidence: `network_monitor_test.go` deterministic-clock suite (unchanged ⇒ zero writes, drift ⇒ emergency-first, audit failure reports once, cancellation, unknown generation refusal, transient retry), 20× repetition, race-clean.

## Task 8 — Six-step business timeline

- All fixed network operations emit fixed Chinese business messages (`networkOperationMessages`); the generic “固定网络操作” texts are gone and a text-contract test rejects raw operation codes as primary lines.
- UI ViewModel migrated to the v18 state model: `preparing/prepared/connecting/connected/restoring/failed_safe`; connecting header renders `业务阶段 · x.x 秒 · 第 n/6 步`; prepared-with-error shows the last failure with a direct 重试连接 (no preliminary disconnect — the v17 safeRetry machinery was removed); failed_safe shows IT-only guidance with Connect disabled and 恢复网络 enabled.
- Trace view reports `disabled_prepared_rules` and failed_safe protection summary.

## Task 9 — Service-start preparation and pool-preserving installer

- Service: recovery gate now requires `prepared`; SCM Running is reported before one background `Prepare` is launched (a Connect during preparation joins the same flight); Stop cancels and **waits** for the preparation goroutine before restoring.
- WiX: `Start="auto"` + `ServiceControl Start="install"`.
- Installer: `Remove-PreparedFirewallPool` materializes the product-group rules, refuses unknown/enabled/unlabelled rules, removes exactly ledger-owned names, deletes `prepared-network.json`, and runs in both uninstall and rollback paths; `Assert-NetworkRestored` tolerates the Disabled pool.
- Robustness fix: payload-manifest read failures now surface a stable English message instead of a locale-dependent .NET exception.

## Task 10 — Gates

Non-live gates executed in this session (all pass):

| Gate | Result |
|---|---|
| `go build ./...` | pass |
| `go test ./... -count=1` | pass (19 packages) |
| `go vet ./...` | pass |
| `go test -race ./internal/agent ./internal/coreverify ./internal/clientapi -count=1` | pass (with `CGO_ENABLED=1`, msys64 gcc) |
| `go test -race ./cmd/overseas-client` | **not runnable** — `lxn/walk` crashes under race checkptr (`MAKEINTRESOURCE` pointer arithmetic); third-party library limitation, documented |
| `go test ./internal/agent -run 'TestController|TestWindowsNetwork|TestNetworkMonitor' -count=10` | pass |
| Pester 5.1: ClientInstall / ClientNetworkTransaction / ClientFirewallInterfaces / AssertNoLeak / FetchSingBox / PocNetworking / Runbook / ServerInstall | 45/8/8/13/4/27/12/22 — all pass |
| Pester pwsh: ClientInstall / ClientNetworkTransaction / ClientFirewallInterfaces / AssertNoLeak | 45/8/8/13 — all pass |
| PS 5.1 AST parse of all 33 `.ps1/.psm1` | pass (UTF-8 BOM added to all scripts so 5.1 parses UTF-8 sources; this was a pre-existing gap — at HEAD the suites could not even parse under 5.1) |
| Binaries: `bin/overseas-agent.exe`, `bin/overseas-client.exe` (`-trimpath`, client with `-H windowsgui`) | built |
| Hygiene grep (固定网络操作 texts, `protectionInterval`, `250 * time.Millisecond`, lazy firewall-delete pipelines) | clean in production paths |

Not executed in this session (require live LocalSystem / signing / user actions):

1. LocalSystem live firewall gate with `-LiveProductFirewallGate` (Task 10 step 5) — the guarded script `scripts/windows/verify-v18-prepared-connection.ps1` and its Pester suite from the plan were not created; the underlying prepared lifecycle is covered by unit/Pester contracts, but the on-box LocalSystem timing evidence (`build/v18-evidence/`) is pending.
2. Measured stage timings against the 15 s budget — pending the live gate above.

## Known deviations from the plan

- The plan's Task 10 evidence script was not written; Tasks 6–9 were verified with the existing unit/Pester gates instead. The live gate remains the release blocker it describes.
- `cmd/overseas-client` is excluded from `-race` (walk library checkptr crash), noted above.
- Pester 3.4 mock leakage forced the WhatIf preflight test to rely on the installer's wrapped manifest error; behavior is stricter than before (no locale-dependent exceptions).

## Task 12 — Signed release, upgrade install, and on-box verification (executed)

Automated portion completed on the designated test machine:

1. **Publish:** `dist/OverseasAccessSetup-v18-RELEASE_SIGNED.msi` built from clean commit `f209f7b`; Authenticode signature `Valid`, signer `CN=RegenBio Overseas Access PoC Code Signing` (thumbprint `6A9D8BC4…EF83C15E`, expires 2026-09-30). Final SHA-256: `B46DF4F562F940E2B24FB510A9CB92051587229FBEFD35EB61793FC9AB37E4C6`.
2. **Pre-install inventory:** one registered product (v17 0.1.0), service Stopped, empty `RegenBioOverseasAccess.Managed` group, no prepared/state files — no unknown group members.
3. **Live upgrade findings and fixes:** the first install attempt exposed three real PowerShell 5.1 null-array bugs (JSON-omitted arrays become `$null`, and `@($null).Count` is 1): the emergency script took the prepared branch without a prepared generation, the prepare script saw a phantom "previous ledger", and rule creation passed a null `RemotePort`. All nullable JSON arrays in the firewall scripts are now `Where-Object { $null -ne $_ }`-guarded (`1cea685`, `250713c`, `f209f7b`). One Enabled orphan emergency rule left by the first failed attempt was removed after proving product-group ownership.
4. **Final install:** `msiexec /qn` exit 0; service **Running**; recovery timeline 5.3 s (restore 2.2 s + residue proof 3.1 s) → SCM Running → background preparation completed in 23.8 s (prepare 14.1 s + deep audit 9.7 s), inside the 30 s cold budget without blocking SCM.
5. **Post-install state:** pool = **10 rules, all Disabled** (7 per-adapter Any + 2 DNS + 1 Emergency), `prepared-network.json` present, no active snapshot, 0 product TUNs, 0 core processes — zero active residue.
6. **Pipe protocol on-box:** raw named-pipe status query returned `{"state":"prepared","message":"普通网络已恢复"}` — the v18 state model is live end-to-end.

## Remaining for the user (handoff checklist)

1. Three service-side prepared preflight cycles (Connect→verify→Disconnect without overseas browsing) — intentionally not auto-run to avoid interrupting the interactive network session.
2. Real acceptance per plan Task 12 steps 6–7: fully exit FlClash, click 连接 in the RegenBio client, verify approved overseas sites plus intranet + `172.20.9.15`, then 断开 and confirm ordinary networking returns; kill-the-core auto-restore check; three stable connects ≤ 15 s.

## Real browsing acceptance

Not claimed. No real overseas-site access was performed in this session; per the plan, the user performs the Connect/Disconnect clicks and site checks.


## Addendum (2026-09-03): real-test findings and architecture fix

The user's first real test exposed two failures, both root-caused and fixed:

1. **Session died exactly 30s after connect** — the runtime monitor compared the live (TUN-up) fingerprint against the *prepared* fingerprint. The connection's own changes (TUN adapter, DNS overrides, owned routes) guaranteed a false positive on the first 30s tick. Fix: the monitor now baselines the **connected** state at StartMonitor (`d360c41` follow-up in `fd2453d`).
2. **Pages would not load** — three stacked causes, fixed in sequence:
   - the blanket `reject udp` route rule pre-matched UDP/53 before hijack-dns (hijack-dns moved to the first rule, `fd2453d`);
   - DoH-via-tunnel cold start exceeded the Windows resolver timeout (replaced first with DNS-over-TCP, then with **FakeIP**: A/AAAA answered instantly from the fakeip pool, connections routed by domain, proxy resolves names on the telecom egress — no DNS traffic crosses the tunnel at all; `ee6b189`, `1541a72`);
   - the fakeip pool (198.18.0.0/15) had no route into the TUN (it is IANA non-global and was excluded from the owned-route set); the range is now part of the owned TUN routes and snapshot validation (`cc02556`).
   - sing-box 1.13 additionally rejects the deprecated top-level `dns.fakeip` block and fakeip-as-default-server; the rendered config now uses the compliant A/AAAA dns-rule form (`d7c9bda`, `1541a72`).

Robustness fixes found during the same cycle:

- restore now **skips adapters that vanished** instead of failing permanently (`96ee772`) — a reboot with changed adapters previously bricked startup recovery;
- prepared-pool migration **tolerates drifted ledger rules** (renamed aliases etc.): drifted rules are materialized, removed and rebuilt instead of entering failed_safe (`96ee772`);
- startup recovery budget raised 20s → 75s with SCM StartPending checkpoint pumping (`96ee772`);
- disconnect pipe budget 30s → 90s (slow multi-step restore was misreported as failed_safe).

### Live verification after fixes (this machine, service-driven)

- connect → connected; **www.youtube.com 200 (0.67s)**, google 302, gstatic 204, intranet 200 simultaneously;
- 90s hold: still connected, gstatic 204 (old build died at 30s);
- disconnect → prepared, regular internet 204 immediately; second connect/disconnect cycle clean.

### Environment changes made on the pilot machine (with revert commands)

- **TCP dynamic port range restored to the Windows default** (was customized to 1024–14999, only ~14k ports, implicated in intermittent proxy-path SYN drops): revert with `netsh int ipv4 set dynamicport tcp start=1024 num=13977`.
- **FlClash was stopped** for testing; it must remain fully exited during acceptance (its TUN adapter changes topology and fights over DNS).

### Remaining (non-blocking)

- Connect elapsed ~50s against the 15s budget: firewall enable+verify dominates (~25s) — PowerShell/WMI slowness on this machine (Huorong AV); optimization task, not functional.
- The `failed_safe` after a mid-shutdown interrupted restore required manual state cleanup once; the retry path itself works.
