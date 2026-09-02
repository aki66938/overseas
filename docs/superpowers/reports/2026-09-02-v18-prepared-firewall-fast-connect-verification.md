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

## Real browsing acceptance

Not claimed. No real overseas-site access was performed in this session; per the plan, the user performs the Connect/Disconnect clicks and site checks after the signed MSI is installed.
