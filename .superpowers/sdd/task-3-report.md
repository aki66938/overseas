# Task 3 Report

Date: 2026-08-28
Base commit: `f990ac4`

## Scope

Implemented Task 3 pinned core acquisition and verification in this worktree:

- Added `internal/coreverify.Verify` with Windows reparse-point, PE-header, hash, ACL/owner, and Authenticode checks.
- Added pinned sing-box acquisition script and manifest for `v1.13.19` Windows amd64.
- Added focused Go and Pester coverage for the verifier and acquisition flow.
- Discharged Task 2's carried gate by validating representative rendered server/client configs with the acquired pinned `sing-box.exe check -c`.

## Official primary sources and pinned facts

Source 1:

- Release API: `https://api.github.com/repos/SagerNet/sing-box/releases/tags/v1.13.19`
- Observed tag: `v1.13.19`
- Observed `published_at`: `2026-08-17T09:47:06Z`
- Observed asset: `sing-box-1.13.19-windows-amd64.zip`
- Observed asset digest field: `sha256:e011a4def2f5e2b143ed54adb2b1a20a6be407806ab4442f3667f1dd817a2c8d`
- Observed immutable asset URL: `https://github.com/SagerNet/sing-box/releases/download/v1.13.19/sing-box-1.13.19-windows-amd64.zip`

Source 2:

- Downloaded from the immutable asset URL above into `artifacts/sing-box-1.13.19-windows-amd64.zip`
- Observed archive SHA-256: `e011a4def2f5e2b143ed54adb2b1a20a6be407806ab4442f3667f1dd817a2c8d`
- Extracted executable SHA-256: `a4476dd768168a77e249050066bb32774addefcc37da123978623e7b2819de28`
- Observed `Get-AuthenticodeSignature` status: `NotSigned`
- Observed signer subject/thumbprint: empty
- Observed `sing-box.exe version` first line: `sing-box version 1.13.19`

Reference used for the Task 2 gate fix:

- Migration note: `https://sing-box.sagernet.org/migration/#migrate-outbound-dns-rule-items-to-domain-resolver`
- Root cause: real `sing-box.exe check -c` rejected the rendered client config because the `direct` outbound had no `domain_resolver` while multiple DNS servers were configured.

## RED -> GREEN record

### Task 3 verifier RED

Command:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./internal/coreverify
```

Result: FAIL.

Observed failure:

- `internal/coreverify` implementation types and `Verify` were missing, so the new tests did not compile.

### Task 3 verifier GREEN

Command:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./internal/coreverify
```

Result: PASS.

### Task 3 acquisition-script RED

Command:

```powershell
Invoke-Pester tests/powershell/FetchSingBox.Tests.ps1
```

Result: FAIL.

Observed failure:

- `scripts/fetch-sing-box.ps1` was absent.

### Task 3 acquisition-script GREEN

Commands:

```powershell
pwsh.exe -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester 'tests/powershell/FetchSingBox.Tests.ps1' -Output Detailed } else { Invoke-Pester -Script 'tests/powershell/FetchSingBox.Tests.ps1' -Verbose }"
```

```powershell
powershell.exe -NoProfile -Command "Invoke-Pester -Script 'tests/powershell/FetchSingBox.Tests.ps1' -Verbose"
```

Result: PASS on `pwsh.exe 7.6.4.0` and `powershell.exe 10.0.28000.1`.

### Task 2 carried gate RED

Representative configs were rendered with:

```powershell
cmd /c "echo MDEyMzQ1Njc4OWFiY2RlZg==|bin\access-config.exe render-server -in deploy\server\server-policy.example.yaml -node vm101 -listen 0.0.0.0 -upstream 127.0.0.1:8080 -out artifacts\task3-config-check\server.json -secret-stdin"
```

```powershell
cmd /c "echo MDEyMzQ1Njc4OWFiY2RlZg==|bin\access-config.exe render-client -in deploy\server\server-policy.example.yaml -node vm101 -out artifacts\task3-config-check\client.json -secret-stdin"
```

Then checked with the acquired binary:

```powershell
artifacts\sing-box-1.13.19-inspect\sing-box-1.13.19-windows-amd64\sing-box.exe check -c artifacts\task3-config-check\client.json
```

Result: FAIL.

Observed failure:

- `missing route.default_domain_resolver or domain_resolver in dial fields is deprecated in sing-box 1.12.0 and will be removed in sing-box 1.14.0`

Hypothesis test:

- Adding `domain_resolver: "corp-dns"` to the rendered `direct` outbound made `sing-box.exe check -c` pass on the client config.

### Task 2 carried gate GREEN

Added a new failing test in `internal/singconfig/client_test.go` asserting `outbounds[0].domain_resolver == "corp-dns"` when corporate DNS is configured, then updated `internal/singconfig/client.go` to render that field on the `direct` outbound.

Focused regression after the fix:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./internal/singconfig ./cmd/access-config
```

Result: PASS.

Representative syntax checks after rebuilding `bin/access-config.exe` and re-rendering:

```powershell
artifacts\sing-box-1.13.19-inspect\sing-box-1.13.19-windows-amd64\sing-box.exe check -c artifacts\task3-config-check\server.json
```

```powershell
artifacts\sing-box-1.13.19-inspect\sing-box-1.13.19-windows-amd64\sing-box.exe check -c artifacts\task3-config-check\client.json
```

Result: PASS for both server and client.

## Files changed

- Added `internal/coreverify/verify.go`
- Added `internal/coreverify/verify_test.go`
- Added `scripts/fetch-sing-box.ps1`
- Added `tests/powershell/FetchSingBox.Tests.ps1`
- Added `sing-box.manifest.json`
- Modified `Makefile`
- Modified `internal/singconfig/client.go`
- Modified `internal/singconfig/client_test.go`

## Verification

Focused Go:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./internal/coreverify
```

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./internal/singconfig ./cmd/access-config
```

Results: PASS.

Full Go regression:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./...
```

Result: PASS for `cmd/access-config`, `cmd/poc-probe`, `internal/accessmodel`, `internal/config`, `internal/coreverify`, `internal/inventory`, `internal/probe`, `internal/singconfig`, and `internal/verdict`.

Focused Pester:

```powershell
pwsh.exe -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester 'tests/powershell/FetchSingBox.Tests.ps1' -Output Detailed } else { Invoke-Pester -Script 'tests/powershell/FetchSingBox.Tests.ps1' -Verbose }"
```

```powershell
powershell.exe -NoProfile -Command "Invoke-Pester -Script 'tests/powershell/FetchSingBox.Tests.ps1' -Verbose"
```

Results: PASS.

Full Pester regression:

```powershell
pwsh.exe -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester tests/powershell -Output Detailed } else { Invoke-Pester -Script tests/powershell -Verbose }"
```

Result: PASS, `48` tests.

Build equivalents:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe build -trimpath -o bin\access-config.exe .\cmd\access-config
```

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe build -trimpath -o bin\poc-probe.exe .\cmd\poc-probe
```

Results: PASS.

Note:

- `make test` / `make build` could not be executed because `make` is not installed in this Windows environment. I ran the exact underlying Go and Pester commands directly instead.

## Self-review notes

- The prolonged step was the one-time immutable GitHub asset download. It was not a hanging test: `curl.exe -L -o artifacts\sing-box-1.13.19-windows-amd64.zip ...` took about 15 minutes 29 seconds because of slow transfer throughput.
- The client-config regression was not in Task 3 itself; the real pinned `sing-box.exe check -c` surfaced a missing `domain_resolver` field in Task 2 output, and that is now fixed in source and covered by test.
- The verifier currently accepts an unsigned pinned binary only when the caller provides no signer allowlist. That matches the observed `NotSigned` upstream state for `v1.13.19`.

## Review follow-up: portability and deterministic reparse coverage

Review item 1 root cause:

- `Makefile` exported a workstation-specific Go path: `C:/Users/Eleme/codex_workspace/.tools/go1.27.0/go/bin`.
- That made repository execution non-portable and blocked callers from injecting their own Go binary.

Review item 2 root cause:

- `TestVerifyRejectsReparsePoint` depended on `os.Symlink`, which can be unavailable without the required Windows privilege.
- The skip avoided false failures, but it also meant the rejection path was not guaranteed to be exercised.

### Review RED

Portable Makefile structural RED:

```powershell
pwsh.exe -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester 'tests/powershell/Runbook.Tests.ps1' -Output Detailed } else { Invoke-Pester -Script 'tests/powershell/Runbook.Tests.ps1' -Verbose }"
```

Observed failure:

- expected `^GO ?= go$`
- file still contained the hardcoded `export PATH := C:/Users/Eleme/...`

Deterministic reparse RED:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./internal/coreverify
```

Observed failure:

- `undefined: installLstatTestSeam`
- the new deterministic test also exposed one unused local binding

### Review GREEN

Fixes applied:

- Replaced the hardcoded path in `Makefile` with `GO ?= go` and switched targets to `$(GO)`.
- Added a production test seam `lstatPath = os.Lstat` and used it from `openRegularFileNoReparse`.
- Switched the reparse test to inject `fs.ModeSymlink` metadata through that seam, so the reparse rejection path runs even when symlink creation is unavailable.

Focused GREEN commands:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./internal/coreverify
```

```powershell
pwsh.exe -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester 'tests/powershell/Runbook.Tests.ps1' -Output Detailed } else { Invoke-Pester -Script 'tests/powershell/Runbook.Tests.ps1' -Verbose }"
```

Results:

- `internal/coreverify`: PASS
- `Runbook.Tests.ps1`: PASS, `4` tests

Regression after the review fixes:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./...
```

```powershell
pwsh.exe -NoProfile -Command "if ((Get-Command Invoke-Pester).Parameters.ContainsKey('Output')) { Invoke-Pester 'tests/powershell/FetchSingBox.Tests.ps1' -Output Detailed } else { Invoke-Pester -Script 'tests/powershell/FetchSingBox.Tests.ps1' -Verbose }"
```

```powershell
powershell.exe -NoProfile -Command "Invoke-Pester -Script 'tests/powershell/FetchSingBox.Tests.ps1' -Verbose"
```

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe build -trimpath -o bin\access-config.exe .\cmd\access-config
```

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe build -trimpath -o bin\poc-probe.exe .\cmd\poc-probe
```

Results:

- Full Go regression: PASS
- Focused FetchSingBox Pester on `pwsh.exe`: PASS, `4` tests
- Focused FetchSingBox Pester on `powershell.exe`: PASS, `4` tests
- Direct builds: PASS

---

# Task 3 implementation report

Status: DONE_WITH_CONCERNS (Windows TUN live route verification remains a release gate; no production operations performed).

## Implemented

- Fixed five-target HTTPS HEAD probes; fresh connections, OS route/DNS path, no environment proxy, normal TLS verification, no redirects, credentials, cookies or request body. HEAD 405 falls back to GET reading at most 1024 bytes. HTTP status retained; 2xx–4xx reachable, 5xx unsuccessful; 403/429 do not establish account/AI access.
- Injected transport/clock; sanitized fixed error codes, UTC-capable timestamps and bounded latency. Five parallel targets share a five-second scheduler timer budget. Standalone Probe also has a five-second context deadline.
- Connected lifecycle callback outside controller mutex, canceled by normal disconnect and automatic restoration. Scheduler performs an immediate round plus 30-second rounds, coalesces manual requests, rejects obsolete sessions and publications, and starts no disconnected traffic.
- Per-target three-failure hysteresis; majority sustained failures yield failed without touching routes or connection state. Recovery clears failure counts; insufficient healthy majority preserves prior quality until sustained threshold. Median successful latency <1000ms good, 1000–5000ms slow.
- Windows service creates scheduler and connects callback/quality publisher; pipe v1 status/probe expose bounded results matching current generation. Disconnected IPC probe returns probe_unavailable. IPC allows 10 seconds total (five-second network budget plus response overhead). Client adds ProbeV1 and StatusDetailsV1; legacy wire fields remain unchanged.
- Explicit opt-in live route verification checklist with truthful current validation status.

## TDD evidence

Go executable: `C:/Users/Eleme/codex_workspace/.tools/go1.27.0/go/bin/go.exe`.

RED 1: `go test ./internal/lineprobe -count=1` failed with undefined Aggregate, Result, NewProber and Target before package implementation.

RED 2: after spec clarification, same command failed `TestProbeTLSStatusesAndNoRedirect/Service_Unavailable`: Reachable:true HTTPStatus:503 ErrorCode empty. Corrected 5xx classification; GREEN same command passed.

RED 3: scheduler tests failed with undefined Timer, NewScheduler, Snapshot before scheduler implementation; GREEN same command passed after implementation.

RED 4: `go test ./internal/agent ./internal/localapi ./internal/clientapi -count=1` failed because ConnectedLifetime, WithLineProbe, ProbeGeneration/ProbeResults and ProbeV1 did not exist. Added lifecycle/API/service integration; GREEN focused suite passed.

RED 5: `TestAggregateRetainsPreviousQualityUntilSustainedMajorityFailure` failed `premature degradation: unknown`. Retained prior quality until the sustained threshold; GREEN focused suite passed.

RED 6: `TestFallbackFailureIsNotReachable` failed with Reachable:true HTTPStatus:405 ErrorCode:network_error; corrected failure result after fallback. GREEN `go test ./internal/lineprobe -count=1` passed.

Final verification: `go test ./... -count=1` exited 0 on Windows, all packages passed (fakeconnect has no test files). Includes service/client builds, agent lifecycle and pipe tests, localapi validation, clientapi tests, TLS tests, fake-clock period/budget/coalescing/cancel/stale-generation/three-failure/recovery/reconnect tests, and existing integration suite. `git diff --check` exited 0; Git prints existing LF→CRLF normalization notices only.

## Files

- internal/lineprobe/{targets,probe,scheduler,aggregate}.go
- internal/lineprobe/{probe,scheduler,aggregate}_test.go
- internal/agent/controller.go; internal/agent/pipe_windows.go
- internal/agent/lineprobe_test.go; internal/agent/lineprobe_windows_test.go
- internal/localapi/protocol.go; internal/localapi/probe_test.go
- internal/clientapi/client.go; internal/clientapi/probe_test.go
- cmd/overseas-agent/main_windows.go
- docs/testing/line-probe-route-verification.md

## Self-review and concerns

No network transaction restructuring; existing controller and pipe files are large, so additions are small and targeted. Scheduler never synchronously calls Controller while holding its mutex. Outdated scheduler contexts cannot start or publish a later round. Buffered per-round responses prevent canceled-round workers from blocking publication. Production transport honors cancellation; injected transports are expected to honor their request context.

No live tunnel or route-path evidence was collected and no production host/configuration/network changes or deployment occurred. The checked-in checklist explains required IPv4/IPv6 interface/PID traffic correlation before release. Current UI work is a later task: expose these results as “HTTPS 首响应耗时”, never bandwidth or AI-feature availability.

## Review amendments — 2026-09-07

Three reviewed issues are corrected:
1. GET fallback now closes the body immediately after response headers (zero bytes read, within the 1024-byte maximum). A stalled body cannot replace a valid HTTP 200 with a synthetic timeout.
2. Latency/CheckedAt describe the selected HEAD or GET request independently. The outer five-second total deadline is still shared across both attempts.
3. Disconnected status / StatusDetailsV1 preserve last results with the original ProbeGeneration and explicit probe_historical:true. History is accepted only in non-connected states at generation <= current; future generations and connected historical results are rejected. Connecting hides old results, successful reconnect clears them. Disconnected probe returns probe_unavailable with optional stored history and sends no traffic.

RED: go test ./internal/lineprobe -count=1 failed TestProbe405BoundedFallbackAndLatency (2400ms accumulated, read=1024) and TestFallbackCompletesAtTLSResponseHeadersWithoutBody ("GET headers arrived, but probe is waiting for response body"). The latter uses a real local TLS server flushing GET 200 headers and then stalling until request cancellation.
GREEN: same command exited 0 after header-only and per-attempt timing changes.

RED: go test ./internal/localapi ./internal/agent ./internal/clientapi -count=1 failed on missing ProbeHistorical field before history contract implementation.
GREEN: same command exited 0 after bounded explicit history support. Tests cover idle older-generation history, automatic-restore equal-generation history, rejected future/connected/unmarked histories, disconnected API calls producing no traffic, reconnect not exposing history, and StatusDetailsV1 returning historical results.

Final amended verification: go test ./... -count=1 exited 0 on Windows, all test packages passed; git diff --check exited 0 (only LF-to-CRLF Git notices).
Files amended: internal/lineprobe/probe.go and probe_test.go; internal/localapi/protocol.go and probe_test.go; internal/agent/pipe_windows.go and lineprobe_windows_test.go; internal/clientapi/probe_test.go; docs/testing/line-probe-route-verification.md; this report.
Live Windows TUN path validation remains unperformed; no production changes or deployment.

This file preserves the earlier pinned-core Task 3 report above; the lineprobe milestone report is appended separately because the requested report path was reused.
