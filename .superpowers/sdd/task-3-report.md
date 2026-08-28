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
