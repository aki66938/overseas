# Task 4 Report — Reversible Windows Forwarding Scripts

## Final status

Task 4 and both safety-review rounds are implemented in the assigned linked worktree. This report supersedes the earlier accumulated Task 4 notes and describes the final code only.

No production networking script was executed. Pester replaced the Windows networking cmdlets with stateful mocks, so development and verification did not change any real adapter, route, forwarding, firewall, or WinNAT state.

Destination authorization remains at the binding enforcement boundary specified by the user: the telecom/operator whitelist. Task 4 deliberately does not duplicate that policy with a brittle resolved-IP firewall list. The probe CLI tests only configured `approved_targets`; the Windows rules provide interface-scoped fail-closed behavior.

## Final implementation

- `snapshot.ps1` validates three distinct canonical interface indexes, captures the baseline inventories, builds a schema-v2 SHA-256 envelope, writes through a flushed create-new temporary file, atomically publishes it, and cleans a failed temporary publication. It returns a path only after publication.
- `apply-poc.ps1` accepts one transaction-level `ShouldProcess` decision. It validates snapshot freshness and integrity, computer/interface identity, sole employee-owned active IPv4 default route, current address/route/internal-CIDR overlap, other CGNAT use, empty WinNAT state, and absence of owned firewall state before mutation.
- Apply creates the employee-interface outbound `RemoteAddress Internet` block first, then two interface-scoped allow rules, verifies their exact identity/direction/action/scope/interface/description/Profile Any in `ActiveStore`, creates the exact NAT, and enables forwarding only on WireGuard and telecom.
- Apply compensation removes permissive rules first, removes NAT, restores attempted forwarding, and positively re-reads all WinNAT and both forwarding baselines. The employee public-Internet block is removed last only when NAT is absent and both forwarding baselines are proven. Otherwise it remains and the thrown error contains an explicit `EMERGENCY` state. A mutation that reports failure after changing state is covered.
- `rollback-poc.ps1` accepts one transaction-level `ShouldProcess` decision. A hash-valid, transaction-bound recovery snapshot does not expire, although future timestamps, wrong computer, edited payloads, adapter/default-route drift, mismatched subnet metadata, and foreign/conflicting state are still rejected.
- Rollback is resumable and idempotent. It accepts each owned NAT/rule already absent and either applied or already-baseline forwarding, derives/binds the subnet through snapshot routes plus the current WireGuard address and any remaining owned metadata, and removes only exact owned names. Markerless forwarding drift is rejected as potentially unrelated state. A missing `ActiveStore` guard triggers emergency cleanup rather than aborting; any effective rule that remains must still match exactly, including Profile Any.
- Rollback `-WhatIf` succeeds from the pristine snapshot baseline and reports the complete intended owned cleanup/forwarding restore without calling a mutator.
- Every inner mutating cmdlet in snapshot, apply, compensation, and rollback explicitly receives `-Confirm:$false` after the single outer transaction decision. There are no selective safety skips.
- The required portable-Go gate exposed a pre-existing Windows clock-resolution flake: a successful loopback dial could measure `0s`. `internal/probe/probe.go` now preserves its positive-latency result invariant by reporting the minimum representable duration (1 ns) only for a successful non-positive measurement. Approved-target selection and dialing policy are unchanged.

## TDD evidence

The second-review behavior tests were added before production changes. The Pester 3.4 RED run against review-fix commit `de4b877` was:

```text
RED: Total=23 Passed=16 Failed=7
```

The seven expected failures were emergency compensation block retention, Profile Any enforcement, expired recovery use, missing-ActiveStore emergency cleanup, partial-rollback retry, nested confirmation suppression, and pristine-baseline rollback preview. The pre-existing stale-apply test remained green, proving the age exemption was scoped to recovery only.

Final self-review added a markerless-forwarding regression before its guard. Its RED evidence was:

```text
SELF_REVIEW_RED Total=27 Passed=26 Failed=1
```

The completed Pester 3.4 suite contains 27 mocked/behavioral and AST tests. In addition to the RED cases, it covers both NAT-removal and forwarding-restoration compensation failures, a cmdlet error after partial mutation, exact rollback scope, preservation of an unrelated same-group rule, markerless forwarding drift, apply failure compensation, edited/stale apply snapshots, canonical-index alias collisions, internal/address/route/CGNAT overlap, sole default-route ownership, existing WinNAT rejection, inactive apply policy, internal-route preservation, atomic snapshot cleanup/publication, and transaction-level WhatIf behavior.

The Go timing flake was reproduced before its fix with the portable toolchain:

```text
go test ./internal/probe -run TestRunSuccessfulHTTPSProbe -count=20
7 of 20 iterations failed: TCPLatency = 0s, want positive
```

After the minimum-duration fix, the focused gate passed 100 consecutive iterations:

```text
ok corp.example/overseas-access-gateway/internal/probe (count=100)
```

## Final verification evidence

Windows PowerShell 5.1.28000.1643 with Pester 3.4.0:

```text
PS5_PESTER Total=27 Passed=27 Failed=0
```

PowerShell 7.6.4 with Pester 3.4.0:

```text
PWSH_PESTER Total=27 Passed=27 Failed=0
```

Portable Go 1.27 regression suite (`C:/Users/Eleme/codex_workspace/.tools/go1.27.0/go/bin/go.exe test ./... -count=1`):

```text
ok corp.example/overseas-access-gateway/cmd/poc-probe
ok corp.example/overseas-access-gateway/internal/config
ok corp.example/overseas-access-gateway/internal/inventory
ok corp.example/overseas-access-gateway/internal/probe
```

PowerShell parser verification:

```text
AST scripts/windows/snapshot.ps1 errors=0
AST scripts/windows/apply-poc.ps1 errors=0
AST scripts/windows/poc-networking-common.ps1 errors=0
AST scripts/windows/rollback-poc.ps1 errors=0
AST tests/powershell/PocNetworking.Tests.ps1 errors=0
```

Source/diff gates:

```text
APPLY_SHOULDPROCESS=1
ROLLBACK_SHOULDPROCESS=1
PROHIBITED_PATTERN_SCAN=none
git diff --check: exit 0
```

The prohibited scan covers `LocalAddress`, firewall-profile changes, `netsh`, group-wide firewall removal, and unscoped NAT removal.

## Remaining concern

The evidence is mock/AST/unit-test evidence, not a live Windows networking integration result. Task 7 must still use the operator-controlled gate to validate the host's actual `Internet` keyword classification, local-policy merge into `ActiveStore`, WinNAT behavior, telecom path, rollback preview, and physical-disconnect no-leak result. No control-plane or employee-client rollout is authorized until that gate reports `PASS`.

## Commit lineage

- `e0320bf feat: add reversible Windows PoC networking`
- `de4b877 fix: harden Windows PoC networking transactions`
- Second-review commit: `fix: make Windows recovery fail-closed and resumable` (the exact hash is reported in the handoff because the report is part of that commit).
