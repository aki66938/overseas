# Probe target health contract follow-up

Date: 2026-09-07
Base: 6be7dea
Status: DONE

## Change

Each published Result now contains optional `consecutive_failures` as `*int` with `omitempty`. Absent remains unknown for older services/responses; a non-nil zero is authoritative zero. Aggregate annotates the completed round using its existing per-target counters (success clears, failures cap at three), preserving raw attempt fields and existing overall quality thresholds. No polling code changes counts.

Scheduler snapshots deep-copy the optional count values so caller mutation cannot alter retained history. Existing canceled-generation history retains counts and original generation; the next connected generation starts a fresh aggregate. Shared IPC encode/decode validation rejects negative or greater-than-three counts and accepts absence. Existing diagnostic functionality and GUI are unchanged.

## TDD evidence

Go executable: C:/Users/Eleme/codex_workspace/.tools/go1.27.0/go/bin/go.exe

RED: `go test ./internal/lineprobe ./internal/localapi -count=1` failed with `ConsecutiveFailures undefined` in new aggregate and optional/bounds contract tests before implementation.

RED extended: `go test ./internal/lineprobe ./internal/localapi ./internal/clientapi -count=1` also failed with `ConsecutiveFailures undefined` in fake-clock scheduler history/reset/deep-copy tests and the newly attached client test.

GREEN: same three-package command passed after adding the optional value, completed-round annotations, deep-copy snapshots and shared validation.

GREEN integration: `go test ./internal/agent ./internal/lineprobe ./internal/localapi ./internal/clientapi -count=1` passed after adding current/historical pipe assertions.

Final full suite (run once): `go test ./... -count=1` exited 0; every test package passed, including new diagnostics and regen-access packages. fakeconnect has no test files. `git diff --check` exited 0 (Git emitted LF-to-CRLF normalization notices only).

## Coverage

- First/second/third failed rounds and count cap at three, independent healthy target stays authoritative zero, recovery resets.
- Fake-clock scheduler counts 0,1,2,3,0,1 across actual completed rounds; repeated Snapshot polls do not change values.
- Mutating a returned counter pointer does not change future current or historical snapshots.
- Disconnect Manual returns retained generation and counter without traffic; reconnection starts fresh at one failure rather than continuing prior count.
- Newly constructed client sees authoritative count three on its first status response, without having observed previous polls.
- Old response without the field decodes as absent; explicit zero survives JSON roundtrip; negative and >3 rejected.
- Pipe current results and disconnected historical results preserve authoritative zero and existing generation semantics.

## Files

- internal/lineprobe/probe.go, aggregate.go, scheduler.go
- internal/lineprobe/aggregate_test.go, scheduler_test.go
- internal/localapi/protocol.go, probe_test.go
- internal/clientapi/probe_test.go
- internal/agent/lineprobe_windows_test.go
- This report

## Self-review / concerns

Only the result contract, completed-round annotation and snapshot copy changed in production. No changes to cadence, timeout, quality thresholds, routes, connection state, diagnostic implementation, GUI or deployed services. No live Internet tests, production operations or deployment. The existing live TUN route verification gate remains separate and unperformed.
