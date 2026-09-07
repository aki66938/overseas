# Task 2 report — local API v1 and compatibility layer

## Implemented

- Added the platform-independent `internal/localapi` v1 request, response, status, validation, projection, and stale-generation cache.
- Kept connection state and route quality as separate fields. Legacy `prepared`/`disconnected` project to `idle`; `failed`/`failed_safe` project to `needs_action` without changing controller state.
- Added a 64 KiB frame bound, fixed action allowlist, v1 validation, response-ID validation, and additive unknown-field handling.
- Restricted diagnostic enablement to the product's fixed 15/30/60-minute choices.
- Added version-aware Windows Named Pipe dispatch. Unversioned Walk requests retain the legacy decoder and connect/disconnect behavior. Presence of a `version` field, including `null`, cannot downgrade to legacy.
- Ordinary v1 responses contain no message/detail/log fields. `probe` and `diagnostic-enable` return explicit `invalid_action` until their owning tasks implement them.
- Added additive `ConnectV1`, `DisconnectV1`, and `StatusV1` client methods. They use the caller's context directly rather than creating a private timeout.
- Added a cancellation watcher that closes an in-flight connection when a deadline-free caller context is canceled, and reject non-empty remote response error codes instead of returning a success-looking status.
- The pipe projects state, error code, and generation from one atomic `Diagnostics()` controller snapshot; raw diagnostic message/detail fields are discarded.
- Added the checked-in `tests/contracts/local-api-v1.json` sample.

## TDD evidence

### RED — shared protocol

Command:

`go test ./internal/localapi ./internal/clientapi`

Expected failure before implementation:

`internal/localapi/protocol_test.go:10:18: undefined: DecodeRequest` (followed by the other new missing protocol symbols); `internal/clientapi` remained green.

### GREEN — shared protocol

Command:

`go test ./internal/localapi ./internal/clientapi`

Result: both packages passed.

### RED — Windows adapter

Command:

`go test ./internal/agent -run 'TestPipeV1' -count=1`

Expected failure before the v1 adapter:

`TestPipeV1ProjectsStatusWithoutLegacyMessage: v1 status returned no response`.

### GREEN — Windows adapter

Command:

`go test ./internal/agent -run 'TestPipeV1' -count=1`

Result: package passed.

### RED/GREEN — v1 client

Before implementation, `go test ./internal/clientapi -run TestRequestV1 -count=1` failed with `client.StatusV1 undefined`. After implementation it passed.

The follow-up duration contract test first failed because `duration_minutes: 1` was accepted; after restricting the decoder to 15/30/60, the focused `TestDecodeRequest` suite passed.

Cancellation/error/coherence follow-ups were also test-first: the client test initially failed to compile without `ErrRequestRejected`, while the pipe test exposed a mixed `connected` generation-13 snapshot. The focused client/pipe v1 suite passed after connection cancellation, response-error, and coherent-snapshot handling were implemented.

## Final verification

- `go test ./internal/localapi ./internal/clientapi`: passed.
- `go test ./internal/agent -count=1`: passed.
- `go test ./... -count=1`: passed, all packages, no failures.
- `git diff --check`: no whitespace errors (only Git's configured LF-to-CRLF warnings).

## Files changed

- `internal/localapi/protocol.go`
- `internal/localapi/projection.go`
- `internal/localapi/protocol_test.go`
- `tests/contracts/local-api-v1.json`
- `internal/clientapi/client.go`
- `internal/clientapi/client_test.go`
- `internal/agent/pipe_windows.go`
- `internal/agent/pipe_windows_test.go`

## Self-review

- Confirmed `internal/localapi` does not import `agent`, platform APIs, UI packages, or log types.
- Confirmed the old strict legacy decoder remains unchanged, while only versioned requests use the additive v1 decoder.
- Confirmed arbitrary unknown fields are ignored but cannot affect dispatch; no path, command, or URL exists in the accepted request model.
- Confirmed response IDs are checked in both the shared decoder and v1 client path.
- Confirmed raw controller messages and diagnostic details are never copied into ordinary v1 responses.

## Concerns

- Quality remains `unknown` until Task 3 publishes a valid current-generation probe result through `UpdateLineQuality`.
- Future action implementations must replace the current explicit `invalid_action` adapter response without changing the v1 action strings.

## Review follow-up

The first review found that the Windows adapter always projected `quality=unknown` and an empty `connected_at`. The fix adds an atomic controller `LocalStatusSnapshot`, records the successful connection time once using `Dependencies.Now`, resets lifecycle metadata on every new generation/automatic restore, and exposes a generation-guarded `UpdateLineQuality` method for Task 3. Invalid, stale, or disconnected quality updates are rejected without changing connection state. The existing `Diagnostics` shape and legacy pipe response remain unchanged.

TDD RED: `go test ./internal/agent -run 'TestControllerLifecycleSnapshot|TestPipeV1ProjectsController' -count=1` failed to compile because `LocalStatusSnapshot`, quality constants, and controller methods did not exist. After adding the initial types, the focused controller test exposed its fixed-clock credential setup (`credential_expired`); the fixture was corrected to use the injected clock. GREEN: the same focused command passed, including connected+slow adapter projection and timestamp formatting.
