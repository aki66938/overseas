# Task 1 report: Darwin local API transport

## Scope

Implemented only the Darwin Unix-domain socket server/client transport and its Darwin tests. The existing non-Windows/non-Linux client stub now excludes Darwin. No service lifecycle, networking, Flutter, packaging, or remote system was changed.

## TDD evidence

- RED: `GOOS=darwin GOARCH=arm64 go test -c ./internal/platform/darwin` failed because `NewSocketServer` and `newSocketServer` did not exist.
- GREEN compile: after implementation, Darwin arm64 test binaries for `./internal/platform/darwin` and `./internal/clientapi` compiled successfully.
- A subsequent Darwin compile caught use of unsupported `unix.SOCK_CLOEXEC`; implementation was corrected to call `unix.CloseOnExec` and both packages compiled successfully.
- Native execution is delegated to the parent Mac validation. Root-only tests explicitly skip when not UID 0 and must not be treated as acceptance when skipped.

## Behavior implemented

- Fixed endpoint `/var/run/regen-access/control.sock`.
- Requires root service execution, resolves the selected UID through Darwin's account database, and rejects absent, low/system, underscore-prefixed, `nobody`, or reserved upper-range identities.
- Requires the final parent directory to be a real root:wheel `0755` directory. The standard `/var` to `/private/var` ancestor mapping is not rejected because only the final runtime directory is checked with `Lstat`.
- Fails closed when the endpoint exists and removes only the exact socket inode created by this server.
- Creates owner-UID:wheel `0600` socket; accepts only root or selected owner UID using Darwin `LOCAL_PEERCRED`/`Xucred`.
- Passes administrator authority only for UID 0.
- Reuses `localapi` bounded framing/codec and agent action deadlines, limits active clients to 16, and closes clients deterministically on cancellation.
- Client validates directory/socket metadata, ensures the socket belongs to its own non-system UID (root may inspect), and verifies the connected service peer is root.
- Root fixtures launch real UID 501 and UID 502 subprocesses: the selected owner completes a request without administrator authority, while the non-owner is denied by the private socket. The root round trip uses the client dialer and therefore exercises root-service peer authentication.

## Verification

- `GOOS=darwin GOARCH=arm64 go test -c ./internal/platform/darwin` — pass (compile only).
- `GOOS=darwin GOARCH=arm64 go test -c ./internal/clientapi` — pass (compile only).
- Windows host: `go test ./internal/clientapi ./internal/localapi` — pass.
- Windows host: `go test ./internal/agent` — pass.
- `git diff --check` — pass; Git emitted only its existing LF/CRLF working-copy warning for `client_stub.go`.
- Native Mac Go 1.27.0: `go test ./internal/platform/darwin ./internal/clientapi` — pass (`darwin` 1.344s, `clientapi` 0.886s).
- Native Mac root test binary: `sudo /Users/codexdiag/regen-access-poc/darwin-socket.test -test.v -test.timeout=60s` — exit 0. Real UID 501/502 credential test passed (0.47s), all four unsafe-path cases passed, root-authenticated client round trip and owned cleanup passed, and the explicit oversized-frame/idle-client cancellation test passed.
- Review-fix RED: Darwin cross-compilation failed on the intentionally missing `validateOwnerUID` API before implementation.
- Review-fix native rerun: both non-root packages passed; the non-root current-account database test passed; the sudo suite passed including `TestSocketRejectsNonOwnerAfterAccept`. That test relaxes only its fixture socket mode and proves a real UID 502 connection is rejected by post-accept `LOCAL_PEERCRED` before dispatch. The current-user lookup test skips under root by design.

## Required native Mac commands

```sh
/Users/codexdiag/regen-access-poc/toolchain/go/bin/go test ./internal/platform/darwin ./internal/clientapi
sudo /Users/codexdiag/regen-access-poc/toolchain/go/bin/go test -v ./internal/platform/darwin
```

The root command is required for filesystem ownership, peer credential, request round-trip, cancellation, and owned-socket cleanup acceptance. A non-root run that skips these fixtures is not acceptance.

## Files

- `internal/platform/darwin/socket_darwin.go`
- `internal/platform/darwin/socket_darwin_test.go`
- `internal/clientapi/client_darwin.go`
- `internal/clientapi/client_stub.go`
- `internal/clientapi/client_stub_test.go`
- `.superpowers/sdd/mac-task-1-report.md`

## Remaining concern

Parent completed both native non-root and root fixture runs, as recorded above. The server intentionally refuses stale sockets rather than unlinking them; protected stale-socket recovery remains a service-composition requirement, not an implemented feature of this transport task.
