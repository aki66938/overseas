# Windows UI Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for inline execution or superpowers:subagent-driven-development for delegated execution. Track steps with checkboxes.

**Goal:** Deploy the approved light-console UI and eight-target probes to the Windows pilot without changing tunnel behavior.

**Architecture:** Keep Flutter presentation separate from API parsing and Go HTTPS measurement. Diagnose Gemini from the installed service's actual errors before selecting a regression fix. Preserve the service API version and native window lifecycle.

**Tech Stack:** Flutter/Dart, Go, Windows PowerShell, WiX MSI, Authenticode.

## Global Constraints

- Main and details remain 460×540 logical size; no maximize.
- Concise Chinese; no homepage site-quality warnings or quality-driven exclamation icon.
- Real connection/service failures remain visible. Details retain real probe failures and history markers.
- Eight sites: Google, Pinterest, Gemini, ChatGPT, Claude, TikTok, 亚马逊, Facebook.
- No TLS bypass, fake latency, new login/update features, or routing/firewall changes.
- Diagnostics default off; preserve untracked Linux supervisor drafts.
- Pilot only: 172.20.20.200, SSH port 22, RegenBio\rb-185, existing id_ed25519.
- No automatic main merge or GitHub push.

## Task 1: Establish Gemini failure evidence

Files: inspect `internal/lineprobe/probe.go`, `scheduler.go`, `targets.go`; use existing workspace `outputs/windows-pilot-20260908/check-service-api.ps1` for bounded status capture.

Interfaces: `Prober.Probe(context.Context, Target) Result`; inspect `error_code`, `http_status`, `latency_ms` from current API status, not browser appearance alone.

- [ ] SSH with BatchMode and StrictHostKeyChecking; confirm installed version and service state.
- [ ] Collect current probe status using the existing SYSTEM one-shot read-only collector. The SSH NETWORK token cannot access the app pipe; do not loosen its ACL.
- [ ] Compare HEAD and GET for `https://gemini.google.com/` and `/app` using verified TLS, recording status, error, and timing. No cookies or credentials.
- [ ] If curl differs from the app, reproduce with the actual Go Prober in a bounded diagnostic test before attributing cause.
- [ ] Record reproducible cause and proposed smallest fix in the acceptance receipt; if not reproducible, report it and leave measurement semantics intact.

## Task 2: Eight-target contract and probe regression

Modify: `internal/lineprobe/targets.go`, `apps/regen_access/lib/model/status.dart`.
Tests: `internal/lineprobe/probe_test.go`, `apps/regen_access/test/status_test.dart`; locate other fixed-five assumptions with `rg 'pinterest|gemini|claude' internal tests apps/regen_access/test`.

Interfaces: retain `Targets() []Target`, `targetNames`, and `Status.fromResponse(Map<String,dynamic>)`.

- [ ] Add a failing target-count/identity test:

```go
func TestEightTargets(t *testing.T) {
    want := []string{"google", "pinterest", "gemini", "chatgpt", "claude", "tiktok", "amazon", "facebook"}
    got := Targets()
    if len(got) != len(want) { t.Fatalf("targets=%d", len(got)) }
    for i, id := range want { if got[i].ID != id { t.Fatalf("target %d=%s", i, got[i].ID) } }
}
```

- [ ] Run Go lineprobe tests; expect target count failure before implementation.
- [ ] Append Go targets `{"tiktok", "https://www.tiktok.com/"}`, `{"amazon", "https://www.amazon.com/"}`, `{"facebook", "https://www.facebook.com/"}` and Dart map entries `'tiktok': 'TikTok', 'amazon': '亚马逊', 'facebook': 'Facebook'`.
- [ ] Add parser tests accepting all eight IDs while still rejecting unknown and duplicate IDs.
- [ ] For a demonstrated Gemini bug, first reproduce the exact error in a local TLS/transport fixture; run RED, make the minimum measured fix, run GREEN. Keep existing timeout, untrusted TLS, redirect, 405 fallback and 5xx tests passing.
- [ ] Run covering Go contracts and Dart status tests; commit only task files.

## Task 3: Light-console presentation

Modify: `apps/regen_access/lib/theme.dart`, `pages/home.dart`, `pages/details.dart`.
Tests: `apps/regen_access/test/pages_test.dart`, `goldens_test.dart`, `goldens/*.png`.

Interfaces: preserve HomePage and DetailsPage constructors/callbacks; retain Status as authoritative connection state.

- [ ] Add widget regression checks for connected quality values `good`, `slow`, `failed`, `unknown`: title remains 已连接; no site-quality subtitle or priority-high icon; real error states remain unchanged.
- [ ] Add an eight-result details fixture and verify all labels, latency, history marker and probe/back callbacks; check no Flutter overflow at standard size and enlarged text.
- [ ] Run widget tests to establish expected RED before changing pages.
- [ ] Apply light gray-green scaffold, white rounded content cards, dark-green typography and restrained borders/shadows. Home uses a connection ring, state, timer, action and details entry with balanced vertical spacing.
- [ ] Bind connected ring appearance to `status.connected`, not aggregate quality. Busy/loading and actual service errors retain distinct visuals and disabled actions.
- [ ] Replace roomy table spacing with eight compact rows; right-align latency, pair small status dots with text, keep update time and bottom probe action. Use scrolling for enlarged text, not a resized window.
- [ ] Run `flutter analyze` and `flutter test`. Update goldens only after reviewing rendered home/details/error/history images at their actual dimensions; rerun tests without update mode.
- [ ] Confirm native window and tray lifecycle tests still pass; commit presentation and reviewed goldens.

## Task 4: Signed pilot upgrade and handoff

Create: `docs/acceptance/windows-ui-refresh-20260908.md`.
Reuse: `scripts/windows/publish-client-release.ps1`; dedicated clean build clone under workspace outputs.

- [ ] Run Go `./internal/lineprobe ./tests/contracts ./cmd/installer-verifier`, complete Flutter tests/analyze and Windows packaging tests before committing final source.
- [ ] Build version 0.1.10 from a clean source checkout using the existing approved PoC signing thumbprint, SDK SignTool and exact DigiCert timestamp endpoint. Preserve the old build clone's untracked collector.
- [ ] Verify MSI signature with `signtool verify /pa /tw`, package manifest with installer verifier and record SHA256/source commit.
- [ ] Copy to the pilot, verify transferred hash; preserve protected rollback backup. Upgrade using MSI logging, allowing the app's normal service/network lifecycle to handle the interruption.
- [ ] Verify MSI exit code, installed version, service Running, installed payload verification and API response. Remove only this run's completed temporary diagnostic task.
- [ ] Record observed Gemini/eight-site results separately from UI and long-duration acceptance. Provide package path and installed-app launch instructions; ask user to inspect real GUI.

## Self-review

The tasks cover visual hierarchy, eight targets, Gemini evidence, truthful details, unchanged window/tray behavior, bounded diagnostics and signed deployment. Gemini cause is deliberately an evidence gate, not a speculative endpoint or TLS change. No production infrastructure or Linux drafts are included.

## Execution receipt — 2026-09-08

- [x] Task 1: Gemini reproduced on pilot; 25 KiB headers exceed old16KiB limit; HEAD sporadic EOF, GET200. Same actual Go Prober validated after fix.
- [x] Task 2: Eight targets and bounded compatibility fallback; TDD and full Go PASS; independent review approved at1d0ff0c, Dart f49651d.
- [x] Task 3: UI4288cac + footer refinement0f325d4; Flutter82PASS/analyze clean,10goldens reviewed, final integrated review approved.
- [x] Task 4: Three initial timestamp failures led to bounded signing retry1239e5b; Pester202PASS and review approved. Signed0.1.10 published/verified, pilotMSI0/payload0/serviceRunning/APIconnected/eighttargetsresponding; interactiveGUI launched.

Detailed evidence, source commit and MSI hash: `docs/acceptance/windows-ui-refresh-20260908.md`. Existing backup retained; no main merge/push. User GUI assessment and long-duration validation remain outside automated completion.
