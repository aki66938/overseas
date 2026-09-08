# Task 3 UI refresh report

## Scope

- Updated `apps/regen_access/lib/theme.dart`, `pages/home.dart`, and `pages/details.dart`.
- Updated focused page regressions and all ten page goldens.
- Did not modify window, tray, networking, or Linux drafts.
- The concurrent parent-owned eight-target model update was used for integration verification but is not part of this task's commit.

## TDD evidence

Baseline before edits:

- `flutter test` — PASS, 76 tests.

RED after adding page tests, before page implementation:

- `flutter test test/pages_test.dart` — expected FAIL.
- Connected `good`, `slow`, `failed`, and `unknown` each failed because the old quality subtitle was still rendered.
- The eight-target details fixture failed because `TikTok` was absent while the model still exposed five targets.
- Parent parser regression was separately observed RED with `FormatException: Invalid probe result` before the parent added the three target IDs.

GREEN after implementation and parent model integration:

- Connected quality regressions pass and verify no quality subtitle or `priority_high_rounded` icon.
- Eight labels and eight distinct latency values render; probe and back callbacks pass.
- Default 460×540, 200% text, and narrow 280×320/200% text checks pass without overflow; the details action remains scroll-reachable.

## Visual review

Generated goldens with `flutter test test/goldens_test.dart --update-goldens`, then inspected every 460×540 PNG at original resolution.

- Home: reviewed idle, connecting, connected, degraded, needs-action, unavailable, configuration, and retry.
- Details: reviewed mixed live and historical results.
- Connected and degraded presentations are intentionally identical: dark-green ring/check, title and timer, with no yellow quality warning.
- Genuine unavailable/recovery/configuration/transaction errors retain amber warning marks and their truthful actions.
- Details shows eight compact rows, right-aligned latency, status dots plus text, timestamp/history marker, and the bottom probe action without clipping.

## Final verification

- `flutter analyze` — PASS, no issues found.
- `flutter test` — PASS, 81 tests.
- This includes page/golden tests plus native window/tray lifecycle suites.

## Self-review

- Constructors and callback contracts are unchanged.
- Connected presentation depends on `status.connected`, not aggregate quality.
- Probe quality remains visible only in details, and status meaning is not conveyed by color alone.
- Enlarged text switches details rows/header to wrapping layouts and relies on the existing vertical scroll container.
- Copy says only `HTTPS 首响应延迟`; it makes no bandwidth, login, or AI-functionality claim.
- No deployment was performed.

## Follow-up: concise home footer

- Added a focused regression that initially failed because the home page still rendered `HTTPS 首响应延迟 · 按需启用`.
- Removed only that explanatory footer while preserving the existing card and action proportions.
- Regenerated and reviewed the affected home goldens; measurement semantics remain represented by the details data rather than extra home-page copy.
