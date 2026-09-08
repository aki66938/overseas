# Compact B Flutter presentation report

## Scope

- Implemented the approved 480 x 224 logical Flutter content shell.
- Added a persistent 138px connection rail shared by home and details.
- Kept one navigation control: `线路详情` / `返回主页` in the rail.
- Rendered all eight real probe targets as two columns and four rows at normal scale.
- Preserved existing client, lifecycle, polling, tray and action callbacks.

## TDD evidence

- Baseline: `flutter test` passed 82 tests before changes.
- RED: focused details test failed because the legacy home had no standalone `08:42` rail duration.
- GREEN: focused Compact B test passed after the presentation implementation.
- Functional suite: `flutter test test/pages_test.dart test/lifecycle_test.dart test/tray_state_test.dart` passed 53 tests, including 480 x 224, 200% DPI, doubled text, narrow viewport, all eight targets and no-overflow assertions.
- Goldens: updated only after functional GREEN; 10 golden tests passed. Visually inspected `home_connected.png`, `details_mixed.png`, and `home_retry.png`.

## Files

- `apps/regen_access/lib/app.dart`
- `apps/regen_access/lib/pages/connection_rail.dart`
- `apps/regen_access/lib/pages/home.dart`
- `apps/regen_access/lib/pages/details.dart`
- `apps/regen_access/lib/theme.dart`
- `apps/regen_access/test/pages_test.dart`
- `apps/regen_access/test/lifecycle_test.dart`
- `apps/regen_access/test/goldens_test.dart`
- `apps/regen_access/test/goldens/*.png` (10 approved-state images)

Unrelated Linux drafts and the parent plan were not modified or staged.

## Follow-up review fixes

- Added a width-bound regression for 280 x 320 at normal text scale with all eight 5000ms results. RED reproduced eight 33px horizontal RenderFlex overflows; GREEN uses the details panel's actual available width to select the single-column layout while retaining four two-column rows at 480 x 224.
- Added assertions that `返回主页` remains enabled and renders with explicit `#edf5ef` foreground; delayed details golden capture until the pressed overlay clears.
- Added a centered home content-group assertion and aligned the approved title/action group vertically.
- Five-character rail errors such as `配置不可用` and `网络未恢复` now use the compact title size rather than orphaning the final character.
- Final verification after all follow-up fixes: full `flutter test` passed 83 tests and `flutter analyze` reported `No issues found`.
