# macOS PKG 与状态栏 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 单个 PKG 安装到应用程序目录，提供纯状态栏紧凑面板，保留已验证的网络核心。

**Architecture:** 原生宿主拥有一个持久 Flutter 控制器和 NSPopover；AccessBridge 仅桥接固定 API 与 shell 操作。PKG 使用版本化暂存 payload，既有受约束安装器负责预检、身份选择、激活和回滚；包脚本不直接覆盖活动安装。

**Tech Stack:** Swift/AppKit、Flutter/Dart、Go、launchd、pkgbuild/productbuild；Apple Silicon 实机。

## Global Constraints

- 规范：`docs/superpowers/specs/2026-09-11-macos-pkg-menubar-design.md`，全部条款适用于下面任务。
- Windows不动、Linux暂缓。保留两份未跟踪 Linux supervisor 文件。
- 不加入企业登录、设备注册、检查更新、复制诊断摘要。
- 保持内网限定、现有节点策略、八站点探测和默认关闭的诊断。
- Developer ID、System Extension、关闭 SIP/Gatekeeper、放宽 authorizationdb 均不在范围内。
- 基准内容尺寸480×224逻辑点，主页面和详情页面相同大小。
- 启动仅显示状态栏图标，不自动弹面板、不自动连接。本轮不新增登录自启动。
- 首次授权必须在本机图形会话验证；不收集管理员密码，不绕过信任验证。
- 改造分两个独立交付：任务1–2状态栏；任务3–5安装器。两者通过任务6整体验收，不把部分交付称作完成。

## 环境与执行约定

仓库为当前 `feature/cross-platform` linked worktree，不再另建或清理工作树。命令除说明外在仓库根执行。本地 Go 为 `C:/Users/Eleme/go-toolchain/go/bin/go.exe`；Mac 源码与工具链沿用 `/Users/codexdiag/regen-access-poc/`，先核验 SSH 主机密钥、当前连接和磁盘状态。

Mac：Go `toolchain/go/bin/go`，Flutter `toolchain/flutter/bin/flutter`（均相对上面的工作目录）。根权限测试只针对测试 Mac，不修改 EC 策略。同步按明确文件列表，不覆盖未知远端改动。每个任务保留 RED/GREEN 命令、退出码和证据；提交只添加该任务路径。

## Task 1：持久状态栏面板宿主

**Files:**
- Create: `apps/regen_access/macos/Runner/MenuBarHost.swift`
- Create: `apps/regen_access/macos/Tests/MenuBarHostTests.swift`
- Modify: `apps/regen_access/macos/Runner/{AccessBridge.swift,MainFlutterWindow.swift,AppDelegate.swift,Info.plist}`
- Modify: `apps/regen_access/macos/Runner/Base.lproj/MainMenu.xib`
- Modify: `apps/regen_access/macos/Runner.xcodeproj/project.pbxproj`

**Interfaces:** `MenuBarHost.init(controller: NSViewController)` owns the popover and status item; `show()`, `toggle()`, `close()`, `setMenu(_ menu: NSMenu)` are main-thread only. `AccessBridge.init(controller: FlutterViewController, host: MenuBarHost)` replaces its weak window reference. AppDelegate retains bridge/host independently of `mainFlutterWindow`.

- [ ] Add native tests before implementation. Test controller identity survives close/show, initial `isShown == false`, content size, and `close()` does not invoke a network action. Essential assertions:

```swift
let controller = NSViewController()
let host = MenuBarHost(controller: controller)
assert(host.popover.contentViewController === controller)
assert(host.popover.contentSize == NSSize(width: 480, height: 224))
assert(!host.popover.isShown)
host.close()
assert(host.popover.contentViewController === controller)
```

- [ ] Run native tests using `xcrun swiftc` with AppKit and production host source; expect missing MenuBarHost before implementation. Tests requiring a status bar run in the console session, not headless SSH alone.
- [ ] Implement host with one persistent popover, `.transient` behavior, status button `.leftMouseUp`/`.rightMouseUp` dispatch. Left toggles; right temporarily presents the menu, then restores button handling. `show()` anchors to the button bounds, constrains to screen visible frame, activates the accessory app and makes the popover key. Esc dismisses. Do not create a network client in host.
- [ ] Move Flutter creation/plugin registration into retained application startup, remove visible nib window and its outlet. Keep exactly one controller and bridge. Add `<key>LSUIElement</key><true/>`. Reopen calls `host.show()` and returns false; app startup does not call show. Update Xcode source references; delete obsolete window code only after all references are removed.
- [ ] Run native tests and `flutter build macos --release`; verify no missing source membership. In console test launch, reopen, Escape, external click, screen edge, details scrolling, and absence from Dock/Cmd-Tab. Record screenshot evidence; a successful build alone is not UI acceptance.
- [ ] Commit: `feat(macos): host compact UI in persistent menu bar popover`.

## Task 2：菜单与安全退出

**Files:** `apps/regen_access/macos/Runner/AccessBridge.swift`, `apps/regen_access/lib/api/mac_shell.dart`, `apps/regen_access/test/mac_shell_test.dart`, `apps/regen_access/macos/Tests/MenuBarHostTests.swift`.

**Interfaces:** existing `regen_access/shell` methods `update`, `action`, `home`, `details`, `safeExit` retain their payloads. `safeExit` returns true only for idle plus `needsRestore == false`. UI error remains Mac-only.

- [ ] Extend existing shell tests: disconnect exception, status exception, connected status, idle-but-needsRestore all return false; only restored idle returns true. Example expected invariant: `expect(await shell.safeExit(), isFalse);` with the existing fake client returning idle/needsRestore.
- [ ] Run `cd apps/regen_access && flutter test test/mac_shell_test.dart test/mac_client_test.dart`; capture a deliberately new failure before code change.
- [ ] Remove home/details menu entries; keep disabled state summary, action, safe exit. Host display on failed exit must show concise `网络尚未恢复，请重试` feedback (native sheet on popover is acceptable), retain icon/process, restore action enabled state from last valid update. Guard repeated exit and disabled actions. Do not force terminate on timeout.
- [ ] Re-run tests/build. Exercise failed and successful exit in controlled test doubles first; actual exit must confirm route/DNS recovery and icon removal. Collapse/reopen must preserve current elapsed time and not trigger extra probe requests.
- [ ] Commit: `fix(macos): preserve safe exit and minimal menu actions`.

## Task 3：安装预检与 launchd 停止等待

**Files:** `scripts/macos/installer/platform_darwin.go`, `platform_darwin_test.go`; create `scripts/macos/installer/owner_darwin.go`, `owner_darwin_test.go`.

**Interfaces:** `selectInstallOwner(existing *receipt, consoleName string) (account, error)` uses `lookupOwner`; receipt is authoritative on upgrade and must resolve back to the same real local UID. `(*macLife).waitUnregistered(deadline time.Time) error` uses existing `registered()` semantics, not process existence.

- [ ] Add table tests for root/loginwindow/empty/unresolvable console users; valid local console UID501; receipt UID501 with different console user still selects501; missing receipt user refuses. Inject account lookup/console identity for tests, never rely on the test runner's own identity.
- [ ] Add lifecycle test command sequences: bootout → registered → absent succeeds; permanent registered times out; unknown launchctl error immediately fails. Exact native absence response remains the only accepted absence.
- [ ] Run `go test ./scripts/macos/installer -count=1` on Mac, expect new behavior tests fail. Use fake clock/sleeper so timeout test is bounded without ten seconds real waiting.
- [ ] Implement console identity using `/dev/console` owner plus local directory lookup and UID consistency; upgrade uses protected receipt. Add bounded 10-second unregister wait at 100ms intervals after successful bootout. Preserve journal and refuse activation on timeout/error.
- [ ] Run regular-user and root installer tests; ensure existing unknown-state, symlink and permissions tests still pass. Root run uses the already authorized maintenance channel, not embedded credentials.
- [ ] Commit: `fix(macos): validate install owner and await launchd removal`.

## Task 4：Applications 迁移事务

**Files:** `scripts/macos/installer/{main.go,package.go,package_test.go,platform_darwin.go,platform_darwin_test.go}`.

**Interfaces:** constant `applicationPath = "/Applications/RegenBio Access.app"`; receipt v2 records App manifest identity and backup location, while accepting a validated v1 receipt for migration. Existing `macLife.prepareStage`, `activate`, `uninstall` retain the lifecycle contract and include external App changes in rollback.

- [ ] Add regression matrix: fresh external App install; v1 internal App migration; valid v2 upgrade; foreign same-name App refusal; symlink destination refusal; failure after App swap restores previous App/backend/plist/receipt; uninstall preserves foreign App and preexisting CA. Inject failure at every mutation boundary in existing fake lifecycle harness.
- [ ] Run installer tests RED. Make expected filesystem and receipt assertions explicit, including both old and new App locations, not just returned error.
- [ ] Stage App on the destination filesystem under root-controlled unique staging. Verify manifest/codesign before activation. Backup only the claimed App; move it atomically within that filesystem. Backend and App swaps form a journaled transaction, recording progress before each mutation. On failure reverse only recorded owned mutations; do not delete unknown state. Interrupted transaction is detected before a new installation proceeds.
- [ ] Update installed validation, package validation, rollback and uninstall to account for external App. Validate legacy internal App against its old protected manifest before retiring its entry; preserve backup. Do not change network config or socket permissions.
- [ ] Run all installer tests regular/root, plus `go test ./...`. Record v1-to-v2 migration evidence on a staged fixture before touching the live installation.
- [ ] Commit: `feat(macos): migrate application with transactional rollback`.

## Task 5：自包含 PKG 与首次授权门禁

**Files:** create `scripts/macos/build-pkg.sh`, `scripts/macos/pkg/{Distribution.xml,postinstall,Welcome.html,License.html}`; modify `scripts/macos/installer/platform_darwin.go`, `deploy/macos/README.md`. Keep legacy DMG build for recovery until new package acceptance.

**Interfaces:** build script arguments are verified App path, pinned core path, new output `.pkg`; uses existing manifest builder and fixed CA digest. New fixed installer mode `install-local --payload ABS` chooses owner internally and invokes the same transaction; no GUI-selected arbitrary shell command.

- [ ] Add package inspection test that expanded payload contains only versioned staging, never live `/Applications` or backend paths. Verify manifest, core digest, CA fingerprint disclosure, root execution guard, no username/TRUST/password prompt. Reject preexisting output instead of overwriting.
- [ ] Run test RED against missing builder. Implement pkgbuild component with root-owned versioned staging and executable postinstall; productbuild wraps it with clear graphical welcome/license consent. Generate escaped XML values safely. Propagate installer nonzero exit to Installer; never append unconditional success.
- [ ] Use `pkgutil --expand-full <new.pkg> <new-temp>` to verify paths, scripts, payload and ownership; `sh -n` scripts; validate XML with `plutil`/XML parser as appropriate. No signing or notarization claim.
- [ ] Test first-time CA operation in a local graphical installation. Exact bundled CA digest: `0D344A6F39FD4252C96F0E5606E2F4E7205CB2E59C44603C542AA8C132A711F8`. Existing valid trust is read-only. Denied/partial import must fail and roll back; preserve other trust entries. If root postinstall cannot request supported system authorization, STOP this task with captured error and a narrowly scoped graphical-authorization design amendment; do not claim completed PKG or weaken authorizationdb.
- [ ] Inspect own transaction receipt and macOS package receipt after success/failure/retry. Do not use macOS package receipt alone as evidence of successful activation. Validate documented IT uninstall restores owned state and leaves unrelated trust untouched.
- [ ] Commit only verified path: `feat(macos): distribute self-contained transactional PKG`.

## Task 6：实机交付与分层验收

**Files:** create `docs/acceptance/2026-09-11-macos-pkg-menubar.md`; update `deploy/macos/README.md`.

- [ ] Record baseline status, app/backend hashes, owner, routes/DNS and trust. If connected, ask for a test interruption window before installing; never silently disconnect. Preserve previous working package and root-owned rollback files.
- [ ] Execute full Go tests, focused Flutter tests, native host tests, release build and package inspection. Full Flutter tests report existing golden failures separately; do not regenerate unrelated golden baselines.
- [ ] Install locally through Installer, verify `/Applications` ownership and ordinary-user startup; capture actual menu/popover visuals. Verify close/reopen, safe exit success/failure, eight sites, one manual probe, elapsed time. Check fixed socket/root peer still enforced.
- [ ] Validate Google/YouTube HTTPS with TLS checking on; browser rendering/video is separate from curl. Disconnect restores baseline routes/DNS, reconnect works. Never use `curl -k` as acceptance.
- [ ] Run 60-minute connected test with provided monitoring mechanism; separately test sleep/wake when user permits. Report untested checks explicitly, including fresh unmanaged-device authorization when no such machine is available.
- [ ] Deliver exact PKG path, SHA256 (`shasum -a 256`), source commit and test report. Commit documentation; no GitHub push or release publication as an implicit packaging step.

## 执行审查

任务1–2覆盖宿主交互和退出；3–4覆盖身份、停止等待、迁移与回滚；5覆盖图形安装和首次信任；6覆盖实际交付与未验证边界。首次CA授权是显式验证门禁，不是预先承诺成功的实现细节。安装器实现前必须完整读取现有 lifecycle/manifest 测试，沿用其注入接口，不另造第二套安装流程。
