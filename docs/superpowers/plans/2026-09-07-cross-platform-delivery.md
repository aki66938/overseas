# Cross-platform Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付 Windows/macOS GUI 与 Ubuntu/Rocky CLI，保留已验证的连接与恢复行为。

**Architecture:** Flutter 负责展示，Go 负责状态、配置、探测与事务。保留 `agent.NetworkManager`、`agent.ProcessSupervisor` 接口，小步接入平台实现。macOS 数据面由 Packet Tunnel Extension 承载。

**Tech Stack:** Go 1.27.0、Flutter、sing-box、Windows Service/Named Pipe、systemd/Unix Socket、Swift/Network Extension、WiX、DEB/RPM、Apple Developer ID。

## Global Constraints

- 规范：`docs/superpowers/specs/2026-09-04-cross-platform-ui-architecture-design.md`，提交 `0443873`。
- Windows/macOS 提供 GUI；Ubuntu 22.04/24.04、Rocky Linux 9 仅 CLI。
- macOS 仅 Apple Silicon，内部签名、公证分发。
- 仅公司内网，IT 预置配置；无账号、注册、公网控制面、自更新。
- 同一个固定尺寸窗口切换主页面与详情；以 460×540 逻辑尺寸为视觉基准；DPI 缩放不改变逻辑尺寸。
- 无最大化；最小化到任务栏/Dock；关闭窗口隐藏到托盘/菜单栏。
- 无检查更新、复制诊断或用户日志入口。
- 诊断默认关闭；管理员可开启 15/30/60 分钟；到期或重启关闭。
- 探测每 30 秒，整轮 5 秒，单目标连续失败 3 次降级。
- 100 次连接循环、72 小时稳定性、每个平台至少 5 台新设备、卸载零网络残留。
- 每个任务独立提交；只提交本任务文件，不使用 `git add .`。

## 执行与依赖

顺序：任务 1–5（共享能力）→ 6–8（Windows）→ 9–10（Linux）→ 11–12（macOS）→ 13（联合验收）。

使用新 worktree 开发，主分支保留已验证版本。任务 1–5 先在 Windows 上运行，每次更改控制器后执行原有回归。iOS/Android 本轮保留协议和展示层复用边界，不计入三端完成。

本机尚未发现 Flutter/Dart 命令。执行时安装并固定 SDK 版本；macOS 需要真实 arm64 Mac、Xcode 和可用 Developer ID 签名身份。不能用 Windows 交叉编译结果代替 Apple 实机证据。

## 文件责任

| 路径 | 责任 |
|---|---|
| `internal/agent/controller.go` | 保留连接事务与恢复语义 |
| `internal/localapi/` | 跨平台 v1 协议、验证、状态投影 |
| `internal/lineprobe/` | 目标探测、调度、结果归并 |
| `internal/diagnosticmode/` | 临时诊断授权和过期 |
| `internal/platform/linux/` | 网络事务、进程、socket |
| `cmd/regen-access/` | Linux/管理员 CLI |
| `cmd/overseas-agent/` | 平台服务入口 |
| `apps/regen_access/` | Flutter GUI、平台桥接和测试 |
| `apps/regen_access/macos/PacketTunnel/` | Apple 隧道扩展 |
| `deploy/linux/` | systemd、DEB/RPM、证书安装 |
| `deploy/macos/` | 签名、公证、PKG |
| `tests/contracts/` | 三端共享协议样本与测试 |
| `docs/acceptance/` | 实机步骤与证据表 |

## Task 1: 基线、工具与平台可行性

**Files:** 新建 `docs/acceptance/platform-prerequisites.md`、`deploy/toolchains.json`；读取现有 `deploy/client/build-lock.json`、`sing-box.manifest.json`、CI。

- [x] 在独立 worktree 执行 `go test ./... -count=1`、`Invoke-Pester tests/powershell -EnableExit`；记录基线失败，未解决前不改事务。2026-09-07：Go 全通过，Pester 143/143。
- [ ] 核对 Flutter 支持平台、Apple Network Extension 分发 entitlement、嵌入 sing-box 构建入口与许可，使用对应官方资料；记录版本、地址、构建命令和校验值。
- [ ] 在实际 macOS arm64 构建最小 Packet Tunnel 容器，验证签名、安装、启动、停止；此任务是可行性门槛，不冒充完整客户端。
- [ ] 清点 Windows、Ubuntu、Rocky、Mac 实机及签名身份；缺少平台只阻塞该平台验收，其余开发继续。
- [ ] 将 SDK 版本和来源固定到工具锁文件，记录 `flutter --version`、`dart --version`、`go version`、`xcodebuild -version`。
- [ ] 提交：`docs(build): record cross-platform prerequisites`。

## Task 2: 本机 API v1 与兼容层

**Files:** 新建 `internal/localapi/protocol.go`、`projection.go`、`protocol_test.go`、`tests/contracts/local-api-v1.json`；修改 `internal/clientapi/client.go`、`internal/agent/pipe_windows.go`。

**Interfaces:** 消费现有 `agent.Status`；输出独立序列化模型。连接状态与线路质量分别保存，线路慢不会伪装成隧道断开。

```go
type Request struct {
    Version int `json:"version"`
    ID string `json:"id"`
    Action string `json:"action"`
    DurationMinutes int `json:"duration_minutes,omitempty"`
}
type Status struct {
    State string `json:"state"`
    Quality string `json:"quality"`
    ErrorCode string `json:"error_code,omitempty"`
    ConnectedAt string `json:"connected_at,omitempty"`
    Generation uint64 `json:"generation"`
}
```

- [ ] 建立行为测试：未知字段可忽略；未知 action、版本错误、超长输入拒绝；响应 ID 必须匹配；过期 generation 不覆盖新状态。
- [ ] 执行 `go test ./internal/localapi ./internal/clientapi`，先确认新用例失败。
- [ ] 实现 v1 解码与状态映射；将旧 `prepared` 映射为用户可见 `idle`，保留原控制器状态，避免再次出现卸载协议字面值冲突。
- [ ] 普通状态不得携带详情日志；限制消息 64 KiB，超时由调用方 context 控制。IPC 不接受任意路径、命令或 URL。
- [ ] Windows Named Pipe 接入兼容适配；旧 Walk 客户端仍可连接与断开。
- [ ] 执行上述测试及 `go test ./internal/agent -count=1`，通过后提交 `feat(api): add versioned local contract`。

## Task 3: 线路探测与调度

**Files:** 新建 `internal/lineprobe/{targets,probe,scheduler,aggregate}.go` 及对应 `_test.go`；API 接入结果。

**Interfaces:** `Probe(ctx context.Context, target Target) Result`；`Target{ID,URL string}`；`Result{ID string, LatencyMS int64, Reachable bool, HTTPStatus int, ErrorCode string, CheckedAt time.Time}`。注入 HTTP transport 与时钟，禁止测试访问公网。

- [ ] 用本地 TLS 测试服务器覆盖 200、302、403、429、503、超时、证书不可信；403/429 仅证明网络可达，不能证明账号或 AI 功能可用。
- [ ] 用假时钟验证 30 秒周期、5 秒总预算、3 次连续失败、恢复成功清零、断开取消、重连结果不串代。
- [ ] 执行 `go test ./internal/lineprobe` 确认失败。
- [ ] 固定目标 URL：`https://www.google.com/`、`https://www.pinterest.com/`、`https://gemini.google.com/`、`https://chatgpt.com/`、`https://claude.ai/`；不带 Cookie、登录凭据或正文。
- [ ] 请求使用 HEAD、独立连接测量 DNS 到首响应；记录原始 HTTP 状态，禁止关闭 TLS 验证。405 可做限长 GET，最多读取 1024 字节。
- [ ] UI 显示 HTTPS 首响应耗时，不称带宽测试；暂定 <1000 ms 为正常、1000–5000 ms 为较慢，原型中的几十毫秒不作为生产阈值。
- [ ] 一次手动探测复用正在进行的一轮；超过半数目标持续失败才降级；探测失败本身不删除路由或切换公网出口。
- [ ] Windows 实机验证请求确经已连接通道；固定目标不能证明所有海外流量可用。通过后提交 `feat(probe): add bounded line health checks`。

## Task 4: 默认关闭的临时诊断

**Files:** 新建 `internal/diagnosticmode/{gate,gate_test}.go`；修改 `cmd/overseas-agent/main_windows.go`、`internal/traceevent/recorder.go`；接入 v1 管理命令。

**Interfaces:** `Enable(now time.Time, duration time.Duration) error`、`Enabled(now time.Time) bool`、`Close() error`；授权由 IPC 端验证真实调用者身份，不能信任 JSON 的管理员字段。

- [ ] 用假时钟测试默认 false、15/30/60 分钟、非法时长拒绝、重启 false、过期关闭文件；普通用户启用被拒绝。
- [ ] 执行 `go test ./internal/diagnosticmode ./internal/traceevent` 确认失败。
- [ ] 默认使用空 Sink，不创建日志文件；仅开启时创建 Recorder。数据面 stdout/stderr 的持久记录同时受门控。
- [ ] 每文件 2 MiB，最多 5 个；保留既有脱敏规则。网络恢复快照属于事务状态，不按诊断日志关闭。
- [ ] 测试开启期间故障、自动过期、服务重启和凭据脱敏；提交 `feat(diagnostics): add expiring admin mode`。

## Task 5: 共享边界和平台编译保护

**Files:** 新建 `tests/contracts/platform_boundary_test.go`；修改必要的平台 build tags、`internal/clientapi/client_stub.go` 和 `.github/workflows/build.yml`。

- [ ] 用 Go import graph 检查 `localapi`、`lineprobe`、`diagnosticmode` 不导入 Windows/Linux/Apple API 或 UI 包。
- [ ] 测试非 Windows 平台协议样本解析；失败原因必须是待适配能力，不应是共享类型丢失。
- [ ] 将共享请求类型从 Windows/stub 重复定义中集中；保持 `NetworkManager` 和 `ProcessSupervisor` 的事务接口。
- [ ] Windows/Linux 原生 runner 执行共享测试；macOS runner执行协议测试；真实网络测试显式 opt-in。
- [ ] 验证三平台编译与 Windows 全量回归，提交 `refactor(core): enforce platform boundaries`。

## Task 6: Flutter 同尺寸主页面与详情

**Files:** 新建 `apps/regen_access/` Flutter 工程；重点 `lib/app.dart`、`lib/api/access_client.dart`、`lib/model/status.dart`、`lib/pages/home.dart`、`lib/pages/details.dart`、`lib/theme.dart`、`test/pages_test.dart`。

**Interfaces:** Dart `AccessClient` 提供 `Future<Status> status()`、`connect()`、`disconnect()`、`Future<List<ProbeResult>> probe()`；测试注入 fake client。

- [ ] Golden/Widget 测试覆盖 idle、connecting、connected、degraded、needs_action；同一窗口切页无尺寸变化。
- [ ] 执行 `flutter test` 确认页面用例失败。
- [ ] 实现固定 460×540 逻辑尺寸、深绿主操作、浅绿成功状态；使用已确认原型作为布局参考，数值明确为假数据。
- [ ] 主页面显示状态、连接时长、连接/断开、详情；详情显示五个目标、延迟、更新时间与立即测速。
- [ ] 错误页只显示短文案和动作；无检查更新、复制诊断或日志入口。窄显示区域、200% DPI、大字体允许内容滚动避免裁切。
- [ ] `flutter analyze`、`flutter test` 通过；提交 `feat(ui): add shared desktop pages`。

## Task 7: Windows IPC、窗口与托盘

**Files:** 新建 `apps/regen_access/windows/runner/access_bridge.{h,cpp}`、`tray_controller.{h,cpp}`；修改 Flutter runner 与 `lib/api/access_client.dart`；新增 `test/tray_state_test.dart`。

- [ ] 对菜单模型测试所有状态：连接中禁止重复请求；故障显示重试与仅恢复网络；隐藏/显示不触发 disconnect。
- [ ] 原生桥只连接固定 Named Pipe，调用在后台线程执行并支持超时；Flutter 不提权。
- [ ] 只保留最小化和关闭；最小化进入任务栏；关闭隐藏；托盘左键聚焦、右键菜单，单实例再次启动聚焦已有窗口。
- [ ] “退出应用”关闭 GUI/托盘并保留服务及当前连接；菜单文案明确为“退出应用”，不混用“断开”。“开机时启动”只控制 UI 登录启动，不自动连接。
- [ ] `flutter test`、`flutter build windows --release`；Windows 实机测试关闭、恢复、DPI、重复启动、Explorer 重启后托盘恢复。
- [ ] 提交 `feat(windows): integrate Flutter shell and tray`。

## Task 8: Windows MSI 与正常升级

**Files:** 修改 `deploy/client/Files.wxs`、`Product.wxs`、`install-client.ps1`、`scripts/windows/build-client-artifacts.ps1`、`publish-client-release.ps1`、`inspect-client-msi.ps1` 和安装器行为测试。

- [ ] 建立旧 0.1.7 → 新 GUI 的升级测试，覆盖代理返回 prepared/idle、活动连接、缺失服务、历史重复注册。
- [ ] 打包 Flutter exe、DLL 和 data 目录，签名并将每个文件纳入 manifest；原有证书指纹验证保留。
- [ ] 修复卸载/升级对恢复状态的判定，仍验证真实零残留，不依赖永久绕过旧保护或手动删服务。
- [ ] 检查准确的证书归属；不能卸载公司共享信任证书；清理由安装器记录的本产品资源负责。
- [ ] `Invoke-Pester tests/powershell -EnableExit`、MSI 解包校验；干净机安装/升级/回滚/卸载实测。
- [ ] 提交 `feat(installer): package Flutter Windows release`。

## Task 9: Linux 服务、网络事务与 CLI

**Files:** 新建 `cmd/regen-access/main.go`、`main_test.go`、`cmd/overseas-agent/main_linux.go`、`internal/platform/linux/{socket,network,supervisor,recovery}.go` 及对应测试。

**Interfaces:** Linux adapter 实现现有 `agent.NetworkManager`、`agent.ProcessSupervisor`；CLI 消费 API v1。

- [ ] CLI golden 测试覆盖 connect/disconnect/status/probe、非零退出码、服务不可用；管理员诊断命令拒绝普通用户。
- [ ] Unix Socket 固定 `/run/regen-access/control.sock`，目录 root 所有，授权组仅允许连接操作；使用 peer credentials 校验诊断权限。
- [ ] 网络测试放在隔离 namespace：IPv4/IPv6、默认路由、NetworkManager、systemd-resolved、SSH 管理连接、网络更换和重复恢复。
- [ ] 服务只修改已记录接口和路由；启动捕获快照、写入前持久化、失败逆序恢复。处理 sing-box 进程组退出与超时，不复用 Windows Job Object 实现。
- [ ] Ubuntu/Rocky 原生执行 `go test ./...`；CLI 从普通账户连接成功，诊断需 sudo；提交 `feat(linux): add service and CLI`。

## Task 10: DEB/RPM 与证书安装

**Files:** 新建 `deploy/linux/regen-access.service`、`deploy/linux/debian/`、`deploy/linux/rpm/regen-access.spec`、`scripts/linux/build-packages.sh`、`tests/linux/package-lifecycle.sh`。

- [ ] 在 Ubuntu 22.04、24.04 与 Rocky 9 新系统测试安装、重装、升级、卸载、重启。
- [ ] 单元文件配置固定服务路径、受限运行目录、启动恢复；启动服务不等于自动连接。
- [ ] 系统 CA 使用发行版原生刷新工具；记录证书指纹及安装前存在性，避免误删共享 CA。
- [ ] CLI 能检测缺配置、权限错误、网关不可达；安装失败保留可执行恢复工具。
- [ ] `dpkg-deb --info`、`rpm -qip` 核对元数据，并原生安装验证；提交 `feat(packaging): add Linux DEB and RPM`。

## Task 11: macOS Packet Tunnel 与 Flutter 桥

**Files:** 新建 `apps/regen_access/macos/PacketTunnel/PacketTunnelProvider.swift`、`TunnelBridge.swift`、entitlements、共享 Go 绑定入口 `mobile/core/`；修改 macOS runner。

- [ ] 在任务 1 已验证的签名环境中编译扩展；验证 App Group、Keychain access group 和 provisioning 匹配。
- [ ] Go 绑定仅暴露平台无关配置、状态和探测；扩展负责 TUN 文件描述符和 OS 网络设置，不能直接启动桌面外置进程。
- [ ] 状态通过 provider message/受保护 App Group 传递；App Group 本身不作为命令鉴权或可靠事件总线。
- [ ] 测试扩展终止、用户撤销 VPN 权限、睡眠/唤醒、Wi-Fi 切换、UI 退出后继续连接以及重启后普通网络可用。
- [ ] Flutter 页面复用；菜单栏和红黄按钮行为按规范实现；DPI 使用逻辑尺寸。
- [ ] Mac 上执行 `flutter test`、`flutter build macos --release`、扩展实机测试；提交 `feat(macos): integrate packet tunnel client`。

## Task 12: macOS 签名、公证与 PKG

**Files:** 新建 `deploy/macos/entitlements/`、`scripts/macos/build-pkg.sh`、`scripts/macos/verify-package.sh`、`tests/macos/install-lifecycle.sh`。

- [ ] 分别核验 App、扩展、嵌入库、PKG 的签名与 entitlement；凭据只从系统安全存储读取。
- [ ] PKG 安装指定 CA 到 System Keychain 并验证信任；不全局放宽 TLS。
- [ ] 提交公证并装订票据；`codesign --verify --deep --strict`、`spctl --assess`、`xcrun stapler validate` 通过。
- [ ] 在没有开发工具链的新 Mac 上安装、首次授权、连接、关闭 UI、卸载恢复；签名/公证成功不代替网络验收。
- [ ] 提交 `feat(packaging): add notarized macOS package`。

## Task 13: 联合验收与发布记录

**Files:** 新建 `docs/acceptance/cross-platform.md`、`scripts/acceptance/`、`outputs/cross-platform-validation/REPORT.md`；更新 README 与 CI。

- [ ] 为每台终端记录 OS、架构、安装包 SHA-256、源提交、证书指纹和测试开始时间；证据不包含账号密码。
- [ ] 每平台至少 5 台新设备；Linux 样本必须覆盖 Ubuntu 22.04/24.04 和 Rocky 9。
- [ ] 100 次连接/断开记录耗时和失败率；中断核心、切网、睡眠/唤醒和卸载后检查恢复到原网络基线。
- [ ] 连续 72 小时观察连接与五个目标，保留汇总证据；用产品提供的监控机制调度长时任务，不在终端循环阻塞等待。
- [ ] 验证默认无诊断文件，管理员诊断到期关闭；确认 GUI 无多余入口。
- [ ] 记录网站拒绝/限流与线路故障的区别；浏览器实际访问验证独立于探测延迟。
- [ ] 任何平台缺少实机或失败都标为未验收；不得写“三端上线完成”。
- [ ] 保存已签名安装包、哈希、源提交和人工回滚说明；人工升级可用，不承诺固定证书和第三方站点永久不变。
- [ ] 验收全部满足后提交报告并按既有授权流程合并、推送 GitHub。

## 自审记录

- 规范 1–3：任务 1、2、5、9、11。
- 规范 4–5：任务 2、3、9、11。
- 规范 6–7：任务 6、7、9、11。
- 规范 8：任务 4；恢复快照不作为调试日志禁用。
- 规范 9：任务 8、10、12；共享证书保留。
- 规范 10–12：任务 5、13 与依赖顺序。
- 原型文件位于 `.superpowers/brainstorm/529-1788517644/content/three-platform-complete-ui.html`；执行时复制为可追踪设计资产，去除会话脚本和密钥。
- 无凭空声明平台测试已完成；Apple 权限与嵌入构建先做可行性验证。
