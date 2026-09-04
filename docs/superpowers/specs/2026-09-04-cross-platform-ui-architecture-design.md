# RegenBio 海外访问跨平台架构与 UI 设计

日期：2026-09-04  
状态：已确认，待书面规范复核

## 1. 目标与范围

第一阶段上线三端：

- Windows：Flutter GUI；
- macOS：Flutter GUI，仅支持 Apple Silicon；
- Ubuntu 22.04/24.04、Rocky Linux 9：Go CLI，无 GUI。

第二阶段增加 iOS、Android Flutter GUI。所有平台仅在公司内网使用，不建设公网接入、企业账号登录、设备自助注册或远程租约控制面。配置由 IT 随安装包或受控配置文件下发。

固定内部发行版不实现自动更新。未来变更通过重新构建、验收和人工分发完成。

## 2. 架构审查结论

当前 Windows PoC 已验证连接事务、网络恢复、证书部署、sing-box TUN 和 HTTP CONNECT 出口。以下部分具有平台耦合：

- Walk Windows UI；
- Windows Service 与 Named Pipe；
- Windows 路由、DNS、防火墙和 Wintun；
- Windows Job Object 与外置 sing-box 监督；
- WiX、DPAPI 和 Windows 证书存储。

不进行整体重写。保留已验证的 Go 事务语义，抽离平台无关核心和明确接口。平台边界以自动化适应度函数保护。

旧的 2026-08-27 WireGuard 草案不再作为实施基线。正式数据面沿用已验证的 sing-box 架构。

## 3. 目标架构

### 3.1 分层

1. 产品层
   - Windows、macOS：Flutter GUI；
   - Linux：Go CLI；
   - iOS、Android：第二阶段 Flutter GUI。
2. 本机协议层
   - 固定 API v1：`status`、`connect`、`disconnect`、`probe`、`diagnostic-enable`；
   - 未知字段忽略；仅不兼容变更升级协议版本。
3. Go 共享核心
   - 连接状态机；
   - 配置校验；
   - 线路探测；
   - 恢复事务；
   - 统一状态和错误码；
   - 脱敏诊断。
4. 平台适配层
   - 网络快照；
   - TUN、路由和 DNS；
   - 数据面生命周期；
   - 密钥和配置保护；
   - IPC 与系统服务。
5. 数据面
   - sing-box；
   - 公司内网经电信海外出口访问目标站点。

Flutter 不直接修改网络，不持有系统网络管理权限。

### 3.2 平台实现

| 平台 | UI/入口 | 权限与 IPC | 数据面 | 配置保护 | 交付 |
|---|---|---|---|---|---|
| Windows | Flutter | LocalSystem Service、Named Pipe | 外置 sing-box | DPAPI | 签名 MSI |
| macOS arm64 | Flutter | Packet Tunnel Extension、App Group | 扩展内嵌数据面 | Keychain | Developer ID 签名、公证 PKG |
| Ubuntu/Rocky | Go CLI | systemd Service、Unix Socket | 外置 sing-box | root-only 文件 | DEB、RPM |
| iOS | Flutter | Packet Tunnel Extension | 内嵌数据面 | Keychain | 第二阶段 |
| Android | Flutter | VpnService | 内嵌数据面 | Android Keystore | 第二阶段 |

macOS 不增加额外高权限常驻 helper。Network Extension 负责受控隧道能力。

## 4. 连接状态机

状态：

- `idle`：未连接；
- `preparing`：准备中；
- `connecting`：连接中；
- `connected`：已连接；
- `degraded`：线路较慢；
- `restoring`：恢复中；
- `needs_action`：需要处理。

连接流程：

1. UI 或 CLI 请求连接；
2. Go 核心校验配置、二进制和环境；
3. 平台适配器清理唯一、可证明归属的历史残留；
4. 创建网络快照；
5. 启动并验证 sing-box；
6. 验证 TUN；
7. 应用路由和 DNS；
8. 探测海外目标；
9. 发布 `connected`。

任一步失败均逆序恢复并验证残留为零。无法证明恢复时进入 `needs_action`，提供“仅恢复网络”。

断开流程逆序停止数据面、恢复 DNS/路由、验证残留并回到 `idle`。

## 5. 动态线路状态

固定目标：

- Google；
- Pinterest（`https://www.pinterest.com/`）；
- Gemini；
- ChatGPT；
- Claude。

规则：

- 连接后每 30 秒并发探测；
- 提供“立即测速”；
- 测量 DNS、TCP、TLS 和首响应总耗时，不使用 ICMP；
- HTTP 2xx–4xx 表示可达；5xx、超时或 TLS 失败表示失败；
- 单轮总预算 5 秒；
- 单目标连续失败 3 次才标记异常；
- 多数目标异常才判定整体线路异常；
- 延迟展示为整数毫秒；
- 未连接时不持续后台探测，只保留最近结果。

## 6. UI 设计

### 6.1 视觉原则

- 采用克制、可信的企业产品风格；
- 文字精简，不做解释性修饰；
- 主任务只有连接、断开和查看线路；
- 普通用户不看到路由、证书、阶段名或错误栈；
- 主页面与详情页面使用同一顶层窗口、相同尺寸和位置。

### 6.2 Windows

- 固定尺寸窗口；允许拖动和最小化；不提供最大化；
- 最小化进入任务栏；
- 关闭按钮始终隐藏到托盘，不断开线路；
- 首次隐藏时显示一次提示；
- 主页面和详情在同一窗口切换；详情提供“返回”；
- 左键托盘图标打开或聚焦窗口；右键打开菜单；不使用双击。

托盘菜单：

- 当前状态与简短延迟；
- 打开主窗口；
- 查看线路详情；
- 开启或关闭海外访问；
- 开机时启动；
- 退出应用。

### 6.3 macOS

- 与 Windows 内容尺寸和层级一致；
- 保留红色关闭和黄色最小化；绿色全屏按钮禁用；
- 关闭红色按钮隐藏窗口，不断开线路；
- 菜单栏图标承担 Windows 托盘功能；
- “登录时启动”替代“开机时启动”。

### 6.4 Linux CLI

固定命令：

- `regen-access connect`；
- `regen-access disconnect`；
- `regen-access status`；
- `regen-access probe`。

CLI 输出只包含状态、连接时长、目标延迟和简短错误。Linux 不提供 GUI 或托盘。

### 6.5 明确删除

- 检查更新；
- 复制诊断摘要；
- 普通用户日志入口；
- 登录、注册和设备管理；
- 冗长说明文字。

## 7. 错误处理

用户可见状态与操作：

| 状态 | 文案 | 操作 |
|---|---|---|
| `degraded` | 线路较慢 | 立即测速 |
| 连接事务失败且已恢复 | 连接失败 | 重试 |
| 无法证明恢复 | 网络未恢复 | 仅恢复网络 |
| 配置或安装不可用 | 配置不可用 | 联系 IT |

同一错误码在所有平台具有相同语义。平台细节仅进入临时诊断。

## 8. 临时诊断模式

- 默认完全关闭；
- UI 不提供日志入口；
- 管理员通过 CLI 临时开启；
- 可选 15、30、60 分钟；
- 到期或服务重启后自动关闭；
- 结构化、脱敏、限额和轮转；
- 不记录凭据、完整配置或私钥。

## 9. 证书部署

- Windows：MSI 安装到 LocalMachine Root；
- macOS：签名 PKG 安装到 System Keychain；
- Ubuntu：DEB 安装到系统 CA 存储并刷新；
- Rocky Linux：RPM 安装到系统 CA 存储并刷新；
- iOS/Android 第二阶段通过内部设备管理或明确安装流程交付所需信任配置。

安装后必须验证唯一证书指纹，不接受同名替代证书。

## 10. 架构适应度函数

- 共享核心不得导入平台网络 API；
- Flutter 进程不得拥有网络管理权限；
- 三端执行同一本机协议契约测试；
- 任一失败、断开和卸载后，TUN、路由、DNS、规则和核心进程残留为零；
- 诊断默认关闭；
- 日志不得包含凭据、私钥或完整配置；
- 动态探测满足固定目标、30 秒周期和 5 秒预算；
- UI 文案来自统一短文本目录，不包含平台技术细节。

## 11. 测试与上线门槛

### 11.1 自动化

- Go 共享核心单元测试；
- 状态机故障注入；
- 本机协议契约测试；
- Flutter Widget 与 Golden 测试；
- 平台适配器集成测试；
- 安装、升级、卸载和证书验证；
- 默认无日志与诊断到期测试；
- 数据面异常和网络恢复测试。

### 11.2 实机验收

每个平台必须满足：

- 100 次连接/断开循环；
- 72 小时持续连接；
- 至少 5 台新设备安装；
- Google、Pinterest、Gemini、ChatGPT、Claude 可达；
- 公司内网访问不受影响；
- 异常退出后普通网络恢复；
- 卸载后网络残留为零。

三端全部通过后才认定第一阶段上线完成。

## 12. 实施顺序

1. 抽离平台无关 Go 核心和 API v1；
2. 保持 Windows 行为等价，替换为 Flutter UI；
3. 实现 Ubuntu/Rocky CLI、systemd、DEB/RPM；
4. 实现 macOS arm64 Flutter、Packet Tunnel Extension、签名与公证；
5. 完成三端实机验收；
6. 第二阶段复用 Flutter 设计系统、API 和状态模型实现 iOS/Android。

每一步独立验收，不采用一次性跨平台重写。

## 13. 架构顾问团结论

- Martin Fowler：保留已验证事务语义，通过接口逐步替换平台耦合，不支付整体重写成本；
- Neal Ford：用协议契约、权限边界、零残留和三端验收作为自动化适应度函数；
- Gregor Hohpe：共享核心必须降低各端认知负担，不能成为新的跨平台耦合层。

三种视角没有方向性冲突。差异只在侧重点：Fowler 强调演进成本，Ford 强调持续验证，Hohpe 强调平台契约与交付边界。
