# v16 可观测调试控制台设计

## 背景与现场证据

Direct HTTP 客户端已经生成从 v1 到 v15 的十五代正式包，另有一次 v15 中间构建。继续在只有“连接失败”与单条错误码的界面上修补，不足以支持后续调试。

2026-09-01 的 generation 5 现场为：

- 状态为 `failed/public_tcp_block_failed`；
- diagnostics 只有 generation 与错误码，没有 `stage` 或 `detail`；
- ActiveStore 中保留 23 条 `RegenBioOverseasAccess.Managed` 防泄漏规则；
- `network-state.json` 存在且 `OwnershipPhase=protected`；
- 没有产品路由、产品 TUN 或 sing-box 子进程；
- `runtime-owned.json` 与 `sing-box.json` 已生成。

现有实现有三个明确的可观测性缺口：

1. UI 在 `Toggle` 阻塞期间将 ViewModel 标记为 busy，普通状态轮询会跳过，因而连接最需要信息时窗口停止更新；
2. Controller 只保存一个 `stage/detail` 快照，而且 `detail` 为空时直接丢弃诊断；超时、上下文取消、进程终止或无 stderr 的 PowerShell 失败因此只剩通用错误码；
3. 连接失败后保留 fail-closed 状态是既有安全语义，但 UI 不显示规则、快照和恢复状态；“重试”也不会先完成显式恢复。

本设计先建立可靠可观测性，不把 generation 5 的底层防火墙失败原因当作已知事实。v16 的真实连接日志用于确定下一步根因，而不是再猜测修复。

## 已批准范围

- v16 是调试版客户端，日志区域默认展开。
- 采用单列时间线布局。
- 日志由服务端同时写入内存环形缓冲区和受保护的 JSONL 文件。
- 失败后提供安全重试、仅恢复网络和复制全部日志。
- 真实链路稳定后另行设计正式界面；正式界面默认隐藏技术日志，不在本轮实现。

## 目标

- 在窗口中实时看到连接、失败、恢复与服务启动恢复的每个阶段。
- 每个阶段具备开始时间、结束结果、耗时、输入规模和脱敏技术详情。
- 即使 PowerShell 不产生 stderr，也能得到有意义的阶段、退出类型和上下文错误。
- UI 连接请求阻塞期间，日志仍能独立刷新。
- 服务崩溃、UI 崩溃或机器重启后仍保留最近五次连接证据。
- 失败状态明确显示 fail-closed 是否仍生效，以及规则、路由、TUN、快照和进程残留。
- 重试前必须证明旧连接状态已恢复，禁止在无法恢复的状态上叠加新 generation。

## 非目标

- 不在本轮修改 VM101、电信客户端或 `172.20.9.15:8080`。
- 不更换 sing-box、TUN 或 HTTP CONNECT 架构。
- 不在没有 v16 现场日志前猜测或修改 generation 5 的底层防火墙逻辑。
- 不实现 macOS/Linux 客户端。
- 不完成正式版视觉设计、日志隐藏策略或普通员工界面。
- 不提供用户可编辑的代理、路由、防火墙或日志配置。

## 结构化事件模型

服务端新增不可变 `TraceEvent`。事件只允许以下字段：

- `schema_version`：固定为 `1`；
- `sequence`：服务实例内严格递增的 `uint64`；
- `timestamp_utc`：RFC3339Nano UTC 时间；
- `generation`：Controller generation；服务启动事件可为 `0`；
- `level`：`info`、`warning` 或 `error`；
- `component`：固定允许值，例如 `controller`、`network`、`powershell`、`core`、`recovery`、`service`；
- `stage`：固定阶段代码；
- `event`：`started`、`succeeded`、`failed`、`state`；
- `elapsed_ms`：结束事件可选的非负耗时；
- `message`：面向 IT 的简短中文说明；
- `detail`：可选的脱敏技术详情，最多 4096 字节；
- `residue`：仅在边界事件上出现的结构化残留摘要。

`residue` 只包含计数或非敏感状态：托管规则数量、产品路由数量、产品 TUN 数量、产品核心进程数量、快照是否存在及快照阶段。不得包含规则的完整远端地址集合、代理认证、策略全文或配置全文。

每个有耗时的操作必须产生同阶段的 `started` 与一个终结事件。终结事件必须是 `succeeded` 或 `failed`，不得只有 started。相同 generation 内事件按 sequence 排序；跨 generation 由 UI 插入分隔行。

## 固定阶段

至少覆盖以下阶段：

1. `request_received`
2. `policy_validation`
3. `binary_verification`
4. `credential_load`
5. `network_capture`
6. `adapter_scan`
7. `firewall_publish`
8. `active_store_verify`
9. `emergency_protection`
10. `config_render`
11. `core_start`
12. `core_ready`
13. `tun_ready`
14. `route_activation`
15. `connected`
16. `core_stop`
17. `network_restore`
18. `residue_verify`
19. `service_recovery`

网络事件记录规模而非敏感内容，例如适配器数量、期望规则数量、回读规则数量和地址条目数量。PowerShell 事件记录固定操作名、运行时、终止方式与退出码。

## 事件采集与持久化

Controller、WindowsNetworkManager、PowerShell runner、核心监督器和服务恢复路径通过窄接口 `TraceSink.Record(TraceEvent)` 发送事件。业务组件不负责 UI 格式化或文件轮转。

TraceSink 同时维护：

- 内存中的有界环形缓冲区，供 Named Pipe 增量读取；
- `C:\ProgramData\RegenBio\OverseasAccess\logs\` 下的 JSONL 文件。

持久化规则：

- 每次连接建立一个日志文件；服务启动恢复使用单独的恢复文件；
- 单文件最多 2 MiB；超过限制时写入明确的截断终结事件，不进行无界追加；
- 只保留最近五次连接/恢复日志；
- 日志目录继承现有 ProgramData 的 SYSTEM/Administrators 保护，普通用户不直接读取；
- 轮转只处理经过验证的固定日志目录及固定命名文件，不触碰其他产品数据；
- terminal failure、恢复结果和服务停止事件必须刷新到磁盘；
- 磁盘写入失败不得阻塞网络安全操作，内存缓冲继续工作，并产生一次 `logging_degraded` 事件。

## 脱敏与诊断完整性

进入 TraceSink 前执行集中脱敏。禁止记录：

- PIN、密码、代理用户名或认证头；
- DPAPI 明文或密文内容；
- `agent.yaml`、`sing-box.json` 或策略全文；
- PowerShell 输入 JSON/Base64 信封；
- 完整远端地址白名单或阻断前缀集合。

允许记录固定路径的基名、计数、哈希前缀、接口别名、接口 GUID、错误码和受限的 PowerShell 错误文本。所有 detail 删除控制字符并限制为 4096 字节。

PowerShell 失败诊断按以下优先级生成：

1. 可解析的 ErrorRecord/CLIXML 文本；
2. 清理后的 stderr；
3. `context deadline exceeded`、`context canceled` 或进程终止类型；
4. 原生退出码与固定操作名。

因此即使 stderr 为空，`stage/detail` 也不得为空。现有单快照 diagnostics 保留作为兼容摘要，但其值由最后一个失败 TraceEvent 生成。

## Named Pipe 增量日志协议

新增只读 `trace` action。Request 增加可选的 `after_sequence` 与 `limit`，只允许 `trace` 使用；其他 action 带这些字段必须被拒绝。响应 message 中包含严格 JSON `TraceBatch`：

- `events`：sequence 大于 `after_sequence` 的有界事件；
- `next_sequence`：下一次增量读取位置；
- `has_more`：本批未包含全部可用事件；
- `oldest_sequence`：用于识别 UI 是否落后并发生环形缓冲覆盖。

协议限制：

- 默认和最大 limit 固定，不能由用户请求无界数据；
- 单个响应仍不得超过 64 KiB；
- 服务端按事件边界减小批次，不截断 JSON；
- DACL、请求 ID 校验、严格字段解码和允许值验证沿用现有 Named Pipe 安全模型；
- 普通状态、连接和断开请求保持兼容。

## UI：方案 A 单列时间线

调试窗口固定约 `820 × 620`，默认展开日志：

1. 顶部摘要显示连接状态、generation、当前阶段、当前阶段耗时和 fail-closed 状态；
2. 中部为只读等宽字体日志控制台；每行显示本地时间、级别标记、组件、阶段、结果、耗时和说明；
3. 技术详情作为紧随失败事件的缩进行，不与前后阶段分离；
4. 底部提供主操作、`仅恢复网络` 与 `复制全部日志`。

调试版以可复制的纯文本时间线为准，不为逐行富文本着色增加额外复杂度。状态摘要可使用现有颜色；日志使用 `[INFO]`、`[WARN]`、`[ERROR]` 与 `✓/→/✕/!` 前缀保证黑白截图仍可读。

UI 使用独立日志轮询循环，每 500 ms 调用 trace action。该循环不检查 ViewModel busy 状态，因此 Connect 在另一个 goroutine 中等待最长 120 秒时，日志仍持续更新。轮询使用 after_sequence 去重；UI 掉线后从最后成功 sequence 继续。

自动滚动规则：日志位于底部时跟随新事件；用户向上查看时暂停；回到底部后恢复。新 generation 不删除旧内容，而是插入明显分隔行。窗口启动时从服务内存加载当前服务会话中可用的最近事件。

## 失败、恢复与按钮行为

连接失败后维持既有 fail-closed 语义，不自动删除防泄漏规则。UI 必须显示最后一次残留摘要，例如“23 条防泄漏规则仍启用；0 路由；0 TUN；快照阶段 protected”。

失败状态提供：

- `安全重试`：UI 先调用 Disconnect。只有服务返回 disconnected，且日志中的 `residue_verify` 确认零连接残留后，才调用 Connect 开始新 generation；
- `仅恢复网络`：只调用 Disconnect，不启动新连接；
- `复制全部日志`：复制当前 generation 的全部已脱敏事件及摘要。

若恢复返回 `restore_failed` 或 residue 非零，安全重试立即停止，按钮保持不可继续连接，并在时间线显示残留项目。不得在旧状态上叠加新连接。

服务启动时的 Recover、服务停止时的 Disconnect 以及失败后的显式恢复全部记录相同的恢复阶段。恢复日志必须区分“删除产品拥有的状态成功”和“未拥有/未修改第三方状态”。FlClash 不在产品清理范围内。

## 错误处理

- trace 拉取失败：UI 追加一次本地 `[WARN] 日志通道暂不可用`，连接控制仍按原协议工作，并按有界退避重试；
- UI 检测到 oldest_sequence 已越过本地 next_sequence：插入“部分早期日志已被内存缓冲覆盖，磁盘仍保留”标记；
- JSONL 写入失败：网络操作不阻塞，内存日志继续；终端摘要标记持久化降级；
- 单事件过长：服务端在事件生成边界脱敏并截断，附加 `detail_truncated=true` 的固定说明，不在管道层切断 JSON；
- 服务崩溃：已刷新的 JSONL 保留；下次服务启动通过 service_recovery 日志记录恢复动作；
- 日志协议发现未知字段、未知阶段或未知级别：客户端拒绝该批次，不显示未经允许的数据。

## 测试设计

所有生产行为先写失败测试，再实现：

1. TraceEvent 架构、允许值、严格 sequence 与 terminal 配对测试；
2. 集中脱敏测试，使用 PIN、密码、代理认证、完整配置和 Base64 信封作为禁止样本；
3. 环形缓冲覆盖、after_sequence、分页、64 KiB 响应边界和未知字段拒绝测试；
4. JSONL create-new、2 MiB 上限、最近五次轮转、受限目录和磁盘失败降级测试；
5. Controller 每个连接/失败/恢复阶段的顺序与 generation 隔离测试；
6. PowerShell stderr、CLIXML、空 stderr、超时、取消和退出码的诊断合成测试；
7. ViewModel 测试证明 Connect 阻塞期间 trace 轮询仍更新日志；
8. 安全重试测试证明 Restore/零残留在新 Connect 之前，恢复失败时不调用 Connect；
9. UI 文本格式、generation 分隔、复制全部日志和自动滚动状态测试；
10. LocalSystem 实机门禁记录完整 capture、scan、publish、verify、restore、residue 时间线，并在显式恢复后证明零残留；
11. Windows PowerShell 5.1、PowerShell 7、全量 Go、`go vet`、脚本 AST、签名和 MSI 生命周期验证。

## 部署与验收

v16 构建前先把 generation 5 的当前诊断摘要与残留计数记录为开发证据。随后通过服务的显式 Disconnect/Recover 清理当前 fail-closed 状态，并验证零托管规则、零产品路由、零产品 TUN、无 network-state 与无 sing-box 进程；不得手工删除不明规则来掩盖恢复缺陷。

安装 v16 后先验证：产品唯一注册、服务可启动、清单绑定最终提交、所有文件哈希与签名有效、日志目录 ACL 正确、空闲态无连接残留。

真实验收由用户完全退出 FlClash 后执行：

1. 打开默认展开日志的调试窗口；
2. 点击一次开启海外访问；
3. 观察阶段日志直到 connected 或明确 failed；
4. 若失败，复制当前 generation 全部日志；
5. 若成功，验证海外站点与内网站点，然后点击仅恢复网络/关闭海外访问；
6. 由 IT 检查断开后零残留。

v16 的交付条件是“任何结果都可定位”：成功必须有完整阶段与断开恢复时间线；失败必须有阶段、耗时、底层错误和残留状态。只有真实链路成功并完成断开恢复后，才进入隐藏技术日志的正式 UI 设计。
