# v15 PowerShell 传输边界与 DNS 前缀修复设计

## 背景与已确认根因

v14 在真实连接事务的 `firewall_publish` 阶段失败。Windows 事件日志记录的第一条原始异常为 `The specified interface was not found on the system`，第二条应急保护异常为“一个或多个地址前缀无效”。

实机字节级复现确认：RegenBio Agent 以 LocalSystem 启动 Windows PowerShell 5.1 时，控制台标准输入和输出使用 GB2312；Go 进程使用 UTF-8 JSON。PowerShell 扫描得到的中文接口别名经 GB2312 标准输出进入 Go 后被替换为无效 Unicode，Go 再把损坏的名称写回 PowerShell，导致 `New-NetFirewallRule -InterfaceAlias` 无法解析真实接口。ASCII 接口先成功、首个中文接口随后失败，和现场残留规则顺序完全一致。

独立复现还确认，当前 DNS 阻断集合中的 50 个前缀有 49 个可被 Windows 防火墙接受，唯一失败项为 `::/0`。等价的 `::/1` 与 `8000::/1` 单独和组合发布均成功。

## 目标

- PowerShell 操作在任意 Windows 系统代码页下无损接收 Go 生成的 UTF-8 JSON。
- PowerShell 返回的中文接口名称能被 Go 作为严格 UTF-8 JSON 解码，不允许静默替换无效字节。
- Progress/CLIXML 不得占用诊断详情并遮蔽真实异常。
- DNS 防泄漏范围保持不变，同时只向 Windows 防火墙提交其接受的前缀。
- 不改变已批准的 TUN、HTTP CONNECT 节点、接口枚举、ActiveStore 精确验证及故障时 fail-closed 语义。

## 方案

### 输入：Base64 ASCII 信封

`powerShellNetworkRunner` 不再把原始 JSON 直接写入标准输入。Go 在启动 PowerShell 前把 JSON 字节编码为标准 Base64，并只把 ASCII Base64 文本写入 stdin。

所有网络 PowerShell 操作共享同一个固定前导：

1. 设置 `$ErrorActionPreference = 'Stop'`；
2. 设置 `$ProgressPreference = 'SilentlyContinue'`；
3. 将控制台输出编码设置为无 BOM UTF-8；
4. 从 stdin 读取 ASCII Base64；
5. 严格 Base64 解码，再以 UTF-8 解码为 JSON 文本；
6. 使用 `ConvertFrom-Json` 构造输入对象。

Base64 字符集在 UTF-8、GB2312 和 OEM 代码页中具有相同字节表示，因此输入不依赖 PowerShell 的控制台输入编码。前导拒绝空信封、非法 Base64 和非法 JSON；不得降级为原始 JSON 兼容模式。

### 输出：显式 UTF-8 与严格解码

前导在任何 cmdlet 或 JSON 输出前将 `[Console]::OutputEncoding` 和 `$OutputEncoding` 设置为同一个无 BOM UTF-8 编码实例。Go 端在消费 PowerShell JSON 前先调用严格 UTF-8 校验；发现非法字节时返回固定操作错误，不允许 `encoding/json` 将其静默转换为 `U+FFFD`。

无 JSON 输出的变更操作仍可返回空 stdout。既有输出 JSON 结构保持不变，因此捕获、扫描和 TUN 就绪对象无需新增协议版本。

### 诊断流

禁用 Progress 流，避免模块首次加载产生的 CLIXML 抢占 512 字节诊断预算。失败时仍使用既有固定阶段：

- `ip_interface_scan`
- `adapter_identity_join`
- `firewall_publish`
- `active_store_verify`
- `emergency_protection`

诊断只保留经过控制字符清理和 512 字节截断的 stderr。不得包含输入信封、完整规则集合、策略、凭据或配置内容。

### DNS IPv6 全空间规范化

Windows 网络策略生成层在把前缀交给防火墙前执行确定性规范化：每个精确的 `::/0` 被替换为 `::/1` 和 `8000::/1`，其他前缀保持顺序和内容不变，最终集合去重。

规范化同时用于普通 DNS 阻断、应急 DNS 阻断、ActiveStore 验证和持久化网络快照，保证期望值、发布值、验证值和恢复值一致。不得使用防火墙关键字 `Any`，因为它会同时扩大 IPv4 语义并破坏精确集合验证。

## 数据流

1. Go 构造 `windowsNetworkInput` 并序列化为 UTF-8 JSON。
2. Runner 将 JSON 编码为 Base64 ASCII stdin。
3. PowerShell 固定前导解码为 UTF-8 JSON，并执行对应操作。
4. JSON 结果以无 BOM UTF-8写入 stdout；Progress 流保持静默。
5. Go 严格验证 UTF-8，再进行 JSON 解码。
6. 防火墙操作使用规范化后的 DNS 前缀；ActiveStore 按相同集合精确回读。

## 失败与恢复

- Base64、UTF-8或 JSON 输入错误：操作立即失败，尚未进行网络变更。
- stdout 非 UTF-8：操作失败并进入现有 fail-closed 处理，不消费损坏对象。
- 普通规则发布失败：继续使用应急保护；v15 的应急 DNS 集合必须可发布。
- 服务停止或显式断开：沿用现有受控恢复，删除本产品拥有的规则、路由、TUN 和快照。
- 发布和恢复只操作固定的 RegenBio 规则组和固定状态文件，不处理第三方代理或 FlClash。

## 测试设计

测试必须先失败再实现：

1. Go 单元测试证明 runner 写入的是 Base64 ASCII，而不是原始 JSON，并能还原原始字节。
2. Windows 进程集成测试在系统代码页环境下往返包含“以太网”“本地连接”的对象，严格比较 Unicode 字符串。
3. 测试用无效 UTF-8 stdout 证明 runner 在 JSON 解码前拒绝数据。
4. 源码契约测试证明所有网络脚本只有一个共享前导、关闭 Progress，并且不再直接读取原始 JSON stdin。
5. 前缀测试证明 `::/0` 精确变换为 `::/1 + 8000::/1`，其余地址不变且无重复。
6. 防火墙脚本测试证明普通、应急和 ActiveStore 验证使用同一个规范化集合。
7. Windows PowerShell 5.1 与 PowerShell 7 全量 Pester、Go 全量测试和 `go vet` 必须通过。
8. 构建签名 v15 后，以 LocalSystem 运行边界往返门禁和完整防火墙发布/验证/恢复门禁；门禁结束必须零产品规则、零诊断规则、零产品路由、零 TUN、零快照。

## 部署与验收

v15 使用既有 PoC 代码签名证书和锁定工具链构建。安装前先受控清理失败状态并卸载唯一 v14 产品；安装后验证 MSI、清单、所有文件哈希和要求签名的二进制，再启动服务。

最终真实验收仍由用户执行：完全退出 FlClash，启动 RegenBio 海外访问，点击一次连接，并验证海外站点、内网站点和断开恢复。只有状态达到 `connected`、用户确认访问成功且断开后零残留，才能宣告端到端问题解决。

## 非目标

- 不更换 sing-box、TUN 或 HTTP CONNECT 架构。
- 不增加 macOS/Linux 客户端。
- 不修改电信客户端、VM101 或 172.20.9.15:8080。
- 不依赖网卡中文名称白名单、驱动名称黑名单或系统区域设置。
