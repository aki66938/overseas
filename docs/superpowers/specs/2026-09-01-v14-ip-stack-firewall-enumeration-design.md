# v14 Windows IP 栈防火墙接口枚举设计

## 背景

v10 至 v13 多次以 `public_tcp_block_failed` 结束。v13 已排除状态为
`Not Present` 的幽灵适配器，但实机仍然失败。失败现场显示，程序已经为第一个
Hyper-V vEthernet 接口创建 TCP、QUIC 和 UDP 规则，随后只留下紧急阻断规则。

逐接口能力探针证明，根因不是某个特定代理软件，而是枚举模型错误：
`Get-NetAdapter` 返回 NDIS 适配器对象，Windows 防火墙的 `-InterfaceAlias`
只接受参与 Windows IP 栈的接口。这两个集合不相等。

本机实测结果如下：

- 8 个同时存在于 `Get-NetIPInterface` 的适配器全部可绑定防火墙接口过滤器。
- 9 个没有 IP 接口和路由的对象全部被防火墙拒绝，错误为
  `The specified interface was not found on the system.`。
- 被拒绝对象包括 WAN Miniport 和 Hyper-V Virtual Switch Extension Adapter；
  其中部分状态仍为 `Up`，因此不能用 `Status` 判定。
- FlClash Meta Tunnel 可以绑定防火墙接口过滤器。它不是本次失败根因。
- 173 个远端前缀的规则规模在可绑定接口上成功，不是容量问题。

## 目标

v14 必须从 Windows IP 栈枚举真正可能承载用户 IP 流量的接口，再为所有非产品
TUN 接口发布防泄漏规则。不得继续依赖设备名称、描述、状态或驱动类型黑名单。

连接前防泄漏保护、TUN 就绪后发布路由、失败关闭和精确恢复等 v12 边界保持不变。
本设计只更换保护接口的发现模型，并补足可诊断性和实机发布前验证。

## 接口发现模型

扫描脚本以 `Get-NetIPInterface` 为入口：

1. 读取 IPv4 和 IPv6 IP 接口，按 `InterfaceIndex` 去重。
2. 对每个索引使用 `Get-NetAdapter -IncludeHidden -InterfaceIndex` 解析适配器。
3. 没有对应 `Get-NetAdapter` 的系统接口（例如 loopback pseudo-interface）不进入
   适配器规则集合。
4. 一个 IP 接口索引必须精确解析出一个适配器，且 Index、GUID、Alias 均有效；
   重复或身份不完整时失败关闭。
5. 输出仍使用 `InterfaceIndex + InterfaceGuid + InterfaceAlias + Status` 的稳定身份。

该模型自然保留下列接口：

- 已连接的 WLAN、以太网和可承载 IP 的虚拟网卡；
- 暂时 Disconnected、但仍注册于 IP 栈的物理网卡和 Wi-Fi Direct 接口；
- 已经建立并进入 IP 栈的第三方 VPN/RAS 接口。

该模型自然排除下列对象：

- 没有 IP 接口的 WAN Miniport 底层 NDIS 对象；
- Hyper-V Virtual Switch Extension Adapter；
- `Not Present` 且不参与 IP 栈的历史设备；
- 无法解析为 `Get-NetAdapter` 身份的 loopback 等系统接口。

不得按照 `WAN Miniport`、`Hyper-V`、厂商名或本地化 Alias 写过滤黑名单。

## 产品 TUN 排除与热插拔

产品 TUN 只能在其身份已经由 `WaitTUNReady` 验证并记录后，以
InterfaceIndex、InterfaceGuid 和 InterfaceAlias 三项全部匹配的方式排除。仅 Alias
相同或仅索引相同都不足以排除。

连接期间保留适配器监控。每轮监控重新从 IP 栈生成完整期望集合：

- 新出现的可路由 IP 接口必须补装规则；
- 从 IP 栈消失的接口对应规则只能在确认规则属于产品且不再属于期望集合后删除；
- 新接口规则发布或 ActiveStore 验证失败时，安装紧急规则、停止核心并保持
  fail-closed；
- 产品 TUN 在创建前会被当作普通 IP 接口保护；身份确认后下一轮协调精确移除它的
  适配器规则，使公网流量只能通过该 TUN 路径。

## 防火墙发布和验证

每个受保护接口继续拥有三条按 GUID 命名的规则：公网 TCP、QUIC 和其他公网 UDP。
DNS 阻断规则继续按既有企业 DNS 豁免策略全局生效。

发布过程必须保持可重入：

1. 校验同名规则是否属于固定产品组；外来同名规则导致失败关闭。
2. 校验现有规则的 InterfaceAlias；身份变化时只重建产品自有规则。
3. 创建本轮缺失规则。
4. 从 ActiveStore 读取并验证完整规则定义和接口过滤器。
5. 只删除不再属于期望集合的产品自有规则。

不得通过捕获 `New-NetFirewallRule` 的“interface not found”错误并静默跳过适配器。
发现阶段必须先产生正确集合；发布阶段的任何接口绑定错误都视为安全失败。

## 可诊断性

固定网络操作必须保留限长、清洗后的 PowerShell stderr。控制器在保持稳定客户端错误码
`public_tcp_block_failed` 的同时，诊断信息必须区分以下阶段：

- `ip_interface_scan`
- `adapter_identity_join`
- `firewall_publish`
- `active_store_verify`
- `emergency_protection`

诊断不得包含凭据、完整 sing-box 配置、访问令牌或任意外部命令行。Windows 原始错误
最多保留固定长度，并移除换行和控制字符。

## TDD 与自动验证

实现前必须先观察回归测试失败。测试至少覆盖：

1. 扫描脚本以 `Get-NetIPInterface` 为入口，并按 InterfaceIndex 联接
   `Get-NetAdapter`。
2. 当前实机形态中，无 IP 接口的 WAN Miniport 和 vSwitch Extension 对象不输出。
3. Disconnected 但具有 IP 接口的物理以太网仍输出。
4. 可路由的第三方 TUN/RAS 接口仍输出。
5. loopback 无适配器身份时安全跳过；同一索引解析出多个身份或身份不完整时失败。
6. 产品 TUN 只在三重身份完全匹配时排除。
7. 热插拔接口加入和移除后，期望规则集合可重入收敛。
8. PowerShell stderr 被限长清洗并传递到内部诊断阶段，但客户端稳定错误码不变。

自动门禁包括：完整 Go tests、`go vet`、Windows PowerShell 5.1 与 PowerShell 7
Pester、Windows amd64 构建、PowerShell AST 解析、MSI 内容/签名/哈希验证和
`git diff --check`。

## 发布前本机验证

不得直接把首次真实验证交给用户。v14 打包前必须在本机完成：

1. 以与服务相同的 LocalSystem 权限执行实际扫描脚本。
2. 将扫描结果与当前 `Get-NetIPInterface`/`Get-NetAdapter` 联接结果逐项比较。
3. 使用保留测试地址为每个输出接口创建、读取、验证和删除临时规则。
4. 证明临时规则、产品规则、TUN、路由和快照均无残留。
5. 安装签名 v14 后验证服务可启动，且未连接时不修改网络。

上述门禁通过后，才由用户关闭 FlClash 进行最终链路验收。最终验收包括连接成功、批准
海外站点访问、企业内网访问、断开恢复，以及失败时无产品规则、路由、TUN 或快照残留。

## 明确不在 v14 范围内

- 不开发 WFP 内核驱动。
- 不修改 VM101、电信客户端或 `172.20.9.15:8080` 上游方式。
- 不增加 macOS/Linux 客户端、AD 授权或多节点负载均衡。
- 不用设备名称或厂商描述建立长期兼容列表。
