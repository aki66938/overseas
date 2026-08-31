# v12 Windows 防泄漏与恢复设计

## 背景与目标

v11 在 Windows 客户端连接阶段先向 loopback 安装 173 条公网 sink route，再安装防火墙并启动 sing-box TUN。实机验证表明该 sink-route 层无法可靠落地，连接因此以 `public_tcp_block_failed` 结束。失败恢复还暴露出第二个问题：捕获快照记录了瞬时 `InterfaceIndex`，WLAN 重新枚举后索引从 14 变为 13，恢复按旧索引操作并以服务错误码 3 停止。

v12 的目标是打通当前 Windows PoC 链路，同时维持明确、可验证的 fail-closed 边界：连接期间由 Windows 出站防火墙阻止物理接口直连公网，只有 sing-box TUN 路径可以承载公网流量；不再宣称对任意新网卡、强主机源绑定或特权注入更具体路由提供零间隙保证。

## 采用方案

采用“防火墙 kill-switch + TUN 就绪后发布路由”。删除 loopback sink-route 的安装、验证和所有权要求，不以路由黑洞作为连接前置条件。

连接顺序固定为：

1. 捕获当前默认出口、DNS、接口身份和到 `172.20.9.15` 的旁路路径，并原子保存快照。
2. 在所有非产品 TUN 适配器上安装产品专属出站防火墙规则，阻断公网 TCP、QUIC、其他 UDP 和未批准 DNS；企业 CIDR、企业 DNS 与节点地址保持豁免。
3. 验证防火墙规则已在 `ActiveStore` 生效。
4. 生成受控 sing-box 配置并启动核心。
5. 验证固定 TUN 身份和地址。
6. 仅在前述步骤全部成功后发布产品拥有的 TUN 路由；节点 `172.20.9.15` 始终通过原物理出口旁路。

任何步骤失败都停止核心、删除产品拥有的规则/路由并按快照恢复；无法证明恢复完成时服务继续 fail-closed，不报告已断开。

## 快照与接口身份

`WindowsInterfaceSnapshot` 增加稳定的 `InterfaceGuid`。捕获时保存 `InterfaceGuid`、当时的 `InterfaceIndex` 和 `InterfaceAlias`。恢复真正被修改过的接口时，先按 GUID 在当前系统精确解析适配器，再使用其当前索引；GUID 缺失、重复或指向产品 TUN 时拒绝恢复。Alias 只作诊断信息，不作为所有权依据。

快照阶段继续区分：

- `captured`：只完成读取和持久化，尚未修改 DNS、metric、路由或防火墙。恢复此阶段不得调用 `Set-DnsClientServerAddress` 或 `Set-NetIPInterface`，只清除可能由失败补偿安装的精确产品规则，并删除经完整性验证的快照。
- `protected`：防火墙 kill-switch 已安装。恢复删除精确产品规则；接口配置仍未修改，不执行 DNS/metric 恢复。
- `tun-owned`：TUN 路由和相关网络配置已发布。恢复必须按 GUID 重新解析物理接口，恢复 DNS/metric，删除精确拥有的路由和规则，最后删除快照。

阶段变更必须在对应网络修改前写入快照意图，并在修改成功后持久化完成状态；中断后恢复依据持久化所有权处理，不依赖进程内状态。

## 防火墙所有权和监控

规则名称、组、方向、动作、协议、端口、远端地址、接口、应用/服务和安全过滤条件均使用既有固定定义。删除前重新读取 `ActiveStore` 并验证完整定义；名称相同但定义不符时保留规则并失败关闭。

连接期间继续监控适配器变化。新出现的非产品适配器必须补装同定义规则；补装或验证失败时安装产品紧急阻断规则并终止连接。v12 不使用 guard routes，因此不得创建 metric 8192 的产品路由。

## 错误与可诊断性

`public_tcp_block_failed` 保留为用户可见错误，但内部将 adapter scan、firewall publish、ActiveStore verify 分成固定阶段。日志/诊断只暴露阶段和经过限长清洗的 Windows 错误，不包含凭据、完整配置或任意命令行。

启动恢复失败继续返回服务特定错误，但 SCM 事件必须区分快照完整性、接口身份、防火墙所有权和网络命令阶段，避免将内部错误码 3误显示为“系统找不到指定路径”而失去语义。

## 测试与验收

严格 TDD，先观察以下回归测试失败：

1. 连接不调用 `guard`，调用顺序为 `capture -> scan -> block -> render -> core start -> ready -> activate`。
2. `captured` 快照恢复不执行接口 DNS/metric 恢复，并能删除精确紧急规则与快照。
3. 物理接口 GUID 不变但索引变化时，`tun-owned` 恢复使用新索引。
4. GUID 缺失、重复或指向产品 TUN 时恢复失败关闭并保留快照。
5. v12 不生成、验证或删除 metric 8192 guard routes。
6. 防火墙必须在核心启动前通过 ActiveStore 完整验证。
7. 失败补偿后服务可再次启动，且没有产品 TUN、路由、规则或残留快照。

自动化门禁包括完整 Go tests、`go vet`、Windows PowerShell 5.1/PowerShell 7 Pester、Windows amd64 客户端构建、安装包内容/签名/哈希检查。实机验收由用户关闭 FlClash 后执行：连接成功、访问批准海外站点、访问企业内网正常、断开后恢复原网络；失败路径不得留下产品规则、路由、TUN 或快照。

## 明确不在 v12 范围内

- 不恢复 sink routes 或声称任意适配器的零间隙路由防泄漏。
- 不修改 VM101、电信客户端或其 `[::]:8080` 监听方式。
- 不增加 macOS/Linux 客户端。
- 不实现 AD 自动授权或多节点负载均衡。
