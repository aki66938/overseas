# Linux 核心隔离验证

日期：2026-09-07。环境：专用 VM116 / Ubuntu 24.04.4。不是客户端完整验收。

## 固定输入

- sing-box 1.13.19 linux-amd64，revision `b5ebaa1fc0f2b94256180b95468e73ef53caa27d`。
- 官方压缩包 SHA-256：`ef88a9e577d474210867bd708933d042e9b70106529df2656182c9db90106aa1`；下载后和上传后均一致。
- 由提交 `3f1d7f1` 的 `singconfig.RenderClient` 生成 schema2 HTTP CONNECT 配置；无凭据。
- `unshare --net --mount --fork`，入口核对 namespace 与宿主不同。仅 namespace 内 dummy 上联网卡 `uplink0`（192.0.2.2/24）；没有连接宿主的 veth，没有公网出口。
- 试验文件与原始日志在工作区 `outputs/regen-access-testvm-20260907/`；不进入产品安装目录。

## 结果

| 测试 | 结果 |
|---|---|
| 原配置 `check` | 通过，但不能证明运行成功 |
| 原配置启动 | 失败：`create ifreq: invalid argument`，未创建 TUN |
| 仅将 `interface_name` 改为 `regen-access` | 启动成功，核心报告约 0.01 秒 |
| 公网/FakeIP 路由查询 | 8.8.8.8 与 198.18.0.1 进入 TUN / table2022 |
| TERM | 退出0，TUN、核心路由和规则恢复到 namespace 原始基线 |
| KILL | 退出137；TUN/link routes 消失，IPv4 policy rules 和 IPv6 unreachable rule 残留 |
| nft / resolv.conf | 此配置未创建 nft 表；resolv.conf 哈希不变 |
| 宿主网络 | 试验前后 route/rule/nft/resolv.conf 比对无变化 |

原名称 `RegenBioOverseasAccess` 为22字符。仅改为12字符的 `regen-access` 即解除启动失败，证明需要窄的平台网卡命名选项，不能直接复用 Windows 名称。未修改生产 renderer。

KILL 后仍存在 IPv4 priority9000–9010 的规则（包括 detached `iif regen-access`、table2022 查询和 goto/nop），以及 IPv6 priority9000 `unreachable`。因此“规则随进程消失”的 Windows 注释不能作为 Linux 恢复依据；必须持久记录精确所有权并处理核心异常退出。

## 对后续实现的约束

1. 复用共享 renderer，只增加有证据需要的平台参数；保留 Windows 原行为。
2. Linux 启动前检查选用的接口、路由表、rule priority 是否冲突；不得删除现存非本产品对象。
3. `Capture` 在任何写入前持久化基线和本次计划；运行后记录实际生成对象。异常恢复仅移除可证明归属的精确规则，不清空整套策略路由。
4. `Residue` 不仅检查 TUN/进程，还检查两种地址族的 policy rules。损坏日志或归属不明应保守失败。
5. 此试验不证明真实 HTTP CONNECT、DNS分流、防泄漏、宿主 resolved/NM 恢复、长期稳定或 Rocky9 兼容；这些仍是验收项。

原始日志：`namespace-current-TERM.log`、`namespace-short-TERM.log`、`namespace-short-KILL.log`。脚本：`namespace-core-probe.sh`、`render-probe.go`。
