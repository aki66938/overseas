# Windows 海外访问客户端 0.1.7 现场验证报告

日期：2026-09-04  
测试终端：Windows 10，`172.20.20.200`  
验证构建：源码提交 `f041f5889357edc958b7632134a68083ff4d267a`

## 结论

0.1.7 修正版在测试终端上完成安装、首次连接、海外 HTTPS 访问、主动断开和再次连接验证。Google 与 YouTube 均通过 Windows HTTP 栈返回 HTTP 200；活动连接断开后遗留的产品自有 phantom Wintun 能被精确识别和移除，再连接耗时 897 ms。

## 已确认根因

1. 终端原先并非可靠安装了所称版本：Windows Installer 中存在 7 条同名注册，全部声明为 0.1.0，运行二进制来自旧提交 `5de032a`。
2. 旧安装缺少电信链路 MITM 根证书，导致海外 HTTPS 报不受信任根；禁用证书验证时传输本身可用。
3. 旧核心异常退出后留下 `SWD\WINTUN\*`、名称为 `sing-tun Tunnel` 的 `CM_PROB_PHANTOM` 设备，后续核心卡在打开 TUN。
4. 零防火墙规则模式仍运行旧 `firewall_audit`，在连接约 5 分钟时错误触发紧急恢复，造成稳定掉线。
5. 初版 phantom 恢复脚本使用 `$matches`；PowerShell 的 `-notmatch` 会覆盖不区分大小写的自动变量 `$Matches`，导致真实重连路径出现 `AddHashTableToNonHashTable`。
6. 历史 MSI 的卸载保护只接受 `disconnected`，但代理在普通网络已恢复时返回 `prepared`，导致安全卸载动作拒绝升级。现场先证明普通网络正常，再精确停止产品服务和删除产品 phantom，随后 7 条历史 MSI 均经 Windows Installer 正常卸载。

## 修复与验证

- 零规则模式不再创建防火墙审计 ticker；拥有规则时仍保持审计、紧急动作和 fail-closed。
- 启动前仅在核心未运行、设备实例/名称/Problem/注册表连接名全部精确匹配时删除唯一产品 phantom；歧义时拒绝操作。
- phantom 恢复变量改为 `$ownedPhantoms`，并增加自动变量冲突回归测试。
- 安装包固定版本 0.1.7、稳定 UpgradeCode、同版本权威替换、内置并安装指定根证书。
- 安装后验收：唯一注册数 1；版本 0.1.7；manifest 提交匹配；根证书指纹 `7903068AAA22CA51185706C23611E6B5EEEF2729`；服务路径为 `C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe`。
- 修正版 MSI SHA-256：`E6839974E996604CEA84B69FCEEB0C3289B3128789A11CEAFA83C678C3C658A9`。
- 自动化验证：`go test ./...` 全部通过；PowerShell 全量测试 143/143 通过（其中安装器测试 49/49）。
- 现场验证：首次连接 2.362 秒；活动连接断开后的再连接 0.897 秒；两次均可访问 Google/YouTube（HTTP 200）。
- 最终修正版重连后持续 5 分 44 秒仍为 `connected`，Google/YouTube 继续返回 HTTP 200，未出现旧版约 5 分钟审计掉线。

## 注意事项

Windows `curl.exe` 默认启用严格 Schannel 吊销检查，会对动态代理证书报告 `CRYPT_E_NO_REVOCATION_CHECK`；Windows `Invoke-WebRequest`（与浏览器常规链验证更接近）及 curl 的 best-effort 吊销模式均返回 200。这与原先的 `CERT_AUTHORITY_INVALID` 已不是同一问题。
