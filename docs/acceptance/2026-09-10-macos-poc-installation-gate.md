# macOS PoC 安装阶段记录

日期：2026-09-10。测试机 RB-LT-N40MJH，Apple Silicon、macOS 26.6.2；日常账户 regen-bio，UID501。

## 当前交付

- 源码提交：`b01c84238fb52ba22197d76b4026211771c40c67`。
- Mac 文件：`/Users/regen-bio/Downloads/RegenBio-Access-macOS-arm64-PoC-b01c842.dmg`。
- SHA256：`de36fc738b52332fb63bb1ec0f071aef15139ac9d80949711c1409ae7f5e4b0d`。
- 包含 GUI、后台服务、固定 sing-box、CLI、安装/卸载器、策略和流量 CA，无需另装开发工具。
- 这是待本机安装授权和网络验证的 PoC，不是已通过联网验收的发行包。旧 b6a35e7、66239dc 镜像不交付。

## 已验证

Darwin Go 全套测试在 Task3 通过；原生 Swift IPC 测试通过。Flutter Release 构建通过；Flutter 测试76通过、10个既有 golden 差异未掩盖。最终安装器普通用户测试和原生 root 19项测试通过。root:wheel 继承缺陷先原生复现再修复；launchd 查询不确定时停止，相关复审通过。

真实安装曾启动后台至 idle，但在流量 CA 信任阶段失败：SSH 无交互会话收到 `SecTrustSettingsSetTrustSettings: The authorization was denied since no user interaction was possible.` 此时证书导入已发生、信任未写入。修复并复审了这一部分失败状态的精确清理路径，最终运行新版 helper 卸载成功。

10:19 UTC 核对：后台服务未注册，无 sing-box 进程；精确新增流量证书已移除，原 ManageEngineCA-Root、MDM、MDM Signing Certificate 三项信任保持。Wi-Fi DNS 为原172.20.9.1，默认网关为原172.20.20.1/en0。整个过程没有调用 connect，没有切换 TUN、DNS或路由。

失败安装已可恢复改名保留在 `/Library/Application Support/RegenBioAccess.uninstalled-20260910T101844.853995000Z`，对应 plist 同样保留；runtime锁目录保留，避免锁 inode 分裂。未改 SIP、Gatekeeper、MDM 或系统授权策略，未改 Windows 安装。

## 本机所需操作

在 Mac 的下载目录打开上述 DMG，运行 `Install.command`。日常用户名填 `regen-bio`；阅读流量 CA 说明后输入 `TRUST`，使用本机管理员密码并处理系统授权弹窗。此流量 CA 供公司出口 HTTPS 检查使用，不是 Developer ID 或应用签名证书。TLS 校验继续开启。

若本机仍拒绝信任授权，保留错误由 IT 处理，不放宽 authorizationdb。安装完成先不要连接，通知开发人员确认后台和独立限时恢复措施后再做首次联网测试。

## 未完成验收

本机交互安装、普通用户 GUI/CLI、真实 Google/YouTube 浏览、断开与重连、核心/后台异常恢复、至少60分钟持续连接、睡眠唤醒均待验证。现有编译和测试不替代这些证据。
