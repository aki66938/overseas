# RegenBio Access macOS 内部 PoC

这是 Apple Silicon 专用的自包含安装镜像，包含 GUI、root LaunchDaemon、固定 sing-box 1.13.19、管理 CLI、安装/卸载程序、固定节点策略和流量 CA。不是 Developer ID 签名或公证发行包；不关闭 SIP、Gatekeeper、MDM，也不安装 sudo 白名单。

打开镜像并运行 `Install.command`，输入实际日常使用者的本地短账户名（测试机为 `regen-bio`；程序查询实际 UID，不硬编码 501）。阅读并明确接受流量 CA 说明后，仅一次 sudo 管理员授权。若系统策略阻止运行，请由 IT 审核来源后通过系统提供的正常批准方式打开；脚本不会绕过系统保护。

脚本只调用一次 sudo，但 macOS 系统证书信任可能另需本机图形会话中的授权确认。实测无交互 SSH 会话中的 root 也可被系统拒绝；此时安装失败并执行回滚，不宣称已安装成功，不放宽 authorizationdb 或其他系统授权策略。

请在日常使用者已登录的 Mac 桌面挂载 DMG，双击 `Install.command`，保持打开的终端窗口在前台，阅读并处理系统可能显示的信任授权。本机 GUI 安装是待验证步骤，不保证仅切换会话就会通过系统策略。若仍出现“no user interaction was possible”，停止重试，由 IT 在本机系统钥匙串界面核对指定 CA 与授权要求；不通过 SSH 放宽授权策略。

安装后的 GUI 路径为 `/Library/Application Support/RegenBioAccess/RegenBio Access.app`。以所选普通账户打开，日常连接与断开无需管理员授权。原 `/Users/Shared/RegenBio-PoC-20260910/RegenBio-UI-Preview.app` 不受影响。后台服务名称为 `com.regenbio.access.poc`，初始状态 idle，不自动连接。

## 流量信任变更

Telecom GoMITM Root 用于企业出口 HTTPS 流量检查，信任它意味着相应网关可以解密和检查 HTTPS 流量；它不是应用签名证书。SHA256 为 `0D344A6F39FD4252C96F0E5606E2F4E7205CB2E59C44603C542AA8C132A711F8`，SHA1 为 `7903068AAA22CA51185706C23611E6B5EEEF2729`。本 PoC 的测试出口已验证需要该 CA，安装需明确输入 TRUST。若系统钥匙串已有精确证书，安装器验证现有信任，不重写；现有信任不足则拒绝安装并回滚。新建信任仅用于 SSL，记录在 root-only receipt.json；卸载仅撤销本次管理安装所添加的精确证书。TLS 验证始终开启。

系统可能先导入证书，再拒绝写入信任。回滚在核对本次新增收据、固定指纹和系统钥匙串中的精确证书后，允许“指定信任记录明确不存在”的固定系统返回，继续删除这张本次新增证书。授权失败、超时或任何不确定返回仍保留证书和安装现场供 IT 处理。

## 安装完整性、升级与卸载

安装前校验完整清单、核心固定摘要、CA 固定摘要及固定 HTTP CONNECT 策略。清单是传输完整性校验，不是供应商身份签名；仅接受 IT 交付且已核对 DMG SHA256 的镜像。原生 GUI 保持 ad-hoc 签名校验。系统路径拒绝符号链接和非 root 可写祖先；App 内仅允许最终目标仍在同一个 App 内的框架链接。

安装目录 root:wheel 0755，二进制 root:wheel 0755，state 0700，配置与安装记录 0600，LaunchDaemon plist 0644。`/private/var/run/regen-access` 为 root:wheel 0755，原系统 `/private/var/run` 的 root:daemon 0775 不改动。后台进程组随 launchd 管理，停止期限 100 秒。

由于 macOS 会继承父目录所属组，安装器对所有新建目录、文件和框架链接显式设定并验证 root:wheel，不依赖进程的主组。已存在但权限或所属组不符的运行目录会被拒绝，需 IT 先审核。launchd 查询只在返回明确的指定服务不存在错误时才允许继续；超时和通信错误均中止操作。停止后再次查询确认服务已注销，不以锁暂时空闲替代该证据。

升级必须 idle；connected 或恢复不确定即拒绝。先停止后台，再调用固定服务 `--restore` 获取独占锁，按持久核心归属记录、网络日志的顺序恢复。恢复不成功保留所有文件。旧安装与旧 plist 在同目录备份；新后台启动失败则停止新服务、执行恢复并还原旧版。备份包含 root-only 状态，永久保留供 IT 审核。安装被强制中断或磁盘故障时可能留下 stage/backup/failed 目录；不要手工删状态或强行重启，先由 IT 审核具体残留。

卸载可运行镜像中的 `Uninstall.command`，也可 `sudo '/Library/Application Support/RegenBioAccess/regen-access-installer' uninstall`。先断开、停止并离线恢复，成功后才将精确安装目录和 plist 改名为 `.uninstalled-时间戳`。此为可恢复卸载，不递归删除状态、旧备份、系统目录、预览包或其他软件；保留运行时锁目录防止锁 inode 分裂。恢复未确认则拒绝卸载。撤销 CA 信任以后，重新使用保留备份必须再次走安装器。

## IT 构建与验收

在已配置的测试 Mac 源码根目录运行：

```sh
GO=/Users/codexdiag/regen-access-poc/toolchain/go/bin/go \
  bash scripts/macos/build-poc.sh /absolute/Release/regen_access.app /absolute/sing-box /absolute/RegenBio-Access-PoC.dmg
```

构建重编服务、CLI 和安装器，复用已验证的 Release GUI；不下载组件，不现场安装。无 `.git` 的源码归档需额外传入 `SOURCE_COMMIT=<真实40位源码提交>`。发布镜像与输出 SHA256 一起交付。`SOURCE-COMMIT.txt` 记录构建源码提交；GUI 输入应由同一审阅源码构建。测试命令为 `go test ./scripts/macos/installer`；Mac root 路径拒绝测试还需 `go test -c -o /absolute/installer.test ./scripts/macos/installer` 后 `sudo /absolute/installer.test`。

固定管理 CLI：`'/Library/Application Support/RegenBioAccess/regen-access' status`，也支持 connect、disconnect、probe。诊断默认关闭，仅 root 可限时启用。首次真实连接前，由 IT 设置独立限时恢复任务，先保存 DNS、路由与代理，再验证 CLI 和 GUI、断开、重连、核心异常退出及持续连接至少 60 分钟。睡眠唤醒需用户协助，不能以脚本空跑替代。Task3 的 PID 身份检查与发信号之间仍存在 macOS 无 pidfd 的窄竞态；未宣称零风险。

紧急恢复需先停止服务，再执行：

```sh
sudo launchctl bootout system/com.regenbio.access.poc
sudo '/Library/Application Support/RegenBioAccess/regen-access-service' --restore
```

若停止失败或 restore 非零，保留文件并联系 IT，不手动删除 journal 或杀其他进程。安装成功不等于真实网络、浏览器、60 分钟或睡眠唤醒验收通过。
