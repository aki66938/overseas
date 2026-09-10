# Mac GUI 本地通信修复

源码：122566058b6fcd3bfaddca5cab59e9dff09099f3。

根因：Foundation resolvingSymlinksInPath 将实际 /private/var 路径简写回 /var，GUI 的精确路径比较错误拒绝正常 socket。UID501 CLI status 正常，所有实际目录/socket权限正常，Swift checkPaths 返回false。

最小修复改用 POSIX realpath 并释放返回缓冲区；保留固定目标、目录/文件权限和后台 root 身份检查。未改 Windows、证书或网络行为。

验证：新增 --installed-service 只读集成测试，以日常UID501运行，原代码明确FAIL，修复后 status 请求和整个 Swift -Onone 测试通过；普通UID502原生非集成套件通过；Flutter Mac client/shell 3项通过。原生 Release构建成功39.3MB。独立只读代码复审通过。

真实部署于2026-09-10 18:35：先确认后台idle且无sing-box，关闭明确的旧GUI进程，再由完整安装器升级成功；保留原有流量CA信任及旧安装备份。以UID501重新启动GUI，新后台和GUI进程均存在，安装后再次运行UID501 Swift真实status回归通过。

安装GUI与构建GUI可执行文件SHA256均为1f440f63967d8f45e416f83c6efed4be6952e2fa90cf3637d460f3ad3259bdcb，codesign --verify --deep --strict通过。

新DMG：/Users/regen-bio/Downloads/RegenBio-Access-macOS-arm64-PoC-1225660.dmg。
SHA256：b4933a85c7c266851b5d7e751994678aaa0828343fa509e781d2a3fb9254d45e。

未进行实际连接/断开网络、60分钟测试或睡眠唤醒；未通过屏幕确认最终GUI显示，待用户观察已重开的窗口。此记录不等于网络PoC验收通过。
