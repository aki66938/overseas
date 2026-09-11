# macOS 状态栏阶段验收

日期：2026-09-11。对应 PKG/menu-bar 计划任务1–3；不是完整 PKG 交付。

## 已完成的代码与检查

- 持久 Flutter 控制器由 AppDelegate 持有；NSStatusItem + NSPopover 替代 nib 主窗口，LSUIElement 开启。
- 左键展开/收起、Esc/外部点击收起设计已实现；同一控制器在收起和展开之间保留。右键仅状态、连接操作、安全退出。
- 新增 SafeExitState，退出中禁止重复操作，恢复失败后还原最近的菜单操作权限并显示简短错误；保留既有 Dart 网络恢复确认。
- 本机编译新增 Swift 测试前先观察到缺少 MenuBarHost/SafeExitState 的失败，然后实现并通过测试。
- 图形测试最初没有等待状态栏布局，出现 isShown=false；测试补入事件循环布局阶段后，实机原生展开/收起/重开断言通过，未为此改动产品代码。
- Flutter 定向测试7项通过（原3项＋4项安全退出已有契约回归），release构建成功39.3MB。构建仍有 Flutter/Xcode 构建阶段及依赖更新提示，未升级依赖。
- 安装预检选择真实本地图形账户；升级按受保护收据保持 owner UID，拒绝不一致的显式用户名。launchd 注销等待10秒总预算，每次查询最多1秒；超时/未知查询不被当作已停止。
- 安装器新增身份/等待测试先失败后通过；macOS 普通用户测试通过，root-only两项在普通用户下跳过后单独通过root全套测试（23个顶层测试）。未在现有安装运行新版安装器。

## 实机操作

主机172.20.21.115；日常账户regen-bio UID501。用户已明确允许短暂中断。

1. 切换前 CLI 状态为connected，持续约1小时3分32秒，八站点均有测量值。这是既有网络核心的状态快照，不代表新版UI完成60分钟稳定性验收。
2. 通过已有CLI断开，返回idle；DNS恢复172.20.9.1，默认网关172.20.20.1/en0，未发现sing-box进程。
3. 核对旧GUI PID29919的UID和完整路径后，仅终止该GUI。后台安装保持不变。
4. 从 `/Users/Shared/RegenBio-MenuBar-20260911.app` 启动独立预览（不是PKG，也未移到Applications）。签名验证通过，Info.plist的LSUIElement为true。
5. 运行时检查：预览PID33570，activationPolicy为accessory；启动时无可见内容窗口。再次open同一路径后，仍为同一PID，出现单个popover窗口。未启动第二个GUI进程。
6. 按既有CLI重连返回connected；Google/YouTube的HTTPS HEAD均为HTTP200，未关闭TLS验证。该检查不是GUI按钮或浏览器视频验收。

## 待验证及剩余工作

- 远程按窗口截图报 `could not create image from window`，未修改系统权限来强制截图。实际Flutter画面、右键点击、Esc、详情与用户操作仍需本机确认；原生宿主测试不能代替实际Flutter画面。
- 真实安全退出成功/失败、睡眠唤醒、新版60分钟、不同显示缩放/屏幕边缘未全部验收。
- PKG、Applications迁移事务、首次未管控设备CA授权尚未完成。
- 当前正式安装仍在 `/Library/Application Support/RegenBioAccess`；需要恢复旧GUI时，先退出预览并确认网络恢复，再打开原App。不要同时运行两个GUI。
- Windows没有改动；两份未跟踪Linux supervisor文件原样保留；未推送GitHub。
