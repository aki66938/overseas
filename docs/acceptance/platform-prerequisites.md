# 跨平台构建门槛

核验日期：2026-09-07。基线：`d807080`；开发分支：`feature/cross-platform`。

## 已验证

- Windows amd64：Go `go1.27.0 windows/amd64`；`go test ./... -count=1` 全部通过。
- Windows PowerShell：`Invoke-Pester tests/powershell -EnableExit`，143 通过、0 失败。
- 以上仅为现有代码回归，不代表跨平台发布通过。
- Flutter 源码固定到 `3.47.2`、提交 `d3b14c876900e553bc736ca19295fc09e3853e8e`。来源为官方 Git 仓库，SDK 依赖初始化尚未完成。

## 平台清单

| 平台 | 当前条件 | 发布门槛 |
|---|---|---|
| Windows | 本机可运行 Go/PowerShell；尚未发现 Visual Studio C++ 工具链 | Flutter 初始化、C++ 工具链、签名 MSI、新终端生命周期测试 |
| Ubuntu 22.04/24.04 | 尚未指定专用测试机 | 原生 CLI、网络 namespace 与 DEB 生命周期测试 |
| Rocky 9 | 尚未指定专用测试机 | 原生 CLI、网络 namespace 与 RPM 生命周期测试 |
| macOS arm64 | 未提供 Mac、Xcode 与 Developer ID 身份 | 最小扩展签名/安装/启停成功后再接入完整隧道 |

不在现有生产服务器上执行改变路由、DNS 或防火墙的开发测试。缺少平台只阻塞该平台验收。

## Flutter

[官方支持矩阵](https://docs.flutter.dev/reference/supported-platforms)支持 Windows 10/11 与 macOS 12 及以上；本项目 macOS 仅 arm64，Linux 不使用 Flutter。

源码获取命令：

```powershell
git clone --depth 1 --branch 3.47.2 https://github.com/flutter/flutter.git flutter-3.47.2
git -C flutter-3.47.2 rev-parse HEAD
flutter-3.47.2/bin/flutter.bat --version
```

提交值见 `deploy/toolchains.json`。必须记录实际 Dart/engine 与编译输出后才标记工具链就绪；不要把源码检出当作 SDK 安装成功。

## macOS 企业直发

[Apple TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)明确：macOS Packet Tunnel 的普通 App Extension 仅限 App Store；Developer ID 直发应使用 **System Extension**。这是已批准 Packet Tunnel 方案的具体打包形式，不改变界面或数据面选择。

- 使用 Packet Tunnel System Extension 与对应 `packet-tunnel-provider-systemextension` entitlement。
- 容器验证 System Extension 安装权限、扩展 provisioning、Team ID、App Group 与 Keychain 权限一致。
- 扩展通过系统激活流程安装；不能仅把 `.appex` 拷入应用并声称支持企业直发。
- 最小验证必须在 arm64 Mac 上完成：签名、激活、授权、启动、停止、卸载。
- Windows 交叉编译和 CI 协议测试不替代这些证据。当前状态：未验证。

## sing-box 嵌入边界

继续固定 `v1.13.19`，Windows 现有归档/可执行文件哈希见 `sing-box.manifest.json`，不升级已经验证的数据面。

[固定版本 Makefile](https://github.com/SagerNet/sing-box/blob/v1.13.19/Makefile)提供 `go run ./cmd/internal/build_libbox -target apple`，实现入口位于 `experimental/libbox`。这是后续 Apple 构建核对入口，不代表当前已生成或验证 framework。Apple 库、绑定工具及源提交仍需单独锁定，不能沿用 Windows exe 哈希。

分发前核验 [固定版本 LICENSE](https://github.com/SagerNet/sing-box/blob/v1.13.19/LICENSE)、嵌入依赖与对应源码交付要求，并保存 notices；尚未完成许可交付清单核验，不把“仅内网”视作自动豁免。

## 待补证据

- Flutter/Dart 实际版本输出与 Windows 构建成功记录。
- 原生 Linux 测试机器，macOS arm64/Xcode/签名身份。
- Apple 最小 System Extension 验证、嵌入构建与许可清单。
- 五台/平台、100 次循环、72 小时稳定性及卸载恢复证据。
