# 跨平台构建门槛

核验日期：2026-09-07。基线：`d807080`；开发分支：`feature/cross-platform`。

## 已验证

- Windows amd64：Go `go1.27.0 windows/amd64`；`go test ./... -count=1` 全部通过。
- Windows PowerShell：`Invoke-Pester tests/powershell -EnableExit`，143 通过、0 失败。
- 以上仅为现有代码回归，不代表跨平台发布通过。
- Flutter `3.47.2`、提交 `d3b14c876900e553bc736ca19295fc09e3853e8e`，Dart `3.13.2 windows_x64`：已运行版本命令验证。来源为官方 Git 仓库与 SDK 自带下载流程。

## 平台清单

| 平台 | 当前条件 | 发布门槛 |
|---|---|---|
| Windows | Go/PowerShell/Flutter 可运行；VS BuildTools 17.14.39；Flutter 原生 Release 样例构建通过 | 产品 Release 构建、签名 MSI、新终端生命周期测试 |
| Ubuntu 22.04/24.04 | 新建 Ubuntu 24.04.4 测试 VM 116，172.20.8.48；原生 Go 全量测试及构建通过 | CLI、网络 namespace 与 DEB 生命周期测试；22.04 仍待验证 |
| Rocky 9 | 尚未指定专用测试机 | 原生 CLI、网络 namespace 与 RPM 生命周期测试 |
| macOS arm64 | 用户指定 EC 唯一受管 Apple 设备，开发后由用户测试；Xcode/Developer ID 未核验 | 最小扩展签名/安装/启停和签名分发仍待验证 |

不在现有生产服务器上执行改变路由、DNS 或防火墙的开发测试。缺少平台只阻塞该平台验收。

### Ubuntu 专用测试机

用户 2026-09-07 授权在 PVE 新建。VM 116 `regen-access-ubuntu-test` 位于 pve02：4 vCPU、4 GiB 内存、32 GiB local-lvm 磁盘；`onboot=0`，不承载业务。DHCP 地址 `172.20.8.48/22`，网关 `172.20.10.1`，DNS `172.20.9.1/.2`。账号 `regenbio` 使用管理公钥，密码登录关闭；主机公钥通过 PVE guest agent 核对后固定到独立 known_hosts。

镜像为 [Ubuntu 官方 24.04 release-20260826](https://cloud-images.ubuntu.com/releases/noble/release-20260826/)，SHA-256 `d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30`，下载完成后复核通过。初始化 `cloud-init status --long` 为 done，errors 为空。已验证 GCC 13.3.0、Git 2.43.0 和 Go 1.27.0 linux/amd64。基础环境可用不等同于产品 Linux 网络验收通过。

## Flutter

[官方支持矩阵](https://docs.flutter.dev/reference/supported-platforms)支持 Windows 10/11 与 macOS 12 及以上；本项目 macOS 仅 arm64，Linux 不使用 Flutter。

源码获取命令：

```powershell
git clone --depth 1 --branch 3.47.2 https://github.com/flutter/flutter.git flutter-3.47.2
git -C flutter-3.47.2 rev-parse HEAD
flutter-3.47.2/bin/flutter.bat --version
```

提交值见 `deploy/toolchains.json`。基础 Flutter Widget 样例测试通过；VS BuildTools 17.14.39 经 winget 校验安装器哈希后静默安装，`vswhere` 确认 C++ 组件、isComplete=true、isLaunchable=true、无需重启。

Windows `flutter build windows --release` 已成功生成独立 SDK 样例 `regen_build_smoke.exe`（构建阶段 39.7 秒）。它只证明工具链可用，不是产品 UI 或产品发布包。Google Storage 引擎下载停滞后，使用 [Flutter 中国网络说明](https://docs.flutter.dev/community/china)列出的 `storage.flutter-io.cn` 镜像完成下载；仅本次构建进程设置变量，未改全局网络或 SDK 版本。

官方发布清单再次确认相同 Flutter/Dart 版本及提交，并提供 Windows 完整归档 SHA-256，已记录到工具锁。本机采用 Git 源码加 SDK 缓存方式安装，未下载该完整归档，不把发布方提供的哈希当作本机归档校验结果。

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

[固定版本 LICENSE](https://github.com/SagerNet/sing-box/blob/v1.13.19/LICENSE)声明 GPL-3.0-or-later，并有名称/关联限制；已读取原文。分发前仍须核验嵌入依赖与对应源码交付要求，保存 notices；许可交付清单尚未完成，不把“仅内网”视作自动豁免。版本 tag 指向 `b5ebaa1fc0f2b94256180b95468e73ef53caa27d`。

## 待补证据

- 产品 Windows release 构建成功记录（SDK 样例已通过）。
- 原生 Linux 测试机器，macOS arm64/Xcode/签名身份。
- Apple 最小 System Extension 验证、嵌入构建与许可清单。
- [实施计划任务 13](../superpowers/plans/2026-09-07-cross-platform-delivery.md)规定的五台/平台、100 次循环、72 小时稳定性及卸载恢复证据。
