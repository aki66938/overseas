# Overseas Access Gateway（海外访问网关）

企业内网用户的海外访问通道。客户端一键连接，经公司电信专线出口访问海外站点；内网流量不受影响。

Windows 客户端（服务 + UI）基于 [sing-box](https://github.com/SagerNet/sing-box) 内核，服务端为 VM 上的 HTTP CONNECT 出口代理。

## 架构（PoC 阶段）

```
用户 PC                                   电信出口
┌─────────────────────────┐              ┌──────────────┐
│ App(浏览器)              │              │              │
│   ↓ 系统解析             │              │              │
│ sing-box TUN (auto_route│   专线       │  VM101 代理   │──→ 海外站点
│   + fakeip DNS)         │──────────────→│  :8080       │
│ RegenBio 服务(LocalSystem)│              │              │
│ RegenBio 客户端 UI       │              └──────────────┘
└─────────────────────────┘
```

- **路由**：sing-box `auto_route` 自管（进程停止路由自动消失）
- **DNS**：fakeip（隧道内零 DNS 流量），原生 `SetInterfaceDnsSettings` 切换，断开按快照精确还原
- **连接事务**：验证 → 预备（内存态）→ 启动核心 → TUN 归属校验 → DNS 切换 → connected；任一步失败自动逆序恢复
- **运行期**：核心存活监控 + 网络指纹监控，异常自动恢复普通网络
- **互斥**：检测其他 TUN VPN（Clash 系/iKuuu/Sakura 等）运行时明确拒绝（`vpn_conflict`）

## 实测（PoC，2026-09）

| 指标 | 数值 |
|---|---|
| 首次连接 | ~3 秒 |
| 二次连接 | ~0.7 秒 |
| 断开恢复 | ~3 秒 |
| 稳定性 | 90 秒持续探测 6/6 全通（海外/内网并存） |

## 仓库布局

```
cmd/
  overseas-agent/          # Windows 服务（连接生命周期、管道 API）
  overseas-client/         # Windows UI（walk）
  overseas-server-service/ # VM101 出口侧服务
internal/
  agent/                   # 连接事务、网络管理、TUN/路由/DNS（原生）
  singconfig/              # sing-box 客户端/服务端配置渲染
  supervisor/              # 核心进程管理（Job Object、二进制验证）
  clientapi/               # 命名管道协议
  traceevent/              # 结构化诊断时间线
deploy/client/             # WiX 安装包、安装事务脚本
scripts/windows/           # 构建/签名/发布流水线
tests/powershell/          # Pester 套件
```

## 构建

要求：Go 1.27+、Windows、WiX v4（哈希锁定于 `deploy/client/build-lock.json`）。

```powershell
go build -trimpath -o bin/overseas-agent.exe ./cmd/overseas-agent
go build -trimpath -ldflags "-H windowsgui" -o bin/overseas-client.exe ./cmd/overseas-client
go test ./...
```

发布签名 MSI（需代码签名证书）：

```powershell
scripts/windows/publish-client-release.ps1 `
  -SigningCertificateThumbprint <thumbprint> -SignToolPath <signtool> `
  -FinalMsiPath dist/OverseasAccessSetup-RELEASE_SIGNED.msi
```

CI：push 到 `main` 自动构建并运行测试（`.github/workflows/build.yml`）。

## 安装与使用

1. 双击 MSI（自动导入签名证书、安装服务、启动并后台预备）
2. 打开「RegenBio 海外访问」→ 点击 **开启海外访问**
3. 断开：点击 **关闭海外访问**（普通网络立即恢复）

要求：管理员安装；使用前退出其他 TUN 类 VPN/代理。

## 安全说明（PoC 阶段）

当前为可行性验证版本：防泄漏防火墙策略尚未启用（出网管控由服务端侧承担），代码签名为内部测试证书。生产化路线：正式代码签名、服务端出口管控强化、客户端防泄漏策略作为可选项回归。

## License

内部项目。sing-box 与 Wintun 的许可文本随安装包分发。
