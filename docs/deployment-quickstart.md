# Windows 转发 PoC 部署速览

## 交付物性质

本发布包用于在 Windows Server 网关 VM 上验证：外部 WireGuard 客户端的流量能否经 Windows NAT 进入已经用 PIN 登录的电信客户端。它不是最终员工客户端，也不会自动登录 PIN。

## Windows VM 前置条件

- Windows Server 2022 或 2025；
- 管理员 PowerShell 和 VM 控制台访问；
- 电信客户端已安装，并由 PIN 持有人手工登录；
- WireGuard for Windows 已安装，且已创建测试隧道接口；
- 三个可区分的接口角色：员工网卡、WireGuard 接口、电信客户端接口；
- 一个运营商明确允许的 HTTPS 测试目标；
- 已批准的维护窗口和 VM 快照。

如果电信客户端没有独立接口或明确的外部路由，先停止，不要猜测接口名称。

## 部署

1. 将整个发布目录复制到 Windows VM，例如 `C:\OverseasGatewayPoc`。
2. 以管理员身份打开 PowerShell，进入该目录。
3. 复制配置：

   ```powershell
   Copy-Item .\configs\poc.example.yaml .\configs\poc.yaml
   ```

4. 编辑 `configs\poc.yaml`，填写真实接口名称、WireGuard 地址池、电信路由前缀、内部网段及批准的 HTTPS 目标。
5. 验证配置：

   ```powershell
   .\poc-probe.exe preflight --config .\configs\poc.yaml
   if (-not $? -or $LASTEXITCODE -ne 0) { throw 'preflight failed' }
   ```

6. 阅读完整操作手册，再执行任何网络修改：

   ```powershell
   Get-Content .\docs\poc-runbook.md
   ```

## 使用顺序

严格按照 `docs\poc-runbook.md` 执行：

1. 验证配置和接口；
2. 创建网络状态快照；
3. 使用 `apply-poc.ps1 -WhatIf` 预演；
4. 采集变更前证据；
5. 执行一次真实 apply；
6. 采集电信线路在线探测；
7. 由 PIN 持有人手工断开电信客户端，执行持续无泄漏检测；
8. 回滚所有 PoC 网络配置；
9. 采集变更后证据并生成 verdict。

只有最终 verdict 为 `PASS`，才证明可以进入正式服务端和员工客户端开发。`FAIL` 或 `INCONCLUSIVE` 均不得继续。

## 回滚入口

真实 apply 前必须保存 `snapshot.ps1` 输出的准确快照路径。发生异常时从 VM 控制台执行：

```powershell
.\scripts\windows\rollback-poc.ps1 -SnapshotPath '<实际快照绝对路径>' -Confirm:$false
```

不要把示例路径、示例接口或 `example.invalid` 用于真实测试。
