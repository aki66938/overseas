# Windows 客户端 MITM 根证书安装修复设计

日期：2026-09-04  
状态：已确认，等待实施

## 1. 问题与证据

`OverseasAccessSetup-v0.1.5-poc.msi` 已包含 `Telecom-GoMITM-Root.cer`，但 MSI 仅将证书复制到安装目录。证书导入函数存在于 `install-client.ps1`，安装执行序列却没有调用该脚本的 `Install` 模式，也没有 WiX Certificate 表或等价的证书安装动作。

VM101 的 HTTP CONNECT 代理能够建立连接。Google、YouTube 和 Pinterest 的实时叶证书均由 `CN=Go MITM Root CA` 签发，其 Authority Key Identifier 为 `2d2518e3674cf636438adbf36d6bb30c228d3c09`；安装包内 `Telecom-GoMITM-Root.cer` 的 Subject Key Identifier 与之完全一致。因此根因不是 CA 版本不匹配，而是新终端没有把正确 CA 安装到系统信任库。

## 2. 本次目标

- MSI 安装时把 `Telecom-GoMITM-Root.cer` 安装到 `LocalMachine\Root`。
- 证书安装参与 MSI 事务；失败时安装回滚，不留下半安装状态。
- 卸载时移除由本产品安装的证书。
- 安装包静态检查能够证明证书不仅存在于 File 表，也存在于证书安装声明和执行链路中。
- 干净 Windows 10 安装后，Google、YouTube、Pinterest 通过 VM101 代理时不再出现 `NET::ERR_CERT_AUTHORITY_INVALID`。
- 保持现有快速连接路径，不在本次修改 UI、授权、安全加固或网络架构。

## 3. 方案

使用 WiX 的声明式、事务化证书安装能力管理 Telecom MITM 根证书。证书组件绑定到现有客户端安装 Feature，并以机器范围写入受信任根证书库。

本次只信任 `Telecom-GoMITM-Root.cer`。`RegenBio-OverseasAccess-PoC-Root.cer` 是代码签名证书，不导入 Root 或 TrustedPublisher；Authenticode 和清单签名仍使用现有固定指纹校验。

不采用以下方案：

- 不通过未被 MSI 调用的 `install-client.ps1` 隐式导入证书。
- 不让长期运行的 Agent 在启动时修改系统信任库。
- 不关闭 Chrome 或系统的证书验证。
- 不使用 `--ignore-certificate-errors`、`-k` 或等价绕过作为验收结果。

## 4. 安装与卸载行为

安装顺序为：复制并验证载荷、安装 Telecom 根证书、安装服务、应用防火墙规则。证书安装失败必须令 MSI 失败并回滚。

卸载由 MSI 组件生命周期移除证书。实现必须避免使用按主题名称模糊删除的脚本；证书身份由 WiX 声明和固定证书载荷确定。

升级继续沿用现有 UpgradeCode。新包使用递增 ProductVersion 和新 ProductCode，确保 Windows Installer 能识别并执行升级，而不是把修复包视为相同版本。

## 5. 测试与 POC 门槛

先新增失败测试，验证当前 MSI 源码缺少证书安装声明。修复后测试至少覆盖：

- WiX 源码声明机器级 Root 证书安装；
- Telecom CA 文件属于安装 Feature；
- 代码签名证书没有被声明为受信任根；
- MSI 静态检查能读取到证书安装相关表或动作；
- MSI、载荷、策略和签名检查全部通过；
- Go 与 PowerShell 现有回归测试通过。

干净 Windows 10 POC 必须记录：安装前证书不存在；MSI 成功安装；安装后固定指纹存在于 `LocalMachine\Root`；连接时间保持当前水平；Google、YouTube、Pinterest 正常完成 TLS 和页面加载；连续运行观察期间没有隧道掉线；卸载后证书和产品网络状态均恢复。

只有上述 POC 通过，才开始后续安全措施和 UI 优化。

## 6. 交付与版本控制

设计、测试、实现和构建修复分别保留清晰提交。最终提交包含源码、测试、版本变更和必要文档，不提交含内部拓扑或终端隐私信息的运行日志。生成的 POC MSI 输出到既有发布目录，并提供 SHA-256、签名状态和对应 Git 提交。
