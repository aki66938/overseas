# Windows 升级测试基线

2026-09-07 只读检查：

| 项目 | 实际结果 |
|---|---|
| 测试设备 | `RB-LT-9BAF42`，`172.20.20.200` |
| SSH | 2222，已有管理公钥可登录 |
| 系统 | Windows 10 LTSC，10.0.19044，64 位 |
| 已安装产品 | RegenBio Overseas Access 0.1.7 |
| MSI ProductCode | `{A74B41C9-80F3-4DE2-A3C9-B6E7466EA085}` |
| 后台服务 | RegenBioOverseasAccessAgent，Running |

检查使用 `hostname`、`Get-CimInstance Win32_OperatingSystem`、`Get-Service` 和卸载注册表读取；未调用 `Win32_Product`，未触发安装修复。未升级、停止服务或修改测试设备网络。

此设备具备旧版升级测试起点；尚未验证新 GUI 安装、升级、回滚或卸载。不能替代干净机及五台设备验收。
