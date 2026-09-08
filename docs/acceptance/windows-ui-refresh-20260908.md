# Windows UI 与探测改版验证

## Gemini 根因与复现

2026-09-08 15:50，172.20.20.200 已安装服务报告 connected、generation 9，Gemini 连续失败 3 次，`network_error`、HTTP 0、1529 ms，其余四目标均可达。

同机使用实际 Go Prober 及相同 TLS 校验策略的只读对照程序验证：

- `/` 与 `/app` 的 HEAD 和 GET 在 16 KiB 响应头上限下均失败，具体错误为 `server response headers exceeded 16384 bytes; aborted`。
- 提升到有限的 64 KiB 上限后，GET 返回 HTTP 200，响应头约 25,783–25,962 字节。
- HEAD 在两轮中出现 EOF，后续轮次也有正常 HTTP 200；因此不是仅改 URL 就能可靠解决的问题。
- 修复后的实际 Prober 在同机 `/` 返回 HTTP 200、1369 ms，`/app` 返回 HTTP 200、1348 ms。此处是诊断二进制验证，尚非升级后服务验收。

Windows curl 默认 Schannel 检查额外遇到 `CRYPT_E_NO_REVOCATION_CHECK`；没有禁用撤销检查或证书验证来取成功结果，也没有将这一独立 curl 错误当作 Go 探测根因。

## 修复边界

响应头上限从 16 KiB 调整为 64 KiB；HEAD 的 EOF/UnexpectedEOF 与既有 405 一样，最多使用一次 GET 回退，共享原 5 秒总预算。仍不读取响应体、跟随重定向、使用环境代理或关闭 TLS 验证。根路径不变。

新增 TikTok、亚马逊、Facebook，Go 固定目标、IPC 数量验证和 Flutter 目标映射同步为八站点；未知或重复目标仍拒绝。

## 回归证据

- RED：26 KiB TLS 响应被误拒绝、HEAD 提前断开不回退、八结果 API 被拒绝；相关新测试均得到预期失败。
- GREEN：26 KiB 接受、80 KiB 拒绝；EOF/UnexpectedEOF 单次回退且不读取响应体；重复 EOF 仍失败；八结果 API 往返及未知/重复目标校验通过。
- Windows `go test ./...` 全部通过；覆盖 agent、localapi、lineprobe、contracts、installer-verifier 等包。
- Flutter 八目标 parser 测试由 UI 实施者先确认预期 FormatException RED，再扩展模型。

## 交付状态

UI 源码完成于 `0f325d4`：轻量卡片布局、两页 460×540、八行详情、主页不再按站点质量显示警告，也无多余解释性页脚。所有十张视觉基线已检查；默认尺寸、200% 文字及窄视口滚动回归通过。Flutter analyze 无问题，82 个测试通过；Pester 198 通过、0 失败。探测专项审查和最终整合审查均批准，无待修问题。

签名安装包发布过程中时间戳服务间歇失败，两次失败分别发生在最终 MSI 与 Flutter EXE 签名，候选临时目录由发布脚本清理。独立时间戳样本签名及 RFC3161 校验通过，未关闭或绕过签名验证。此时尚未升级测试机。

最终版本、哈希及升级后验证另行记录；上述测试不代替用户实机 GUI 评价或长期稳定性验收。

## 最终部署结果

- 版本：0.1.10，构建源 `1239e5b15a2ad57546e3e8eb810fcc99d20c0506`。
- MSI SHA256：`241BD51916930EFEA36DE2A0E422AB797039A1A5A1B70E5741613DFCE3193EA3`。
- 本地包：工作区 `outputs/windows-ui-refresh-20260908/source-lf/dist/OverseasAccessSetup-v0.1.10-poc-RELEASE_SIGNED.msi`。
- 时间戳重试补充：每个签名至多三次、间隔两秒，持续失败仍阻止发布；没有更换信任或去掉时间戳。专项 RED→GREEN、Pester 最终 202/202、Go verifier/contracts 通过、原生签名样本校验通过，补充审查批准。
- 最终发布、29 项包内清单检查、SignTool `/pa /tw` 校验通过。WiX 反编译保留既有 WIX1059/WIX1060 提示，原始 MSI 表与清单验收通过。
- 测试机 172.20.20.200：MSI 退出 0；安装后 payload verifier 退出 0；仅一个 0.1.10 注册项；服务 Running，安装清单版本和源提交一致。
- 升级后初始 idle；使用正常 API 恢复连接，generation 2，16:15:39 开始连接。
- 已在用户交互会话 2 打开安装目录中的新 GUI（PID 2168）。一次性启动任务已删除；默认诊断模式未开启。
- 16:16:13 八目标 HTTPS 首响应结果全部 reachable：Google 327 ms/200、Pinterest 619 ms/200、Gemini 1310 ms/200、ChatGPT 998 ms/403、Claude 987 ms/403、TikTok 858 ms/200、亚马逊 735 ms/200、Facebook 464 ms/200。403 表示站点回应，并不证明账号或功能可用。
- 首次收集器结果读取出现任务退出码竞态（267009 为运行中旧值），刷新最终状态后复核 API_TASK_EXIT=0，响应 ID、版本与完整帧均验证；这不是应用错误，未更改产品代码。
- 保留既有受保护回滚备份及本次升级日志 `C:\ProgramData\RegenBio\PilotBackup-20260908\upgrade-0110.log`。

交付为 Windows 测试版；GUI 审美由用户实机复核，长时间稳定性、Mac/Linux 不包含在本次结论。未合并主分支或推送 GitHub。
