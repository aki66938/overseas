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

UI 与签名安装包仍在实施验证中；本记录不代表已部署或完成实机 GUI 验收。最终版本、哈希、升级结果和 UI 测试记录将在交付时补充。
