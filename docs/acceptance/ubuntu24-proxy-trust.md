# Ubuntu 24：代理与证书预检

日期：2026-09-07。专用测试 VM116，Ubuntu24.04.4，172.20.8.48。仅验证指定 HTTP CONNECT 代理与显式 CA 文件；未安装应用、未修改系统 CA、路由、DNS、防火墙或服务。

## 固定输入

- 代理：当前已配置节点 `172.20.9.15:8080`。
- CA：仓库 `deploy/client/Telecom-GoMITM-Root.cer`，本地与测试机复制后 SHA256 相同：`0d344a6f39fd4252c96f0e5606e2f4e7205cb2e59c44603c542aa8c132a711f8`。
- 证书 Subject/Issuer：`CN=Go MITM Root CA`。此处不是 AD 根证书，也不是 PoC 代码签名根证书。
- curl8.5.0，OpenSSL3.0.13；单次 HEAD，无 Cookie/凭据，无重定向跟随。连接5秒、总预算10秒；未使用 `-k` 或关闭证书校验。
- 测试脚本：工作区 `outputs/regen-access-testvm-20260907/probe-certificate.sh`。CA 只转换成测试目录内 PEM，通过 `--cacert` 供该请求使用。

## 实测

默认系统 CA 请求 Google：CONNECT200，但 curl60，`self-signed certificate in certificate chain`。

同一代理、显式上述 CA：

| 目标 | HTTP | CONNECT | TLS verify | 总耗时秒 | curl退出码 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Google | 200 | 200 | 0 | 0.189839 | 0 |
| Pinterest | 200 | 200 | 0 | 0.641424 | 0 |
| Gemini | 200 | 200 | 0 | 0.745406 | 0 |
| ChatGPT | 403 | 200 | 0 | 0.591383 | 0 |
| Claude | 403 | 200 | 0 | 1.153030 | 0 |

这证明测试时节点与固定 CA 可建立这些目标的受验证 HTTPS 连接。403 表示站点拒绝该请求，不证明账号或 AI 功能可用。请求由 curl 显式走代理，不是产品 TUN：不能替代 CLI、DNS 分流、IPv6 防泄漏、浏览器、系统 CA 安装、稳定性或三端验收。耗时仅此时点样本，不作为延迟承诺。
