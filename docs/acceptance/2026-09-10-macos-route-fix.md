# macOS 路由身份修复与实测

源码提交 bf46833461f4b16450413e49b255343551064ef7。

实际失败证据：journal记录0.0.0.0/1、Gateway=link#19、Interface=utun9、Index=19；netstat实际显示 `0/1 utun9 UScg utun9`。路由已创建，但原始文本身份比较拒绝并触发回滚。

修复仅在实际接口为utun9、网关字段同名、无RTF_GATEWAY大写G标志时，统一为link#实际正数索引。其他接口、IP下一跳和错误link索引不归一化。连接/监测/恢复统一使用parseRoutes，不跳过目标与网卡身份校验。

测试：原生新identity测试与名称渲染生命周期先RED，再全Darwin非root/root套件PASS；全原生go test ./... PASS；只读代码复审通过。Windows代码未改。

部署：完整安装器升级成功，后台重启且诊断默认关闭。升级首次因此前错误状态拒绝；明确disconnect后bootout存在短暂退出过渡，再确认服务确实不存在后重试成功。没有绕过安装器校验。

首次修复后连接前设root-owned独立launchd600秒恢复任务，测试结束在确认正常断开恢复后注销任务，未留活动定时任务。当前再次连接供用户实测。

真实结果（2026-09-10约19:11）：
- UID501 connect返回connected。
- 无显式HTTP代理的curl请求Google HTTP200、TLS验证0、约0.24秒；YouTube HTTP200、TLS验证0、约0.35秒。
- 八项probe均返回延迟：Google325ms、Pinterest613ms、Gemini1362ms、ChatGPT1000ms、Claude994ms、TikTok840ms、Amazon649ms、Facebook472ms；一次采样不代表长期性能。
- disconnect返回idle，DNS恢复172.20.9.1，默认网关保持172.20.20.1/en0，分流路由消失，sing-box不存在。
- 再次connect成功；再次YouTube HTTP200、TLS验证0。

DMG已复制并核对：/Users/regen-bio/Downloads/RegenBio-Access-macOS-arm64-PoC-bf46833.dmg。
SHA256 d6f72234297c80d62772540698b3640db27fafbe50ff2d9621bb1f7b657237b1。

这是短时连接、HTTPS、断开和重连验证；尚不等于浏览器视频播放、持续60分钟、真实进程崩溃或睡眠唤醒验收。
