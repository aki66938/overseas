# Ubuntu 24.04 共享层验证

日期：2026-09-07。专用 VM 116：Ubuntu 24.04.4 LTS，Go 1.27.0 linux/amd64，GCC 13.3.0。真实网络变更门控 `OVERSEAS_ACCESS_NETWORK_GATE=0`。

## RED

提交 `ae1a837` 原生全量测试失败：Windows DPAPI 路径在 Linux 上被宿主机 `filepath.IsAbs` 拒绝；部分 Windows 运维夹具混入共享测试。不是编译错误。

## GREEN

提交 `3f1d7f1`：

```text
go test ./... -count=1   PASS
go build ./...          PASS
```

源码归档 SHA-256：`c8e1661fc7f26de4f2e4d97160b999ff0d4d050ce69c077e33dfe2258cd6eb94`。工作区证据：`outputs/regen-access-testvm-20260907/native-red.log`、`native-3f1d7f1.log`。归档在传入 VM 后再次校验。

修正保留 Windows 路径原始值及策略哈希，保持 Windows 专属测试；共享协议和行为测试仍在 Ubuntu 原生执行。单独代码审查通过。

此证据仅覆盖共享核心及现有测试，不证明 Linux TUN、路由恢复、DEB/RPM、Ubuntu 22.04、Rocky 9、macOS 或长期稳定性通过。
