# Linux 打包预检

2026-09-07，专用 VM116（Ubuntu24.04.4，172.20.8.48）。这是构建环境准备，不是产品安装或 Rocky 运行验收。

## 工具

原有 dpkg-deb1.22.6。先执行 apt 模拟安装，确认仅新增10个 RPM 构建依赖、无升级或删除；随后从既有 Ubuntu 源安装 `rpm`，结果退出0。下载810kB，新增磁盘约2854kB。`rpm --version` 与 `rpmbuild --version` 均为4.18.2；`dpkg --audit` 无输出。

新增包：debugedit、libfsverity0、liblua5.3-0、librpm9t64、librpmbuild9t64、librpmio9t64、librpmsign9t64、rpm、rpm-common、rpm2cpio。没有启动产品服务，没有安装 NetworkManager，没有修改系统信任库。needrestart 报告 unattended-upgrades 重启延期，未要求重启机器。

完成后 SSH、systemd-networkd、systemd-resolved 均 active。默认路由仍为 `172.20.10.1 dev eth0 src 172.20.8.48 metric100`。这不是完整的网络状态差异验收。

## 固定核心 ELF 预检

文件来自此前已验证 SHA256 的 sing-box1.13.19 Linux amd64 归档；身份见 [核心隔离测试](linux-core-namespace.md)。只用 file/readelf 读取，不安装产物。

- sing-box：动态 ELF，解释器 `/lib64/ld-linux-x86-64.so.2`；本次 version-info 输出没有 GLIBC 版本标签，不能据此认定不存在 libc 依赖或保证跨发行版兼容。
- libcronet.so：依赖 libdl、libpthread、libm、libgcc_s、libc 和 ELF loader；观察到的 GLIBC 符号版本最高2.17。

项目自己的 Go agent/CLI 打包应避免无意绑定构建机较新的 glibc；是否可使用 CGO_ENABLED=0 需结合实际依赖与测试决定。RPM 在 Ubuntu 上能构建不代表可在 Rocky 安装运行。Ubuntu22.04 与 Rocky9 的原生包生命周期、系统 CA、DNS 管理器及网络恢复仍未验证。
