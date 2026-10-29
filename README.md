<p align="center">
  <img src="crates/hakimi-ui/assets/app-icon.png" width="128" height="128" alt="hakimi">
</p>

<h1 align="center">hakimi</h1>

<p align="center">以 Rust 实现的本地 TLS 反向代理，为目录内站点提供直连加速。</p>

## 这是什么

hakimi 运行在本机，通过 PAC 或系统代理接管目录内域名的流量，对 TLS 做本地终结后按站点选择连接策略（直连 / ECH / 伪装 SNI），再转发到真实上游。它只加速目录内的站点，不是全局代理。

工作流程：

```
浏览器 ──PAC/系统代理──> hakimi(本地终结 TLS)
                            │
                     决策引擎按站点选路
                     ├─ 直连（目录 IP / DoH / last_good）
                     ├─ ECH（Encrypted Client Hello）
                     └─ 伪装 SNI
                            │
                       上游连接池 ──> 真实站点
```

目录内站点：GitHub、Pixiv、AO3、E-Hentai、Hitomi、nhentai、Hanime、Steam、Poipiku。

## 为什么需要信任一个本地证书

站点目录里的多数域名无法用传统 hosts 方式直连（TLS 层会被识别和干扰），hakimi 必须在本地终结 TLS 才能改写握手参数。因此它会生成一个仅存在于本机的 CA，并在你的授权下加入系统信任：

- CA 与私钥在本机生成、本机保存，不经过网络
- 终结意味着 hakimi 能看到这些站点的 TLS 内容——这是此类工具的工作前提，是否接受由你决定
- 关闭 hakimi 后可以随时卸载并撤销信任

## 功能

- **路由决策引擎**：候选 IP 按历史延迟与失败记录评分，失败自动惩罚并周期性再探测恢复；识别上游 block page 并换路
- **三种连接策略**：直连、ECH、伪装 SNI；每个域名可覆盖分组默认顺序
- **DoH 解析**：主备端点竞速、可加自定义端点、结果负缓存、过期答案 stale-while-revalidate
- **IP 目录**：远程目录驱动（支持镜像与可选签名校验），配合 last_good 路由记忆
- **启动预热**：启动即对目录内域名做一轮连接预探索，浏览器首次访问不再为冷路由等待
- **上游连接池**：HTTP/2 多路复用与 keepalive 探测；图片类 CDN 独立 HTTP/1.1 池保证并发；半死连接自动进恢复池
- **传输层细节**：Happy-Eyeballs 双栈竞速、响应头读超时、TCP keepalive
- **诊断**：域名级全链路诊断、状态端点、脱敏日志

## 平台

| 平台 | 形态 | 证书 |
| --- | --- | --- |
| Windows x64 | 桌面应用 | 引导自动安装与信任 |
| macOS arm64 | 桌面应用 | 引导自动安装与信任 |
| Android 13+ | 应用（JNI 壳） | 手动导出并导入用户 CA |
| Linux x64 | 命令行 | 安装到发行版信任库（需 root） |

## 快速开始

### 桌面

1. 启动 hakimi，按引导完成本地 CA 的安装与信任
2. 选择接管系统代理或使用 PAC，之后正常访问目录内站点即可

### Android

1. 手动导出 CA 证书，导入到系统"用户凭据"中
2. 将设备代理指向本机地址与端口
3. 建议使用 Edge、Via 等第三方浏览器访问。Android 7 以后应用可以选择不信任用户 CA，部分系统浏览器有内置的代理与证书策略，行为不可控

### Linux（命令行）

Linux 上没有统一的系统代理，因此 hakimi 只提供代理端口，**不接管系统设置**，由你自己决定谁走它。目前需要从源码构建：`cargo build --release -p hakimi-cli`。

1. 启动：`hakimi serve --log-stdout`（前台运行；`packaging/hakimi.service` 是现成的 systemd user unit）
2. 信任本地 CA（一次性，需要 root）：
   `sudo hakimi --data-dir "$HOME/.local/share/hakimi" ca install`
   Debian/Ubuntu 走 `update-ca-certificates`，Fedora/RHEL 走 `update-ca-trust extract`，Arch/p11-kit 走 `trust extract-compat`
   不想改动系统信任库时，用 `hakimi ca export --out hakimi-ca.pem` 导出后自己导入；Firefox 等 NSS 程序必须单独导入（`certutil -d sql:$HOME/.pki/nssdb -A …`）
3. 让命令行走代理：`eval "$(hakimi env)"`；浏览器可以用 `hakimi pac` 输出的脚本
4. 停止：`hakimi stop`

不装 CA 时，hakimi 对所有站点都只做原样转发（浏览器看到的就是站点自己的证书），只有直连能通的站点可用；需要伪装 SNI 或 ECH 的站点（例如 Pixiv）必须信任 CA。

## 配置

配置文件为数据目录下的 `config.json`。文件只保存你改动过的值，未改动的项跟随程序默认值，升级后新默认会自动生效。

| 段 | 说明 |
| --- | --- |
| `doh` | DoH 主/备端点与自定义端点 |
| `catalogs` | IP 目录与 DoH 目录的远程源、镜像、超时 |
| `proxy` | 接管方式（PAC、本地 HTTP 代理或关闭）、端口、绑定地址、是否接管系统代理 |
| `groups` | 各站点的域名与路由策略，可在界面中增删 |
| `advanced` | 调优项：候选超时、plan 缓存时长、上游空闲时长、h1 主机清单、响应头读超时、伪装 SNI 候选等 |

## 诊断与运维

运行中的 hakimi 在本地端口上提供以下端点：

- `/hakimi/status`：运行状态、各域名当前策略（`?all=1` 查看全部域名）
- `/hakimi/health`：存活探针
- `/hakimi/pause`、`/hakimi/resume`：暂停 / 恢复加速
- `/hakimi/stop`：停止进程，需带 `x-hakimi-control: 1` 请求头（浏览器页面无法伪造该头）
- `/proxy.pac`：PAC 脚本

日志写入数据目录 `logs/hakimi.log`，仅存本地，URL 与目录源脱敏，超限自动轮转。

## 性能

性能设计围绕一件事：把等待降到网络本身的下限。

- **更少的等待**：启动预热把冷路由探索前移到启动时；路由决策与 DoH 解析结果缓存，命中后新连接不再重复发现与解析；候选地址并行竞速，单个地址黑洞不拖慢整体
- **更少的握手**：上游连接池化复用，HTTP/2 多路复用让页面后续请求共享已有连接；TLS 会话恢复削减重复握手
- **更低的转发开销**：数据路径全程流式，无全量缓冲、无不必要的拷贝，大文件与长连接保持平稳
- 具体表现随网络环境而异，以上为设计目标与实测观察的定性口径

## 隐私与数据

- 终结 TLS 是工作前提：目录内站点的 TLS 内容对本机进程可见
- 所有数据保存在本地数据目录；日志脱敏，不包含完整 URL
- 持久化内容仅有：配置（用户改动值）、最近可用的路由记忆、fake-SNI 记忆；DoH 解析结果不落盘

## 已知限制

- 不支持 QUIC / HTTP/3，浏览器会回退到 HTTP/2 或 HTTP/1.1
- 只加速目录内站点；不支持作为全局代理，也不支持转发到上游代理
- Linux 不接管系统代理：`proxy.takeover` 在该平台被忽略，改用 `hakimi env` 或 PAC 自行配置
- 依赖对本地 CA 的信任，卸载前请知悉其含义
- 目录来自远程源（可配镜像），源不可达时依赖本地缓存与 DoH 继续工作
- 站点 CDN 架构变化时，需要目录更新才能恢复最佳路由


## 许可

MIT，见 [LICENSE](LICENSE)
