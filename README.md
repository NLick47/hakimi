社区交流：[linux.do](https://linux.do)

<p align="center">
  <img src="crates/hakimi-ui/assets/app-icon.png" width="128" height="128" alt="hakimi">
</p>

<h1 align="center">hakimi</h1>

<p align="center">以 Rust 实现的本地 TLS 代理，让已启用站点直连</p>

## 这是什么

hakimi 运行在本机，接管已启用站点的流量，按域名选择线路后转发到真实上游，可以用它直连 GitHub、Pixiv、Hugging Face 这类站点，其他站点也可以自己添加

它的工作前提是信任一个本地证书：站点在 TLS 层被识别和干扰时，只有本地终结 TLS 才能改写握手参数，证书装一次长期有效，不用了可以随时卸载并撤销信任；只对已启用站点做终结和选路，其余流量直接透传

```
浏览器 / 应用
   │  PAC、固定代理或 VPN
   ▼
 hakimi
   ├─ 已启用站点 ──> 本地终结 TLS
   │                   └─ 选路：直连 / ECH / 伪装 SNI ──> 上游连接池 ──> 真实站点
   └─ 其他站点 ──> 原样转发，不碰 TLS（用 PAC 时直接直连，不经过 hakimi）
```

## 功能

- 内置了一部分站点（GitHub、Pixiv、Hugging Face、E-Hentai、Hitomi、Hanime、Steam、Poipiku），也可以自己添加，域名和线路都能改
- 线路默认自动，直连、ECH、伪装 SNI 同时试，哪个先通就用哪个
- IP 选择：按实测延迟排序，快的优先、失败的降权，记忆上次可用的地址
- 在用的线路定期与备选地址复测，保持最优 IP连接
- DoH、IP 目录、镜像列表都已内置，到手即用
- DoH 端点自动排序，慢就并行补一个，多端点答案合并，过期答案先用后刷新
- GitHub 下载：release 文件走镜像，并按分块并行下载
- 图片中转：把指定域名的图片请求改走中转，加速图片加载；默认规则开箱即用，可按需对某个站点全图加速，也可以自建 Worker
- TCP 中继：给 cloudflared tunnel 这类不走代理的客户端用，国内打隧道时可以避开干扰（试验性，默认关闭）
- 并发连接：默认对 GitHub、Pixiv 的资源走 h1 独立并发连接，JS 这类小文件更快加载；可以在配置页添加或移除并发站点
- HTTP/2 多路复用，半死连接自动进恢复池重试
- 启动时预热已启用域名，首次访问不用等冷路由

## 快速开始

### 桌面

启动后按引导走完，之后正常访问已启用站点即可，证书安装和系统代理都会在引导里自动完成

### Android

推荐 Android 13 及以上，用 VPN 模式自动接管流量，13 以下只能用本地代理模式，要手动把 Wi-Fi 代理指向 `127.0.0.1:8443`

装好后先导出 CA，导入系统「用户凭据」，浏览器推荐 Via，它可以关掉证书警告

### Linux

只有 CLI 版本，需要自己编译：

```sh
cargo build --release -p hakimi-cli     # 产物在 target/release/hakimi
sudo target/release/hakimi --data-dir "$HOME/.local/share/hakimi" ca install
target/release/hakimi serve --log-stdout
eval "$(target/release/hakimi env)"
```

Linux 上没有统一的系统代理，hakimi 只提供代理端口，不接管系统设置，`packaging/hakimi.service` 是现成的 systemd user unit，目前只在 CI 上跑过冒烟测试，实用性未知

## 配置

配置文件是数据目录下的 `config.json`，只保存改动过的值，未改动的项跟随程序默认值：

| 段 | 说明 |
| --- | --- |
| `doh` | DoH 主/备端点与自定义端点 |
| `catalogs` | IP 目录与 DoH 目录的远程源、镜像、超时 |
| `proxy` | 接管方式（PAC、本地 HTTP 代理或关闭）、端口、绑定地址、是否写入系统代理 |
| `groups` | 各站点的域名与线路，可在界面中增删 |
| `advanced` | 调优项：下载分块、独立连接的站点、TCP 中继、图片中转、候选超时、plan 缓存时长等 |

每个域名都可以单独设线路，默认自动：直连、ECH、伪装 SNI 同时尝试，哪个先通用哪个，成功的线路会被记住

图片中转的参数与匹配规则见 [docs/image-relay.md](docs/image-relay.md)，自己部署 Worker 见 [docs/self-hosted-relay.md](docs/self-hosted-relay.md)

## 隐私与数据

- 终结 TLS 是工作前提：已启用站点的 TLS 内容对本机进程可见
- 所有数据保存在本地数据目录；日志脱敏，不包含完整 URL
- 持久化内容只有配置（改动值）、最近可用的线路记忆、fake-SNI 记忆；DoH 解析结果不落盘

## 文档

- [图片中转](docs/image-relay.md)：参数、匹配规则、全站图片加速与隐私说明
- [自建图片中转 Worker](docs/self-hosted-relay.md)：用自己的 Cloudflare 账号部署一份，做全站加速时推荐

## 许可

MIT，见 [LICENSE](LICENSE)
