# hakimi 加速实现设计文档

- 状态：设计稿 v0.2（性能修订：上游连接池、真实连接即校验、全量精确域名预热）
- 范围：加速链路、策略、DoH、远程 IP/DoH 目录、缓存、分组、状态、桌面端实现
- 不在本文档范围：UI 视觉与页面结构
- 本文档取代此前文档中关于**分片、站点级 DoH、手动 IP、内置 IP** 的设计

---

## 1. 目标与非目标

### 目标

- 桌面端浏览器一次点击即可访问默认站点。
- 不需要 VPS、域名、Cloudflare。
- 使用干净 DoH 解析，避免 DNS 投毒。
- 本机 MITM + 本地 CA，让浏览器用上 ECH / 伪 SNI。
- 按“站点组”管理站点，组内子域名可以独立解析和连接。
- 用户可添加 DoH、可维护远程 IP 目录、可自定义分组。
- 每个组、每个域名都有可解释的状态和失败原因。
- 优先使用远程 IP，失败后回退 DoH；保存上次成功 IP 7 天。
- 远程目录更新后，优先测试新 IP，而不是旧缓存。

### 非目标

- 不做 VPS、远程中转、代理服务器。
- 不做自建 DoH、域名、Cloudflare Worker。
- 不做内置浏览器、自研 WebView 客户端。
- 不做分片策略。
- 不做站点级 DoH。
- 不做手动 IP、内置 IP。
- 不做全局 VPN、游戏加速。
- 暂不做 iOS / Linux。
- 暂不处理需要证书固定的非浏览器 App。

---

## 2. 术语

| 术语 | 含义 |
|---|---|
| 组（Group） | UI、策略、状态的单位，包含多个域名/通配符 |
| 域名（Domain） | 解析、IP 测试、缓存、TLS 连接的单位 |
| 主域名 | 组内第一个精确域名，用于启动时快速检测和组状态 |
| direct | 不经过 MITM，直接连接 |
| ECH | 用 HTTPS RR 的 ECHConfig 加密 SNI |
| 伪 SNI | 发送一个不被阻断的 SNI，但仍按真实域名校验证书 |
| DoH | DNS over HTTPS |
| 远程 IP 目录 | 放在 Gitee 等位置的 JSON，提供候选 IP |
| 远程 DoH 目录 | 提供可用 DoH 列表的 JSON |
| last-good IP | 上次 TLS 校验成功的 IP，保存 7 天 |
| catalogVersion | 远程目录版本，用于决定是否跳过旧缓存 |

---

## 3. 总体架构

```text
浏览器
  ↓ 系统代理 / PAC（Windows、macOS）
本地 HTTP 代理（MITM + 本地 CA）
  ↓
域名 → 组匹配
  ↓
连接决策引擎
  ├─ last-good IP 缓存
  ├─ 远程 IP 目录
  ├─ 全局 DoH（主 / 备 / 自定义）
  └─ DoH 结果缓存
  ↓
策略引擎：direct / ECH / 伪 SNI
  ↓
目标站点
```

### 3.1 桌面端

- 第一版只做浏览器场景：系统代理 + PAC。
- 不做 TUN，不装内核驱动。
- 只拦截组内域名，其他流量 DIRECT。
- 本地代理负责 TLS 终止、HTTP/2、流式响应、WebSocket / SSE。

### 3.2 Android（预留）

- VpnService + fake-IP + tun2socks。
- 设计上假设 Android 信任用户 CA；不实现 WebView 客户端。
- Android 的实际 CA 信任、QUIC/DoH 绕过在桌面端验证后再做。
- 本文档只保留接口和风险，不展开实现。

### 3.3 共享 Rust core

模块划分：

- `config`：全局配置、组配置、目录配置。
- `catalog`：远程 IP/DoH 目录拉取、校验、缓存、签名。
- `resolver`：DoH、A/AAAA/HTTPS RR、ECH 解析。
- `ip_tester`：按顺序测试 IP，TCP/TLS 校验。
- `strategy`：direct / ECH / 伪 SNI / auto。
- `proxy`：本地 HTTP/2 代理、MITM、回源；上游 HTTP/2/HTTP/1.1 连接池。
- `ca`：本地 CA、叶子证书、信任状态。
- `status`：组/域名状态、诊断、失败原因。
- `log`：本地日志、脱敏、导出。

桌面 shell 通过 C ABI 调用；Android 预留 JNI。

---

## 4. 核心流程

### 4.1 启动

1. 加载配置、last-good 缓存、远程目录缓存。
2. 启动本地代理。
3. 检查/安装本地 CA。
4. 接管系统代理 / PAC。
5. 后台预热每个启用组的**所有精确域名**：用 `HEAD /` 建立真实上游连接并写入可复用路由；通配符不展开，保持懒检测。
6. 后台拉取远程 IP / DoH 目录；有新版本则标记受影响域名跳过旧缓存一次，并让缓存路由失效一次。

### 4.2 浏览器请求

1. PAC 判断域名是否属于启用组。
2. 不属于 → DIRECT。
3. 属于 → 交给本地代理。
4. 本地代理匹配组，执行连接决策。
5. 终止浏览器 TLS，按策略回源。
6. 流式回传响应，更新域名/组状态。

### 4.3 单域名连接决策

```text
resolve(domain):
  group = match_group(domain)
  if group == null or !group.enabled: return DIRECT

  strategy = group.strategy or AUTO

  if strategy == AUTO:
    try DIRECT
    try ECH
    try SNI
  else:
    try locked strategy

  each strategy:
    candidates = []
    if cache.valid(domain) and !cache.skipOnce:
      candidates += cache.ip
    candidates += remote_ips(domain)       // 按 JSON 顺序
    candidates += doh_ips(domain)          // 主 DoH → 备用 DoH
    candidates += doh_cache_ips(domain)    // stale 兜底

    for ip in candidates:                  // 严格按顺序
      if test(ip, strategy, domain):
        save_cache(domain, ip, strategy)
        return ip

  return FAILED
```

- 顺序测试，不做并发抢最快。
- 单 IP 超时 2 秒，单域名最多测试 8 个 IP。
- 只有 TLS 握手 + 证书校验通过才写入缓存。
- **性能修订**：代理热路径不再额外建立探测连接。候选规划与探测分离，真实回源连接本身就是 TCP + TLS + 证书校验；失败后按顺序尝试下一个候选。`doctor` 和手动诊断仍执行独立探测。
- 成功的路由按域名缓存（默认 10 分钟），仅用于新建上游连接；已建立的 HTTP/2/HTTP/1.1 连接直接复用，不重复决策。
- **图片主机连接级并行**：`advanced.http1Hosts`（默认 `*.pximg.net`、`img.poipiku.com`、`cdn.poipiku.com`）强制 HTTP/1.1 回源，使并发图片使用多条独立连接，避免单条 HTTP/2 连接在限速链路上成为瓶颈。实测 4 路并发 Pixiv 图片分片从 39.1 秒降到 13.8 秒。

### 4.4 全部失败

- 本地代理返回 502 本地错误页，说明：
  - 使用了哪个策略；
  - 试过哪些 IP 来源；
  - 最近的 DoH 状态；
  - 失败原因；
  - 下一步建议（检查 CA、网络、DoH、站点配置）。
- CA 未信任时无法 MITM，直接让浏览器显示证书错误，同时状态里提示 `ca_untrusted`。

---

## 5. 策略

### 5.1 direct

- 不经过 MITM。
- 测试：TCP 443 + TLS 握手（真实 SNI）+ 证书匹配真实域名。
- 不要求 HTTP 200；Cloudflare 返回 403 也算网络可达。
- 通过后直接连接，状态为 `direct`。

### 5.2 ECH

- 从全局 DoH 的 HTTPS RR 读取 `ech`。
- 使用 BoringSSL 设置 ECHConfig。
- 证书仍按真实域名校验。
- ECHConfig 缓存，按 HTTPS RR TTL 刷新。
- ECH 失败或没有 ECHConfig：
  - `auto`：回退到伪 SNI；
  - 锁定 `ech`：直接失败。

### 5.3 伪 SNI

- 工具需要控制 TLS 客户端，发送一个伪 SNI。
- 仍按真实域名校验证书；证书不匹配就失败。
- 伪 SNI 候选顺序：
  1. 远程 JSON 中该组的 `sni`（如果有）；
  2. 高级设置中的组级覆盖；
  3. 内置候选列表：
     - 空 SNI（不发送 SNI）
     - `www.baidu.com`
     - `www.cloudflare.com`
     - `www.bing.com`
     - `www.apple.com`
- 对每个候选：
  - 连接目标 IP；
  - 发送候选 SNI；
  - 校验返回证书是否匹配真实域名；
  - 通过则缓存该组/域名/网络下的可用伪 SNI；
  - 失败则换下一个。
- 伪 SNI 只对“服务器不依赖 SNI 选择证书”的站点有效；否则会返回默认证书，校验失败。
- 注意：空 SNI 和 `www.baidu.com` 本身不一定被阻断，但仍需验证目标服务器是否返回真实证书。

### 5.4 auto

顺序：

1. `direct`
2. `ECH`（需要 ECHConfig）
3. 伪 SNI

没有任何“分片”步骤。

---

## 6. DoH

### 6.1 全局 DoH

- 只有全局 DoH，没有站点级 DoH。
- 主 DoH：默认 CleanBrowsing Security。
- 备用 DoH：默认 Applied Privacy。
- 用户可添加自定义 DoH。
- 优先级：

```text
主 DoH
→ 备用 DoH（用户排序）
→ 最近成功的 DoH 结果缓存（stale）
→ 失败
```

- 不做 DoH 结果交叉校验；主 DoH 失败才切备用。
- ECHConfig 只从当前使用的 DoH 的 HTTPS RR 获取。

### 6.2 远程 DoH 目录

- 独立 URL，HTTP/HTTPS 都支持。
- 只提供“可用列表”，不会自动改用户的主/备设置。
- 首次安装使用内置默认 + 用户选择。
- 远程条目与用户条目合并：
  - 用户手动添加/修改的优先；
  - 远程目录其次；
  - 内置默认最后。
- 目录更新 6 小时一次 + 手动刷新。
- 支持 ETag / Last-Modified、缓存、原子更新。
- 可选 Ed25519 签名；签名失败丢弃更新。

### 6.3 DoH 缓存与健康

- DNS 缓存按 `domain + qtype` 分开。
- 记录 TTL；过期后仍可作为最后兜底，标记 `stale`。
- 健康检查时机：启动、网络变化、手动、使用失败后。
- 不做高频轮询。

### 6.4 自定义 DoH

- 只支持标准 RFC 8484 wire format（POST `application/dns-message`）。
- 必须 HTTPS，正常校验证书。
- 支持可选 bootstrap IP，避免 DoH 域名本身被污染。
- 自定义 DoH 的隐私和安全由用户承担。

---

## 7. 远程 IP 目录

### 7.1 JSON 格式

```json
{
  "v": 1,
  "groups": {
    "github": [
      "github.com",
      "api.github.com",
      "raw.githubusercontent.com",
      "*.githubusercontent.com",
      "githubassets.com"
    ],
    "pixiv": [
      "pixiv.net",
      "www.pixiv.net",
      "i.pximg.net",
      "*.pximg.net"
    ],
    "ao3": [
      "archiveofourown.org",
      "*.archiveofourown.org"
    ],
    "eh": [
      "e-hentai.org",
      "exhentai.org",
      "*.e-hentai.org",
      "*.exhentai.org",
      "ehgt.org",
      "*.ehgt.org"
    ],
    "steam": [
      "store.steampowered.com",
      "steamcommunity.com",
      "*.steamcommunity.com",
      "*.steampowered.com",
      "*.steamstatic.com"
    ],
    "poipiku": [
      "poipiku.com",
      "*.poipiku.com"
    ]
  },
  "ips": {
    "github.com": ["20.205.243.166", "140.82.121.4"],
    "api.github.com": ["20.205.243.168"],
    "raw.githubusercontent.com": ["185.199.108.133"],
    "pixiv.net": ["210.140.139.155", "210.140.139.161"],
    "poipiku.com": ["18.182.121.133"]
  },
  "sni": {
    "pixiv": "www.cloudflare.com",
    "steam": "www.baidu.com"
  }
}
```

字段：

- `v`：schema 版本。
- `groups`：组 ID → 域名/通配符数组。
- `ips`：域名/通配符 → 按顺序测试的 IP 数组。
- `sni`：可选，组 ID → 伪 SNI；空字符串表示不发 SNI。
- 域名没有 IP 条目 → 走 DoH。
- `ips` 中的域名必须被某个组覆盖；未覆盖的条目忽略。
- 通配符 `*.example.com` 只匹配子域名，不匹配根域名。
- 精确匹配优先于通配符；多个通配符时最长后缀优先。

### 7.2 默认组

| 组 | 主域名 | 启动预热 | 默认策略 | 默认状态 |
|---|---|---|---|---|
| GitHub | github.com | 所有精确域名 | auto | 启用 |
| Pixiv | pixiv.net | 所有精确域名 | auto | 启用 |
| AO3 | archiveofourown.org | 所有精确域名 | auto | 启用 |
| E-Hentai | e-hentai.org | 所有精确域名 | auto | **默认关闭，标记实验性** |
| Steam | store.steampowered.com | 所有精确域名 | auto | 启用 |
| Poipiku | poipiku.com | 所有精确域名 | direct | 启用 |

说明：

- E-Hentai 没有 ECH，伪 SNI 也不接受；砍掉分片后大概率不可用。默认关闭，等实测后再决定。
- GitHub 不做特殊处理；按组和子域名正常测试。
- 用户可新建自定义组，填写多个域名/通配符。

### 7.3 拉取与校验

- 支持多个源，按顺序尝试：
  1. 用户配置的主源；
  2. 备用镜像；
  3. 本地缓存。
- HTTP / HTTPS 都支持；HTTPS 优先。
- 请求带 ETag / If-Modified-Since。
- 超时 5 秒，失败不阻塞启动。
- 校验：
  - schema 版本合法；
  - 域名/通配符合法；
  - 只允许公网 IP，拒绝私网、回环、链路本地、组播、保留地址；
  - 单域名最多 8 个 IP；
  - 总组/域名数量上限；
  - `ips` 的域名必须被组覆盖；
  - 可选签名校验。
- 校验通过后原子替换缓存；失败保留旧缓存。
- 目录更新 6 小时一次 + 手动刷新。

### 7.4 目录更新后的优先级

受影响域名标记 `skipOnce`：

```text
新远程 IP（按 JSON 顺序）
→ last-good IP 缓存
→ DoH
→ DoH 缓存
```

成功使用新远程 IP 后清除 `skipOnce`，并更新 last-good 缓存。

---

## 8. 优先级与缓存

### 8.1 正常启动

```text
last-good IP 缓存（7 天内）
→ 远程 IP（按 JSON 顺序）
→ DoH（主 → 备）
→ DoH 结果缓存（stale）
```

### 8.2 远程目录更新后

```text
新远程 IP（按 JSON 顺序）
→ last-good IP 缓存
→ DoH
→ DoH 缓存
```

### 8.3 last-good IP 缓存

按域名保存：

```json
{
  "domain": "github.com",
  "ip": "20.205.243.166",
  "strategy": "direct",
  "source": "remote",
  "networkId": "wifi:xxx",
  "savedAt": "2026-10-19T14:21:03+08:00",
  "catalogVersion": 3
}
```

- 只在 TCP + TLS + 证书校验通过后写入。
- 保存 7 天；超过则丢弃。
- 每次使用前仍然测试，不直接信任。
- 跨网络保留；网络变化后仍先测缓存，失败再走远程/DoH。
- 远程目录版本变化时，受影响域名跳过缓存一次。

### 8.4 IP 测试

- 严格按候选顺序测试。
- 单 IP 超时 2 秒。
- 单域名最多 8 个候选。
- 第一个通过即使用，不并发抢最快。
- 测试内容包括 TCP 443、TLS 握手、证书校验。
- 代理热路径中这些检查由真实回源连接完成，不额外建立探测连接；探测与回源分离只保留在 `doctor` / 后台诊断中。

### 8.5 DoH 缓存

- 按 `domain + qtype` 保存。
- 记录 TTL。
- 过期后可作为最后兜底，标记 `stale`。
- ECHConfig 单独缓存，按 HTTPS RR TTL 刷新。

---

## 9. 分组与检测

### 9.1 职责

- **组**：UI、策略、状态聚合。
- **域名**：解析、IP 测试、TLS 连接、缓存。
- 组策略对所有域名生效；域名不单独设置策略。
- 每个域名独立解析、独立测试、独立缓存。

### 9.2 检测时机

1. 启动时：每个组测主域名。
2. 后台：启动时预热每个组的全部精确域名；跳过通配符。
3. 懒检测：通配符域名和其他未覆盖主机第一次被请求时检测。
4. 网络变化、手动诊断、失败后重试。

### 9.3 组状态聚合

| 情况 | 组状态 |
|---|---|
| 主域名失败 | 失败 |
| 主域名正常，部分已测子域名失败 | 部分异常 |
| 已测域名全部正常/直连 | 正常 |
| 主域名检测中 | 检测中 |
| 组未启用 | 未启用 |
| 全局关闭 | 已暂停 |

未检测的域名标记“未检测”，不影响组状态直到被请求或后台探测。

---

## 10. 状态与诊断

### 10.1 状态

```text
disabled / paused / checking / normal / direct / degraded / failed
```

### 10.2 失败原因

- `doh_failed`
- `doh_fallback`
- `remote_catalog_unavailable`
- `remote_ip_rejected`
- `tcp_timeout`
- `tls_reset`
- `cert_invalid`
- `ech_unavailable`
- `sni_rejected`
- `ca_untrusted`
- `proxy_not_applied`
- `quic_bypass`
- `unsupported_without_proxy`

### 10.3 诊断字段

```json
{
  "group": "github",
  "domain": "api.github.com",
  "state": "normal",
  "strategy": "direct",
  "ip": "20.205.243.168",
  "ipSource": "remote",
  "dohSource": null,
  "latencyMs": 38,
  "lastCheck": "2026-10-19T14:21:03+08:00",
  "catalogVersion": 3,
  "cache": "fresh",
  "error": null
}
```

- `ipSource`：`cache` / `remote` / `doh` / `doh-cache`
- `dohSource`：`primary` / `fallback` / `cache`
- `cache`：`fresh` / `stale` / `none`

### 10.4 诊断流水线

1. 组/域名是否启用。
2. 当前策略。
3. 候选 IP 来源与顺序。
4. TCP 443 结果。
5. TLS 握手结果。
6. 证书校验结果。
7. ECHConfig 是否可用。
8. 伪 SNI 候选结果。
9. 最终使用的 IP / 策略 / DoH。
10. 失败原因与建议。

---

## 11. 本地代理与 CA

### 11.1 桌面端代理

- 系统代理 / PAC。
- PAC 规则：
  - 组内域名 → 本地代理；
  - 其他域名 → DIRECT。
- 不接管非目标流量。
- 本地代理支持 HTTP/1.1 CONNECT、HTTP/2、流式响应、Range、WebSocket、SSE。

### 11.2 MITM

- 本地 CA + 按域名动态签发证书。
- 只对启用组内的域名 MITM。
- 证书 SAN 必须匹配真实域名。
- 不关闭证书校验。

### 11.3 CA 管理

- 生成、安装、修复、卸载、重新生成。
- Windows：用户证书库。
- macOS：Keychain。
- Android：假设信任用户 CA，后续验证。
- 私钥保存在系统安全存储。
- 记录浏览器/系统信任状态。
- 证书固定站点可能失败，浏览器一般不受影响。

### 11.4 QUIC / DoH / Private DNS

- 桌面端：系统代理场景下，浏览器通常不会对代理连接使用 QUIC；仍将 QUIC 绕过列为已知风险。
- Android（后续）：对目标 IP 阻断 UDP 443，检测外部 DoH / Private DNS。
- 不做全局阻断，避免影响其他流量。

---

## 12. 配置模型

### 12.1 全局配置

```json
{
  "doh": {
    "primary": "https://doh.cleanbrowsing.org/doh/security-filter/",
    "fallback": "https://doh.applied-privacy.net/query"
  },
  "catalogs": {
    "ip": "https://gitee.com/.../raw/ips.json",
    "doh": "https://gitee.com/.../raw/doh.json"
  },
  "proxy": {
    "mode": "pac",
    "port": 8443
  },
  "groups": [],
  "catalogVersion": 3
}
```

### 12.2 组配置

```json
{
  "id": "github",
  "name": "GitHub",
  "domains": [
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "*.githubusercontent.com",
    "githubassets.com"
  ],
  "strategy": "auto",
  "enabled": true,
  "sni": null
}
```

- 没有 `dohId`。
- 没有 `ipMode`。
- 没有手动 IP 列表。

### 12.3 缓存

- last-good IP：按域名。
- DoH：按域名 + qtype。
- ECHConfig：按域名。
- 伪 SNI：按组/域名/网络。
- 全部本地保存，退出/崩溃不丢失。

---

## 13. 功能清单

### 核心

- 默认组 + 自定义组。
- 组启用/关闭。
- 策略：direct / ECH / 伪 SNI / auto。
- 全局 DoH：主 / 备 / 自定义。
- 远程 IP 目录、远程 DoH 目录。
- last-good IP 缓存 7 天。
- 远程目录更新后优先新 IP。
- 顺序 IP 测试。
- 组/域名状态与诊断。
- 本地 CA 管理。
- 系统代理 / PAC。
- 启动接管、退出恢复。
- 开机自启、托盘。
- 网络变化重测。
- 日志、诊断报告。

### 高级

- 远程目录签名。
- 自定义伪 SNI。
- 自定义组。
- 目录源/镜像配置。
- 手动刷新目录。
- 日志级别。
- 诊断导出。

### 删除

- 分片策略。
- 站点级 DoH。
- 手动 IP。
- 内置 IP。

---

## 14. 安全与隐私

- 所有 TLS 连接必须校验证书，远程 IP 也不例外。
- 远程 IP 目录只是候选，不能绕过证书校验。
- 远程目录严格 schema 校验；失败不覆盖缓存。
- 远程目录可选 Ed25519 签名。
- HTTP 目录可用，但建议 HTTPS；HTTP 内容被篡改最多导致 DoS/错误 IP，不能冒充站点。
- 自定义 DoH 的隐私由用户承担。
- 默认无遥测、无账号、无云同步。
- 日志、缓存、诊断报告只保存在本地；导出时脱敏。
- CA 私钥保存在系统安全存储；CA 只用于组内域名。

---

## 15. 风险与限制

1. **E-Hentai 大概率不可用**：无 ECH、伪 SNI 不接受、没有分片。默认关闭，标记实验性。
2. **GitHub 可能失败**：部分 IP 直接超时；无 VPS 时无法确保所有网络可用。
3. **伪 SNI 依赖服务器**：服务器必须接受伪 SNI 并返回真实证书。
4. **ECH 覆盖有限**：E-Hentai、GitHub、Steam 没有可用 ECH；Pixiv 的 Cloudflare 主机通过共享 `cloudflare-ech.com` 配置使用 ECH。
5. **Android CA 信任未验证**：设计假设信任，但不做 WebView 客户端；后续必须真机验证。
6. **QUIC / DoH 绕过**：桌面端列为已知风险；Android 后续处理。
7. **远程目录依赖**：Gitee 不可用、限流、内容错误都会影响 IP 来源；DoH 仍可兜底。
8. **DoH 可信度**：使用可信 DoH；不做交叉校验。
9. **证书固定**：非浏览器 App 可能失败。
10. **无分片**：不再覆盖只靠 SNI 阻断、且不支持 ECH/伪 SNI 的站点。

---

## 16. 实施顺序

1. config / cache / catalog 数据结构。
2. 远程 IP / DoH 目录拉取、校验、缓存、签名。
3. IP 顺序测试 + direct / 伪 SNI 策略。
4. 全局 DoH + HTTPS RR + ECH 解析。
5. 优先级引擎 + last-good 缓存 + 目录更新 skipOnce。
6. 本地代理 + MITM + CA。
7. 系统代理 / PAC + 状态 / 诊断。
8. 桌面 UI 接入。
9. Android VpnService + CA 验证（后续）。

---

## 17. 验收标准

- 默认组在支持的站点上可访问。
- 远程 IP 目录可拉取、校验、缓存；更新后优先新 IP。
- 全局 DoH 可切换主/备；DoH 失败时能回退。
- last-good IP 保存 7 天，启动时先测缓存；失败后按 远程 → DoH 回退。
- 组内所有精确域名启动预热；通配符懒检测。
- 代理热路径复用上游 HTTP/2/HTTP/1.1 连接，不做探测 + 回源的双重握手。
- 组状态正确聚合；每个域名有状态、IP、策略、来源、延迟。
- 没有分片、站点级 DoH、手动 IP、内置 IP。
- 不需要 VPS、域名、Cloudflare。
- 本地 CA 可安装/修复/卸载；浏览器可正常访问。
- 远程目录 HTTP/HTTPS 都可用；解析失败不覆盖旧缓存。
- 默认无遥测，日志与缓存仅本地保存。

---

## 18. 已确认决策

- Android 默认按“信任用户 CA”设计；不做 WebView 客户端。
- 远程 JSON 接受可选 `sni` 字段。
- 伪 SNI 候选包含空 SNI、`www.baidu.com`、`www.cloudflare.com` 等。
- 直连判定：TCP + TLS + 证书匹配，不要求 HTTP 200。
- 桌面端优先；Android 预留。
- 分片、站点级 DoH、手动 IP、内置 IP 全部砍掉。
- 远程目录更新后优先新 IP。
- 默认组：GitHub、Pixiv、AO3、E-Hentai、Steam、Poipiku；E-Hentai 默认关闭、标记实验性。
- 组检测：启动时预热所有精确域名 + 通配符懒检测。
- 代理热路径：真实回源连接即校验，探测连接不进入请求路径。
- 全局 DoH 默认 CleanBrowsing + Applied Privacy；不做交叉校验。
- 远程目录 6 小时自动刷新 + 手动刷新；HTTP/HTTPS 都支持；签名可选。
- IPv4 优先，IPv6 后续。
- 失败时返回本地 502 错误页。
