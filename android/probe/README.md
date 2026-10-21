# hakimi Android 最小验证（Probe）

这是一个**验证用** Android App，不是最终的 VpnService 客户端。它的目的只有一个：

> 证明 `hakimi-core` 能在 Android 上跑起来，并且“用户 CA + MITM + 伪 SNI/ECH”这条链路能真正加速浏览器。

当前状态：**已在 Android 16 x86_64 模拟器与一加 Ace 2（Android 15）真机上验证通过**。

界面使用 Kotlin + 原生 View 实现，亮色「光环」配色；不依赖 AndroidX、Compose 或任何第三方 UI 库。构建仍不使用 Gradle：`aapt2 + kotlinc + d8 + apksigner`。

---

## 已验证的结果

| 项目 | 结果 |
|---|---|
| `hakimi-core` Android 交叉编译 | 通过（NDK 27 + `aws-lc-rs`） |
| 本地 HTTP 代理 | 通过（`127.0.0.1:8443`） |
| DoH | 通过（AliDNS，`dohSource=primary`） |
| 用户 CA 识别 | 通过（`userCa=true`） |
| Chrome 通过代理 | 通过（加载 `github.com`） |
| Chrome + 用户 CA + MITM | 通过（完整加载 `store.steampowered.com`、`www.pixiv.net`） |
| 伪 SNI 上游 | 通过（`www.pixiv.net` 的 Direct 被 `TlsReset` 后改用 ECH；`i.pximg.net`/AO3 走 `strategy=sni`） |
| ECH 上游 | 通过（`www.pixiv.net`、`crypto.cloudflare.com` 均为 `strategy=ech`、`state=normal`） |
| 远程 IP 目录 | 通过（`examples/multi-site/ips.json`，44 域名 / 129 IP，`ipVersion=1`） |
| 证书链 | 通过（`openssl s_client` 显示 issuer=`CN=Hakimi Android Probe CA`，`Verify return code: 0 (ok)`） |

实测截图：Steam 商店页和 Pixiv 首页均在 Chrome 中正常加载。Pixiv 的核心日志显示：

```text
failed candidate before success ... strategy=Direct ip=172.64.145.17 error=Some(TlsReset)
failed candidate before success ... strategy=Direct ip=104.18.42.239 error=Some(TlsReset)
resolved connection strategy group=pixiv domain=www.pixiv.net ip=172.64.145.17 mode=ech source=remote
```

即 Direct 被重置后，ECH 成功接管——这是 Android 上 SNI 伪装链路的关键证据。

### 全量站点测试（加载 `examples/multi-site/ips.json` 后）

| 域名 | HTTP | 结论 |
|---|---:|---|
| github.com | 400 | 路由正常（GitHub 对代理请求返回 400；页面可加载） |
| api.github.com | 200 | 成功 |
| raw.githubusercontent.com | 301 | 成功 |
| pixiv.net | 301 | 成功 |
| www.pixiv.net | 200 | 成功（ECH） |
| i.pximg.net | 200 | 成功（SNI） |
| s.pximg.net | 200 | 成功 |
| booth.pximg.net | 301 | 成功 |
| img.pximg.net | 200 | 成功 |
| archiveofourown.org | 200 | 成功（SNI） |
| www.archiveofourown.org | 301 | 成功 |
| hitomi.la | 200 | 成功（直连） |
| ltn.gold-usergeneratedcontent.net | 404 | 路由成功 |
| nhentai.net | 403 | 路由成功（Cloudflare 人机验证） |
| www.nhentai.net | 502 | 无可用候选 |
| i.nhentai.net | 502 | TLS/H2 被重置 |
| hanime.tv / www.hanime.tv | 403 | 路由成功（Cloudflare 人机验证） |
| store.steampowered.com | 502 | 所有候选 IP `tcp_timeout`（含 last-good） |
| steamcommunity.com / www / api | 502 | 所有候选 IP `tcp_timeout` |
| cdn.cloudflare.steamstatic.com | 502 | 所有候选 IP `tcp_timeout` |
| poipiku.com | 200 | 成功 |
| img.poipiku.com | 200 | 成功 |
| cdn.poipiku.com | 403 | 路由成功 |
| e-hentai.org / exhentai.org | 000 | 组已禁用 → 直连；网络不可达 |
| crypto.cloudflare.com | 502 → 后续 normal | ECH 链路可用，首次请求有瞬时 502 |
| www.baidu.com | 200 | 对照组：非组成员直连 |
| www.google.com | 000 | 对照组：网络不可达 |

Steam 的失败不是路由没跑：状态里有完整的 attempts，4 个远程 IP + last-good 全部 `tcp_timeout`，说明这批 Akamai IP 在当前模拟器网络不可达。换网络或换一份更新的远程目录后需要重测。

---

## 目录

```text
crates/hakimi-android/        JNI shell：启动 core 本地代理、CA PEM、状态
crates/hakimi-core/src/ca.rs  Android 用户 CA 信任覆盖（JNI 上报）
android/probe/                Kotlin 原生 App（无 Gradle，aapt2 + kotlinc + d8 + apksigner）
```

`android/probe` 现在有两种运行模式：

- **本地代理**：core 监听 `127.0.0.1:8443`，浏览器手动配置代理；App 不再写全局 `http_proxy`。
- **VPN · 全部应用**（默认）：`VpnService` 接管所有应用（含浏览器和 WebView），通过静态 HTTP 代理把请求交给 core；核心只接管启用中的站点，其他站点由核心直接隧道转发。VPN 本身不读取 TUN，也不需要 tun2socks。这里不能用 PAC：WebView 系浏览器（如 Via）不读取 VPN 下发的 PAC，会绕过核心直连。

VPN 模式已在 Android 16 x86_64 模拟器（Chrome）和一加 Ace 2 真机（Via）上验证通过；always-on 仍待验证。

---

## 构建

依赖：

- Android SDK / Build Tools 37 / NDK 27
- Rust targets：
  ```bash
  rustup target add x86_64-linux-android aarch64-linux-android
  ```
- `cargo-ndk`
- JDK（Android Studio 的 JBR 即可）
- Git Bash、`openssl`、Python 3

如果 crates.io 需要代理：

```bash
export CARGO_HTTP_PROXY=http://127.0.0.1:10810
cargo fetch --target x86_64-linux-android
```

构建 APK：

```bash
cd android/probe
./build.sh
```

脚本会：

1. 用 `cargo-ndk` 生成 `x86_64` / `arm64-v8a` 的 `libhakimi_android.so`；
2. 如果 `assets/ca/` 不存在，用 openssl 生成一个验证 CA；
3. 用 `aapt2` / `javac` / `d8` / `zipalign` / `apksigner` 打包并签名。

只重新打包 APK、不重编 Rust：

```bash
SKIP_RUST=1 ./build.sh
```

产物：`android/probe/hakimi-probe.apk`（约 6.9MB，含 `x86_64` + `arm64-v8a` 两套 `.so`）。

---

## 安装与启动

```bash
adb install -r android/probe/hakimi-probe.apk
# 可选：仅用于清理旧版本可能留下的全局代理；正式使用不需要
adb shell pm grant com.hakimi.probe android.permission.WRITE_SECURE_SETTINGS
adb shell pm grant com.hakimi.probe android.permission.POST_NOTIFICATIONS

# 启动 App
adb shell am start -n com.hakimi.probe/.MainActivity --ez start true
```

不要再用 `adb shell settings put global http_proxy ...`。全局代理会比 App 进程活得更久，App 崩溃或被 kill 后浏览器会一直指向死端口。旧版本如果留下过这个设置，先清理：

```bash
adb shell settings delete global http_proxy
adb shell settings delete global global_http_proxy_host
adb shell settings delete global global_http_proxy_port
adb shell settings delete global global_proxy_pac_url
```

App 内入口：

- **首页圆环 / 开启 / 暂停**：按当前运行模式启动或停止加速。
- **设置 → 运行模式**：本地代理 / VPN · 浏览器。切换时会短暂停止并重建。
- **设置 → 接管浏览器**：VPN 模式下选择要接管的浏览器（Chrome/Via/HeyTap 等）。
- **设置 → 始终开启**：打开系统 VPN 设置，为 hakimi 打开始终开启。开启后 App 内的「暂停」需要先关闭始终开启。
- **设置 → 后台保活**：请求忽略电池优化，减少息屏后回收。
- **设置 → 本地 CA**：导出证书、查看安装状态、重新检查。

---

## CA 安装

### 真机（推荐路径）

1. App 里点 **Export CA**，保存 `hakimi-ca.crt`。
2. 设置 → 安全 → 加密与凭据 → 安装证书 → **CA 证书** → 仍然安装 → 选择文件。
3. **一定装成“用户 CA”**。不要装进系统证书库：Chrome 99+ 会对系统库里的自签名 CA 强制 CT，直接报 `ERR_CERTIFICATE_TRANSPARENCY_REQUIRED`。
4. Chrome 设置 → 隐私和安全 → 使用安全 DNS → 关闭（避免 Chrome 用 ECH 隐藏内层 SNI，导致无法 MITM）。
5. 重启 Chrome。

Chrome / WebView / Brave / Edge 会信任用户 CA；多数原生 App 不会。Firefox 需要在浏览器内手动信任证书，或打开 Secret Settings 的 “Use third-party CA certificates”。

### 模拟器（本次验证使用）

在 userdebug 模拟器上可以直接把 CA 放进用户证书库，省去手动点击：

```bash
HASH=$(openssl x509 -in android/probe/assets/ca/ca.pem -subject_hash_old -noout)
adb root
adb push android/probe/assets/ca/ca.pem /data/local/tmp/hakimi-ca.pem
adb shell "mkdir -p /data/misc/keychain/cacerts-added /data/misc/user/0/cacerts-added"
adb shell "cp /data/local/tmp/hakimi-ca.pem /data/misc/keychain/cacerts-added/$HASH.0"
adb shell "cp /data/local/tmp/hakimi-ca.pem /data/misc/user/0/cacerts-added/$HASH.0"
adb shell "chown system:system /data/misc/keychain/cacerts-added/$HASH.0 /data/misc/user/0/cacerts-added/$HASH.0"
adb shell "chmod 644 /data/misc/keychain/cacerts-added/$HASH.0 /data/misc/user/0/cacerts-added/$HASH.0"
adb shell "restorecon -RF /data/misc/keychain/cacerts-added /data/misc/user/0/cacerts-added"
adb reboot
```

重启后启动 App，logcat 里应出现：

```text
HakimiProbe: init=true userCa=true proxy=true error=
```

### Chrome 首次运行（模拟器）

```bash
adb shell am force-stop com.android.chrome
adb shell "echo 'chrome --disable-fre --no-first-run --no-default-browser-check --disable-features=EncryptedClientHello' > /data/local/tmp/chrome-command-line"
adb shell chmod 644 /data/local/tmp/chrome-command-line
adb shell am start -a android.intent.action.VIEW -d https://store.steampowered.com/
```

---

## 验证命令（不依赖 Chrome UI）

把设备上的代理端口转发到主机：

```bash
adb forward tcp:18443 tcp:8443
curl --noproxy '*' http://127.0.0.1:18443/hakimi/status
curl --noproxy '*' http://127.0.0.1:18443/hakimi/health
```

验证 MITM 证书链：

```bash
openssl s_client -proxy 127.0.0.1:18443 -connect store.steampowered.com:443 \
  -servername store.steampowered.com -CAfile android/probe/assets/ca/ca.pem \
  -showcerts < /dev/null
```

期望输出包含：

```text
issuer=CN=Hakimi Android Probe CA
Verify return code: 0 (ok)
```

验证页面：

```bash
curl -sS --noproxy '' -x http://127.0.0.1:18443 -k \
  -o /dev/null -w '%{http_code}\n' https://store.steampowered.com/
```

---

## 远程 IP 目录对照实验

主站（Pixiv/AO3/Hitomi）之前失败，是因为默认配置里 `catalogs.ip` 为空，只能尝试 DoH 返回的单个 IP。用仓库自带的 `examples/multi-site/ips.json` 作为远程目录后，Pixiv/AO3/Hitomi 都恢复。复现步骤：

```bash
# 1. 主机上提供目录（仅监听本机）
cd examples/multi-site
python -m http.server 8000 --bind 127.0.0.1

# 2. 让设备通过 adb reverse 访问主机的 8000
adb reverse tcp:8000 tcp:8000

# 3. 把 config.json 拉下来，设置 catalogs.ip
adb pull /data/user/0/com.hakimi.probe/files/hakimi/config.json /tmp/config.json
# 编辑 /tmp/config.json： "ip": "http://127.0.0.1:8000/ips.json"

# 4. 以 app 身份写回（直接 root push 会导致 app 读不到）
adb push /tmp/config.json /data/local/tmp/hakimi-config.json
adb shell "rm -f /data/user/0/com.hakimi.probe/files/hakimi/config.json"
adb shell "run-as com.hakimi.probe cp /data/local/tmp/hakimi-config.json files/hakimi/config.json"
adb shell "run-as com.hakimi.probe chmod 600 files/hakimi/config.json"

# 5. 重启服务
adb shell am force-stop com.hakimi.probe
adb shell am start-foreground-service -n com.hakimi.probe/.ProxyService
```

状态里应出现：

```json
"catalogs": {"ipLoaded": true, "ipDomains": 44, "ipIps": 129, "ipVersion": 1, ...}
```

注意：`examples/multi-site/ips.json` 只是测试夹具，里面的 IP 会过期。生产需要真实维护的远程目录，并配合 last-good 缓存。

---

### Pixiv 主站的路由经验（真机实测）

- `www.pixiv.net` 的主站入口是 Cloudflare 前置 IP（`104.18.42.239` / `172.64.145.17`）+ ECH；`210.140.139.155/161` 虽然属于 Pixiv，但直接请求主站会返回 **403 Forbidden**，只能用于图片/CDN。
- 建议把 `www.pixiv.net`、`pixiv.net` 加入 `advanced.http1Hosts`，强制 HTTP/1.1 回源。真机上曾出现 Cloudflare 前置的 HTTP/2 upstream 中断：
  ```text
  upstream request failed host="www.pixiv.net" path=/login.php
  error=client error (SendRequest) / hyper::Error(To, Kind(ConnectionAborted))
  ```
  加 HTTP/1.1 后 Via 通过代理可稳定加载 Pixiv 首页。
- 测试用 catalog 通过 `adb reverse tcp:8000 tcp:8000` 提供；**adb server 重启后 reverse 规则会丢失**，表现为 `Connection refused`、`ipLoaded=false`，需要重新执行。
- 真机默认浏览器是 `com.heytap.browser`，Via 是 `mark.via`；设备上没有 Chrome。Via 在代理下加载 Pixiv 已实测成功。

## 本次验证的已知问题

1. **Steam 系列当前全部超时**：`store.steampowered.com`、`steamcommunity.com`、`api.steampowered.com`、`cdn.cloudflare.steamstatic.com` 的所有候选 IP（远程目录 + last-good）都 `tcp_timeout`。这是模拟器网络对这批 Akamai IP 不可达，不是路由没跑；状态里的 attempts 能完整看到尝试记录。换网络或更新远程目录后需要重测。
2. **部分站点被 Cloudflare 挑战**：`nhentai.net`、`hanime.tv` 返回 403，说明代理/SNI 链路已经通了，但 Cloudflare 需要浏览器人机验证。Chrome 里通常能继续。
3. **`www.nhentai.net` / `i.nhentai.net` 失败**：远程目录 IP 不可达或 TLS/H2 被重置；需要更新目录。
4. **`crypto.cloudflare.com` 首次请求 502**：后续状态恢复为 `strategy=ech`、`state=normal`，属于计划缓存/瞬时问题；Pixiv 的 ECH 已稳定成功。
5. **e-hentai / exhentai / google**：分别是“组已禁用 → 直连”和“网络不可达”，不是 probe 问题。
6. **不再使用全局 HTTP 代理**：本地代理模式需要浏览器手动配置；VPN 模式是 per-app 静态代理，不读取 TUN，也不会写 `Settings.Global.HTTP_PROXY`。
7. **CA 私钥打包在 APK 里**：这是验证用 CA，不能用于生产。生产应由 core 在设备上生成 CA，再引导用户安装。
8. **真机 VPN 模式未验证**：APK 已包含 `x86_64` + `arm64-v8a` 两套 `.so`；VPN 模式在 Android 16 x86_64 模拟器 + Chrome 上验证通过，真机 Via/HeyTap 仍需实测。
9. **Chrome 安全 DNS**：如果开启，Chrome 可能使用 ECH，内层 SNI 不可见，MITM 无法命中；本次已通过命令关闭 ECH 特性。
10. **VPN 模式要求 Android 13+**：依赖 `VpnService.Builder.setHttpProxy`（API 29）和 `excludeRoute`（API 33）。更老的系统只能使用本地代理模式。
11. **IPv6 在 VPN 模式下仍是直连兜底**：实测 VPN 路由里 `::/0` 是 unreachable，IPv6-only 站点可能不可用；需要后续补齐 IPv6 排除或明确提示。

### 用 `diagnose` 查看失败详情

App 支持一个 intent extra，把 `HakimiRuntime::diagnose` 的结果写到应用私有目录：

```bash
adb shell am force-stop com.hakimi.probe
adb shell am start -n com.hakimi.probe/.MainActivity \
  --es diagnose www.nhentai.net
# 文件位于 /data/user/0/com.hakimi.probe/files/diagnose-www.nhentai.net.json
adb root
adb pull /data/user/0/com.hakimi.probe/files/diagnose-www.nhentai.net.json
```

diagnose 会真正执行 TCP/TLS 探测，并给出每个候选 IP、策略、SNI 和失败原因，用来区分“IP 不可达”和“路由逻辑问题”。

---

## 下一步

1. **真机 VPN 模式验证**：一加 Ace 2 上用 Via / HeyTap 验证静态代理是否生效。WebView 系浏览器不读取 VPN PAC，必须使用静态代理；Chromium 系浏览器两者都支持。
2. **Always-on 真机验证**：系统开机恢复、always-on 下 App 内停止、per-app 与 always-on 的兼容性。
3. **IPv6**：补齐 IPv6 直连排除，或明确只支持 IPv4。
4. **CA 安装向导**：设备端生成 CA、导出、手动安装、`AndroidCAStore` 检测。
5. **ECH 请求路径修复**：排查 `cached_plan` / `UpstreamPool` 在 ECH 模式下的复用。
6. **arm64 真机回归**：Wi-Fi/蜂窝切换、Chrome/WebView/Firefox、Pixiv/GitHub/Steam。
