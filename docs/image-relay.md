# 图片中转

hakimi 的图片中转会把指定域名的图片请求改写到另一个前缀，从而加速图片加载。

以 Pixiv 为例：中转可以用于加速其图片加载。中转只影响图片请求，网页与 API 仍走原来的线路。

## 生效前提

中转发生在 hakimi 解密后的 HTTP 请求上，所以域名得先被它接管：

- 域名出现在某个启用的站点分组里（默认分组已包含 `i.pximg.net`）
- 该域名的线路不是「强制直连」
- 本机已信任 hakimi 的 CA
- 代理没有暂停

不满足时请求走原始 TCP 隧道，hakimi 看不到路径，中转不会生效。给别的域名加中转时，先把它加进分组。

## 默认配置

开箱即用，不需要任何设置。内置规则：

| 参数 | 值 |
| --- | --- |
| 启用 | 是 |
| 中转地址 | `https://pic-relay.cyou/pximg` |
| 适用域名 | `i.pximg.net` |
| 只匹配路径 | `/img-original/`、`/img-master/` |
| 请求 UA | `Piku/3.7.0` |
| 失败回落直连 | 是 |
| 超时 | 5000 ms |

内置中转地址由 [Piku](https://github.com/NLick47/Piku) 项目提供：一个自建的 Cloudflare Worker，没有商业服务承诺，可用性取决于那台 Worker 和 Cloudflare 的状态，所以默认开启「失败回落直连」，中转不可用时自动改走源站。默认 UA `Piku/3.7.0` 也来自该项目。

配置文件只保存改动过的值。`config.json` 里没有 `advanced.imageRelays`，说明用的就是上面这份默认值，不是没有配置。

## 参数

| 参数 | 含义 | 约束 |
| --- | --- | --- |
| `id` | 规则标识，界面和 CLI 靠它定位 | 字母、数字、`-`、`_`，不可重复 |
| `enabled` | 是否启用这条规则 | 关掉后该域名完全不中转 |
| `hosts` | 适用域名，命中其中任意一个即可 | 最多 16 条；支持 `*.example.com`，不含裸域 |
| `paths` | 只中转这些路径前缀，命中任意一个即可 | 最多 8 条；留空表示该域名下所有路径 |
| `base` | 中转前缀，最终地址是 `base + 原路径与查询串` | 必须 https，不能带查询串 |
| `referer` | 发给中转的 `Referer` | 留空则不覆盖浏览器的值 |
| `userAgent` | 发给中转的 `User-Agent` | 留空则透传浏览器的值 |
| `fallbackDirect` | 中转失败时是否改走源站 | 关掉后失败直接报错，不会偷偷直连 |
| `timeoutMs` | 等待响应头的上限 | 500–30000；只限制响应头，已经开始的响应体不会被中断 |

## 匹配规则

`hosts` 和 `paths` 各自是「任意一项命中即可」，两者之间必须同时满足。顺序无关，不是按位置配对。

例如 `hosts` 填 `i.pximg.net, *.pximg.net`，`paths` 填 `/img-original/, /img-master/`：

| 请求 | 域名 | 路径 | 走中转 |
| --- | --- | --- | --- |
| `i.pximg.net/img-original/a.jpg` | 命中 | 命中 | 是 |
| `i.pximg.net/img-master/a.jpg` | 命中 | 命中 | 是 |
| `s.pximg.net/img-master/a.jpg` | 通配命中 | 命中 | 是 |
| `i.pximg.net/c/250x250/img-master/a.jpg` | 命中 | 未命中（以 `/c/` 开头） | 否 |
| `i.pximg.net/img/a.jpg` | 命中 | 未命中 | 否 |
| `example.com/img-original/a.jpg` | 未命中 | 命中 | 否 |

几个容易踩的点：

- 路径是**前缀匹配**，不是通配符。写 `/img-master`（不带尾斜杠）会连 `/img-master2/...` 一起命中，建议一律带尾斜杠。
- 缩略图路径是 `/c/.../img-master/...`，以 `/c/` 开头，不会被 `/img-master/` 匹配到，所以默认规则不中转缩略图。
- 只有 `GET` 和 `HEAD` 会被中转。
- 多条规则按数组顺序判断，第一条域名和路径都命中的规则生效。

## 全站图片加速

默认规则只中转 `/img-original/` 和 `/img-master/`。想让某个站点的图片全部走中转，把 `paths` 留空即可——留空表示该域名下所有路径都中转，同时把图床域名填全：

- `hosts`：列出该站所有图片域名，或用 `*.pximg.net` 这类通配一次覆盖子域（通配不含裸域）
- `paths`：留空

界面里清空「只匹配路径」，或命令行：

```bash
hakimi config set advanced.imageRelays.0.paths '[]'
```

注意：

- 中转按域名匹配，不按文件类型。只有该域名是独立图床时才适合留空 `paths`；如果它还承载网页或 API，要用路径前缀把图片目录圈出来，否则这些请求也会被一起中转。
- 只有 `GET`、`HEAD` 会走中转。
- 全站加速会让中转请求量明显上升。

**这种用法建议配自建中转。** 内置地址是公开的，所有使用者共用同一份额度，还会被爬虫等无关请求消耗；把整站图片压上去会更快耗尽额度，也更容易撞到配额上限。按 [自建图片中转 Worker](self-hosted-relay.md) 部署一份自己的，用自己的 Cloudflare 账号和额度，既不给公用地址添负担，也不受共享配额牵制。

## 请求会怎么改

- 地址改写为 `base + 原路径 + 原查询串`
- `Host` 换成中转主机
- `Referer`、`User-Agent` 按规则覆盖（留空则保留浏览器的值）
- `Cookie`、`Authorization`、`Proxy-Authorization` 在发出前被移除
- 响应里的 `Set-Cookie`、`Set-Cookie2` 会被移除，不写回浏览器
- 中转返回 403、429、5xx，或响应头超时、连接失败时：`fallbackDirect` 为真就改走源站，为假就返回错误
- 连续失败 3 次后该规则冷却 60 秒；冷却期内 `fallbackDirect` 决定是直连还是直接报错，成功一次就恢复

## 怎么改

### 界面

设置 → 网络 → 图片中转。界面只编辑 `id` 为 `pixiv` 的那条规则，手写的其它规则不受影响。多个值用逗号分隔，中文逗号也可以。

### 命令行

```bash
hakimi config set advanced.imageRelays.0.enabled false
hakimi config set advanced.imageRelays.0.paths '["/img-original/"]'
hakimi config set advanced.imageRelays.0.base https://your-relay.example/pximg
```

改完需要重启实例才生效。

### 手改 config.json

文件在数据目录下，`hakimi config path` 可以直接打印路径。

```json
{
  "advanced": {
    "imageRelays": [
      {
        "id": "pixiv",
        "enabled": true,
        "hosts": ["i.pximg.net"],
        "paths": ["/img-original/", "/img-master/"],
        "base": "https://pic-relay.cyou/pximg",
        "referer": "https://www.pixiv.net/",
        "userAgent": "Piku/3.7.0",
        "fallbackDirect": true,
        "timeoutMs": 5000
      }
    ]
  }
}
```

整体限制：最多 8 条规则；同一个域名模式不能被两条规则同时声明；`base` 不能指向本规则自己处理的域名（否则会自己转自己）。

## 自建中转

不想共用内置中转，可以部署一份自己的 Worker：源码在 `workers/pximg-relay/`，一键部署脚本是 `scripts/deploy_relay.py`。完整步骤、验证方法和常见问题见 [自建图片中转 Worker](self-hosted-relay.md)。

## 隐私

- 图片字节和完整图片 URL 会经过中转方；默认中转方是 [Piku](https://github.com/NLick47/Piku) 项目部署的 Worker
- 中转前会移除 `Cookie`、`Authorization`、`Proxy-Authorization`，中转方拿不到你的登录态
- 中转返回的 `Set-Cookie` 会被丢弃，不会污染源站域
- 网页、API 和其它请求不经过中转
- 不想让图片请求经过任何中转服务，可以按 [自建文档](self-hosted-relay.md) 部署自己的 Worker，或把「启用中转」关掉
