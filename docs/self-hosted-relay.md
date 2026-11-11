# 自建图片中转 Worker

只想中转原图和预览图，用内置地址就够了。如果要做全站图片加速，建议先按下面部署一份自己的：内置地址是公开的，额度由所有使用者共用，还会被爬虫等无关请求消耗，全站加速的请求量会更快把它吃满。用自己的 Cloudflare 账号和额度就没有这层顾虑。中转本身的参数和匹配规则见 [图片中转](image-relay.md)。

## 它做什么

仓库里的 Worker 在 `workers/pximg-relay/`，只有一个 `index.js`，不依赖 KV、R2 或任何绑定：

- 接收 `/pximg/...`，回源到 `https://i.pximg.net/...`；前缀固定是 `/pximg`
- 只接受 `GET` 和 `HEAD`，其它方法返回 405；前缀不对返回 404
- 转发时固定带 `Referer: https://www.pixiv.net/`，`User-Agent` 用浏览器的，没有就用 `Piku/3.7.0`
- 透传 `Accept`、`Range`、`If-None-Match`、`If-Modified-Since`
- 成功响应加 `Cache-Control: public, max-age=604800, immutable`，并让 Cloudflare 缓存 7 天
- 丢弃上游的 `Set-Cookie`
- 上游固定在 `i.pximg.net`，不是开放代理，别人拿它转发不了别的站

## 什么是 workers.dev 子域

Cloudflare 给每个账号一个免费域名，形如 `yourname.workers.dev`，用来放你部署的 Worker。每个 Worker 会自动得到一个 `<Worker 名>.<子域>.workers.dev` 的地址：Worker 叫 `hakimi-relay`、子域是 `demo`，地址就是 `https://hakimi-relay.demo.workers.dev`。

几个特点：

- 名字全局唯一，被别人占了只能换一个
- 账号第一次用 Workers 时设置，之后这个账号下所有 Worker 共用它
- 证书由 Cloudflare 管理，不能换成自己的；要用自己的域名见下面「换成自己的域名」
- 部署脚本的 `--subdomain` 就是在这个账号还没有子域时创建它；API 只能创建，改名要去控制台

## 方式一：部署脚本

需要 Python 3（不用装 Node）和一个 Cloudflare API Token，至少要有 `Workers Scripts: Edit`。如果账户还没有 workers.dev 子域，创建时可能还需要其它 Workers 权限，缺权限脚本会直接报出来。

```bash
export CLOUDFLARE_API_TOKEN=...
python3 scripts/deploy_relay.py --apply
```

脚本会依次做几件事：选账号（只有一个时自动选，多个会列出来让你用 `--account` 指定）→ 上传脚本 → 读 workers.dev 子域（没有就提示）→ 打开该 Worker 的 workers.dev 路由 → 打印中转地址。

常用参数：

| 参数 | 作用 |
| --- | --- |
| `--account <id>` | 指定账号，多账号时必填 |
| `--name <名字>` | Worker 名，同时决定 `<名字>.<子域>.workers.dev` |
| `--subdomain <名字>` | 账号还没有 workers.dev 子域时创建；名字全局唯一，建完要改名得去控制台 |
| `--apply` | 把地址写进 hakimi 配置（只改 `advanced.imageRelays.0.base`） |
| `--dry-run` | 只打印要上传的内容，不发任何请求 |

输出大致是：

```
uploaded hakimi-relay (1432 bytes) to account ...
relay base: https://hakimi-relay.<你的子域>.workers.dev/pximg
hakimi setting:
  hakimi config set advanced.imageRelays.0.base https://hakimi-relay.<你的子域>.workers.dev/pximg
```

带 `--apply` 时脚本会先确认 0 号规则是内置的 `pixiv` 规则，再写入；改完需要重启 hakimi 实例才生效。

## 方式二：wrangler

已经有 Node 环境的话，直接用它更省事：

```bash
cd workers/pximg-relay
npx wrangler deploy
```

`wrangler.toml` 里已经写好 `name`、`main`、`compatibility_date` 和 `workers_dev = true`。部署完把输出地址加上 `/pximg` 填到「中转地址」：

```bash
hakimi config set advanced.imageRelays.0.base https://<name>.<subdomain>.workers.dev/pximg
```

## 部署后验证

直接请求一次，注意带上 UA：

```bash
curl -sI -A 'Piku/3.7.0' \
  'https://<name>.<subdomain>.workers.dev/pximg/img-original/img/2024/08/31/00/41/05/121982540_p0.jpg' | head
```

预期看到 `HTTP/2 200`、`content-type: image/jpeg`，以及 `cf-cache-status` 字段（命中缓存为 `HIT`，否则为 `MISS`）。

用浏览器直接开这个地址也可以，但 `workers.dev` 有 Browser Integrity Check，默认的脚本 UA（比如 `Python-urllib`）会被拦成 1010 错误，所以自动化请求记得自己带 UA。

## 换成自己的域名

Worker 跑起来后可以绑自己的域名：Cloudflare 控制台 → Workers & Pages → 选中刚部署的 Worker → Settings → Domains & Routes → Add → Custom Domain。绑好后把中转地址换成 `https://你的域名/pximg` 即可，Worker 代码不用改。

注意 `base` 必须保留 `/pximg` 这一段，Worker 靠它识别前缀、剥掉之后再拼回源地址。

## 常见问题

- **workers.dev 子域**：一个账号只有一个，名字全局唯一；API 只能创建，改名要去控制台，别重复跑 `--subdomain`。
- **401 / 403**：Token 没给 `Workers Scripts: Edit`，或者账号 ID 不对。
- **配额**：Worker 请求数和 CPU 时间受 Cloudflare 套餐限制，具体额度以你账号当前的套餐说明为准。
- **想多部署几个**：换 `--name` 即可，同一个子域下可以有多个 Worker。
