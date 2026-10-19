# Multi-site preset catalog (AO3 / GitHub / Pixiv / Poipiku / Steam)

Local test data used for the live PAC validation.

## Strategies

| Group | Domains | Strategy | Fixed IPs / notes |
|---|---|---|---|
| ao3 | archiveofourown.org, www, `*.archiveofourown.org` | `sni` (`sni: ""`) | Cloudflare `104.20.9.2`, `104.20.8.2` |
| github | github.com, api, raw, `*.githubusercontent.com`, `*.githubassets.com` | `auto` | direct works: `20.205.243.166`, `20.250.119.72`, `185.199.108-111.133/.215/.154` |
| pixiv | pixiv.net, www, i.pximg.net, `*.pximg.net` | `auto`, `echShared: true` | main/www use Cloudflare `172.64.145.17`, `104.18.42.239` for ECH; origin `210.140.139.155/.161` as SNI fallback; i.pximg origin `.129-.136` |
| poipiku | poipiku.com, `*.poipiku.com` | `direct` | AWS `18.182.121.133`, `52.197.148.72` |
| steam | store, community, wildcards | `auto` | store direct `88.221.170.104`; community SNI `88.221.168.230`; static `146.75.123.52` |

`www.pixiv.net` has no ECH RR of its own. `echShared: true` uses Cloudflare's shared
`cloudflare-ech.com` ECHConfig (outer SNI `cloudflare-ech.com`, real `www.pixiv.net` inside),
fetched through the configured DoH/fallback AliDNS and cached. This is the same approach used by
the Piku project. Bare `pixiv.net` and `i.pximg.net` are not CF-fronted, so `auto` falls back to
fake SNI (empty) for those.

## Use

```bash
python -m http.server 18470 --bind 127.0.0.1 --directory examples/multi-site
./target/debug/hakimi --data-dir target/multi \
  catalog refresh --kind all --force
./target/debug/hakimi --data-dir target/multi doctor www.pixiv.net --json
./target/debug/hakimi --data-dir target/multi serve --no-takeover
```

The live PAC instance used by the browser is configured from `data/ao3-live` (same groups, local
catalog cache, installed CA, PAC on `127.0.0.1:18471`).
