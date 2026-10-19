# AO3 local catalog example

Local test data for `archiveofourown.org` with an empty fake SNI.

- `ips.json`: remote IP catalog (Cloudflare `104.20.9.2`, `104.20.8.2`, empty group SNI).
- `doh.json`: remote DoH catalog (trusted CleanBrowsing policies + Applied Privacy).
- `config.json`: hakimi test config in `sni` mode with `sni: ""`.

## Reproduce

```bash
# 1. Serve the catalogs locally
python -m http.server 18470 --bind 127.0.0.1 --directory examples/ao3-local-catalog

# 2. Load both catalogs
./target/debug/hakimi --data-dir target/ao3-example catalog refresh --kind all --force
./target/debug/hakimi --data-dir target/ao3-example status --json
./target/debug/hakimi --data-dir target/ao3-example doh health

# 3. Diagnose
./target/debug/hakimi --data-dir target/ao3-example doctor archiveofourown.org --json

# 4. Run the proxy (PAC on 127.0.0.1:18471) and fetch AO3 through it
./target/debug/hakimi --data-dir target/ao3-example serve --no-takeover
curl --noproxy '' --proxy http://127.0.0.1:18471 \
  --cacert target/ao3-example/ca/ca.pem --ssl-no-revoke \
  https://archiveofourown.org/
```

Expected: `state=normal`, `strategy=sni`, `ipSource=remote`, and AO3 returns
`200` with title `Home | Archive of Our Own`.

## Notes

- `sni: ""` means "send no SNI"; this worked for AO3 behind Cloudflare in testing.
- ECH also works for AO3 in this network, but this example intentionally locks `sni`.
- DNSPod/AliDNS were reachable during testing but returned `199.16.156.103` for
  `www.archiveofourown.org` (not an AO3 address), so they are not included. Use only
  DoH providers you trust.
- Curl on Windows uses Schannel; `--ssl-no-revoke` avoids its revocation check for the
  locally generated CA.
