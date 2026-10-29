#!/usr/bin/env bash
# End-to-end check of the Linux CA path, run on a real runner:
#   1. export the CA as PEM and check it parses
#   2. install it into the system trust store (needs root, passwordless on CI)
#   3. start the proxy and let it terminate TLS for a real site
#   4. uninstall and confirm the system store no longer lists it
#
# Run as a normal user: the trust-store steps call sudo themselves.
set -euo pipefail

BIN="${BIN:-target/debug/hakimi}"
BIN="$(realpath "$BIN")"
DATA="$(mktemp -d)"
PROXY="http://127.0.0.1:8443"
INSTALLED=0

log() { printf '\n== %s\n' "$*"; }

cleanup() {
  "$BIN" --data-dir "$DATA" stop >/dev/null 2>&1 || true
  if [ "$INSTALLED" = 1 ]; then
    sudo "$BIN" --data-dir "$DATA" ca uninstall >/dev/null 2>&1 || true
  fi
  rm -rf "$DATA"
}
trap cleanup EXIT

log "1/5 export the CA as PEM"
"$BIN" --data-dir "$DATA" ca export --out "$DATA/exported.pem"
openssl x509 -in "$DATA/exported.pem" -noout -subject | grep -q "hakimi Local CA"
echo "pem ok"

log "2/5 install into the system trust store"
# Marked before the command: a half-finished install still leaves an anchor
# behind, and the trap has to clean it up.
INSTALLED=1
sudo "$BIN" --data-dir "$DATA" ca install
"$BIN" --data-dir "$DATA" --json ca status | jq -e '.installed == true' >/dev/null
echo "system store trusts the CA"

log "3/5 proxy terminates TLS with that CA"
"$BIN" --data-dir "$DATA" config update <<'JSON' >/dev/null
{
  "catalogs": { "ip": "", "doh": "" },
  "doh": {
    "primary": "https://cloudflare-dns.com/dns-query",
    "fallback": "https://dns.google/dns-query"
  }
}
JSON
"$BIN" --data-dir "$DATA" group add smoke --domain example.com --route auto >/dev/null
"$BIN" --data-dir "$DATA" serve --no-takeover >"$DATA/serve.log" 2>&1 &

for _ in $(seq 1 200); do
  if curl -s --noproxy '*' -m 1 "http://127.0.0.1:8443/hakimi/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if ! curl -s --noproxy '*' -m 2 "http://127.0.0.1:8443/hakimi/health" >/dev/null; then
  echo "the proxy did not start"
  tail -40 "$DATA/serve.log" || true
  exit 1
fi

# Without --cacert: curl trusts the system store, so a 200 means the CA really
# landed there and the proxy really terminated the connection.
code="$(curl -s --noproxy '' -m 30 -o /dev/null -w '%{http_code}' -x "$PROXY" https://example.com)"
if [ "$code" != 200 ]; then
  echo "expected 200 through the proxy, got $code"
  echo "--- diagnostics"
  "$BIN" --data-dir "$DATA" doctor example.com || true
  tail -40 "$DATA/serve.log" || true
  exit 1
fi

# The leaf must be ours: a tunnel would show the site's real issuer instead.
issuer="$(curl -s --noproxy '' -m 30 -v -o /dev/null -x "$PROXY" https://example.com 2>&1 | grep 'issuer:' | head -1 || true)"
echo "${issuer:-no issuer line in the curl output}"
case "$issuer" in
  *hakimi*) ;;
  *) echo "the proxy tunneled instead of terminating TLS"; exit 1 ;;
esac

log "4/5 uninstall, and uninstall again to prove it is a no-op"
"$BIN" --data-dir "$DATA" stop
sudo "$BIN" --data-dir "$DATA" ca uninstall
INSTALLED=0
sudo "$BIN" --data-dir "$DATA" ca uninstall
"$BIN" --data-dir "$DATA" --json ca status | jq -e '.installed == false' >/dev/null

log "5/5 done"
