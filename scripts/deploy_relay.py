#!/usr/bin/env python3
"""Deploy the pximg relay Worker to Cloudflare and wire it into hakimi.

Needs nothing but Python 3 and a Cloudflare API token with
`Workers Scripts: Edit`. Creating a workers.dev subdomain may need more.
"""
import argparse
import json
import os
import pathlib
import secrets
import subprocess
import sys
import urllib.error
import urllib.request

DEFAULT_API = "https://api.cloudflare.com/client/v4"
COMPATIBILITY_DATE = "2026-01-01"
WORKER_DIR = pathlib.Path(__file__).resolve().parent.parent / "workers" / "pximg-relay"
WORKER_FILE = "index.js"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNFINISHED = 2


class ApiError(Exception):
    def __init__(self, status, errors):
        detail = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errors) or "no detail"
        super().__init__(f"Cloudflare API returned {status}: {detail}")
        self.status = status
        self.codes = {e.get("code") for e in errors}


def call(method, path, token, body=None, api=DEFAULT_API, timeout=60):
    data = None
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(api + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            errors = json.loads(raw).get("errors") or []
        except ValueError:
            errors = [{"message": raw.decode("utf-8", "replace")[:200]}]
        raise ApiError(error.code, errors) from None
    if not payload.get("success", False):
        raise ApiError(200, payload.get("errors") or [])
    return payload.get("result")


def multipart(fields):
    boundary = "----hakimi" + secrets.token_hex(8)
    body = bytearray()
    for name, filename, content_type, data in fields:
        disposition = f'form-data; name="{name}"'
        if filename:
            disposition += f'; filename="{filename}"'
        body += f"--{boundary}\r\n".encode()
        body += f"Content-Disposition: {disposition}\r\n".encode()
        body += f"Content-Type: {content_type}\r\n\r\n".encode()
        body += data + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return boundary, bytes(body)


def upload(token, account, name, source, api, dry_run):
    metadata = {
        "main_module": WORKER_FILE,
        "compatibility_date": COMPATIBILITY_DATE,
        "observability": {"enabled": True},
    }
    fields = [
        ("metadata", None, "application/json", json.dumps(metadata).encode()),
        (WORKER_FILE, WORKER_FILE, "application/javascript+module", source),
    ]
    path = f"/accounts/{account}/workers/scripts/{name}"
    if dry_run:
        print(f"dry run: would upload {len(source)} bytes to PUT {api}{path}")
        print(json.dumps(metadata, indent=2))
        return
    boundary, body = multipart(fields)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }
    request = urllib.request.Request(api + path, data=body, headers=headers, method="PUT")
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            errors = json.loads(raw).get("errors") or []
        except ValueError:
            errors = [{"message": raw.decode("utf-8", "replace")[:200]}]
        raise ApiError(error.code, errors) from None
    if not payload.get("success", False):
        raise ApiError(200, payload.get("errors") or [])


def resolve_account(token, wanted, api):
    if wanted:
        return wanted
    accounts = call("GET", "/accounts?per_page=50", token, api=api) or []
    if len(accounts) == 1:
        return accounts[0]["id"]
    if not accounts:
        raise SystemExit("this token cannot see any account")
    listing = "\n".join(f"  {a['id']}  {a['name']}" for a in accounts)
    raise SystemExit(f"pick one with --account:\n{listing}")


def account_subdomain(token, account, api):
    try:
        result = call("GET", f"/accounts/{account}/workers/subdomain", token, api=api)
    except ApiError as error:
        # 10007: the account never registered a workers.dev subdomain.
        if 10007 in error.codes:
            return None
        raise
    return (result or {}).get("subdomain")


def create_subdomain(token, account, name, api):
    call("PUT", f"/accounts/{account}/workers/subdomain", token, {"subdomain": name}, api=api)
    return name


def enable_script_subdomain(token, account, script, api):
    try:
        call(
            "POST",
            f"/accounts/{account}/workers/scripts/{script}/subdomain",
            token,
            {"enabled": True, "previews_enabled": False},
            api=api,
        )
    except ApiError as error:
        if error.status not in (403, 404):
            raise


def hakimi_command(base):
    return ["hakimi", "config", "set", "advanced.imageRelays.0.base", base]


def apply_to_hakimi(base):
    try:
        probe = subprocess.run(
            ["hakimi", "config", "get", "advanced.imageRelays.0.id"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return False, "hakimi binary not found on PATH"
    if probe.returncode != 0 or probe.stdout.strip() != "pixiv":
        return False, "the first image relay rule is not the shipped pixiv one"
    done = subprocess.run(hakimi_command(base), capture_output=True, text=True, timeout=30)
    if done.returncode != 0:
        return False, (done.stderr or done.stdout).strip()
    return True, ""


def main():
    parser = argparse.ArgumentParser(
        description="Deploy the hakimi pximg relay Worker and print its base URL."
    )
    parser.add_argument("--token", default=os.environ.get("CLOUDFLARE_API_TOKEN"))
    parser.add_argument("--account", default=os.environ.get("CLOUDFLARE_ACCOUNT_ID"))
    parser.add_argument("--name", default="hakimi-relay", help="Worker name, also its workers.dev label")
    parser.add_argument("--subdomain", help="workers.dev subdomain to create if the account has none")
    parser.add_argument("--worker", default=str(WORKER_DIR), help="directory holding index.js")
    parser.add_argument("--api-base", default=DEFAULT_API, help=argparse.SUPPRESS)
    parser.add_argument("--apply", action="store_true", help="write the base into the hakimi config")
    parser.add_argument("--dry-run", action="store_true", help="print the upload without sending it")
    args = parser.parse_args()

    source_path = pathlib.Path(args.worker) / WORKER_FILE
    if not source_path.is_file():
        raise SystemExit(f"missing worker source: {source_path}")
    source = source_path.read_bytes()

    if not args.dry_run and not args.token:
        raise SystemExit("set CLOUDFLARE_API_TOKEN or pass --token")
    if args.dry_run:
        upload(None, "dry-run", args.name, source, args.api_base, True)
        return EXIT_OK

    account = resolve_account(args.token, args.account, args.api_base)
    try:
        upload(args.token, account, args.name, source, args.api_base, False)
    except ApiError as error:
        if error.status in (401, 403):
            raise SystemExit(f"{error}\nthe token needs Workers Scripts: Edit on that account")
        raise SystemExit(str(error))
    print(f"uploaded {args.name} ({len(source)} bytes) to account {account}")

    subdomain = account_subdomain(args.token, account, args.api_base)
    if subdomain is None:
        if not args.subdomain:
            print("this account has no workers.dev subdomain yet.")
            print("re-run with --subdomain <name>, or set one in the dashboard, then deploy again.")
            return EXIT_UNFINISHED
        subdomain = create_subdomain(args.token, account, args.subdomain, args.api_base)
        print(f"created workers.dev subdomain {subdomain}")
    enable_script_subdomain(args.token, account, args.name, args.api_base)

    base = f"https://{args.name}.{subdomain}.workers.dev/pximg"
    print(f"relay base: {base}")
    print("hakimi setting:")
    print("  " + " ".join(hakimi_command(base)))

    if args.apply:
        applied, reason = apply_to_hakimi(base)
        if applied:
            print("written to the hakimi config; restart the proxy to use it")
        else:
            print(f"not written automatically: {reason}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
