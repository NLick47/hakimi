#!/usr/bin/env python3
"""Contract test for scripts/deploy_relay.py against a fake Cloudflare API.

Checks the multipart upload shape, the account/subdomain calls, and the base
URL the script prints. No network and no Cloudflare account involved.
"""
import json
import pathlib
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "scripts" / "deploy_relay.py"
WORKER = ROOT / "workers" / "pximg-relay" / "index.js"

ACCOUNT = "acc123"
SCRIPT = "hakimi-relay"
captured = {}


def parse_multipart(content_type, body):
    boundary = content_type.split("boundary=", 1)[1].encode()
    parts = {}
    for chunk in body.split(b"--" + boundary)[1:-1]:
        head, _, data = chunk.partition(b"\r\n\r\n")
        fields = {}
        for line in head.decode().split("\r\n"):
            if ":" in line:
                name, value = line.split(":", 1)
                fields[name.strip().lower()] = value.strip()
        disposition = fields.get("content-disposition", "")
        name = disposition.split('name="', 1)[1].split('"', 1)[0]
        parts[name] = {
            "filename": 'filename="' in disposition,
            "content_type": fields.get("content-type", ""),
            "data": data[: -len(b"\r\n")],
        }
    return parts


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/client/v4/accounts?"):
            self.reply(200, {"success": True, "result": [{"id": ACCOUNT, "name": "Demo"}]})
        elif self.path == f"/client/v4/accounts/{ACCOUNT}/workers/subdomain":
            if captured.get("subdomain_created"):
                self.reply(200, {"success": True, "result": {"subdomain": captured["subdomain"]}})
            else:
                self.reply(
                    404,
                    {"success": False, "errors": [{"code": 10007, "message": "no subdomain"}]},
                )
        else:
            self.reply(404, {"success": False, "errors": [{"code": 7003, "message": self.path}]})

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.path == f"/client/v4/accounts/{ACCOUNT}/workers/subdomain":
            captured["subdomain"] = json.loads(body)["subdomain"]
            captured["subdomain_created"] = True
            self.reply(200, {"success": True, "result": {"subdomain": captured["subdomain"]}})
            return
        if self.path == f"/client/v4/accounts/{ACCOUNT}/workers/scripts/{SCRIPT}":
            captured["parts"] = parse_multipart(self.headers["Content-Type"], body)
            self.reply(200, {"success": True, "result": {"id": SCRIPT}})
            return
        self.reply(404, {"success": False, "errors": [{"code": 7003, "message": self.path}]})

    def do_POST(self):
        if self.path == f"/client/v4/accounts/{ACCOUNT}/workers/scripts/{SCRIPT}/subdomain":
            captured["script_subdomain"] = True
            self.reply(200, {"success": True, "result": {"enabled": True, "previews_enabled": False}})
            return
        self.reply(404, {"success": False, "errors": [{"code": 7003, "message": self.path}]})


def run(*extra):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    api = f"http://127.0.0.1:{server.server_port}/client/v4"
    try:
        return subprocess.run(
            [
                sys.executable,
                str(DEPLOY),
                "--token",
                "test-token",
                "--account",
                ACCOUNT,
                "--name",
                SCRIPT,
                "--api-base",
                api,
                *extra,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        server.shutdown()


def check(label, condition, detail=""):
    if condition:
        print(f"ok   {label}")
        return 0
    print(f"FAIL {label} {detail}")
    return 1


def main():
    failures = 0
    first = run()
    failures += check("upload happens before any subdomain exists", first.returncode == 2, first.stdout)
    failures += check("unfinished run says how to finish", "--subdomain" in first.stdout)

    parts = captured.get("parts") or {}
    metadata = json.loads(parts.get("metadata", {}).get("data", b"{}"))
    module = parts.get("index.js", {})
    failures += check("metadata part is not a file", not parts.get("metadata", {}).get("filename", True))
    failures += check("main_module names the module part", metadata.get("main_module") == "index.js", metadata)
    failures += check("compatibility_date is pinned", metadata.get("compatibility_date") == "2026-01-01")
    failures += check(
        "module part uses the module content type",
        module.get("content_type") == "application/javascript+module",
        module.get("content_type"),
    )
    failures += check("module bytes match the source", module.get("data") == WORKER.read_bytes())

    second = run("--subdomain", "demo")
    failures += check("second run succeeds", second.returncode == 0, second.stdout + second.stderr)
    failures += check("subdomain was created", captured.get("subdomain") == "demo")
    failures += check("script subdomain enabled", captured.get("script_subdomain") is True)
    failures += check(
        "prints the relay base URL",
        "https://hakimi-relay.demo.workers.dev/pximg" in second.stdout,
        second.stdout,
    )
    failures += check(
        "prints the hakimi command",
        "hakimi config set advanced.imageRelays.0.base" in second.stdout,
    )
    if failures:
        print(f"\n{failures} check(s) failed")
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
