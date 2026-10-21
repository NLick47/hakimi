#!/usr/bin/env python3
"""Exercise every CA outcome without touching the real trust store.

The desktop app drives the local CA through the `security` CLI. This harness
puts a fake `security` first on PATH and runs the real `hakimi ca ...` commands,
so the Rust state machine, rollback and logging are tested end to end while the
actual keychain stays untouched.

Scenarios: success, cancel (exit 1), cancel (exit 0), wrong password, import
without trust, trust that lands late, uninstall, and uninstall of a missing CA.

Usage: python3 scripts/ca_scenarios.py [--bin target/debug/hakimi]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

FAKE_SECURITY = r'''#!/usr/bin/env python3
import json, os, subprocess, sys

state_path = os.environ["FAKE_CA_STATE"]
cert_path = os.environ["FAKE_CA_CERT"]


def fingerprint():
    """The real fingerprint of the temporary CA, so the app's hash check passes."""
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-fingerprint", "-sha1"],
            capture_output=True, text=True, check=True,
        ).stdout
        return out.strip().split("=")[-1].replace(":", "").upper()
    except Exception:
        return ""


scenario = os.environ.get("FAKE_CA_SCENARIO", "ok")
try:
    with open(state_path) as handle:
        state = json.load(handle)
except FileNotFoundError:
    state = {"imported": False, "trusted": False, "verify_calls": 0, "delete_calls": 0}


def save():
    with open(state_path, "w") as handle:
        json.dump(state, handle)


args = sys.argv[1:]
command = args[0] if args else ""

if command == "find-certificate":
    if state["imported"]:
        print("SHA-1 hash: " + fingerprint())
        print('keychain: "/Users/test/Library/Keychains/login.keychain-db"')
    save()
    sys.exit(0)

if command == "verify-cert":
    state["verify_calls"] += 1
    if not state["trusted"] and scenario == "delayed_trust" and state["verify_calls"] >= 3:
        state["trusted"] = True
    save()
    if state["trusted"]:
        sys.exit(0)
    print("Cert Verify Result: CSSMERR_TP_NOT_TRUSTED", file=sys.stderr)
    sys.exit(1)

if command == "add-trusted-cert":
    # `security` imports the certificate before it asks for authorization.
    state["imported"] = True
    # delayed_trust keeps trust unset here so the verify loop has to retry.
    state["trusted"] = scenario == "ok"
    save()
    if scenario == "cancel_exit1":
        print("SecTrustSettingsSetTrustSettings: The authorization was canceled by the user.", file=sys.stderr)
        sys.exit(1)
    if scenario == "cancel_exit0":
        print("User canceled the operation.", file=sys.stderr)
        sys.exit(0)
    if scenario == "wrong_password":
        print("SecKeychainItemImport: The user name or passphrase you entered is not correct.", file=sys.stderr)
        sys.exit(1)
    # imported_untrusted: command "succeeds" but trust never lands.
    sys.exit(0)

if command == "delete-certificate":
    state["delete_calls"] += 1
    wants_trust = "-t" in args
    if scenario == "delete_fails" or not state["imported"]:
        save()
        print("Unable to delete certificate matching the given hash", file=sys.stderr)
        sys.exit(1)
    state["imported"] = False
    if wants_trust:
        state["trusted"] = False
    save()
    sys.exit(0)

sys.exit(0)
'''


class Scenario:
    def __init__(self, name, command, scenario, installed, trusted, expect_ok, expect_installed):
        self.name = name
        self.command = command
        self.scenario = scenario
        self.installed = installed
        self.trusted = trusted
        self.expect_ok = expect_ok
        self.expect_installed = expect_installed


SCENARIOS = [
    Scenario("install succeeds", "install", "ok", False, False, True, True),
    Scenario("install cancelled (exit 1)", "install", "cancel_exit1", False, False, False, False),
    Scenario("install cancelled (exit 0)", "install", "cancel_exit0", False, False, False, False),
    Scenario("wrong keychain password", "install", "wrong_password", False, False, False, False),
    Scenario("imported but never trusted", "install", "imported_untrusted", False, False, False, False),
    Scenario("trust lands late (retry)", "install", "delayed_trust", False, False, True, True),
    Scenario("uninstall succeeds", "uninstall", "ok", True, True, True, False),
    Scenario("uninstall when missing", "uninstall", "ok", False, False, False, False),
]


def run(binary, scenario):
    workdir = tempfile.mkdtemp(prefix="hakimi-ca-")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir, exist_ok=True)
    security = os.path.join(bindir, "security")
    with open(security, "w") as handle:
        handle.write(FAKE_SECURITY)
    os.chmod(security, 0o755)

    state_path = os.path.join(workdir, "state.json")
    with open(state_path, "w") as handle:
        json.dump(
            {
                "imported": scenario.installed,
                "trusted": scenario.trusted,
                "verify_calls": 0,
                "delete_calls": 0,
            },
            handle,
        )

    data_dir = os.path.join(workdir, "data")
    env = dict(os.environ)
    env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
    env["FAKE_CA_STATE"] = state_path
    env["FAKE_CA_CERT"] = os.path.join(data_dir, "ca", "ca.pem")
    env["FAKE_CA_SCENARIO"] = scenario.scenario

    proc = subprocess.run(
        [binary, "--data-dir", data_dir, "ca", scenario.command],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )

    with open(state_path) as handle:
        state = json.load(handle)
    log_path = os.path.join(data_dir, "logs", "hakimi.log")
    log = open(log_path).read() if os.path.exists(log_path) else ""

    shutil.rmtree(workdir, ignore_errors=True)
    return proc, state, log


def status_installed(proc):
    """Read `installed` from the printed CaStatus JSON, if the command succeeded."""
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)["installed"]
    except (json.JSONDecodeError, KeyError):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", default="target/debug/hakimi")
    args = parser.parse_args()

    failures = 0
    print(f"{'scenario':32} {'command':10} {'ok':6} {'installed':10} checks")
    for scenario in SCENARIOS:
        proc, state, log = run(args.bin, scenario)
        ok = proc.returncode == 0
        installed = status_installed(proc)

        checks = []
        checks.append(("exit", ok == scenario.expect_ok))
        if scenario.expect_ok:
            checks.append(("installed", installed == scenario.expect_installed))
        # A failed install must not leave an imported certificate behind.
        if scenario.command == "install" and not scenario.expect_ok:
            checks.append(("rolled back", state["imported"] is False))
        if scenario.command == "uninstall" and scenario.expect_ok:
            checks.append(("trust cleared", state["trusted"] is False))
        if scenario.scenario == "delayed_trust":
            checks.append(("retried verify", state["verify_calls"] >= 3))
        if scenario.command == "uninstall" and scenario.expect_ok:
            checks.append(("used -t", "delete-certificate" in log))

        bad = [name for name, passed in checks if not passed]
        failures += bool(bad)
        detail = " ".join(f"{name}={'ok' if passed else 'FAIL'}" for name, passed in checks)
        print(
            f"{scenario.name:32} {scenario.command:10} {str(ok):6} "
            f"{str(installed):10} {detail}"
        )
        if bad:
            print("  stderr:", proc.stderr.strip().replace("\n", " ")[:300])

    print()
    print(f"{len(SCENARIOS) - failures}/{len(SCENARIOS)} scenarios passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
