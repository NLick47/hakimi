#!/usr/bin/env python3
"""Validate a client release version and, optionally, write it into Cargo.toml.

Usage:
    python3 scripts/ci/version.py 0.3.0
    python3 scripts/ci/version.py --apply 0.3.0

The version must be SemVer ``MAJOR.MINOR.PATCH`` with an optional
``-prerelease`` / ``+build`` suffix. A leading ``v`` is accepted so manual
runs can paste a tag verbatim.

``--apply`` only rewrites the workspace ``[workspace.package] version`` used by
the desktop/Android clients. The proxy core keeps its own version in
``crates/hakimi-core/Cargo.toml`` and is intentionally not touched.

The last line printed is the Android versionCode. It is derived as
``MAJOR * 1_000_000 + MINOR * 1_000 + PATCH`` (minor and patch must be < 1000).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NoReturn

REPO_ROOT = Path(__file__).resolve().parents[2]
CARGO_TOML = REPO_ROOT / "Cargo.toml"

SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\."
    r"(?P<minor>0|[1-9]\d*)\."
    r"(?P<patch>0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?"
    r"(?:\+[0-9A-Za-z.-]+)?$"
)

MAX_VERSION_CODE = 2_100_000_000


def fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_version(raw: str) -> tuple[str, int]:
    version = raw.strip()
    if version.startswith("v"):
        version = version[1:]

    match = SEMVER_RE.fullmatch(version)
    if match is None:
        fail(
            f"invalid version {raw!r}; expected MAJOR.MINOR.PATCH, "
            "e.g. 0.3.0 or 0.3.0-test.1"
        )

    major = int(match.group("major"))
    minor = int(match.group("minor"))
    patch = int(match.group("patch"))
    if minor > 999 or patch > 999:
        fail("minor and patch must be between 0 and 999")

    version_code = major * 1_000_000 + minor * 1_000 + patch
    if version_code > MAX_VERSION_CODE:
        fail(f"versionCode {version_code} exceeds Android's limit {MAX_VERSION_CODE}")

    return version, version_code


def apply_version(version: str) -> None:
    text = CARGO_TOML.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    section = None
    replaced = False

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped
            continue
        if section != "[workspace.package]":
            continue
        if re.match(r"^version\s*=", line):
            newline = "\n" if line.endswith("\n") else ""
            lines[index] = f'version = "{version}"{newline}'
            replaced = True
            break

    if not replaced:
        fail('could not find version = "..." under [workspace.package] in Cargo.toml')

    updated = "".join(lines)
    if updated != text:
        CARGO_TOML.write_text(updated, encoding="utf-8")
        print(f"updated {CARGO_TOML.relative_to(REPO_ROOT)} -> {version}", file=sys.stderr)


def main(argv: list[str]) -> int:
    args = argv[1:]
    apply = False
    if args and args[0] == "--apply":
        apply = True
        args = args[1:]

    if len(args) != 1:
        fail("usage: version.py [--apply] VERSION")

    version, version_code = parse_version(args[0])
    if apply:
        apply_version(version)

    print(version_code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
