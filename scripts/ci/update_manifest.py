#!/usr/bin/env python3
"""Build the update manifest attached to every GitHub Release.

The manifest is the only thing the desktop and Android update checkers read.
It deliberately contains versions and links only; release notes live in the
GitHub Release body, which is generated from CHANGELOG.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from version import parse_version  # noqa: E402


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--release-url", required=True)
    parser.add_argument("--desktop-version", required=True)
    parser.add_argument("--desktop-windows-asset", required=True)
    parser.add_argument("--desktop-macos-asset", required=True)
    parser.add_argument("--android-version", required=True)
    parser.add_argument("--android-apk-asset", required=True)
    parser.add_argument("--android-apk-armv7-asset", required=True)
    args = parser.parse_args(argv)

    release = args.release.strip()
    release_url = args.release_url.strip()
    if not release:
        fail("release tag is empty")
    if not release_url.startswith("https://github.com/"):
        fail("release URL must be a GitHub URL")

    desktop_version, _ = parse_version(args.desktop_version)
    android_version, android_version_code = parse_version(args.android_version)

    windows_asset = args.desktop_windows_asset.strip()
    macos_asset = args.desktop_macos_asset.strip()
    apk_asset = args.android_apk_asset.strip()
    apk_armv7_asset = args.android_apk_armv7_asset.strip()
    if not windows_asset or not macos_asset or not apk_asset or not apk_armv7_asset:
        fail("asset names must not be empty")

    manifest = {
        "schema": 1,
        "release": release,
        "desktop": {
            "version": desktop_version,
            "url": release_url,
            "assets": {
                "windows-x64": windows_asset,
                "macos-arm64": macos_asset,
            },
        },
        "android": {
            "version": android_version,
            "versionCode": android_version_code,
            "url": release_url,
            "assets": {
                "arm64": apk_asset,
                "armv7": apk_armv7_asset,
            },
        },
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
