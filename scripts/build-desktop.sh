#!/usr/bin/env bash
# Build the desktop UI only (no CLI, no FFI) with the size-optimised profile.
#
# Usage:
#   ./scripts/build-desktop.sh
#   HAKIMI_TARGET=x86_64-pc-windows-gnu ./scripts/build-desktop.sh
#
# The resulting binary is copied to target/desktop/. Site icons are embedded
# in the executable, so no asset directory is needed next to it.
set -euo pipefail

cd "$(dirname "$0")/.."

profile="desktop-release"
target="${HAKIMI_TARGET:-}"

args=(build --profile "$profile" -p hakimi-ui)
if [[ -n "$target" ]]; then
    args+=(--target "$target")
fi

cargo "${args[@]}"

base="target"
if [[ -n "$target" ]]; then
    base="$base/$target"
fi

bin="$base/$profile/hakimi-ui"
if [[ "$target" == *windows* ]]; then
    bin="$bin.exe"
fi

if [[ ! -f "$bin" ]]; then
    echo "error: built binary not found: $bin" >&2
    exit 1
fi

size=$(wc -c < "$bin" | tr -d '[:space:]')
echo "built: $bin"
echo "size:  $size bytes"

# Cargo's strip=symbols should leave a release binary with almost no symbols.
nm_cmd="nm"
if [[ "$target" == *windows* ]] && command -v x86_64-w64-mingw32-nm >/dev/null 2>&1; then
    nm_cmd="x86_64-w64-mingw32-nm"
fi
if command -v "$nm_cmd" >/dev/null 2>&1; then
    syms=$("$nm_cmd" "$bin" 2>/dev/null | wc -l | tr -d '[:space:]' || true)
    echo "symbols: ${syms:-0}"
    if [[ -n "${syms:-}" ]] && (( syms > 1000 )); then
        echo "error: symbols were not stripped" >&2
        exit 1
    fi
fi

# A Windows UI build must use the GUI subsystem, otherwise a console window
# flashes on every launch.
if [[ "$target" == *windows* ]] && command -v x86_64-w64-mingw32-objdump >/dev/null 2>&1; then
    # Capture first: `objdump | grep -q` can trip pipefail when grep exits early.
    pe_info=$(x86_64-w64-mingw32-objdump -p "$bin")
    if [[ "$pe_info" != *"Windows GUI"* ]]; then
        echo "error: Windows binary is not using the GUI subsystem" >&2
        exit 1
    fi
    echo "subsystem: Windows GUI"
fi

out_dir="target/desktop"
mkdir -p "$out_dir"
cp "$bin" "$out_dir/"
echo "copied: $out_dir/$(basename "$bin")"
