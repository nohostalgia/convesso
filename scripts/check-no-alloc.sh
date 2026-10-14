#!/bin/sh
# Proves the no-allocator guarantee is enforced, not merely true today:
#
#   scripts/check-no-alloc.sh <target>
#
# Copies the workspace to a temporary directory, makes a crate depend on
# `alloc`, and builds the firmware that links it for <target>. That build MUST
# fail for want of a global allocator. If it succeeds, the firmware is no
# longer a check on the crate and the script fails. Two crates are checked:
# convesso-core, through the reference firmware, and convesso-stream (without
# its `alloc` feature), through `reference-stream`.
set -eu

target="${1:?usage: check-no-alloc.sh <target>}"
root="$(cd "$(dirname "$0")/.." && pwd)"

check() { # crate, cargo arguments of the firmware build
    crate=$1
    shift
    scratch="$(mktemp -d)"
    (cd "$root" && tar --exclude=target -cf - Cargo.toml rust-toolchain.toml crates firmware) \
        | tar -xf - -C "$scratch"
    printf '\nextern crate alloc;\n' >> "$scratch/crates/$crate/src/lib.rs"
    if output="$(cd "$scratch/firmware" && cargo build --release --target "$target" "$@" 2>&1)"; then
        rm -rf "$scratch"
        echo "FAIL: the firmware linked a $crate that depends on alloc, for $target" >&2
        exit 1
    fi
    rm -rf "$scratch"
    if ! printf '%s' "$output" | grep -q 'no global memory allocator found'; then
        echo "FAIL: the build failed for another reason than the missing allocator:" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
    echo "ok: a $crate depending on alloc is refused for $target"
}

check convesso-core
check convesso-stream --features stream --bin reference-stream
