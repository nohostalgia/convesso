#!/bin/sh
# Runs fuzz targets for a bounded time each: every target, or those named.
#
#   sh scripts/fuzz.sh [seconds per target, default 60] [target...]
#
# Needs cargo-fuzz and the nightly toolchain pinned in fuzz/rust-toolchain.toml.
# Exits non-zero as soon as a target finds a crash; libFuzzer leaves the input
# that caused it under fuzz/artifacts/. A name that is not a target is an
# error, so a list that goes stale fails rather than fuzzing nothing.
set -eu

seconds="${1:-60}"
[ "$#" -gt 0 ] && shift
cd "$(dirname "$0")/../fuzz"
all="$(cargo fuzz list)"
if [ "$#" -eq 0 ]; then
    set -- $all
fi
for target in "$@"; do
    if ! printf '%s\n' "$all" | grep -qx "$target"; then
        echo "no fuzz target named $target" >&2
        exit 1
    fi
done
for target in "$@"; do
    echo "==> fuzz $target for ${seconds}s"
    cargo fuzz run "$target" -- -max_total_time="$seconds"
done
