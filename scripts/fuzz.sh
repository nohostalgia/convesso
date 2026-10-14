#!/bin/sh
# Runs every fuzz target for a bounded time:
#
#   sh scripts/fuzz.sh [seconds per target, default 60]
#
# Needs cargo-fuzz and the nightly toolchain pinned in fuzz/rust-toolchain.toml.
# Exits non-zero as soon as a target finds a crash; libFuzzer leaves the input
# that caused it under fuzz/artifacts/.
set -eu

seconds="${1:-60}"
cd "$(dirname "$0")/../fuzz"
for target in $(cargo fuzz list); do
    echo "==> fuzz $target for ${seconds}s"
    cargo fuzz run "$target" -- -max_total_time="$seconds"
done
