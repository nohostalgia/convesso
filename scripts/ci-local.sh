#!/bin/sh
# Runs the CI of .github/workflows/ci.yml locally, in a Linux container, until
# the repository has a remote where GitHub can run it:
#
#   sh scripts/ci-local.sh
#
# Needs Docker. The working tree is mounted read-only and copied into the
# container, so nothing here is modified; the cargo registry is kept in a named
# volume (convesso-ci-cargo), and cargo-fuzz in another (convesso-ci-tools), so
# that later runs do not download or build them again.
#
# The steps are those of the workflow's three jobs, in the same order: `checks`
# (what the files cite, formatting, clippy, tests, dependency policy),
# `embedded` (embedded builds, the no-allocator check, the vectors under QEMU,
# the footprint budget) and `fuzz` (every fuzz target for FUZZ_SECONDS, default
# 60). Exits non-zero at the first failing step.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
# Docker on Windows wants a Windows path for the bind mount.
if command -v cygpath >/dev/null 2>&1; then
    root="$(cygpath -m "$root")"
fi

CARGO_DENY_VERSION=0.20.2
CARGO_FUZZ_VERSION=0.13.2
FUZZ_SECONDS="${FUZZ_SECONDS:-60}"

MSYS_NO_PATHCONV=1 exec docker run --rm \
    -v "$root:/src:ro" \
    -v convesso-ci-cargo:/usr/local/cargo/registry \
    -v convesso-ci-tools:/tools \
    -e CARGO_DENY_VERSION="$CARGO_DENY_VERSION" \
    -e CARGO_FUZZ_VERSION="$CARGO_FUZZ_VERSION" \
    -e FUZZ_SECONDS="$FUZZ_SECONDS" \
    rust:1.95 sh -euc '
step() { printf "\n==> %s\n" "$1"; }

step "copy the working tree"
mkdir /w && cd /src && tar --exclude=target -cf - . | tar -xf - -C /w && cd /w

step "install QEMU and cargo-deny"
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-system-arm qemu-system-misc python3 >/dev/null 2>&1
curl -sSfL "https://github.com/EmbarkStudios/cargo-deny/releases/download/$CARGO_DENY_VERSION/cargo-deny-$CARGO_DENY_VERSION-x86_64-unknown-linux-musl.tar.gz" \
    | tar -xzf - -C /usr/local/bin --strip-components=1 "cargo-deny-$CARGO_DENY_VERSION-x86_64-unknown-linux-musl/cargo-deny"

step "install the pinned toolchain"
rustup toolchain install >/dev/null 2>&1

# job: checks
step "checks: the repository explains itself"
python3 scripts/check-public.py
step "checks: formatting"
cargo fmt --all --check
(cd firmware && cargo fmt --check)
step "checks: clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings
step "checks: tests"
cargo test --workspace --all-features
step "checks: dependency policy"
cargo deny check advisories bans sources

# job: embedded
step "embedded: build the core, the embedded driver and the stream crate for the embedded targets"
for target in thumbv7em-none-eabihf riscv32imc-unknown-none-elf; do
    cargo build -p convesso-core --target "$target"
    cargo build -p convesso-embassy --target "$target"
    cargo build -p convesso-embassy --features stream --target "$target"
    cargo build -p convesso-stream --target "$target"
done
step "embedded: build the firmware"
(cd firmware && for target in thumbv7em-none-eabihf riscv32imc-unknown-none-elf; do
    cargo build --release --target "$target"
    cargo build --release --target "$target" --features stream --bin reference-stream
done)
step "embedded: clippy on the firmware"
(cd firmware && for target in thumbv7em-none-eabihf riscv32imc-unknown-none-elf; do
    cargo clippy --release --target "$target" -- -D warnings
    cargo clippy --release --target "$target" --features stream --bin reference-stream -- -D warnings
done)
step "embedded: a core or a stream crate that needs an allocator is refused"
sh scripts/check-no-alloc.sh thumbv7em-none-eabihf
sh scripts/check-no-alloc.sh riscv32imc-unknown-none-elf
step "embedded: official vectors under QEMU"
sh scripts/run-vectors-qemu.sh thumbv7em-none-eabihf
sh scripts/run-vectors-qemu.sh riscv32imc-unknown-none-elf
step "embedded: footprint within budget"
python3 scripts/footprint.py

# job: fuzz
step "fuzz: install cargo-fuzz and the pinned nightly"
[ -x /tools/bin/cargo-fuzz ] || cargo install --quiet --locked --root /tools "cargo-fuzz@$CARGO_FUZZ_VERSION"
export PATH="/tools/bin:$PATH"
(cd fuzz && rustup toolchain install >/dev/null 2>&1)
step "fuzz: every target for ${FUZZ_SECONDS}s"
sh scripts/fuzz.sh "$FUZZ_SECONDS"

printf "\nCI OK\n"
'
