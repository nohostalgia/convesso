# Contributing to convesso

Thanks for looking. A few things are worth knowing before you open a pull request.

## The contributor licence agreement

convesso is published under the AGPL-3.0, and the project also wants to be able to offer it under
other terms, for example a commercial licence for a company that can't ship AGPL code. That's only
possible if the project has permission to relicense every line in it, yours included.

So before your first pull request is merged, you'll be asked to sign the [CLA](CLA.md). A bot
comments on the pull request with a link, and signing takes a minute. You keep the copyright on what
you write. The CLA grants the project a licence to it, it doesn't take it from you. You sign once,
not per pull request.

## Before a big change

Open an issue or a discussion first, so nobody spends a week on something that won't be merged.
That matters most for the protocol. The bytes in [PROTOCOL.md](PROTOCOL.md), and the test vectors
under `crates/convesso-core/vectors/` that fix them, are what two devices agree on. Changing one is
a protocol change, and two versions stop talking to each other.

The same goes for the three things convesso never trades away: security at least equal to
WireGuard's, a device at rest that sends nothing, and a core that runs on a 32-bit microcontroller
without an allocator. [DESIGN.md](DESIGN.md) says why.

## Building and testing

You need [rustup](https://rustup.rs/). `rust-toolchain.toml` pins the Rust every build uses, and
rustup installs it the first time you run `cargo` here. Before you push:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
python3 scripts/check-public.py
```

Clippy runs with the workspace's lints, which CI turns into errors: no `unwrap`, `expect` or
`panic!`, and no unchecked indexing outside tests. Network behaviour is tested in a deterministic
simulator with a virtual clock (`crates/convesso-relay/src/tests/`), so a test about a minute of
traffic takes milliseconds.

A change to `convesso-core`, `convesso-stream` or `convesso-embassy` can grow the firmware. Build
the reference firmware for both embedded targets and measure it:

```sh
cd firmware
for target in thumbv7em-none-eabihf riscv32imc-unknown-none-elf; do
    cargo build --release --target "$target"
    cargo build --release --target "$target" --features stream --bin reference-stream
done
cd .. && python3 scripts/footprint.py
```

If it grows, `python3 scripts/footprint.py --record` raises `footprint-budget.toml`. Commit that in
the same pull request, where a reviewer can see it.

## What CI checks

Every pull request runs [`ci.yml`](.github/workflows/ci.yml), and its jobs are required: a pull
request with one of them red isn't merged. Each job runs when the files it checks changed.

| Job | What it runs |
|---|---|
| `checks` | formatting, clippy with warnings as errors, the tests, `scripts/check-public.py`, and [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) against [`deny.toml`](deny.toml): RustSec advisories, minimum versions of the cryptographic crates, licences, and crates.io as the only source |
| `secrets` | [`gitleaks`](https://github.com/gitleaks/gitleaks) on the tree, and on every commit the pull request adds |
| `embedded` | the core and the embedded driver built for ARM Cortex-M and RISC-V without an allocator, the test vectors under QEMU, and the firmware against `footprint-budget.toml` |
| `fuzz` | every fuzz target of the crates that changed, 60 seconds each |

A new dependency has to come from crates.io under a licence `deny.toml` allows. If it needs one that
isn't there, say so in the pull request: the list is short on purpose, and every entry is compatible
with the AGPL. A cryptographic dependency follows the rule in [DESIGN.md](DESIGN.md) §3. A test
string that looks like a secret and isn't takes an inline `gitleaks:allow` comment.

## What a good pull request looks like here

- **One change, explained.** Say in the title and description what changed and why.
- **Tests for behaviour.** If it changes what the library does, a test should fail without it.
- **Comments say why.** The code around you explains the reasons for its decisions, and yours
  should too. A comment that leans on the design cites `DESIGN.md §N` or `PROTOCOL.md §N`, and
  `scripts/check-public.py` checks that the section exists. Match the style of the file you're in.
- **English** for code, comments and documentation.

## Your commits are public

The name and email on your commits are visible to anyone. If you'd rather not publish your email,
GitHub gives you a `noreply` address under *Settings → Emails*.

## Security issues

Not here: see [SECURITY.md](SECURITY.md).
