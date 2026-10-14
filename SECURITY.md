# Security

## Reporting a vulnerability

Please report it privately, through GitHub's "Report a vulnerability" on this repository
(Security, then Advisories). Do not open a public issue for it.

Say what you found, how to reproduce it, and which commit you looked at. You will get an answer,
and credit in the advisory if you want it.

## What to expect from this code

- **It has not been audited.** An external audit is planned before version 1.0. Until then, do not
  rely on convesso where a failure would cause harm.
- **The cryptography is not ours.** The primitives come from the RustCrypto and dalek crates, and
  the handshake is one Noise instance, `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, checked byte for
  byte against `snow`. See [DESIGN.md](DESIGN.md) §3.
- **The wire format is public,** in [PROTOCOL.md](PROTOCOL.md), with the test vectors that fix it.

## What counts

Anything that lets someone without the right keys read, forge, replay or redirect traffic; make an
endpoint or a relay crash, hang or use memory without a bound from the network; make an endpoint
answer a stranger; or make an idle device send traffic.

A relay learns which keys use it and which pairs of keys talk. That is by design (DESIGN.md §6),
and is not a vulnerability. That a relay could read or alter what it carries would be.
