# Design

The choices convesso is built on, and the reasons for them. The code cites these sections as
`DESIGN.md §4`; the numbers stay stable because they are cited. The bytes on the wire are in
[PROTOCOL.md](PROTOCOL.md).

convesso connects two devices that know each other's public key. The connection is encrypted end
to end. It goes directly when the network allows it, and through a relay when it does not. While
nobody has anything to say, it tries to send nothing at all. The same core is meant to run on a
server and on a 32-bit microcontroller.

The name is Italian for *convex*: a set is convex when the straight line between any two of its
points stays inside it. Finding that straight line between two nodes is what the library tries
to do.

## 1. Three goals

Most decisions below come from one of these three goals. When they pull in different directions,
we look for a design that keeps all three rather than trading one away.

- **Sound security**, from established constructions and audited code (§3).
- **Silence at rest.** Nothing is sent periodically unless it is declared and measured (§4).
- **A core small enough for a 32-bit microcontroller**: Cortex-M, RISC-V, ESP32 class. 8-bit
  devices are out of scope.

## 2. The core does no input or output

The protocol lives in `convesso-core`, a set of state machines: bytes and the current time go in,
bytes and the next deadline come out.

- **No sockets, no threads, no async runtime.** The core is `no_std`. Whoever embeds it owns the
  network, and the core makes the protocol's decisions.
- **No allocator.** The core does not ask for memory. Its tables (sessions, known peers, pending
  handshakes) are supplied by the integrator through a storage configuration: fixed capacity on a
  microcontroller (`Mcu`), growable on a server (`Server`, behind the `alloc` feature). An
  integrator who needs other sizes derives a configuration from either, naming only what changes
  (`convesso_core::profile!`, and `convesso_stream::config!` for the stream layer's buffers). When
  a table is full, the core returns a named error instead of growing.
- **Time is passed in.** The core does not read a clock. Every call takes "now", and every poll
  returns the next deadline. This lets the tests drive every timer with a virtual clock, and lets
  a microcontroller drive the core from its own timer.
- **Decoders are written not to panic.** Any bytes from the network give a result or an error.
  A decoder does not panic, allocate without a bound, or read beyond its input; fuzzing checks
  this (§9).

The crates are layered so that a microcontroller links only what it needs:

| Crate | What it is |
|---|---|
| `convesso-core` | the protocol: handshake, sessions, relay client, direct paths |
| `convesso-stream` | optional reliable messages (§8); `no_std`, no allocator needed |
| `convesso-relay` | the relay server's logic, without I/O |
| `convesso-tokio` | the driver for servers, desktops and phones, and the `convesso-relay` binary |
| `convesso-embassy` | the driver for microcontrollers |

## 3. Cryptography

- **Established constructions only.** No primitive is written by hand, and the handshake is a
  published pattern: one Noise instance, `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`.
- **No negotiation.** A wire version runs exactly one Noise instance. A version an endpoint does
  not speak is refused with an explicit message, so the caller can tell what went wrong.
- **An identity is a key.** An endpoint is its Ed25519 public key. There is no certificate
  authority, account or name service in the library: an application decides which keys it trusts.
- **Everything after the handshake is encrypted and authenticated**, with forward secrecy and
  protection against replay. A packet is not trusted because of the address it came from.
- **Keys are short-lived.** A key pair is renewed after 120 seconds of use and deleted after 180.
  A device that slept runs a fresh handshake when it wakes, in about one round trip.

The primitives come from widely used crates, audited where an audit exists, and each is kept
above the version that fixes its known advisories:

| Primitive | Crate |
|---|---|
| X25519 | `x25519-dalek` over `curve25519-dalek` |
| ChaCha20-Poly1305, XChaCha20-Poly1305 | `chacha20poly1305` |
| BLAKE2s | `blake2` |
| HMAC, for Noise's key derivation | `hmac` |

The official test vectors of every primitive run on every target, the embedded ones included. The
handshake is compared byte for byte with `snow`, an audited Noise implementation. `cargo-deny`
fails the build on any dependency with a published advisory.

convesso itself has not been audited yet. We plan an external audit before version 1.0, and until
then it should be treated as young code.

## 4. Silence at rest

Keeping a connection "alive" usually means sending something every so often, whether or not
anyone has anything to say. On a battery-powered device, or on a metered link, that cost adds up.
convesso tries to avoid it.

- **Every timer that sends a packet is documented** next to it in the code, with its interval and
  what would break without it.
- **With no session in use, one thing may recur:** a device that asked to stay reachable through a
  relay sends one keep-alive a minute on its TCP link, about 4.6 MB a month. Without it, the NAT in
  front of the device would forget the link, and the device could no longer be reached.
- **Everything else happens on use.** Key renewals, the search for a direct path and the checks of
  that path are all caused by traffic. A session nobody uses lets its keys expire and becomes
  *dormant*: it sends nothing and sets no timer. The next datagram reopens it.
- **Traffic at rest is measured.** The tests run an idle month on a virtual clock and count what
  was sent.

This has a cost you may notice: after a pause, the first packet may go through the relay again
while the direct path is checked (§7). It is the price of not keeping a hole open in the NAT.

## 5. Drivers carry out the core's decisions

A driver owns the sockets, the clock and the random generator, and leaves the protocol's decisions
to the core.

- It hands the core every packet its sockets receive, with where it came from.
- It sends what the core outputs, on the path the core names.
- It opens and closes the relay's TCP link when the core asks, and reports what happened.
- It wakes the core at each deadline.

The decisions themselves (which path a packet takes, when to retry, how long to back off, when a
link is dead) are made in the core. This keeps the tokio driver and the embedded driver behaving
alike, and leaves a new driver less room for protocol mistakes.

A driver uses **one UDP socket** for the relay and for peers alike, so that the address the relay
sees is the address peers will reach.

A driver **never waits on the application**, and never stops reading its socket or the relay link
for it: one part of an application that does not read must not hold back another (§10). Its timers,
acknowledgements, keep-alives and commands go on whatever the application reads.

- **A datagram** for a context whose event stream has no room is dropped and counted. For its
  sender that is a loss on the network, which datagrams already expect.
- **Events without data** wait aside while their stream is full, one per context, peer and kind
  (for the node's own events, one per kind), the latest replacing the earlier: an application that
  reads late sees the latest state of each peer and of the relay, not every step.
- **Reliable messages** wait in their channel while their context's stream is full: its window
  closes, and only their sender waits (§8).

An embedded device is given its identity when it is made, as a 64-byte record, and takes its
randomness from the chip's hardware generator. If the generator does not work, the driver does not
start.

## 6. The relay

Two devices behind NATs often cannot reach each other at first. A relay helps them meet.

- **It forwards sealed packets between keys.** The relay cannot read, forge or alter what it
  carries. It does learn which keys use it and which pairs talk, but not what they say.
- **Its key is pinned.** A client is given the relay's public key, and accepts no other relay in
  its place. The relay is reached through an ordinary convesso session, so an impostor on the
  network fails the handshake.
- **TCP keeps a device reachable, UDP carries the traffic.** A resting device keeps one TCP link,
  through which the relay can wake it. Active traffic moves to UDP as soon as UDP is seen to work.
- **A device that wakes reaches a peer in one datagram.** The first packet for the peer travels
  inside the handshake with the relay.
- **The relay tells a client its public address,** inside their session, when it changes, so no
  separate address probes are needed.
- **The relay does not wait on a slow recipient.** Each client has limits; a packet beyond them,
  or for a recipient whose queue is full, is dropped.
- **A client backs off until it is registered.** A link attempt that ends before the client is
  registered on it waits for a backoff of 1 to 60 seconds, with jitter. That covers a link not
  opened, an opening that hangs, a link that dies, and a relay session the relay refuses or does
  not answer. A relay shedding load is thus asked at most once a minute, never hammered. Only a
  link the client was registered on is replaced at once.
- **The application knows whether its relay is available.** It is told when the client is
  registered, and each time an attempt ends or a registered link is lost, with the reason.

## 7. Paths

- **The relay first, then a direct path.** A session opens through the relay. The two sides
  exchange the addresses each might be reached at, and probe them at the same moment.
- **A path is used only once it has been seen to work both ways:** an answer to a probe came back
  from that address.
- **The best working path is preferred:** an address on the same local network, then IPv6, then
  IPv4, and the relay when there is none.
- **A direct path is trusted for 15 seconds after the last packet on it.** After a longer pause,
  the next packet goes through the relay, which still works, while one probe checks the direct
  path. If the path answers, the packets after it go directly again.
- **No port prediction.** When a NAT gives a different port to each destination, the session stays
  on the relay rather than trying to guess ports.
- **An application can exclude address ranges,** such as those of its own tunnels, so that a path
  never loops through them.

## 8. Reliable messages

The core carries datagrams: small, unordered, and possibly lost. Many applications also need
messages that arrive whole and in order. That is `convesso-stream`, kept outside the core so that
a device that does not need it does not carry it.

- **Standard algorithms:** the retransmission timeout of RFC 6298, NewReno congestion control
  (RFC 5681, RFC 6582), selective acknowledgements (RFC 6675). Only the frame format is new.
- **One ordered channel per session.** A message arrives whole, once and in order, or the channel
  is reset, with one event on each side.
- **The reader decides how much each peer may hand it.** With delivery credit, a channel hands out
  only as many bytes as its reader granted, so a reader that stops taking one peer's messages holds
  back that peer's sender alone, through the channel's own window. A reader that gives a channel up
  resets it on its side, and the sender is told. The tokio driver builds a receiver per peer on
  this, for the contexts that ask for it.
- **Each context may take smaller messages** than the configuration's largest: its channels
  advertise that size, refuse a larger one from the application, and reset a peer that sends one.
  The buffers stay the configuration's.
- **Datagrams do not wait for messages.**
- **Quiet at rest:** with everything acknowledged, the channel sets no timer.

## 9. How it is checked

- **A deterministic simulator** runs the core with a virtual clock, loss, reordering, duplication
  and NATs of each behaviour.
- **Every decoder is fuzzed,** and the fuzz targets run in CI (`fuzz/`).
- **Test vectors are committed** and run on every target: on the host, and under QEMU for ARM
  Cortex-M and RISC-V (`firmware/`). They are produced or checked by implementations independent
  of convesso's own code, so a disagreement points to a bug on one side.
- **Flash and RAM are budgeted.** The reference firmware is built for both embedded targets on
  every change, and compared with `footprint-budget.toml`. A change that grows either raises the
  budget in the same diff, where a reviewer can see it.
- **A check that the core needs no allocator** runs on every change.
- **Every change reaches `main` through a pull request,** checked as merged with `main`. Each
  check runs when the files it covers change: the host checks always, the embedded ones for what
  the firmware links, the fuzz targets of the crates that changed. Everything runs every week and
  before a release.

## 10. Contexts

A **context** is an application protocol, named by the application: a chat, a file transfer, a
sensor's readings. Every handshake is bound to one, through the Noise prologue (`PROTOCOL.md §3`),
so a session in one context is never a session in another, and a peer that dials a context the node
does not serve meets silence, as a stranger does.

- **A node serves contexts while it runs.** It starts serving none. The application opens a
  context, gets a handle for it, and closes it by dropping the handle: a library started later, or
  a feature switched on at runtime, takes its protocol without restarting the node, and a library
  that stops releases it. Closing a context closes its sessions, each with one authenticated close.
- **Each context has its own access:** a policy that admits peers, one peer it is bound to, or
  none, when the application only dials in it. Changing the access judges again the sessions this
  side accepted in that context, and closes those no longer admitted; sessions this side dialled go
  on, since access governs who may reach the node.
- **Each handle sees its context alone:** its peers' connections, datagrams, messages and closes.
  Two libraries on one node do not see each other's peers, and one that does not read holds back
  neither the other nor the node (§5). The node's own events (the relay's availability, the
  address it is seen at) have a stream of their own.
- **How many contexts** a node serves is its storage configuration's, like its other tables
  (§2): 4 on the reference microcontroller configuration, the relay's included; as memory allows
  on a server.

**Names** are bytes, up to 32, and nothing enforces their form. The convention is that of ALPN,
`organisation/protocol/version`, such as `example.org/chat/1`, so that two libraries do not pick
the same name by chance.

**Versions** are contexts: a protocol that changes incompatibly takes a new name. To migrate, a
node serves both versions for as long as old peers remain, and a dialer tries the newer first,
falling back to the older when the newer meets silence. A context is not negotiated with the peer:
a dialer names the one it wants.
