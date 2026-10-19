# Protocol

The bytes convesso puts on the wire, in version 1. The code cites these sections as
`PROTOCOL.md §3`; the numbers stay stable because they are cited. The reasons behind the choices
are in [DESIGN.md](DESIGN.md).

Conventions:
- every multi-byte integer is little-endian;
- a table gives a packet from its first byte, with offsets and lengths in bytes;
- each section names the file of test vectors that fixes its bytes (§9). The vectors, not this
  text, are the reference: where they disagree, this document is wrong.

## 1. Every packet

**Byte 0 is the version**, in every packet of every version:

| Byte 0 | Meaning |
|---|---|
| `0x00` | the "version not supported" message, below |
| `0x01` to `0xFE` | a protocol version; this document describes `0x01` |
| `0xFF` | reserved, never sent |

An empty packet, or one that starts with `0xFF`, is dropped without an answer.

**A first contact** is the packet that opens a handshake. In every version it is at least 33 bytes
and ends with two 16-byte fields, `mac1` then `mac2`.

**`mac1` proves that the sender knows whom it is writing to.** With `A` the responder's 32-byte
address and `P` the packet of length `n`:

```text
key  = BLAKE2s-256("convesso-mac1" || A)
mac1 = BLAKE2s(key, 16 bytes)(P[0 .. n-32])
```

`"convesso-mac1"` is the 13 ASCII bytes `63 6f 6e 76 65 73 73 6f 2d 6d 61 63 31`. A responder
checks `mac1` first, in constant time. A packet whose `mac1` is wrong gets no answer and leaves no
state, so a sender that does not know an endpoint's address gets no answer from it.

**An unknown version is refused, not ignored.** A packet of a version the responder does not
speak, with a valid `mac1`, is answered with:

| Offset | Length | Content |
|---|---|---|
| 0 | 1 | `0x00` |
| 1 | 1 | `k`, how many versions follow, 1 to 15 |
| 2 | `k` | the versions spoken, strictly increasing |
| `2 + k` | 16 | the `mac1` of the packet being answered |

The answer is never longer than the packet it answers. An initiator acts on it only when the
echoed `mac1` is one it sent and is waiting on; it then reports the peer's versions, and never
retries with another version by itself.

Vectors: `wire-format.json`.

## 2. Identities

- **An address** is a 32-byte Ed25519 public key. It is what an application is given to reach a
  peer.
- **A peer id** is the X25519 public key converted from the address: the Montgomery
  `u = (1 + y) / (1 − y) mod 2^255 − 19` of the point the address encodes, as 32 bytes. It is what
  the handshake authenticates, and what an application admits, refuses and compares.
- The secret key is the X25519 scalar of the same Ed25519 key (RFC 8032 §5.1.5). It never signs.

An address is refused when its encoding is not canonical, is not a point of the curve, has small
order, or lies outside the prime-order subgroup. A static key received in a handshake is accepted
only in its one canonical form, for the same reason: each private key has exactly one peer id.

Vectors: `identity.json`.

## 3. The handshake

Version 1 runs `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` (Noise, revision 34), with the responder's
peer id as the pre-message.

**The prologue** binds the handshake to an application's *context*, a name of 0 to 32 bytes that
both sides must use:

```text
"convesso" (8 bytes: 63 6f 6e 76 65 73 73 6f) || 0x01 || L (1 byte) || context (L bytes)
```

The pre-shared key is the one the application holds for the peer, or 32 zero bytes.

**The first contact** is exactly 134 bytes:

| Offset | Length | Content |
|---|---|---|
| 0 | 1 | `0x01`, the version |
| 1 | 1 | `0x01`, first contact |
| 2 | 4 | the initiator's index |
| 6 | 32 | the initiator's ephemeral public key |
| 38 | 48 | the initiator's static public key, encrypted |
| 86 | 16 | the tag of the empty payload |
| 102 | 16 | `mac1` (§1) |
| 118 | 16 | `mac2` (§4), or zeros |

**A first contact may carry a payload** of 1 to 1,200 bytes, where the context allows it. Its type
byte is `0x05`, and the payload with its tag takes the place of the empty payload's tag, so the
packet is `134 + n` bytes. Such a payload is authenticated, but it can be replayed, and it loses
its secrecy if the responder's key is ever stolen; the application is told it is *unconfirmed*. The
relay uses it to deliver a first packet in one datagram (§6).

**The response** is exactly 61 bytes:

| Offset | Length | Content |
|---|---|---|
| 0 | 1 | `0x01`, the version |
| 1 | 1 | `0x02`, response |
| 2 | 4 | the responder's index |
| 6 | 4 | the initiator's index |
| 10 | 32 | the responder's ephemeral public key |
| 42 | 19 | the decision, encrypted: 3 bytes and a tag |

The decision is `00 00 00` to accept, or `01` and a 2-byte refusal code. Accepting and refusing
are the same length. Codes `0x0001` (capacity exhausted) and `0x0002` (busy) are the library's,
`0x0100` to `0xFFFF` the application's.

**Rules:**
- **Silence towards strangers.** A first contact with a wrong `mac1`, that does not decrypt under a
  context the responder serves, or with an unusable key, gets no answer and leaves no state.
- **The application admits.** Once a first contact passes every check, the application is asked
  whether to admit that peer id in that context. A refusal travels encrypted and authenticated.
- **A context can be bound to one peer.** Everyone else is then treated as a stranger.
- **The responder's result is pending** for 5 seconds. It becomes a session when the initiator's
  first transport packet arrives (§5), so a replayed first contact never displaces a session.
- **Retries.** An initiator sends a new first contact, with a fresh ephemeral key, 1, 3 and 7
  seconds after the first, and gives up at 15 seconds.
- **Channel binding.** Both sides expose the Noise handshake hash, 32 bytes, equal at both ends
  and different for every handshake.

Vectors: `cacophony-ikpsk2.json` (the official Noise vectors) and `handshake-v1.json` (whole
transcripts, each checked against `snow`).

## 4. Under load

A handshake costs the responder several Diffie-Hellman operations. Under a flood, it first makes
senders prove they can receive at the address they claim.

- **Load.** A responder counts the first contacts it processes in a token bucket. While the bucket
  is empty it is *under load*; otherwise `mac2` is ignored.
- **The cookie** is tied to where the packet came from:

  ```text
  cookie = BLAKE2s(secret, 16 bytes)(tag || source)
  ```

  `tag` is `0x01` for an IP address and port, `0x02` for a sender named by the relay. The secret
  is 32 random bytes, replaced every 120 seconds.
- **`mac2`** proves the sender received that cookie:
  `mac2 = BLAKE2s(cookie, 16 bytes)(P[0 .. n-16])`.
- Under load, a first contact with a valid `mac2` proceeds, at no more than 20 a second per
  source. One without it is answered with a cookie reply, and costs no Diffie-Hellman.

**The cookie reply** is exactly 62 bytes, never more than the packet it answers:

| Offset | Length | Content |
|---|---|---|
| 0 | 1 | `0x01`, the version |
| 1 | 1 | `0x03`, cookie reply |
| 2 | 4 | the initiator's index |
| 6 | 24 | a random nonce |
| 30 | 32 | the cookie, encrypted, and its tag |

The cookie is encrypted with XChaCha20-Poly1305 under
`key = BLAKE2s-256("convesso-cookie" || A)`, with the first contact's `mac1` as associated data.
`"convesso-cookie"` is the 15 ASCII bytes `63 6f 6e 76 65 73 73 6f 2d 63 6f 6f 6b 69 65`. An
initiator uses a cookie only from the responder it dialled, for 120 seconds, and never sends
sooner because of one.

A responder also remembers the ephemeral key of each first contact it processed for 5 seconds, and
drops one it has seen.

Vectors: `dos-v1.json`.

## 5. Sessions

**A transport packet** carries everything after the handshake:

| Offset | Length | Content |
|---|---|---|
| 0 | 1 | `0x01`, the version |
| 1 | 1 | `0x04`, transport |
| 2 | 4 | the receiver's index for the session |
| 6 | 8 | the counter |
| 14 | `1 + n + 16` | ChaCha20-Poly1305 of the inner type and `n` bytes of data, and its tag |

The key is the sender's, from the handshake. The nonce is 4 zero bytes and the counter. The 14
header bytes are the associated data. There is no padding: a packet is 31 bytes longer than its
data.

**The inner type** is the first decrypted byte:

| Inner type | Carries |
|---|---|
| `0x00` | a keepalive, with no data |
| `0x01` | a datagram: the application's bytes |
| `0x02` | a close, with a 2-byte code |
| `0x03` | candidates (§7) |
| `0x04` | a probe (§7) |
| `0x05` | a probe's answer (§7) |
| `0x06` | stream data (§8) |
| `0x07` | a stream acknowledgement (§8) |

Other values are reserved: such a packet is counted against replay, and its content ignored.

**Rules:**
- **Each packet is accepted once.** A receiver keeps the highest counter seen and a window below
  it (256 counters on a microcontroller, 8,192 on a server). A packet that is older, or already
  seen, is dropped.
- **Confirmation.** The responder starts using a handshake's keys when the initiator's first
  packet opens under them. An initiator with nothing to send confirms with a keepalive.
- **Renewal, only while sending.** Sending under keys older than 120 seconds starts a new
  handshake. Receiving never does. Keys are deleted 180 seconds after their handshake, or after
  2^60 packets.
- **Two key pairs.** A session sends with its current keys, and still receives with the previous
  ones, so packets in flight across a renewal are not lost.
- **Dormancy.** A session with no keys left sends nothing and waits for nothing. The next datagram
  starts a handshake and waits in a bounded queue (1,024 bytes on a microcontroller, 65,536 on a
  server); a datagram that does not fit is refused.
- **A session reopens only from an address,** since `mac1` needs the address. Sending by peer id
  works only while the session has keys.
- **Close** is one authenticated packet with a code. It is not retransmitted. Codes `0x0001` to
  `0x00FF` are the library's, `0x0100` to `0xFFFF` the application's, as for refusals; `0x0000` is
  not sent. `0x0001` is a close without a code: one asked with `0x0000`, or a context closed by
  dropping its handle (`DESIGN.md §10`).
- **A datagram too large for the path is refused,** never truncated.
- **The channel binding** of a session is that of the handshake that opened it, kept across
  renewals.

Vectors: `transport-v1.json`.

## 6. The relay

A client reaches a relay through an ordinary session (§3, §5) in the context `convesso-relay` (14
bytes: `63 6f 6e 76 65 73 73 6f 2d 72 65 6c 61 79`), towards the one relay whose address it was
given. That session is never shown to the application.

**Relay frames** are the data of that session's datagrams. The first byte is the type. A recipient
or a sender is the byte `0x01` followed by a 32-byte peer id.

| Type | Name | Direction | After the type byte | Length |
|---|---|---|---|---|
| `0x01` | forward | client to relay | recipient (33), packet (`m`) | `34 + m` |
| `0x02` | deliver | relay to client | sender (33), packet (`m`) | `34 + m` |
| `0x03` | not connected | relay to client | recipient (33) | 34 |
| `0x04` | register | client to relay | the client's address (32) | 33 |
| `0x05` | observed address | relay to client | link (`0x00` UDP, `0x01` TCP), family (`0x04` or `0x06`), address (4 or 16), port (2) | 9 or 21 |

A carried packet is 1 to 1,380 bytes. A frame that is malformed, or of an unknown type, is ignored.

**The TCP link** starts, in each direction, with a 9-byte preamble: `63 6f 6e 76 65 73 73 6f 01`,
the ASCII `convesso` and the framing version. Then each packet is sent as its length (2 bytes)
followed by its bytes. A length of 0 is the keep-alive. A wrong preamble, or a length above 1,500,
closes the link. The preamble's first byte is never `0x16`, the first byte of a TLS record, so a
relay can serve plain and TLS-wrapped links on one port.

**A TLS-wrapped link** (optional, for networks that let out only TLS) begins with the client's TLS
1.3 handshake (RFC 8446); the preamble and the packets then travel as TLS application data, exactly
as on a plain link. A relay tells the two apart by the first byte: `0x63` is a preamble, `0x16` a
TLS handshake, and anything else, or a TLS handshake that fails, closes the link with nothing sent.
**TLS authenticates nothing.** The client accepts any certificate, self-signed, for another name,
or presented by a proxy that inspects TLS; the relay is authenticated by its pinned key alone, in
the relay session. The client names the relay's host in the handshake (SNI) when it is a name, and
none when it is an IP address. A handshake that fails is a link that did not open, with its backoff.
Each keep-alive and its answer cost one TLS record: 22 bytes more each way.

**Rules:**
- **The relay names the sender itself.** A deliver carries the peer id that the sender's session
  authenticated, and the packet unchanged. The relay does not read or answer a carried packet.
- **End to end is untouched.** A client hands a delivered packet to its own endpoint as coming
  from that sender through the relay; every check of §3, §4 and §5 applies to it.
- **Not connected.** When the relay cannot reach a recipient, it tells the sender, at most once a
  second per pair. It is reported as information, not as the failure of a session.
- **No address is trusted before it is authenticated.** The relay records a client's address only
  from a packet that opened under that client's keys with a new counter. Until then it sends an
  address no more bytes than it received from it.
- **UDP for traffic, TCP for reachability.** UDP counts as *proven* for 15 seconds after an
  authenticated packet arrived over it. Each side uses UDP while it is proven, and the TCP link
  otherwise. A client on TCP also sends one packet every 10 seconds over UDP, to find out when UDP
  works again.
- **A wake in one datagram.** With no keys for the relay, a client sends a first contact whose
  payload is the forward. The relay does the same towards a resting client with a TCP link, whose
  address the client registered.
- **Observed address.** The relay tells a client the address it sees it at, when that changes, and
  tells nobody else.
- **Keep-alive.** A client keeping a TCP link sends one keep-alive when the link has been silent
  for a minute; the relay answers each. An answer missing for 20 seconds means the link is dead.
  A failed link is retried after 1 second, doubling up to 60, each wait lengthened at random by up
  to half.
- **One relay at a time.** A client may replace its relay, or remove it, while it runs. Everything
  of the old relay goes: its session, its link (closed without an unavailability event), and the
  public candidates it reported; the relay context is served to the new relay alone. Sessions with
  peers are untouched: one last heard through the relay goes on through the new one. Peers on
  different relays reach each other only directly; the new relay answers "not connected" for a
  peer still on the old one.

**Which path a packet takes** is decided by the client's core, in this order:
1. the session's direct path, when it is proven and fresh (§7);
2. the relay, with one probe on the direct path, when that path is proven but not fresh;
3. where the peer's newest packet came from, directly or through the relay: a packet that
   arrives after a newer one, late or reordered, does not move the session. After this
   endpoint's network changes, a direct source heard before is no longer used while a relay is
   pinned: the packets take the relay until the peer is heard again (§7);
4. with nothing heard yet: a dial's first attempt goes at once to every address hint the
   application gave (up to 8 per peer), and its later attempts to the relay; with no relay, every
   attempt goes to every hint; everything else goes through the relay;
5. with neither a hint nor a relay, the send fails with a "no path" error.

An answer goes back the way the packet came.

Vectors: `relay-v1.json`.

## 7. Direct paths

**Candidates** are the addresses a peer might reach an endpoint at: its interfaces' addresses
(*local*), its public address as the relay sees it (*public*), and an address a peer saw it at
(*seen by peer*). At most 8, local first, then public IPv6, then public IPv4.

When a session runs through the relay, each side sends its candidates as inner type `0x03`, and
again when they change:

| Length | Content |
|---|---|
| 2 | the list's generation; an older list is ignored |
| 1 | `c`, how many entries follow, 0 to 8 |
| each entry | kind (`0x00` local, `0x01` public, `0x02` seen by peer), family (`0x04` or `0x06`), address (4 or 16), port (2) |

**Probes.** On receiving the other's list, each side probes every candidate: inner type `0x04`
with an 8-byte random nonce, in 5 rounds at 0, 250, 500, 1,000 and 2,000 milliseconds. Both sides
start together, so their probes cross and open both NATs. A probe is answered with inner type
`0x05`: the nonce, then the address the probe came from (family, address, port).

**Rules:**
- **A path is proven** when the answer to a probe comes back from the address it was sent to.
- **The best proven path is used**: local, then IPv6, then IPv4; the relay when there is none.
- **A direct path is fresh for 15 seconds** after an authenticated packet arrived on it. A packet
  sent later goes through the relay, and one probe goes on the direct path; its answer makes the
  path fresh again.
- **A direct path is stale at once**, proven or taken from the peer's packets alike:
  - when this endpoint's network changes;
  - when the peer's new list no longer holds the path's address;
  - when the peer's newest packet, under the current keys, arrives through the relay after its
    packets had come on the path: the peer is elsewhere, or no longer reaches this side directly.
    A late or replayed packet does not count, nor does one before the peer has used the path.
- **A change of network is told at once.** After this endpoint's network changes, with a relay
  pinned, each session with live keys sends its peer one packet through the relay: its new list
  if one is owed, else a keep-alive. Arriving newest through the relay, it ends the peer's direct
  path to where this endpoint was, even when the application here has nothing to send. A dormant
  session sends nothing.
- **A silent path is retried on use,** at most once every 30 seconds.
- **A symmetric NAT is recognised** when a peer is seen at another port than the relay sees it
  at. No ports are guessed: that session stays on the relay.
- **Excluded prefixes** are never offered, probed or used, whichever side names them.
- **Nothing at rest.** Candidates, probes and answers are all caused by a session in use. A
  dormant session forgets its paths with its keys.

Vectors: `paths-v1.json`.

## 8. Reliable messages

An optional layer, in the crate `convesso-stream`. Each session has at most one channel, carried
by inner types `0x06` and `0x07`. A message is 1 byte or more; it arrives whole, once and in
order, or the channel is reset.

**Stream data** (`0x06`):

| Length | Content |
|---|---|
| 8 | the sender's channel incarnation, random |
| 4 | the fragment's sequence number |
| 1 | flags: bit 0 FIRST fragment of a message, bit 1 LAST, bit 2 START (no acknowledgement received yet in this incarnation) |
| 4 | the message's length, only with FIRST |
| 1 to 1,332 | the fragment |

**Stream acknowledgement** (`0x07`):

| Length | Content |
|---|---|
| 8 | the incarnation being acknowledged |
| 1 | flags: bit 0 RESET, "this channel is reset here" |
| 4 | the next sequence expected; everything before it was received |
| 4 | the window: bytes the receiver can still take |
| 4 | the largest message the receiver accepts |
| 1 | how many ranges follow, 0 to 4 |
| 8 each | a range of fragments received beyond that point: start and end, the end excluded |

Sequence numbers are compared in serial-number arithmetic (RFC 1982). A frame that breaks a rule
is ignored whole.

**Rules:**
- **Loss recovery.** A fragment is sent again when three fragments sent after it are
  acknowledged, or when its timeout expires. The timeout follows RFC 6298, between 200 ms and 15
  s. No round-trip sample is taken from a fragment that was sent twice.
- **Congestion control** is NewReno (RFC 5681, RFC 6582), in bytes, starting at 10 fragments.
- **Flow control.** A receiver holds only what fits its advertised window. A sender accepts a
  message only when it fits its buffer, and says when room opens again.
- **Reset.** A channel is reset when data has waited 30 seconds with no acknowledgement, when the
  peer starts a new incarnation, when the peer says so, when a message is too large, or when the
  session closes. Each side gets one event, and the next message opens a new incarnation.
- **Silent at rest.** With everything acknowledged, the channel holds no timer and sends nothing.
- **The channel does not delay datagrams.**

Two configurations are provided: `Mcu` (messages up to 2,048 bytes, 4 channels, fixed buffers) and
`Server` (messages up to 262,144 bytes, buffers that grow).

Vectors: `stream-v1.json`.

## 9. Vectors

Each file is produced, or checked, by an implementation independent of convesso's own code: a
Python script beside it, the official Noise vectors, or `snow`. The vectors run on the host and on
both embedded targets.

| File | Fixes |
|---|---|
| `crates/convesso-core/vectors/wire-format.json` | `mac1`, the "version not supported" message (§1) |
| `crates/convesso-core/vectors/identity.json` | addresses, peer ids, refused encodings (§2) |
| `crates/convesso-core/vectors/cacophony-ikpsk2.json` | the Noise layer, official vectors (§3) |
| `crates/convesso-core/vectors/handshake-v1.json` | whole handshakes, checked against `snow` (§3) |
| `crates/convesso-core/vectors/dos-v1.json` | cookies, `mac2`, the cookie reply (§4) |
| `crates/convesso-core/vectors/transport-v1.json` | transport packets (§5) |
| `crates/convesso-core/vectors/relay-v1.json` | relay frames and the TCP link (§6) |
| `crates/convesso-core/vectors/paths-v1.json` | candidates, probes and answers (§7) |
| `crates/convesso-stream/vectors/stream-v1.json` | stream frames (§8) |
