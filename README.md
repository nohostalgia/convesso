# convesso

Encrypted connections between two devices that know each other's public key.

- **Direct when the network allows it, through a relay when it does not.** A session opens through
  a relay, and moves to a direct path as soon as one is proven.
- **Silent at rest.** A device with nothing to say sends nothing, except one keep-alive a minute
  if it asked to stay reachable. No session is kept "alive" for its own sake.
- **From a server to a microcontroller.** The protocol core is `no_std`, needs no allocator and
  does no I/O; it runs on 32-bit microcontrollers (ARM Cortex-M, RISC-V).
- **Datagrams, and reliable messages if you want them.** Datagrams are small and may be lost. An
  optional crate adds messages that arrive whole, once and in order.

The name is Italian for *convex*: a set where the straight line between any two points stays
inside it.

> **Status:** early. The protocol is version 1 and has not been audited yet; an external audit is
> planned before 1.0. The crates are not published, and the licence is not chosen yet.

## The crates

| Crate | What it is |
|---|---|
| `convesso-core` | the protocol, as state machines without I/O |
| `convesso-stream` | optional reliable messages |
| `convesso-tokio` | the driver for servers, desktops and phones; the `convesso-relay` binary |
| `convesso-embassy` | the driver for microcontrollers |
| `convesso-relay` | the relay server's logic |

## A first look

```rust
use convesso_tokio::identity::load_or_create;
use convesso_tokio::{Config, NodeEvent, RelayLocation};

// An identity is a key, kept in a file created on first use.
let (identity, _created) = load_or_create("alice.key".as_ref())?;
println!("my address: {:?}", identity.address());

let (node, mut events) = convesso_tokio::start(
    identity,
    Config {
        context: b"chat".to_vec(),               // both sides use the same
        relay: Some(RelayLocation { address: relay_address, host: "relay.example:7400".into() }),
        ..Config::default()
    },
)
.await?;
node.set_reachable(true).await?;                 // peers can reach us through the relay

node.send(peer_address, b"hello".to_vec()).await?;
while let Some(event) = events.next().await {
    if let NodeEvent::Datagram { data, relayed, .. } = event {
        println!("{} ({})", String::from_utf8_lossy(&data), if relayed { "relayed" } else { "direct" });
    }
}
```

The whole program is `crates/convesso-tokio/examples/chat.rs`:

```sh
cargo run --example chat -- --key alice.key --relay <relay-address>@<host:port> --peer <bob-address>
```

## A relay

```sh
docker build -f docker/relay/Dockerfile -t convesso-relay .
docker run -d --name convesso-relay -p 7400:7400/udp -p 7400:7400/tcp \
    -v convesso-relay-data:/data convesso-relay
docker logs convesso-relay      # prints the relay's address, which clients are given
```

A relay forwards sealed packets between keys: it cannot read them. Clients are given its public
key, and accept no other relay in its place. Its limits are set in `docker/relay/relay.toml`.

## How it works

- [DESIGN.md](DESIGN.md): what the library is built on, and why.
- [PROTOCOL.md](PROTOCOL.md): the bytes on the wire, and the test vectors that fix them.

## Building and testing

```sh
cargo test --workspace --all-features
sh scripts/ci-local.sh          # the whole CI in a container: needs Docker
```

The CI also builds the reference firmware for both embedded targets, runs the test vectors on them
under QEMU, checks flash and RAM against `footprint-budget.toml`, and runs every fuzz target.

## Security

See [SECURITY.md](SECURITY.md).
