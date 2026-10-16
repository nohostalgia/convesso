//! The embedded driver over the in-memory sockets (`DESIGN.md §5`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use convesso_core::endpoint::{ExcludeError, SendError};
use convesso_core::handshake::ChannelBinding;
use convesso_core::identity::{Address, PeerId};
use convesso_core::storage::Mcu;
use convesso_embassy::rng::{RngFailed, SecureRng};
use convesso_embassy::{
    Config, Context, ContextEvent, ContextEvents, ContextOptions, ContextSlot, Node, NodeError,
    RelayLocation, Shared, StartError, Stats,
};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use support::{MemDatagrams, MemInterfaces, Net, RelayHost};
use tokio::time::timeout;

type TestNode = Node<'static, NoopRawMutex, Mcu, MemDatagrams>;
type TestContext = Context<'static, NoopRawMutex, Mcu, MemDatagrams>;
type TestEvents = ContextEvents<'static, NoopRawMutex, Mcu, MemDatagrams>;

/// A node and its one context, `app`, with what the tests here use of both.
struct Peer {
    node: TestNode,
    app: TestContext,
}

impl Peer {
    async fn address(&self) -> Address {
        self.node.address().await
    }

    async fn send(&self, to: &Address, data: &[u8]) -> Result<(), NodeError> {
        self.app.send(to, data).await
    }

    async fn send_to_peer(&self, peer: PeerId, data: &[u8]) -> Result<(), NodeError> {
        self.app.send_to_peer(peer, data).await
    }

    async fn set_hint(&self, peer: PeerId, at: SocketAddr) -> Result<(), NodeError> {
        self.node.set_hint(peer, at).await
    }

    async fn set_reachable(&self, on: bool) {
        self.node.set_reachable(on).await;
    }

    async fn stats(&self) -> Stats {
        self.node.stats().await
    }

    async fn relay_udp_proven(&self) -> bool {
        self.node.relay_udp_proven().await
    }

    async fn network_changed(&self) {
        self.node.network_changed().await;
    }

    async fn exclude_prefix(&self, ip: IpAddr, len: u8) -> Result<(), NodeError> {
        self.node.exclude_prefix(ip, len).await
    }

    async fn set_excluded(&self, prefixes: &[(IpAddr, u8)]) -> Result<(), NodeError> {
        self.node.set_excluded(prefixes).await
    }

    async fn channel_binding(&self, peer: PeerId) -> Option<ChannelBinding> {
        self.app.channel_binding(peer).await
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// A generator for tests: a counter, never failing.
struct TestRng(u64);

impl SecureRng for TestRng {
    fn try_fill(&mut self, dest: &mut [u8]) -> Result<(), RngFailed> {
        for byte in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (self.0 >> 56) as u8;
        }
        Ok(())
    }
}

/// A generator that cannot be read.
struct BrokenRng;

impl SecureRng for BrokenRng {
    fn try_fill(&mut self, _dest: &mut [u8]) -> Result<(), RngFailed> {
        Err(RngFailed)
    }
}

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

/// Starts node `key` of the vectors on `ips` at `port`, pinned to `relay`,
/// with the context `app` and `events` bytes for its events, its runner
/// spawned on the `LocalSet`.
async fn node(
    net: &Net,
    key: usize,
    ips: &[IpAddr],
    port: u16,
    relay: &RelayHost,
    events: usize,
) -> (Peer, TestEvents) {
    let (node, events, _) = node_with(net, key, port, relay, events, MemInterfaces::new(ips)).await;
    (node, events)
}

/// [`node`] with the interfaces given, which the test may change, and the
/// runner's task, which it may abort: a reset.
async fn node_with(
    net: &Net,
    key: usize,
    port: u16,
    relay: &RelayHost,
    events: usize,
    interfaces: MemInterfaces,
) -> (Peer, TestEvents, tokio::task::JoinHandle<()>) {
    let ips = interfaces.0.borrow().clone();
    let datagrams: &'static MemDatagrams = leak(net.bind(&ips, port));
    let slot: &'static mut Option<Shared<'static, NoopRawMutex, Mcu, MemDatagrams>> = leak(None);
    let (node, runner, _node_events) = convesso_embassy::start(
        support::identity(key),
        Config {
            relay: Some(RelayLocation {
                address: relay.address,
                primary: relay.udp[0],
                other: relay.udp.get(1).copied(),
            }),
        },
        datagrams,
        net.stream(ips[0]),
        interfaces,
        leak(TestRng(key as u64 * 1000 + u64::from(port))),
        leak(vec![0u8; 64]).as_mut_slice(),
        slot,
    )
    .unwrap_or_else(|_| panic!("node {key} starts"));
    let task = tokio::task::spawn_local(async move {
        let _: () = runner.run().await;
    });
    let (app, events) = open(node, b"app", events).await;
    (Peer { node, app }, events, task)
}

/// Opens `name` on `node`, with `events` bytes for its events.
async fn open(node: TestNode, name: &[u8], events: usize) -> (TestContext, TestEvents) {
    node.context(
        name,
        ContextOptions {
            access: convesso_embassy::Access::Everyone,
            events: leak(vec![0u8; events]).as_mut_slice(),
            slot: leak(ContextSlot::new()),
            #[cfg(feature = "stream")]
            credit: false,
            #[cfg(feature = "stream")]
            max_message: None,
        },
    )
    .await
    .unwrap()
}

/// The next datagram event, skipping others, within `secs` seconds.
async fn datagram(events: &mut TestEvents, secs: u64) -> (Vec<u8>, bool) {
    timeout(Duration::from_secs(secs), async {
        let mut buf = [0u8; 1500];
        loop {
            if let Some(ContextEvent::Datagram { data, relayed, .. }) = events.next(&mut buf).await
            {
                return (data.to_vec(), relayed);
            }
        }
    })
    .await
    .expect("a datagram in time")
}

async fn local<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::LocalSet::new().run_until(f).await
}

fn world() -> (Net, RelayHost) {
    let net = Net::new();
    let relay = support::spawn_relay(&net, &[ip("192.0.2.1"), ip("2001:db8::1")], 7400);
    (net, relay)
}

/// Scenario: two applications exchange datagrams through a relay, each
/// knowing only the other's key and the relay's address.
#[tokio::test(flavor = "current_thread")]
async fn two_applications_exchange_datagrams_through_a_relay() {
    local(async {
        let (net, relay) = world();
        net.no_direct(true);
        let (a, mut a_events) = node(&net, 1, &[ip("10.0.0.1")], 7500, &relay, 8192).await;
        let (b, mut b_events) = node(&net, 2, &[ip("10.0.1.1")], 7500, &relay, 8192).await;
        b.set_reachable(true).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        a.send(&b.address().await, b"hello from a").await.unwrap();
        assert_eq!(
            datagram(&mut b_events, 5).await,
            (b"hello from a".to_vec(), true)
        );
        b.send(&a.address().await, b"hello from b").await.unwrap();
        assert_eq!(
            datagram(&mut a_events, 5).await,
            (b"hello from b".to_vec(), true)
        );
    })
    .await;
}

/// Scenario: a send's error reaches the application: a datagram too large for
/// its path gets the core's size error, and nothing leaves.
#[tokio::test(flavor = "current_thread")]
async fn a_sends_error_reaches_the_application() {
    local(async {
        let (net, relay) = world();
        let (a, _a_events) = node(&net, 1, &[ip("10.0.0.1")], 7500, &relay, 8192).await;
        let b = support::identity(2);
        let before = net.sent(|from, _| from.ip() == ip("10.0.0.1"));
        let result = a.send(b.address(), &[0u8; 1500]).await;
        assert!(
            matches!(result, Err(NodeError::Send(SendError::TooLarge { .. }))),
            "{result:?}"
        );
        assert_eq!(net.sent(|from, _| from.ip() == ip("10.0.0.1")), before);
    })
    .await;
}

/// Scenario: a full buffer holds back no other context. B reads none of one
/// context's events for 65 s while A sends it datagrams in both, through the
/// relay: the unread context's datagrams beyond its buffer are dropped and
/// counted, the other's keep arriving, B's relay keep-alives go on, and its
/// sends complete.
#[tokio::test(flavor = "current_thread")]
async fn a_full_buffer_holds_back_no_other_context() {
    local(async {
        let (net, relay) = world();
        net.no_direct(true);
        let (a, mut a_events) = node(&net, 1, &[ip("10.0.0.1")], 7500, &relay, 8192).await;
        // Room for the largest datagram's worth of events, and a little.
        let (b, _b_slow) = node(&net, 2, &[ip("10.0.1.1")], 7500, &relay, 2048 + 400).await;
        let (a_other, _a_other_events) = open(a.node, b"other", 8192).await;
        let (_b_other, mut b_other) = open(b.node, b"other", 8192).await;
        a.set_reachable(true).await;
        b.set_reachable(true).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let keepalives = b.stats().await.keepalives_sent;
        let (a_address, b_address) = (a.address().await, b.address().await);
        // B reads the other context as its datagrams come.
        let reader = tokio::task::spawn_local(async move {
            let mut got = Vec::new();
            for _ in 0u8..30 {
                got.push(datagram(&mut b_other, 5).await.0);
            }
            got
        });
        for i in 0u8..30 {
            a.send(&b_address, &[i; 100]).await.unwrap();
            a_other.send(&b_address, &[i; 100]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            reader.await.unwrap(),
            (0u8..30).map(|i| vec![i; 100]).collect::<Vec<_>>(),
            "every datagram of the other context, in order"
        );
        tokio::time::sleep(Duration::from_secs(65)).await;
        let stats = b.stats().await;
        assert!(stats.datagrams_dropped >= 1, "{stats:?}");
        assert!(stats.keepalives_sent > keepalives, "the keep-alives go on");
        b.send(&a_address, b"meanwhile").await.unwrap();
        let (data, _) = datagram(&mut a_events, 5).await;
        assert_eq!(data, b"meanwhile", "a send completes");
    })
    .await;
}

/// Scenarios: a generator failure stops the start, and a chip without a
/// generator does not start: no packet leaves.
#[tokio::test(flavor = "current_thread")]
async fn a_generator_failure_stops_the_start() {
    local(generator_failure()).await;
}

async fn generator_failure() {
    let (net, relay) = world();
    let datagrams: &'static MemDatagrams = leak(net.bind(&[ip("10.0.0.1")], 7500));
    let slot: &'static mut Option<Shared<'static, NoopRawMutex, Mcu, MemDatagrams>> = leak(None);
    let result = convesso_embassy::start(
        support::identity(1),
        Config {
            relay: Some(RelayLocation {
                address: relay.address,
                primary: relay.udp[0],
                other: None,
            }),
        },
        datagrams,
        net.stream(ip("10.0.0.1")),
        MemInterfaces::new(&[ip("10.0.0.1")]),
        leak(BrokenRng),
        leak(vec![0u8; 64]).as_mut_slice(),
        slot,
    );
    assert!(matches!(result, Err(StartError::Rng(RngFailed))));
    assert_eq!(net.sent(|_, _| true), 0, "no packet left");
}

// --- the relay link ----------------------------------------------------------------------

/// A reachable node keeps its link: with its UDP blocked, everything for it
/// comes over the link, whose keep-alive the relay answered, and its UDP to
/// the relay is not proven.
#[tokio::test(flavor = "current_thread")]
async fn a_reachable_node_is_reached_over_its_link() {
    local(async {
        let (net, relay) = world();
        net.no_direct(true);
        let (a, _a_events) = node(&net, 1, &[ip("10.0.0.1")], 7500, &relay, 8192).await;
        let (b, mut b_events) = node(&net, 2, &[ip("10.0.1.1")], 7500, &relay, 8192).await;
        net.fail_sends_from(ip("10.0.1.1"), true);
        b.set_reachable(true).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        a.send(&b.address().await, b"over the link").await.unwrap();
        assert_eq!(
            datagram(&mut b_events, 5).await,
            (b"over the link".to_vec(), true)
        );
        assert!(!b.relay_udp_proven().await);
        assert_eq!(net.connects(), 1, "one link, kept");
    })
    .await;
}

/// Scenario: a socket error is an input, not a crash. A link the relay
/// refuses is retried with the core's backoff, and meanwhile the node keeps
/// working over UDP.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_link_is_an_input_not_a_crash() {
    local(async {
        let (net, relay) = world();
        net.no_direct(true);
        net.refuse(relay.udp[0], true);
        let (a, mut a_events) = node(&net, 1, &[ip("10.0.0.1")], 7500, &relay, 8192).await;
        let (b, mut b_events) = node(&net, 2, &[ip("10.0.1.1")], 7500, &relay, 8192).await;
        b.set_reachable(true).await;
        tokio::time::sleep(Duration::from_millis(3500)).await;
        let attempts = net.connects();
        assert!(
            (2..=4).contains(&attempts),
            "backoff of 1 s doubling: {attempts} attempts in 3.5 s"
        );
        // Over UDP, B opens its relay session by sending (A is not at the
        // relay yet); then A reaches B, and B answers.
        b.send(&a.address().await, b"anyone?").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        a.send(&b.address().await, b"still here").await.unwrap();
        assert_eq!(
            datagram(&mut b_events, 5).await,
            (b"still here".to_vec(), true)
        );
        b.send(&a.address().await, b"and back").await.unwrap();
        // B's first datagram was not lost: its dial retried until A was known.
        assert_eq!(
            datagram(&mut a_events, 5).await,
            (b"anyone?".to_vec(), true)
        );
        assert_eq!(
            datagram(&mut a_events, 5).await,
            (b"and back".to_vec(), true)
        );
    })
    .await;
}

/// Scenario: a relay reachable in both families. The relay's traffic goes to
/// its first address; the question over the other family to the second.
#[tokio::test(flavor = "current_thread")]
async fn a_relay_in_both_families() {
    local(async {
        let (net, relay) = world();
        net.no_direct(true);
        let ips = [ip("10.0.0.1"), ip("2001:db8:a::1")];
        let (a, _a_events) = node(&net, 1, &ips, 7500, &relay, 8192).await;
        let (b, mut b_events) = node(&net, 2, &[ip("10.0.1.1")], 7500, &relay, 8192).await;
        b.set_reachable(true).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        a.send(&b.address().await, b"hello").await.unwrap();
        datagram(&mut b_events, 5).await;
        let v4 = net.sent(|from, to| from.ip() == ips[0] && to == relay.udp[0]);
        let v6 = net.sent(|from, to| from.ip() == ips[1] && to == relay.udp[1]);
        assert!(v4 >= 2, "the relay's traffic on the first address: {v4}");
        assert!(
            (1..=2).contains(&v6),
            "the question over the other family: {v6}"
        );
    })
    .await;
}

// --- local addresses and resets ---------------------------------------------------------

async fn locals(node: &Peer) -> Vec<SocketAddr> {
    let mut out = [convesso_core::paths::Candidate {
        kind: convesso_core::paths::CandidateKind::Local,
        address: SocketAddr::new(ip("0.0.0.0"), 0),
    }; 8];
    let n = node.node.candidates(&mut out).await;
    out[..n]
        .iter()
        .filter(|c| c.kind == convesso_core::paths::CandidateKind::Local)
        .map(|c| c.address)
        .collect()
}

/// The core's candidates are the interfaces' addresses, with the socket's
/// port; after a change of network, the new ones.
#[tokio::test(flavor = "current_thread")]
async fn the_candidates_are_the_interfaces_addresses() {
    local(async {
        let (net, relay) = world();
        let interfaces = MemInterfaces::new(&[ip("10.0.0.1"), ip("2001:db8:a::1")]);
        let (a, _events, _) = node_with(&net, 1, 7500, &relay, 8192, interfaces.clone()).await;
        assert_eq!(
            locals(&a).await,
            [
                "10.0.0.1:7500".parse::<SocketAddr>().unwrap(),
                "[2001:db8:a::1]:7500".parse().unwrap()
            ]
        );
        *interfaces.0.borrow_mut() = vec![ip("10.0.0.7")];
        a.network_changed().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            locals(&a).await,
            ["10.0.0.7:7500".parse::<SocketAddr>().unwrap()]
        );
    })
    .await;
}

/// Scenario: an excluded prefix leaves the candidates, and
/// comes back when the set is replaced without it; a prefix longer than its
/// address is refused with the core's error.
#[tokio::test(flavor = "current_thread")]
async fn an_excluded_prefix_leaves_the_candidates() {
    local(async {
        let (net, relay) = world();
        let ips = [ip("10.0.0.1"), ip("100.64.3.7")];
        let (a, _events) = node(&net, 1, &ips, 7500, &relay, 8192).await;
        let tunnel: SocketAddr = "100.64.3.7:7500".parse().unwrap();
        assert!(locals(&a).await.contains(&tunnel));

        a.exclude_prefix(ip("100.64.0.0"), 10).await.unwrap();
        assert!(!locals(&a).await.contains(&tunnel));
        assert_eq!(
            a.exclude_prefix(ip("10.0.0.0"), 33).await,
            Err(NodeError::Exclude(ExcludeError::TooLong { len: 33 }))
        );

        a.set_excluded(&[(ip("10.8.0.0"), 24)]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(locals(&a).await.contains(&tunnel));
    })
    .await;
}

/// Scenario: two embedded nodes agree on the channel
/// binding; a peer without a session has none.
#[tokio::test(flavor = "current_thread")]
async fn two_nodes_agree_on_the_binding() {
    local(async {
        let (net, relay) = world();
        let (a, _a_events) = node(&net, 1, &[ip("10.0.0.1")], 7500, &relay, 8192).await;
        let (b, mut b_events) = node(&net, 2, &[ip("10.0.1.1")], 7500, &relay, 8192).await;
        let b_address = b.address().await;
        a.set_hint(b_address.peer_id(), SocketAddr::new(ip("10.0.1.1"), 7500))
            .await
            .unwrap();
        a.send(&b_address, b"hello").await.unwrap();
        datagram(&mut b_events, 5).await;
        let at_a = a.channel_binding(b_address.peer_id()).await;
        let at_b = b.channel_binding(a.address().await.peer_id()).await;
        assert!(at_a.is_some());
        assert_eq!(at_a, at_b);
        let stranger = support::identity(3).peer_id();
        assert_eq!(a.channel_binding(stranger).await, None);
    })
    .await;
}

/// Scenarios: a device reset in the middle of a session is reached again,
/// and nothing of a session from before the reset is accepted after it.
#[tokio::test(flavor = "current_thread")]
async fn a_device_reset_mid_session_is_reached_again() {
    local(async {
        let (net, relay) = world();
        net.no_direct(true);
        let device_ips = [ip("10.0.1.1")];
        let (a, mut a_events) = node(&net, 1, &[ip("10.0.0.1")], 7500, &relay, 8192).await;
        let (device, mut device_events, task) =
            node_with(&net, 2, 7500, &relay, 8192, MemInterfaces::new(&device_ips)).await;
        // A is reachable: the relay knows it before the device sends.
        a.set_reachable(true).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let a_address = a.address().await;
        device.send(&a_address, b"before").await.unwrap();
        assert_eq!(datagram(&mut a_events, 5).await, (b"before".to_vec(), true));
        a.send_to_peer(device.address().await.peer_id(), b"reply")
            .await
            .unwrap();
        assert_eq!(
            datagram(&mut device_events, 5).await,
            (b"reply".to_vec(), true)
        );
        let device_at = SocketAddr::new(device_ips[0], 7500);
        let captured = net
            .last_packet(relay.udp[0], device_at)
            .expect("a packet to the device");

        // The reset: the runner and its state are gone; a new one starts from
        // the same record.
        task.abort();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (device, mut device_events, _) =
            node_with(&net, 2, 7500, &relay, 8192, MemInterfaces::new(&device_ips)).await;
        let sent = net.sent(|from, _| from == device_at);
        net.inject(relay.udp[0], device_at, &captured);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            net.sent(|from, _| from == device_at),
            sent,
            "nothing in response to a packet of the old session"
        );

        // The device sends first: a fresh session, and the datagrams arrive.
        device.send(&a_address, b"after").await.unwrap();
        assert_eq!(datagram(&mut a_events, 5).await, (b"after".to_vec(), true));
        a.send_to_peer(device.address().await.peer_id(), b"welcome back")
            .await
            .unwrap();
        assert_eq!(
            datagram(&mut device_events, 5).await,
            (b"welcome back".to_vec(), true)
        );
    })
    .await;
}

// --- the relay changed while running --------------------------------------------------

/// Where `relay` is, as the driver takes it.
fn location(relay: &RelayHost) -> RelayLocation {
    RelayLocation {
        address: relay.address,
        primary: relay.udp[0],
        other: relay.udp.get(1).copied(),
    }
}

/// Whether a datagram arrives within `ms` milliseconds.
async fn any_datagram(events: &mut TestEvents, ms: u64) -> bool {
    timeout(Duration::from_millis(ms), datagram(events, 60))
        .await
        .is_ok()
}

/// Scenario: the embedded driver moves too: its link to the old relay is
/// closed, it registers on the new one, and its relayed session carries on
/// through it.
#[tokio::test(flavor = "current_thread")]
async fn the_embedded_driver_moves_too() {
    local(async {
        let (net, r1) = world();
        let r2 = support::spawn_relay_with(&net, 4, &[ip("192.0.2.2"), ip("2001:db8::2")], 7400);
        net.no_direct(true);
        let (a, _a_events) = node(&net, 1, &[ip("10.0.0.1")], 7500, &r1, 8192).await;
        let (b, mut b_events) = node(&net, 2, &[ip("10.0.1.1")], 7500, &r1, 8192).await;
        b.set_reachable(true).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let b_address = b.address().await;
        a.send(&b_address, b"through r1").await.unwrap();
        assert_eq!(
            datagram(&mut b_events, 5).await,
            (b"through r1".to_vec(), true)
        );
        let connects = net.connects();

        b.node.set_relay(Some(location(&r2))).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(net.connects(), connects + 1, "a link to the new relay");
        // A, still on R1, no longer reaches B there: B left it.
        a.send(&b_address, b"lost").await.unwrap();
        assert!(!any_datagram(&mut b_events, 500).await, "B left R1");

        a.node.set_relay(Some(location(&r2))).await.unwrap();
        a.send(&b_address, b"through r2").await.unwrap();
        assert_eq!(
            datagram(&mut b_events, 5).await,
            (b"through r2".to_vec(), true)
        );
    })
    .await;
}
