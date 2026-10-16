//! Measurements on real sockets. Ignored by default; run in
//! release:
//! `cargo test -p convesso-tokio --release --test measure -- --ignored --nocapture`.
//! The two idle hours take an hour of real time; the others, seconds.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_precision_loss
)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use convesso_core::identity::{Address, Identity};
use convesso_relay::{Config as RelayConfig, Limits, Open, Relay};
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::{
    Config, Context, ContextEvent, ContextEvents, ContextOptions, Delivery, Events, Node,
    NodeError, RelayLocation, Stats,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

const HOUR: Duration = Duration::from_secs(3600);

async fn relay(limits: Limits) -> RelayLocation {
    let identity = Identity::from_ed25519_seed(&[150; 32]).unwrap();
    let address = *identity.address();
    let (udp, listener, port) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
            break (udp, listener, port);
        }
    };
    let config = RelayConfig {
        limits,
        ..RelayConfig::default()
    };
    let relay = Relay::new(
        identity,
        Open,
        OsEntropy,
        config,
        convesso_core::time::Instant::from_millis(0),
    )
    .unwrap();
    tokio::spawn(convesso_tokio::relay_server::serve(relay, udp, listener));
    RelayLocation {
        address,
        host: format!("127.0.0.1:{port}"),
    }
}

/// A node and its one context, `app`, with what the measurements use.
struct N {
    node: Node,
    app: Context,
    _events: Events,
}

impl N {
    fn address(&self) -> Address {
        self.node.address()
    }

    async fn set_reachable(&self, on: bool) -> Result<(), NodeError> {
        self.node.set_reachable(on).await
    }

    async fn stats(&self) -> Result<Stats, NodeError> {
        self.node.stats().await
    }

    async fn send(&self, to: Address, data: Vec<u8>) -> Result<(), NodeError> {
        self.app.send(to, data).await
    }

    fn local_addr(&self) -> SocketAddr {
        self.node.local_addr()
    }

    async fn set_hint(
        &self,
        peer: convesso_core::identity::PeerId,
        at: SocketAddr,
    ) -> Result<(), NodeError> {
        self.node.set_hint(peer, at).await
    }
}

async fn node(seed: u8, relay: &RelayLocation) -> (N, ContextEvents) {
    node_with(seed, relay, Delivery::Events).await
}

async fn node_with(seed: u8, relay: &RelayLocation, delivery: Delivery) -> (N, ContextEvents) {
    let (node, events) = convesso_tokio::start(
        Identity::from_ed25519_seed(&[seed; 32]).unwrap(),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            relay: Some(relay.clone()),
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let (app, app_events) = node
        .context(
            b"app",
            ContextOptions {
                delivery,
                events: 65_536,
                ..ContextOptions::default()
            },
        )
        .await
        .unwrap();
    (
        N {
            node,
            app,
            _events: events,
        },
        app_events,
    )
}

async fn next_datagram(events: &mut ContextEvents) -> Vec<u8> {
    loop {
        if let Some(ContextEvent::Datagram { data, .. }) = events.next().await {
            return data;
        }
    }
}

fn delta(after: Stats, before: Stats) -> Stats {
    Stats {
        udp_sent: after.udp_sent - before.udp_sent,
        udp_sent_bytes: after.udp_sent_bytes - before.udp_sent_bytes,
        udp_received: after.udp_received - before.udp_received,
        udp_received_bytes: after.udp_received_bytes - before.udp_received_bytes,
        frames_sent: after.frames_sent - before.frames_sent,
        link_sent_bytes: after.link_sent_bytes - before.link_sent_bytes,
        frames_received: after.frames_received - before.frames_received,
        link_received_bytes: after.link_received_bytes - before.link_received_bytes,
        keepalives_sent: after.keepalives_sent - before.keepalives_sent,
        keepalives_received: after.keepalives_received - before.keepalives_received,
        links_opened: after.links_opened - before.links_opened,
        core_udp_outputs: after.core_udp_outputs - before.core_udp_outputs,
        core_link_outputs: after.core_link_outputs - before.core_link_outputs,
        #[cfg(feature = "stream")]
        stream_frames_sent: after.stream_frames_sent - before.stream_frames_sent,
        datagrams_dropped: after.datagrams_dropped - before.datagrams_dropped,
    }
}

/// Scenario: an idle hour with a link matches the simulation: 60 keep-alives
/// sent, 60 answers received, nothing else, within one at each end.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "an hour of real time"]
async fn an_idle_hour_with_a_link() {
    let relay = relay(Limits::default()).await;
    let (node, _events) = node(1, &relay).await;
    node.set_reachable(true).await.unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let before = node.stats().await.unwrap();
    tokio::time::sleep(HOUR).await;
    let hour = delta(node.stats().await.unwrap(), before);
    std::println!("idle hour with a link: {hour:?}");
    assert!((59..=61).contains(&hour.keepalives_sent), "{hour:?}");
    assert!((59..=61).contains(&hour.keepalives_received), "{hour:?}");
    assert_eq!(
        (hour.udp_sent, hour.frames_sent, hour.links_opened),
        (0, 0, 0)
    );
    assert_eq!(hour.link_sent_bytes, 2 * hour.keepalives_sent);
    std::println!(
        "a month: {} keep-alives each way, {} bytes of payload",
        hour.keepalives_sent * 24 * 30,
        (hour.link_sent_bytes + hour.link_received_bytes) * 24 * 30
    );
}

/// Scenario: an idle hour without a link sends nothing after the sessions
/// went dormant.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "an hour of real time"]
async fn an_idle_hour_without_a_link() {
    let relay = relay(Limits::default()).await;
    let (sender, _sender_events) = node(2, &relay).await;
    let (receiver, mut receiver_events) = node(3, &relay).await;
    receiver.set_reachable(true).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    sender
        .send(receiver.address(), b"one reading".to_vec())
        .await
        .unwrap();
    timeout(Duration::from_secs(5), next_datagram(&mut receiver_events))
        .await
        .unwrap();
    // The keys expire after 180 s; then the session is dormant.
    tokio::time::sleep(Duration::from_secs(190)).await;
    let before = sender.stats().await.unwrap();
    tokio::time::sleep(HOUR).await;
    let hour = delta(sender.stats().await.unwrap(), before);
    std::println!("idle hour without a link: {hour:?}");
    assert_eq!(hour, Stats::default());
}

/// Scenario: an idle hour after an exchange of messages, in the per-peer
/// mode, counts what it counts in the event-stream mode: two pairs side by
/// side, one per mode, exchange 100 messages, wait for their sessions to go
/// dormant, and are counted for an hour.
#[cfg(feature = "stream")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "an hour of real time"]
async fn an_idle_hour_after_messages_in_both_modes() {
    use convesso_tokio::Received;

    let relay = relay(Limits::default()).await;
    let start = |seed: u8, delivery: Delivery| {
        let relay = relay.clone();
        async move { node_with(seed, &relay, delivery).await }
    };
    let per_peer = Delivery::PerPeer {
        messages: 1 << 20,
        datagrams: 1 << 18,
    };
    let mut pairs = Vec::new();
    for (seed, delivery) in [(20, Delivery::Events), (22, per_peer)] {
        let (sender, sender_events) = start(seed, Delivery::Events).await;
        let (receiver, mut receiver_events) = start(seed + 1, delivery).await;
        receiver.set_reachable(true).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let opened = match delivery {
            Delivery::PerPeer { .. } => Some(
                receiver
                    .app
                    .receiver(sender.address().peer_id())
                    .await
                    .unwrap(),
            ),
            Delivery::Events => None,
        };
        for i in 0..100u8 {
            sender
                .app
                .send_message(receiver.address(), vec![i; 1000])
                .await
                .unwrap();
        }
        let mut got = 0;
        while got < 100 {
            match &opened {
                Some(open) => {
                    if let Ok(Received::Message(_)) =
                        timeout(Duration::from_secs(10), open.recv()).await
                    {
                        got += 1;
                    }
                }
                None => {
                    if let Ok(Some(ContextEvent::Message { .. })) =
                        timeout(Duration::from_secs(10), receiver_events.next()).await
                    {
                        got += 1;
                    }
                }
            }
        }
        pairs.push((sender, sender_events, receiver, receiver_events, opened));
    }
    // The keys expire after 180 s; then the sessions are dormant.
    tokio::time::sleep(Duration::from_secs(190)).await;
    let mut before = Vec::new();
    for (sender, _, receiver, _, _) in &pairs {
        before.push((
            sender.stats().await.unwrap(),
            receiver.stats().await.unwrap(),
        ));
    }
    tokio::time::sleep(HOUR).await;
    let mut hours = Vec::new();
    for ((sender, _, receiver, _, _), (s, r)) in pairs.iter().zip(before) {
        hours.push((
            delta(sender.stats().await.unwrap(), s),
            delta(receiver.stats().await.unwrap(), r),
        ));
    }
    std::println!("an idle hour after messages, events: {:?}", hours[0]);
    std::println!("an idle hour after messages, per peer: {:?}", hours[1]);
    for (sender, receiver) in &hours {
        assert_eq!(*sender, Stats::default(), "the sender sends nothing");
        assert!(
            (59..=61).contains(&receiver.keepalives_sent),
            "{receiver:?}"
        );
        assert_eq!(
            (
                receiver.udp_sent,
                receiver.frames_sent,
                receiver.stream_frames_sent
            ),
            (0, 0, 0),
            "only keep-alives"
        );
    }
    let (events, per_peer) = (hours[0].1, hours[1].1);
    assert!(events.keepalives_sent.abs_diff(per_peer.keepalives_sent) <= 1);
}

/// The first datagram's time: through a local relay, and over a hint.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, meaningful only in release"]
async fn first_datagram_time() {
    let relay = relay(Limits::default()).await;
    let (a, _a_events) = node(4, &relay).await;
    let (b, mut b_events) = node(5, &relay).await;
    b.set_reachable(true).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let start = Instant::now();
    a.send(b.address(), b"first".to_vec()).await.unwrap();
    next_datagram(&mut b_events).await;
    let relayed = start.elapsed();

    let (c, _c_events) = node(6, &relay).await;
    let (d, mut d_events) = node(7, &relay).await;
    c.set_hint(d.address().peer_id(), d.local_addr())
        .await
        .unwrap();
    let start = Instant::now();
    c.send(d.address(), b"first".to_vec()).await.unwrap();
    next_datagram(&mut d_events).await;
    let direct = start.elapsed();
    std::println!(
        "first datagram, loopback: through the relay {relayed:?} (relay handshake, peer handshake, data), over a hint {direct:?}"
    );
}

/// The relay's forwarding rate over the loopback: one sender, one receiver,
/// 1,280-byte datagrams, limits out of the way.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, meaningful only in release"]
async fn relay_forwarding_over_the_loopback() {
    let unlimited = Limits {
        bytes_per_second: u64::MAX / 2000,
        bytes_burst: u64::MAX / 2000,
        packets_per_second: u64::MAX / 2000,
        packets_burst: u64::MAX / 2000,
    };
    let relay = relay(unlimited).await;
    let (a, _a_events) = node(8, &relay).await;
    let (b, mut b_events) = node(9, &relay).await;
    b.set_reachable(true).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    a.send(b.address(), b"warm".to_vec()).await.unwrap();
    next_datagram(&mut b_events).await;
    let count = 20_000usize;
    let data = vec![0x5a; 1280];
    let start = Instant::now();
    let receiver = tokio::spawn(async move {
        let mut got = 0usize;
        while timeout(Duration::from_millis(500), next_datagram(&mut b_events))
            .await
            .is_ok()
        {
            got += 1;
            if got == count {
                break;
            }
        }
        got
    });
    for _ in 0..count {
        a.send(b.address(), data.clone()).await.unwrap();
    }
    let got = receiver.await.unwrap();
    let elapsed = start.elapsed();
    std::println!(
        "relay over the loopback: {got} of {count} 1,280-byte datagrams in {elapsed:?}: {:.0} packets/s, {:.0} Mbit/s delivered",
        got as f64 / elapsed.as_secs_f64(),
        got as f64 * 1280.0 * 8.0 / elapsed.as_secs_f64() / 1e6
    );
}
