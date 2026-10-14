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

use convesso_core::identity::Identity;
use convesso_relay::{Config as RelayConfig, Limits, Open, Relay};
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::{Config, Events, Node, NodeEvent, RelayLocation, Stats};
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

async fn node(seed: u8, relay: &RelayLocation) -> (Node, Events) {
    convesso_tokio::start(
        Identity::from_ed25519_seed(&[seed; 32]).unwrap(),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            relay: Some(relay.clone()),
            events: 65_536,
            ..Config::default()
        },
    )
    .await
    .unwrap()
}

async fn next_datagram(events: &mut Events) -> Vec<u8> {
    loop {
        if let Some(NodeEvent::Datagram { data, .. }) = events.next().await {
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
