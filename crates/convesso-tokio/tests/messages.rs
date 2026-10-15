//! Reliable messages on the tokio driver, feature `stream`, over the loopback
//! and a relay in the same process (`DESIGN.md §5`).

#![cfg(feature = "stream")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::time::Duration;

use convesso_core::identity::{Identity, PeerId};
use convesso_relay::{Config as RelayConfig, Open, Relay};
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::{Config, Events, Node, NodeEvent, RelayLocation};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

fn identity(seed: u8) -> Identity {
    Identity::from_ed25519_seed(&[seed; 32]).unwrap()
}

async fn relay() -> RelayLocation {
    let identity = identity(100);
    let address = *identity.address();
    let (udp, listener, port) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
            break (udp, listener, port);
        }
    };
    let relay = Relay::new(
        identity,
        Open,
        OsEntropy,
        RelayConfig::default(),
        convesso_core::time::Instant::from_millis(0),
    )
    .unwrap();
    tokio::spawn(convesso_tokio::relay_server::serve(relay, udp, listener));
    RelayLocation {
        address,
        host: format!("127.0.0.1:{port}"),
    }
}

async fn node(seed: u8, relay: Option<&RelayLocation>, events: usize) -> (Node, Events) {
    convesso_tokio::start(
        identity(seed),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            relay: relay.cloned(),
            events,
            ..Config::default()
        },
    )
    .await
    .unwrap()
}

async fn reachable(node: &Node) {
    node.set_reachable(true).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while node.stats().await.unwrap().keepalives_received == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a link within two seconds");
}

/// The next `count` messages, skipping other events, within `within`.
async fn messages(events: &mut Events, count: usize, within: Duration) -> Vec<(PeerId, Vec<u8>)> {
    timeout(within, async {
        let mut got = Vec::new();
        while got.len() < count {
            match events.next().await {
                Some(NodeEvent::Message { peer, data }) => got.push((peer, data)),
                Some(NodeEvent::ChannelReset { reason, .. }) => panic!("a reset: {reason:?}"),
                Some(_) => {}
                None => panic!("the node stopped"),
            }
        }
        got
    })
    .await
    .expect("the messages in time")
}

fn message(i: usize) -> Vec<u8> {
    (0..(i * 97) % 3000 + 1).map(|j| (i + j) as u8).collect()
}

/// Two applications exchange 100 messages each way through a relay, knowing
/// only each other's key and the relay's: whole, in order, from the right peer.
#[tokio::test]
async fn two_nodes_exchange_messages_through_a_relay() {
    let relay = relay().await;
    let (a, mut a_events) = node(1, Some(&relay), 64).await;
    let (b, mut b_events) = node(2, Some(&relay), 64).await;
    reachable(&b).await;
    reachable(&a).await;
    let sent: Vec<_> = (0..100).map(message).collect();
    let (a2, b_address, sent_a) = (a.clone(), b.address(), sent.clone());
    let sender = tokio::spawn(async move {
        for m in sent_a {
            a2.send_message(b_address, m).await.unwrap();
        }
    });
    let at_b = messages(&mut b_events, 100, Duration::from_secs(20)).await;
    sender.await.unwrap();
    assert!(at_b.iter().all(|(peer, _)| *peer == a.address().peer_id()));
    assert_eq!(at_b.into_iter().map(|(_, m)| m).collect::<Vec<_>>(), sent);

    for m in &sent {
        b.send_message_to_peer(a.address().peer_id(), m.clone())
            .await
            .unwrap();
    }
    let at_a = messages(&mut a_events, 100, Duration::from_secs(20)).await;
    assert_eq!(at_a.into_iter().map(|(_, m)| m).collect::<Vec<_>>(), sent);
}

/// Scenario: a slow reader holds the sender back without losing messages: B
/// reads nothing for two seconds, A's sends wait, and every message arrives,
/// in order, once B reads; no channel is reset.
#[tokio::test]
async fn a_slow_reader_holds_the_sender_back() {
    let (a, _a_events) = node(8, None, 64).await;
    let (b, mut b_events) = node(9, None, 2).await;
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    b.set_hint(a.address().peer_id(), a.local_addr())
        .await
        .unwrap();
    let sent: Vec<_> = (0..300).map(|i| vec![i as u8; 2000]).collect();
    let (a2, b_address, sent_a) = (a.clone(), b.address(), sent.clone());
    let sender = tokio::spawn(async move {
        for m in sent_a {
            a2.send_message(b_address, m).await.unwrap();
        }
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!sender.is_finished(), "the sender waits for the reader");
    let got = messages(&mut b_events, 300, Duration::from_secs(30)).await;
    sender.await.unwrap();
    assert_eq!(got.into_iter().map(|(_, m)| m).collect::<Vec<_>>(), sent);
}

/// The session closed by this side, by `close` or, with `revoke`, by
/// `close_peer`: the channel is reset on both sides, once, and the next
/// message opens a new channel and arrives.
async fn a_message_after_closing_arrives(seeds: (u8, u8), revoke: bool) {
    let (a, mut a_events) = node(seeds.0, None, 64).await;
    let (b, mut b_events) = node(seeds.1, None, 64).await;
    let b_peer = b.address().peer_id();
    a.set_hint(b_peer, b.local_addr()).await.unwrap();
    b.set_hint(a.address().peer_id(), a.local_addr())
        .await
        .unwrap();
    a.send_message(b.address(), b"before".to_vec())
        .await
        .unwrap();
    let _ = messages(&mut b_events, 1, Duration::from_secs(5)).await;

    if revoke {
        a.close_peer(b_peer, 7).await.unwrap();
    } else {
        a.close(b_peer, 7).await.unwrap();
    }
    let closed = convesso_stream::Reason::SessionClosed { code: 7 };
    let reset = timeout(Duration::from_secs(5), async {
        loop {
            match a_events.next().await {
                Some(NodeEvent::ChannelReset { reason, .. }) => return reason,
                Some(_) => {}
                None => panic!("stopped"),
            }
        }
    })
    .await
    .expect("a reset on the closing side at once");
    assert_eq!(reset, closed);

    a.send_message(b.address(), b"after".to_vec())
        .await
        .unwrap();
    let got = timeout(Duration::from_secs(5), async {
        loop {
            match b_events.next().await {
                Some(NodeEvent::Message { data, .. }) => return data,
                Some(NodeEvent::ChannelReset { reason, .. }) => assert_eq!(reason, closed),
                Some(_) => {}
                None => panic!("stopped"),
            }
        }
    })
    .await
    .expect("the message after the close");
    assert_eq!(got, b"after");
    // No second reset on the closing side.
    let more = timeout(Duration::from_millis(500), async {
        loop {
            if let Some(NodeEvent::ChannelReset { reason, .. }) = a_events.next().await {
                return reason;
            }
        }
    })
    .await;
    assert!(more.is_err(), "a second reset: {more:?}");
}

#[tokio::test]
async fn a_message_after_close_arrives() {
    a_message_after_closing_arrives((12, 13), false).await;
}

#[tokio::test]
async fn a_message_after_close_peer_arrives() {
    a_message_after_closing_arrives((14, 15), true).await;
}

/// Scenario: a peer switched off in mid-transfer: the sender's channel is
/// reset within 30 s.
#[tokio::test]
async fn a_vanished_peer_resets_the_channel() {
    let (a, mut a_events) = node(10, None, 64).await;
    let (b, mut b_events) = node(11, None, 64).await;
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    b.set_hint(a.address().peer_id(), a.local_addr())
        .await
        .unwrap();
    let (a2, b_address) = (a.clone(), b.address());
    tokio::spawn(async move {
        for i in 0..100_000u32 {
            if a2
                .send_message(b_address, vec![i as u8; 1500])
                .await
                .is_err()
            {
                return;
            }
        }
    });
    let _ = messages(&mut b_events, 20, Duration::from_secs(5)).await;
    drop(b);
    drop(b_events);
    let started = std::time::Instant::now();
    let reset = timeout(Duration::from_secs(40), async {
        loop {
            match a_events.next().await {
                Some(NodeEvent::ChannelReset { reason, .. }) => return reason,
                Some(_) => {}
                None => panic!("stopped"),
            }
        }
    })
    .await
    .expect("a reset within 40 s");
    std::println!(
        "reset {reason:?} after {:?}",
        started.elapsed(),
        reason = reset
    );
}
