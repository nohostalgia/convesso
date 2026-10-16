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
use convesso_tokio::{
    Config, Context, ContextEvent, ContextEvents, ContextOptions, Events, Node, RelayLocation,
};
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
        tls: false,
    }
}

/// A node with the context `app`, `events` of it waiting at most.
async fn node(
    seed: u8,
    relay: Option<&RelayLocation>,
    events: usize,
) -> (Node, Events, Context, ContextEvents) {
    let (node, node_events) = convesso_tokio::start(
        identity(seed),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            relay: relay.cloned(),
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let (app, app_events) = open(&node, b"app", events).await;
    (node, node_events, app, app_events)
}

async fn open(node: &Node, name: &[u8], events: usize) -> (Context, ContextEvents) {
    node.context(
        name,
        ContextOptions {
            events,
            ..ContextOptions::default()
        },
    )
    .await
    .unwrap()
}

async fn hints(a: &Node, b: &Node) {
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    b.set_hint(a.address().peer_id(), a.local_addr())
        .await
        .unwrap();
}

/// The next channel reset, skipping other events, within `within`.
async fn reset(events: &mut ContextEvents, within: Duration) -> convesso_stream::Reason {
    timeout(within, async {
        loop {
            match events.next().await {
                Some(ContextEvent::ChannelReset { reason, .. }) => return reason,
                Some(_) => {}
                None => panic!("the context closed"),
            }
        }
    })
    .await
    .expect("a reset in time")
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
async fn messages(
    events: &mut ContextEvents,
    count: usize,
    within: Duration,
) -> Vec<(PeerId, Vec<u8>)> {
    timeout(within, async {
        let mut got = Vec::new();
        while got.len() < count {
            match events.next().await {
                Some(ContextEvent::Message { peer, data }) => got.push((peer, data)),
                Some(ContextEvent::ChannelReset { reason, .. }) => panic!("a reset: {reason:?}"),
                Some(_) => {}
                None => panic!("the context closed"),
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
    let (a, _a_node, a_app, mut a_events) = node(1, Some(&relay), 64).await;
    let (b, _b_node, b_app, mut b_events) = node(2, Some(&relay), 64).await;
    reachable(&b).await;
    reachable(&a).await;
    let sent: Vec<_> = (0..100).map(message).collect();
    let (a2, b_address, sent_a) = (a_app.clone(), b.address(), sent.clone());
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
        b_app
            .send_message_to_peer(a.address().peer_id(), m.clone())
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
    let (a, _a_node, a_app, _a_events) = node(8, None, 64).await;
    let (b, _b_node, _b_app, mut b_events) = node(9, None, 2).await;
    hints(&a, &b).await;
    let sent: Vec<_> = (0..300).map(|i| vec![i as u8; 2000]).collect();
    let (a2, b_address, sent_a) = (a_app.clone(), b.address(), sent.clone());
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
    let (a, _a_node, a_app, mut a_events) = node(seeds.0, None, 64).await;
    let (b, _b_node, _b_app, mut b_events) = node(seeds.1, None, 64).await;
    let b_peer = b.address().peer_id();
    hints(&a, &b).await;
    a_app
        .send_message(b.address(), b"before".to_vec())
        .await
        .unwrap();
    let _ = messages(&mut b_events, 1, Duration::from_secs(5)).await;

    if revoke {
        a.close_peer(b_peer, 7).await.unwrap();
    } else {
        a_app.close(b_peer, 7).await.unwrap();
    }
    let closed = convesso_stream::Reason::SessionClosed { code: 7 };
    assert_eq!(reset(&mut a_events, Duration::from_secs(5)).await, closed);

    a_app
        .send_message(b.address(), b"after".to_vec())
        .await
        .unwrap();
    let got = timeout(Duration::from_secs(5), async {
        loop {
            match b_events.next().await {
                Some(ContextEvent::Message { data, .. }) => return data,
                Some(ContextEvent::ChannelReset { reason, .. }) => assert_eq!(reason, closed),
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
            if let Some(ContextEvent::ChannelReset { reason, .. }) = a_events.next().await {
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
/// reset within 30 s. B runs on a runtime of its own, shut down at once: its
/// task ends without closing anything, as a process killed would.
#[tokio::test(flavor = "multi_thread")]
async fn a_vanished_peer_resets_the_channel() {
    let (a, _a_node, a_app, mut a_events) = node(10, None, 64).await;
    let elsewhere = tokio::runtime::Runtime::new().unwrap();
    let (b, b_node, b_app, mut b_events) = elsewhere
        .spawn(async { node(11, None, 64).await })
        .await
        .unwrap();
    hints(&a, &b).await;
    let (a2, b_address) = (a_app.clone(), b.address());
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
    elsewhere.shutdown_background();
    // Its handles never drop: a dropped context would close its sessions.
    std::mem::forget((b, b_node, b_app, b_events));
    let started = std::time::Instant::now();
    let reset = reset(&mut a_events, Duration::from_secs(40)).await;
    std::println!(
        "reset {reason:?} after {:?}",
        started.elapsed(),
        reason = reset
    );
}

/// Scenario: a slow reader of one context's messages holds back no other
/// context: the messages in the other keep arriving, and the sender waits only
/// in the unread one.
#[tokio::test]
async fn a_slow_reader_of_one_contexts_messages_holds_back_no_other() {
    let (a, _a_node, a_app, _a_events) = node(16, None, 64).await;
    let (a_other, _a_other_events) = open(&a, b"other", 64).await;
    let (b, _b_node, _b_app, mut b_slow) = node(17, None, 2).await;
    let (_b_other, mut b_other) = open(&b, b"other", 64).await;
    hints(&a, &b).await;
    let b_address = b.address();
    // A clone: the context stays open after the last send, until it arrives.
    let a_slow = a_app.clone();
    let slow = tokio::spawn(async move {
        for i in 0..300u32 {
            a_slow
                .send_message(b_address, vec![i as u8; 2000])
                .await
                .unwrap();
        }
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    let sent: Vec<_> = (0..50).map(message).collect();
    for m in &sent {
        a_other.send_message(b_address, m.clone()).await.unwrap();
    }
    let got = messages(&mut b_other, 50, Duration::from_secs(10)).await;
    assert_eq!(got.into_iter().map(|(_, m)| m).collect::<Vec<_>>(), sent);
    assert!(!slow.is_finished(), "the unread context's sender waits");
    let got = messages(&mut b_slow, 300, Duration::from_secs(30)).await;
    assert_eq!(got.len(), 300);
    slow.await.unwrap();
}
