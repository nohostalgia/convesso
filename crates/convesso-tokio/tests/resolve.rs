//! The relay's host resolved when the relay is needed (`DESIGN.md §5`): a node
//! starts and changes relay whatever the name server does, and asks it again
//! only with the link's attempts or its own packets for the relay.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use convesso_core::endpoint::{LinkFailure, RelayError};
use convesso_core::identity::Identity;
use convesso_relay::{Config as RelayConfig, Open, Relay};
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::{
    Config, Context, ContextEvent, ContextEvents, ContextOptions, Events, Node, NodeEvent,
    RelayLocation, Resolver,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

fn identity(seed: u8) -> Identity {
    Identity::from_ed25519_seed(&[seed; 32]).unwrap()
}

/// A relay on the loopback, UDP and TCP on one port, named `relay.test`;
/// returns where it is and its address.
async fn relay() -> (RelayLocation, SocketAddr) {
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
    let location = RelayLocation {
        address,
        host: format!("relay.test:{port}"),
        tls: false,
    };
    (location, SocketAddr::from(([127, 0, 0, 1], port)))
}

/// A name server that answers `at` once `failures` queries have failed, and
/// counts every query.
fn resolver(failures: usize, at: Option<SocketAddr>) -> (Resolver, Arc<AtomicUsize>) {
    let asked = Arc::new(AtomicUsize::new(0));
    let count = asked.clone();
    let resolver: Resolver = Arc::new(move |_host: String| {
        let n = count.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            match at {
                Some(at) if n >= failures => Ok(vec![at]),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no answer",
                )),
            }
        })
    });
    (resolver, asked)
}

async fn node(
    seed: u8,
    relay: Option<RelayLocation>,
    resolver: Option<Resolver>,
) -> (Node, Events, Context, ContextEvents) {
    let (node, events) = convesso_tokio::start(
        identity(seed),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            relay,
            resolver,
            ..Config::default()
        },
    )
    .await
    .expect("a node starts whatever the name server does");
    let (app, app_events) = node
        .context(b"app", ContextOptions::default())
        .await
        .unwrap();
    (node, events, app, app_events)
}

async fn datagram(events: &mut ContextEvents, secs: u64) -> Vec<u8> {
    timeout(Duration::from_secs(secs), async {
        loop {
            if let Some(ContextEvent::Datagram { data, .. }) = events.next().await {
                return data;
            }
        }
    })
    .await
    .expect("a datagram in time")
}

/// Scenario: a node starts with its relay's name unresolved, its relay
/// pinned, and reaches a peer at a hint.
#[tokio::test]
async fn a_node_starts_with_its_relays_name_unresolved() {
    let (location, _) = relay().await;
    let (never, _) = resolver(usize::MAX, None);
    let (a, _a_node, a_app, _a_events) = node(1, Some(location), Some(never)).await;
    let (b, _b_node, _b_app, mut b_events) = node(2, None, None).await;
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    a_app
        .send(b.address(), b"on the LAN".to_vec())
        .await
        .unwrap();
    assert_eq!(datagram(&mut b_events, 2).await, b"on the LAN");
}

/// Scenario: changing to a relay whose name does not resolve is accepted, and
/// the node goes on.
#[tokio::test]
async fn changing_to_a_relay_whose_name_does_not_resolve_is_accepted() {
    let (location, at) = relay().await;
    let (some, _) = resolver(0, Some(at));
    let (a, _a_node, _a_app, _a_events) = node(3, Some(location.clone()), Some(some)).await;
    let elsewhere = RelayLocation {
        host: "nowhere.invalid:7400".into(),
        address: *identity(101).address(),
        tls: false,
    };
    a.set_relay(Some(elsewhere)).await.unwrap();
    a.stats().await.unwrap();
}

/// Scenario: a name that resolves later brings the relay: a node keeping a
/// link sees two attempts fail while its relay's name does not resolve, then
/// registers, without a restart.
#[tokio::test]
async fn a_name_that_resolves_later_brings_the_relay() {
    let (location, at) = relay().await;
    let (late, asked) = resolver(3, Some(at));
    let (a, mut a_node, _a_app, _a_events) = node(4, Some(location), Some(late)).await;
    a.set_reachable(true).await.unwrap();
    let mut unavailable = 0;
    timeout(Duration::from_secs(10), async {
        loop {
            match a_node.next().await.expect("the node runs") {
                NodeEvent::RelayUnavailable {
                    error: RelayError::Link(LinkFailure::NotOpened),
                } => unavailable += 1,
                NodeEvent::RelayAvailable => return,
                _ => {}
            }
        }
    })
    .await
    .expect("registered once the name resolves");
    assert!(unavailable >= 2, "{unavailable} attempts failed first");
    assert!(asked.load(Ordering::SeqCst) >= 4);
}

/// A node without a link asks the name server when it has a packet for the
/// relay, once per backoff, and its dial's next attempt reaches the relay once
/// the name resolves: the session with the peer opens through it.
#[tokio::test]
async fn a_node_without_a_link_resolves_when_it_needs_the_relay() {
    let (location, at) = relay().await;
    let (b_resolver, _) = resolver(0, Some(at));
    let (b, mut b_node, _b_app, _b_events) =
        node(5, Some(location.clone()), Some(b_resolver)).await;
    b.set_reachable(true).await.unwrap();
    timeout(Duration::from_secs(3), async {
        while !matches!(b_node.next().await, Some(NodeEvent::RelayAvailable)) {}
    })
    .await
    .expect("B on the relay");

    // A's name server fails its first two answers: at start, and for A's
    // first packet for the relay; it answers the next.
    let (a_resolver, asked) = resolver(2, Some(at));
    let (_a, _a_node, a_app, mut a_events) = node(6, Some(location), Some(a_resolver)).await;
    assert_eq!(asked.load(Ordering::SeqCst), 1, "once, at start");
    a_app
        .send(b.address(), b"through the relay".to_vec())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        asked.load(Ordering::SeqCst),
        2,
        "once, for the first packet"
    );
    let peer = b.address().peer_id();
    timeout(Duration::from_secs(12), async {
        loop {
            if let Some(ContextEvent::Connected { peer: p }) = a_events.next().await
                && p == peer
            {
                return;
            }
        }
    })
    .await
    .expect("the dial reaches B through the relay once the name resolves");
    assert_eq!(
        asked.load(Ordering::SeqCst),
        3,
        "one more, after the backoff"
    );
}

/// Scenario: a node without a link asks no name server at rest.
#[tokio::test(start_paused = true)]
async fn a_node_without_a_link_asks_no_name_server_at_rest() {
    let (location, _) = relay().await;
    let (never, asked) = resolver(usize::MAX, None);
    let (_a, _a_node, _a_app, _a_events) = node(7, Some(location), Some(never)).await;
    let at_start = asked.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(asked.load(Ordering::SeqCst), at_start, "nothing in an hour");
}
