//! What the application is told about its relay, over the loopback and a
//! relay in the same process (`DESIGN.md §6`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::Duration;

use convesso_core::endpoint::RelayError;
use convesso_core::handshake::{DialError, RefusalCode};
use convesso_core::identity::{Identity, PeerId};
use convesso_relay::{Admit, Config as RelayConfig, Open, Policy, Relay};
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::{Config, Events, Node, NodeEvent, RelayLocation};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{Instant, timeout_at};

fn identity(seed: u8) -> Identity {
    Identity::from_ed25519_seed(&[seed; 32]).unwrap()
}

/// A relay shedding load: it refuses everyone, as busy.
struct Busy;

impl Policy for Busy {
    fn admit(&mut self, _peer: &PeerId) -> Admit {
        Admit::Refuse(RefusalCode::BUSY)
    }
}

async fn relay_with<P: Policy + Send + 'static>(policy: P) -> RelayLocation {
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
        policy,
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

async fn node(seed: u8, relay: &RelayLocation) -> (Node, Events) {
    convesso_tokio::start(
        identity(seed),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            relay: Some(relay.clone()),
            ..Config::default()
        },
    )
    .await
    .unwrap()
}

/// The relay events within `secs`.
async fn relay_events(events: &mut Events, secs: u64) -> Vec<NodeEvent> {
    let end = Instant::now() + Duration::from_secs(secs);
    let mut got = Vec::new();
    while let Ok(Some(event)) = timeout_at(end, events.next()).await {
        if matches!(
            event,
            NodeEvent::RelayAvailable | NodeEvent::RelayUnavailable { .. }
        ) {
            got.push(event);
        }
    }
    got
}

/// Scenario: a client is told when it is registered: a reachable node gets
/// one relay-available event, and no relay-unavailable one.
#[tokio::test]
async fn a_reachable_node_is_told_its_relay_is_available() {
    let relay = relay_with(Open).await;
    let (node, mut events) = node(1, &relay).await;
    node.set_reachable(true).await.unwrap();
    assert_eq!(
        relay_events(&mut events, 3).await,
        vec![NodeEvent::RelayAvailable]
    );
}

/// Scenario: a refused client is told once per attempt: over ten seconds, a
/// node its relay refuses gets one relay-unavailable event per attempt,
/// naming the refusal, as few as the backoff allows, and never
/// relay-available.
#[tokio::test]
async fn a_refused_node_is_told_once_per_attempt() {
    let relay = relay_with(Busy).await;
    let (node, mut events) = node(2, &relay).await;
    node.set_reachable(true).await.unwrap();
    let got = relay_events(&mut events, 10).await;
    std::println!("{got:?}");
    let opened = node.stats().await.unwrap().links_opened;
    assert!(!got.contains(&NodeEvent::RelayAvailable));
    // Backoff of 1, 2, 4 s and jitter: at most 4 attempts in 10 s, where the
    // relay used to be dialled 8 times a second.
    assert!((1..=4).contains(&got.len()), "{got:?}");
    assert!(got.len() as u64 <= opened, "{got:?} for {opened} links");
    assert!(got.contains(&NodeEvent::RelayUnavailable {
        error: RelayError::Dial(DialError::Refused(RefusalCode::BUSY)),
    }));
}
