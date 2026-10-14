//! The tokio driver on real sockets, over the loopback, against a relay in
//! the same process (`DESIGN.md §5`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::time::Duration;

use convesso_core::endpoint::SendError;
use convesso_core::handshake::Entropy;
use convesso_core::identity::Identity;
use convesso_core::relay::Link;
use convesso_relay::{Config as RelayConfig, Open, Relay};
use convesso_tokio::entropy::{EntropyError, OsEntropy, SystemEntropy};
use convesso_tokio::{Config, Events, Node, NodeError, NodeEvent, RelayLocation, StartError};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

fn identity(seed: u8) -> Identity {
    Identity::from_ed25519_seed(&[seed; 32]).unwrap()
}

/// A relay on the loopback, UDP and TCP on one port; returns where it is.
async fn relay() -> RelayLocation {
    let identity = identity(100);
    let address = *identity.address();
    // UDP and TCP on one port: a port the system gives for UDP may be one it
    // reserves for TCP (Windows), so try until both bind.
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

/// The next datagram event, skipping others, within two seconds.
async fn datagram(events: &mut Events) -> (Vec<u8>, bool) {
    timeout(Duration::from_secs(2), async {
        loop {
            match events.next().await {
                Some(NodeEvent::Datagram { data, relayed, .. }) => return (data, relayed),
                Some(_) => {}
                None => panic!("the node stopped"),
            }
        }
    })
    .await
    .expect("a datagram within two seconds")
}

/// Waits until `node` has an established link: it answered keep-alives.
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

// --- the start ------------------------------------------------------------------------

struct Failing;

impl Entropy for Failing {
    fn fill(&mut self, _dest: &mut [u8]) {
        unreachable!("never used: the check fails first")
    }
}

impl SystemEntropy for Failing {
    fn check(&mut self) -> Result<(), EntropyError> {
        Err(EntropyError("injected".into()))
    }
}

/// Scenario: a generator failure stops the start, before any socket exists.
#[tokio::test]
async fn a_generator_failure_stops_the_start() {
    let result = convesso_tokio::start_with(identity(1), Config::default(), Failing).await;
    match result {
        Err(StartError::Entropy(error)) => assert!(error.to_string().contains("generator")),
        Err(other) => panic!("another error: {other}"),
        Ok(_) => panic!("a node started without entropy"),
    }
}

// --- datagrams through a relay, and the paths -----------------------------------------

/// Scenario: two applications exchange datagrams through a relay, knowing
/// only each other's key and the relay's; and every packet their sockets sent
/// is one the core output, on the path it named.
#[tokio::test]
async fn two_nodes_exchange_datagrams_through_a_relay() {
    let relay = relay().await;
    let (a, mut a_events) = node(1, Some(&relay), 64).await;
    let (b, mut b_events) = node(2, Some(&relay), 64).await;
    reachable(&b).await;
    a.send(b.address(), b"hello from a".to_vec()).await.unwrap();
    assert_eq!(
        datagram(&mut b_events).await,
        (b"hello from a".to_vec(), true)
    );
    b.send(a.address(), b"hello from b".to_vec()).await.unwrap();
    assert_eq!(
        datagram(&mut a_events).await,
        (b"hello from b".to_vec(), true)
    );
    for node in [&a, &b] {
        let stats = node.stats().await.unwrap();
        assert_eq!(stats.udp_sent, stats.core_udp_outputs, "{stats:?}");
        assert_eq!(
            stats.frames_sent + stats.keepalives_sent,
            stats.core_link_outputs,
            "{stats:?}"
        );
    }
}

/// Scenarios: with a hint, two applications talk directly, marked direct, and
/// B never needs the relay; A, which has a relay pinned, handles B's datagrams
/// as direct packets, not relay packets; the relay and the peer see the same
/// local port.
#[tokio::test]
async fn a_hint_gives_a_direct_path_on_the_same_socket() {
    let relay = relay().await;
    let (a, mut a_events) = node(3, Some(&relay), 64).await;
    let (b, mut b_events) = node(4, Some(&relay), 64).await;
    let (c, mut c_events) = node(10, Some(&relay), 64).await;
    // A sends to C through the relay first: its UDP to the relay is proven,
    // and the relay reports the address it sees. At rest it would not be.
    reachable(&c).await;
    a.send(c.address(), b"through the relay".to_vec())
        .await
        .unwrap();
    assert_eq!(
        datagram(&mut c_events).await,
        (b"through the relay".to_vec(), true)
    );
    let observed = timeout(Duration::from_secs(2), async {
        loop {
            match a_events.next().await {
                Some(NodeEvent::ObservedAddress {
                    link: Link::Udp,
                    address,
                }) => return address,
                Some(_) => {}
                None => panic!("the node stopped"),
            }
        }
    })
    .await
    .expect("the relay reports the UDP address it sees");
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    a.send(b.address(), b"over the loopback".to_vec())
        .await
        .unwrap();
    assert_eq!(
        datagram(&mut b_events).await,
        (b"over the loopback".to_vec(), false)
    );
    b.send(a.address(), b"and back".to_vec()).await.unwrap();
    assert_eq!(datagram(&mut a_events).await, (b"and back".to_vec(), false));
    // One socket: the port the relay saw is the one B's datagrams came from.
    assert_eq!(observed.port(), a.local_addr().port());
    let stats = b.stats().await.unwrap();
    assert_eq!(stats.links_opened, 0, "B never needed the relay");
}

/// Scenario: a send's error reaches the application, and nothing is sent.
#[tokio::test]
async fn a_send_error_reaches_the_application() {
    let relay = relay().await;
    let (a, _a_events) = node(5, Some(&relay), 64).await;
    let (b, _b_events) = node(6, Some(&relay), 64).await;
    let before = a.stats().await.unwrap();
    assert!(matches!(
        a.send(b.address(), vec![0; 2000]).await,
        Err(NodeError::Send(SendError::TooLarge { .. }))
    ));
    let (c, _c_events) = node(7, None, 64).await;
    assert_eq!(
        c.send(b.address(), b"no relay, no hint".to_vec()).await,
        Err(NodeError::Send(SendError::NoPath))
    );
    assert_eq!(a.stats().await.unwrap().udp_sent, before.udp_sent);
}

/// Scenario: a slow reader loses no event: while the application does not
/// read, the node stops (it answers nothing, so it reads no socket either),
/// and every datagram is there once it reads again.
#[tokio::test]
async fn a_slow_reader_loses_no_event() {
    let (a, _a_events) = node(8, None, 64).await;
    let (b, mut b_events) = node(9, None, 2).await;
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    b.set_hint(a.address().peer_id(), a.local_addr())
        .await
        .unwrap();
    a.send(b.address(), b"open".to_vec()).await.unwrap();
    assert_eq!(datagram(&mut b_events).await.0, b"open".to_vec());
    for i in 0u8..20 {
        a.send(b.address(), vec![i; 8]).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    // B is blocked on its full event channel: it does not even answer.
    assert!(
        timeout(Duration::from_millis(200), b.stats())
            .await
            .is_err()
    );
    let mut got = Vec::new();
    while got.len() < 20 {
        got.push(datagram(&mut b_events).await.0);
    }
    assert_eq!(got, (0u8..20).map(|i| vec![i; 8]).collect::<Vec<_>>());
    assert!(timeout(Duration::from_millis(500), b.stats()).await.is_ok());
}
