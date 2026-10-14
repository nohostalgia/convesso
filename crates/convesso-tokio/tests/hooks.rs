//! What the tokio driver gives an application beyond sending: the candidates,
//! the excluded prefixes, the channel binding, and the socket hook
//! (`DESIGN.md §5`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use convesso_core::endpoint::ExcludeError;
use convesso_core::identity::Identity;
use convesso_core::paths::CandidateKind;
use convesso_relay::{Config as RelayConfig, Open, Relay};
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::{
    Config, Events, Node, NodeError, NodeEvent, RelayLocation, SocketHandle, SocketHook, StartError,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

fn identity(seed: u8) -> Identity {
    Identity::from_ed25519_seed(&[seed; 32]).unwrap()
}

/// A relay on the loopback, UDP and TCP on one port; returns where it is.
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

async fn node(seed: u8, config: Config) -> (Node, Events) {
    convesso_tokio::start(identity(seed), config).await.unwrap()
}

fn loopback() -> Config {
    Config {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..Config::default()
    }
}

/// Whether the socket behind `handle` is still unused: not bound to a port,
/// not connected.
fn unused(handle: SocketHandle) -> bool {
    // SAFETY: the driver owns the socket and keeps it open while the hook
    // runs; the borrow ends before the hook returns.
    #[cfg(unix)]
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(handle) };
    // SAFETY: as above.
    #[cfg(windows)]
    let borrowed = unsafe { std::os::windows::io::BorrowedSocket::borrow_raw(handle) };
    let socket = socket2::SockRef::from(&borrowed);
    let unbound = socket.local_addr().map_or(true, |local| {
        local.as_socket().is_none_or(|a| a.port() == 0)
    });
    unbound && socket.peer_addr().is_err()
}

// --- the channel binding --------------------------------------------------------------

/// Scenario: two nodes on the tokio driver agree on the binding, and a node
/// with no session with a peer gets nothing.
#[tokio::test]
async fn two_nodes_agree_on_the_binding() {
    let (a, _a_events) = node(1, loopback()).await;
    let (b, mut b_events) = node(2, loopback()).await;
    let stranger = identity(3).peer_id();
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    a.send(b.address(), b"hello".to_vec()).await.unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            if let Some(NodeEvent::Datagram { .. }) = b_events.next().await {
                return;
            }
        }
    })
    .await
    .expect("a datagram within two seconds");

    let at_a = a.channel_binding(b.address().peer_id()).await.unwrap();
    let at_b = b.channel_binding(a.address().peer_id()).await.unwrap();
    assert!(at_a.is_some());
    assert_eq!(at_a, at_b);
    assert_eq!(a.channel_binding(stranger).await.unwrap(), None);
}

// --- the candidates and the excluded prefixes ---------------------------------------

/// Scenario: an excluded prefix leaves the candidates, and comes back when the
/// set is replaced without it.
#[tokio::test]
async fn an_excluded_prefix_leaves_the_candidates() {
    let (node, _events) = node(4, Config::default()).await;
    let locals = |candidates: &[convesso_core::paths::Candidate]| -> Vec<SocketAddr> {
        candidates
            .iter()
            .filter(|c| c.kind == CandidateKind::Local)
            .map(|c| c.address)
            .collect()
    };
    let before = locals(&node.candidates().await.unwrap());
    let Some(first) = before.first().copied() else {
        panic!("a host with no interface but loopback: nothing to exclude");
    };
    let len = if first.is_ipv4() { 32 } else { 128 };
    node.exclude_prefix(first.ip(), len).await.unwrap();
    let excluded = locals(&node.candidates().await.unwrap());
    assert!(!excluded.contains(&first), "{excluded:?}");

    node.set_excluded(Vec::new()).await.unwrap();
    let after = locals(&node.candidates().await.unwrap());
    assert!(after.contains(&first), "{after:?}");
}

/// Scenario: a prefix longer than its address is refused with the core's
/// error, and the set is unchanged; so is a set over the bound.
#[tokio::test]
async fn a_prefix_longer_than_its_address_is_refused() {
    let (node, _events) = node(5, loopback()).await;
    let ten: IpAddr = "10.0.0.0".parse().unwrap();
    assert_eq!(
        node.exclude_prefix(ten, 33).await,
        Err(NodeError::Exclude(ExcludeError::TooLong { len: 33 }))
    );
    let seventeen = (0..17).map(|i| (IpAddr::from([10, i, 0, 0]), 16)).collect();
    assert_eq!(
        node.set_excluded(seventeen).await,
        Err(NodeError::Exclude(ExcludeError::Full { bound: 16 }))
    );
    node.exclude_prefix(ten, 8).await.unwrap();
}

// --- the socket hook --------------------------------------------------------------------

/// Scenario: the hook sees the UDP socket, and each TCP connection to the
/// relay, each before it is used.
#[tokio::test]
async fn the_hook_sees_both_sockets() {
    let relay = relay().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let early = Arc::new(AtomicUsize::new(0));
    let hook: SocketHook = {
        let (calls, early) = (calls.clone(), early.clone());
        Arc::new(move |handle| {
            calls.fetch_add(1, Ordering::SeqCst);
            if unused(handle) {
                early.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        })
    };
    let (node, _events) = node(
        6,
        Config {
            relay: Some(relay),
            socket_hook: Some(hook),
            ..loopback()
        },
    )
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the UDP socket, at start");

    node.set_reachable(true).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while node.stats().await.unwrap().keepalives_received == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a link within two seconds");
    let links = node.stats().await.unwrap().links_opened;
    assert!(links >= 1);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1 + usize::try_from(links).unwrap()
    );
    assert_eq!(early.load(Ordering::SeqCst), calls.load(Ordering::SeqCst));
}

/// Scenario: a hook that fails stops the start.
#[tokio::test]
async fn a_hook_that_fails_stops_the_start() {
    let hook: SocketHook = Arc::new(|_| Err(std::io::Error::other("refused by the hook")));
    let result = convesso_tokio::start(
        identity(7),
        Config {
            socket_hook: Some(hook),
            ..loopback()
        },
    )
    .await;
    match result {
        Err(StartError::Hook(error)) => assert_eq!(error.to_string(), "refused by the hook"),
        Err(other) => panic!("another error: {other}"),
        Ok(_) => panic!("a node started past its hook"),
    }
}

/// A hook that refuses the relay's TCP connection: no link opens, and the
/// core asks for one again.
#[tokio::test]
async fn a_refused_relay_connection_opens_no_link() {
    let relay = relay().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let hook: SocketHook = {
        let calls = calls.clone();
        Arc::new(move |_| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::other("no relay link"))
            }
        })
    };
    let (node, _events) = node(
        8,
        Config {
            relay: Some(relay),
            socket_hook: Some(hook),
            ..loopback()
        },
    )
    .await;
    node.set_reachable(true).await.unwrap();
    timeout(Duration::from_secs(5), async {
        while calls.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the link is tried again");
    assert_eq!(node.stats().await.unwrap().links_opened, 0);
}
