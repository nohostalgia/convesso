//! The tokio driver on real sockets, over the loopback, against a relay in
//! the same process (`DESIGN.md §5`): the node, and a handle per context.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::time::Duration;

use convesso_core::endpoint::SendError;
use convesso_core::handshake::{Admission, Decision, Entropy, RefusalCode, ResponderError};
use convesso_core::identity::{Identity, PeerId};
use convesso_core::relay::Link;
use convesso_relay::{Config as RelayConfig, Open, Relay};
use convesso_tokio::entropy::{EntropyError, OsEntropy, SystemEntropy};
use convesso_tokio::{
    Access, Config, Context, ContextEvent, ContextEvents, ContextOptions, Events, Node, NodeError,
    NodeEvent, RelayLocation, StartError,
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

async fn start(seed: u8, relay: Option<&RelayLocation>) -> (Node, Events) {
    convesso_tokio::start(
        identity(seed),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            relay: relay.cloned(),
            ..Config::default()
        },
    )
    .await
    .unwrap()
}

/// Opens `name` on `node`, everyone admitted, `events` waiting at most.
async fn open(node: &Node, name: &[u8], events: usize) -> (Context, ContextEvents) {
    open_with(node, name, Access::Everyone, events).await
}

async fn open_with(
    node: &Node,
    name: &[u8],
    access: Access,
    events: usize,
) -> (Context, ContextEvents) {
    node.context(
        name,
        ContextOptions {
            access,
            events,
            ..ContextOptions::default()
        },
    )
    .await
    .unwrap()
}

/// A node with one context, `app`.
async fn node(
    seed: u8,
    relay: Option<&RelayLocation>,
    events: usize,
) -> (Node, Events, Context, ContextEvents) {
    let (node, node_events) = start(seed, relay).await;
    let (app, app_events) = open(&node, b"app", events).await;
    (node, node_events, app, app_events)
}

/// The next event that `pick` takes, skipping others, within two seconds.
async fn next<T>(events: &mut ContextEvents, mut pick: impl FnMut(ContextEvent) -> Option<T>) -> T {
    timeout(Duration::from_secs(2), async {
        loop {
            match events.next().await {
                Some(event) => {
                    if let Some(found) = pick(event) {
                        return found;
                    }
                }
                None => panic!("the context closed"),
            }
        }
    })
    .await
    .expect("an event within two seconds")
}

/// The next datagram event, skipping others, within two seconds.
async fn datagram(events: &mut ContextEvents) -> (Vec<u8>, bool) {
    next(events, |event| match event {
        ContextEvent::Datagram { data, relayed, .. } => Some((data, relayed)),
        _ => None,
    })
    .await
}

/// The next close, skipping others, within two seconds.
async fn closed(events: &mut ContextEvents) -> (PeerId, u16, bool) {
    next(events, |event| match event {
        ContextEvent::Closed {
            peer,
            code,
            by_peer,
        } => Some((peer, code, by_peer)),
        _ => None,
    })
    .await
}

/// Every event already waiting, without waiting for more.
async fn waiting(events: &mut ContextEvents) -> Vec<ContextEvent> {
    let mut got = Vec::new();
    while let Ok(Some(event)) = timeout(Duration::from_millis(50), events.next()).await {
        got.push(event);
    }
    got
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

/// Gives each of two nodes the other's address.
async fn hints(a: &Node, b: &Node) {
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    b.set_hint(a.address().peer_id(), a.local_addr())
        .await
        .unwrap();
}

/// Waits `ms` milliseconds of real time: what a packet over the loopback
/// takes, with room.
async fn settle(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
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
    let (a, _a_node, a_app, mut a_events) = node(1, Some(&relay), 64).await;
    let (b, _b_node, b_app, mut b_events) = node(2, Some(&relay), 64).await;
    reachable(&b).await;
    a_app
        .send(b.address(), b"hello from a".to_vec())
        .await
        .unwrap();
    assert_eq!(
        datagram(&mut b_events).await,
        (b"hello from a".to_vec(), true)
    );
    b_app
        .send(a.address(), b"hello from b".to_vec())
        .await
        .unwrap();
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
    let (a, mut a_node, a_app, mut a_events) = node(3, Some(&relay), 64).await;
    let (b, _b_node, b_app, mut b_events) = node(4, Some(&relay), 64).await;
    let (c, _c_node, _c_app, mut c_events) = node(10, Some(&relay), 64).await;
    // A sends to C through the relay first: its UDP to the relay is proven,
    // and the relay reports the address it sees. At rest it would not be.
    reachable(&c).await;
    a_app
        .send(c.address(), b"through the relay".to_vec())
        .await
        .unwrap();
    assert_eq!(
        datagram(&mut c_events).await,
        (b"through the relay".to_vec(), true)
    );
    let observed = timeout(Duration::from_secs(2), async {
        loop {
            match a_node.next().await {
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
    a_app
        .send(b.address(), b"over the loopback".to_vec())
        .await
        .unwrap();
    assert_eq!(
        datagram(&mut b_events).await,
        (b"over the loopback".to_vec(), false)
    );
    b_app.send(a.address(), b"and back".to_vec()).await.unwrap();
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
    let (a, _a_node, a_app, _a_events) = node(5, Some(&relay), 64).await;
    let (b, _b_node, _b_app, _b_events) = node(6, Some(&relay), 64).await;
    let before = a.stats().await.unwrap();
    assert!(matches!(
        a_app.send(b.address(), vec![0; 2000]).await,
        Err(NodeError::Send(SendError::TooLarge { .. }))
    ));
    let (_c, _c_node, c_app, _c_events) = node(7, None, 64).await;
    assert_eq!(
        c_app.send(b.address(), b"no relay, no hint".to_vec()).await,
        Err(NodeError::Send(SendError::NoPath))
    );
    assert_eq!(a.stats().await.unwrap().udp_sent, before.udp_sent);
}

// --- contexts ---------------------------------------------------------------------------

/// Scenario: two libraries on one node see only their own: each handle's
/// stream carries its context's connection and datagrams alone, and closing
/// the session in one leaves the other's.
#[tokio::test]
async fn two_libraries_on_one_node_see_only_their_own() {
    let (a, _a_node) = start(11, None).await;
    let (b, _b_node) = start(12, None).await;
    hints(&a, &b).await;
    let (a_chat, _a_chat_events) = open(&a, b"example.org/chat/1", 64).await;
    let (a_files, _a_files_events) = open(&a, b"example.org/files/1", 64).await;
    let (_b_chat, mut b_chat_events) = open(&b, b"example.org/chat/1", 64).await;
    let (_b_files, mut b_files_events) = open(&b, b"example.org/files/1", 64).await;

    a_chat.send(b.address(), b"chat".to_vec()).await.unwrap();
    a_files.send(b.address(), b"files".to_vec()).await.unwrap();
    assert_eq!(datagram(&mut b_chat_events).await.0, b"chat".to_vec());
    assert_eq!(datagram(&mut b_files_events).await.0, b"files".to_vec());
    settle(100).await;
    assert!(waiting(&mut b_chat_events).await.is_empty());
    assert!(waiting(&mut b_files_events).await.is_empty());

    a_chat.close(b.address().peer_id(), 0x0100).await.unwrap();
    let a_peer = a.address().peer_id();
    assert_eq!(closed(&mut b_chat_events).await, (a_peer, 0x0100, true));
    a_files
        .send(b.address(), b"still here".to_vec())
        .await
        .unwrap();
    assert_eq!(
        datagram(&mut b_files_events).await.0,
        b"still here".to_vec()
    );
    assert!(waiting(&mut b_files_events).await.is_empty());
}

/// Scenario: a dropped handle closes its context: both peers' sessions in it
/// are closed with an authenticated close, the context is no longer served,
/// and the node's other contexts go on.
#[tokio::test]
async fn a_dropped_handle_closes_its_context() {
    let (a, _a_node, a_app, _a_events) = node(13, None, 64).await;
    let (b, _b_node, b_app, mut b_events) = node(14, None, 64).await;
    let (c, _c_node, c_app, mut c_events) = node(15, None, 64).await;
    let (a_other, _a_other_events) = open(&a, b"other", 64).await;
    let (_b_other, mut b_other_events) = open(&b, b"other", 64).await;
    hints(&a, &b).await;
    hints(&a, &c).await;
    b_app.send(a.address(), b"b".to_vec()).await.unwrap();
    c_app.send(a.address(), b"c".to_vec()).await.unwrap();
    a_other.send(b.address(), b"other".to_vec()).await.unwrap();
    assert_eq!(datagram(&mut b_other_events).await.0, b"other".to_vec());
    settle(200).await;

    drop(a_app);
    let a_peer = a.address().peer_id();
    assert_eq!(
        closed(&mut b_events).await,
        (a_peer, convesso_tokio::DROPPED, true)
    );
    assert_eq!(
        closed(&mut c_events).await,
        (a_peer, convesso_tokio::DROPPED, true)
    );
    // No longer served: B's datagram in it starts a handshake that meets
    // silence.
    let sent = a.stats().await.unwrap().udp_sent;
    b_app.send(a.address(), b"again".to_vec()).await.unwrap();
    settle(300).await;
    assert_eq!(a.stats().await.unwrap().udp_sent, sent, "A answers nothing");
    // The other context goes on.
    a_other
        .send(b.address(), b"other again".to_vec())
        .await
        .unwrap();
    assert_eq!(
        datagram(&mut b_other_events).await.0,
        b"other again".to_vec()
    );
}

/// Scenario: a dial-only context is reached by no one: the session it dials
/// carries datagrams both ways, and another peer's first contact meets
/// silence.
#[tokio::test]
async fn a_dial_only_context_is_reached_by_no_one() {
    let (a, _a_node) = start(16, None).await;
    let (a_app, mut a_events) = open_with(&a, b"app", Access::DialOnly, 64).await;
    let (b, _b_node, b_app, mut b_events) = node(17, None, 64).await;
    let (c, _c_node, c_app, _c_events) = node(18, None, 64).await;
    hints(&a, &b).await;
    hints(&a, &c).await;

    a_app.send(b.address(), b"out".to_vec()).await.unwrap();
    assert_eq!(datagram(&mut b_events).await.0, b"out".to_vec());
    b_app.send(a.address(), b"back".to_vec()).await.unwrap();
    assert_eq!(datagram(&mut a_events).await.0, b"back".to_vec());

    let sent = a.stats().await.unwrap().udp_sent;
    c_app.send(a.address(), b"knock".to_vec()).await.unwrap();
    settle(300).await;
    assert_eq!(a.stats().await.unwrap().udp_sent, sent, "silence towards C");
    assert!(waiting(&mut a_events).await.is_empty());
}

/// Scenario: a context opened twice is refused, and so is the relay context;
/// the open context is unchanged.
#[tokio::test]
async fn a_context_opened_twice_is_refused() {
    let (a, _a_node, a_app, _a_events) = node(19, None, 64).await;
    let (b, _b_node, _b_app, mut b_events) = node(20, None, 64).await;
    hints(&a, &b).await;
    for access in [Access::Everyone, Access::DialOnly] {
        let refused = a
            .context(
                b"app",
                ContextOptions {
                    access,
                    ..ContextOptions::default()
                },
            )
            .await;
        assert!(matches!(
            refused,
            Err(NodeError::Context(ResponderError::AlreadyServed))
        ));
    }
    assert!(matches!(
        a.context(convesso_core::relay::CONTEXT, ContextOptions::default())
            .await,
        Err(NodeError::Context(ResponderError::RelayContext))
    ));
    a_app
        .send(b.address(), b"unchanged".to_vec())
        .await
        .unwrap();
    assert_eq!(datagram(&mut b_events).await.0, b"unchanged".to_vec());
}

/// Admits the peers named, refusing every other with `0x0123`.
struct Only(Vec<PeerId>);

impl Admission for Only {
    fn admit(&mut self, peer: &PeerId, _context: &[u8]) -> Decision {
        if self.0.contains(peer) {
            Decision::Accept { psk: None }
        } else {
            Decision::Refuse {
                code: RefusalCode::application(0x0123).unwrap(),
                psk: None,
            }
        }
    }
}

/// Scenario: a narrowed access closes the sessions no longer admitted: from a
/// policy admitting A and B to one bound to A.
#[tokio::test]
async fn a_narrowed_access_closes_the_sessions_no_longer_admitted() {
    let (a, _a_node, a_app, mut a_events) = node(21, None, 64).await;
    let (b, _b_node, b_app, mut b_events) = node(22, None, 64).await;
    let (s, _s_node) = start(23, None).await;
    let policy = Only(vec![a.address().peer_id(), b.address().peer_id()]);
    let (s_app, mut s_events) = open_with(&s, b"app", Access::Admit(Box::new(policy)), 64).await;
    hints(&s, &a).await;
    hints(&s, &b).await;
    a_app.send(s.address(), b"a".to_vec()).await.unwrap();
    b_app.send(s.address(), b"b".to_vec()).await.unwrap();
    datagram(&mut s_events).await;
    datagram(&mut s_events).await;

    s_app
        .set_access(Access::Bound(a.address().peer_id()), 0x0200)
        .await
        .unwrap();
    let s_peer = s.address().peer_id();
    assert_eq!(closed(&mut b_events).await, (s_peer, 0x0200, true));
    s_app
        .send(a.address(), b"still admitted".to_vec())
        .await
        .unwrap();
    assert_eq!(datagram(&mut a_events).await.0, b"still admitted".to_vec());
    assert!(
        !waiting(&mut a_events)
            .await
            .iter()
            .any(|e| matches!(e, ContextEvent::Closed { .. }))
    );
}

// --- the application's pace -------------------------------------------------------------

/// Scenario: a slow reader of one context holds back no other: the unread
/// context's datagrams beyond its stream's room are dropped and counted, the
/// other's keep arriving, and the node answers its commands.
#[tokio::test]
async fn a_slow_reader_of_one_context_holds_back_no_other() {
    let (a, _a_node, a_app, _a_events) = node(24, None, 64).await;
    let (a_fast, _a_fast_events) = open(&a, b"fast", 64).await;
    let (b, _b_node, _b_app, mut b_slow) = node(25, None, 4).await;
    let (_b_fast, mut b_fast) = open(&b, b"fast", 64).await;
    hints(&a, &b).await;
    a_app.send(b.address(), b"open".to_vec()).await.unwrap();
    a_fast.send(b.address(), b"open".to_vec()).await.unwrap();
    settle(200).await;
    // B reads nothing of `app` now.
    for i in 0u8..20 {
        a_app.send(b.address(), vec![i; 8]).await.unwrap();
        a_fast.send(b.address(), vec![i; 8]).await.unwrap();
    }
    settle(300).await;
    let stats = timeout(Duration::from_millis(200), b.stats())
        .await
        .expect("B answers while a stream is full")
        .unwrap();
    assert!(stats.udp_received >= 40, "B kept reading: {stats:?}");
    assert!(
        stats.datagrams_dropped >= 16,
        "beyond the room, dropped: {stats:?}"
    );
    let fast: Vec<Vec<u8>> = waiting(&mut b_fast)
        .await
        .into_iter()
        .filter_map(|e| match e {
            ContextEvent::Datagram { data, .. } => Some(data),
            _ => None,
        })
        .collect();
    assert_eq!(fast.len(), 21, "every datagram of the other context");
    let slow = waiting(&mut b_slow).await;
    assert_eq!(slow.len(), 4, "the slow context's stream holds its room");
}

/// Scenario: a full event stream loses no event without data: once the
/// application reads again, it finds each peer's latest connection or close.
#[tokio::test]
async fn a_full_event_stream_loses_no_event_without_data() {
    let (s, _s_node, s_app, mut s_events) = node(26, None, 1).await;
    let mut peers = Vec::new();
    for seed in 27..30 {
        let (p, p_node, p_app, p_events) = node(seed, None, 64).await;
        hints(&s, &p).await;
        peers.push((p, p_node, p_app, p_events));
    }
    // One event fills S's stream; the rest wait aside.
    for (p, ..) in &peers {
        s_app.send(p.address(), b"hi".to_vec()).await.unwrap();
    }
    settle(300).await;
    for (p, ..) in &peers[..2] {
        s_app.close(p.address().peer_id(), 0x0300).await.unwrap();
    }
    // The third peer closes its side.
    peers[2]
        .2
        .close(s.address().peer_id(), 0x0301)
        .await
        .unwrap();
    settle(300).await;
    let got = waiting(&mut s_events).await;
    for (i, (p, ..)) in peers.iter().enumerate() {
        let peer = p.address().peer_id();
        let latest = got
            .iter()
            .rev()
            .find(|e| match e {
                ContextEvent::Connected { peer: p } | ContextEvent::Closed { peer: p, .. } => {
                    *p == peer
                }
                _ => false,
            })
            .unwrap_or_else(|| panic!("peer {i}: no event in {got:?}"));
        if i == 2 {
            assert_eq!(
                *latest,
                ContextEvent::Closed {
                    peer,
                    code: 0x0301,
                    by_peer: true
                }
            );
        } else {
            assert!(
                matches!(latest, ContextEvent::Connected { .. }),
                "a close made here raises no event: {latest:?}"
            );
        }
    }
}
