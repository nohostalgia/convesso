//! The per-peer delivery mode, and a driver that never waits on the
//! application, over the loopback and a relay in the same process
//! (`DESIGN.md §5`, `DESIGN.md §8`).

#![cfg(feature = "stream")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_precision_loss
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use convesso_core::handshake::RefusalCode;
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_relay::{Admit, Config as RelayConfig, Open, Policy, Relay};
use convesso_stream::Reason;
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::{
    Config, Context, ContextEvent, ContextEvents, ContextOptions, Delivery, ELEMENT_COST, Events,
    Node, NodeError, NodeEvent, Received, Receiver, RelayLocation, SessionClosed, Stats,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

const PER_PEER: Delivery = Delivery::PerPeer {
    messages: 300_000,
    datagrams: 64_000,
};

fn identity(seed: u8) -> Identity {
    Identity::from_ed25519_seed(&[seed; 32]).unwrap()
}

async fn relay() -> RelayLocation {
    relay_with(Open).await
}

/// A relay that refuses everyone.
struct RefuseAll;

impl Policy for RefuseAll {
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
        tls: false,
    }
}

/// A node and its one context, `app`, with what the tests here use of both.
#[derive(Clone)]
struct N {
    node: Node,
    app: Context,
    node_events: Arc<tokio::sync::Mutex<Events>>,
}

impl N {
    fn address(&self) -> Address {
        self.node.address()
    }

    fn local_addr(&self) -> SocketAddr {
        self.node.local_addr()
    }

    async fn send(&self, to: Address, data: Vec<u8>) -> Result<(), NodeError> {
        self.app.send(to, data).await
    }

    async fn send_message(&self, to: Address, data: Vec<u8>) -> Result<(), NodeError> {
        self.app.send_message(to, data).await
    }

    async fn receiver(&self, peer: PeerId) -> Result<Receiver, NodeError> {
        self.app.receiver(peer).await
    }

    async fn close(&self, peer: PeerId, code: u16) -> Result<(), NodeError> {
        self.app.close(peer, code).await
    }

    async fn stats(&self) -> Result<Stats, NodeError> {
        self.node.stats().await
    }

    async fn set_hint(&self, peer: PeerId, at: SocketAddr) -> Result<(), NodeError> {
        self.node.set_hint(peer, at).await
    }

    async fn set_reachable(&self, on: bool) -> Result<(), NodeError> {
        self.node.set_reachable(on).await
    }
}

/// A node with the context `app`, delivering by `delivery`; `events` of the
/// node's and of the context's wait at most.
async fn node(
    seed: u8,
    relay: Option<&RelayLocation>,
    events: usize,
    delivery: Delivery,
) -> (N, ContextEvents) {
    let (node, node_events) = convesso_tokio::start(
        identity(seed),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            relay: relay.cloned(),
            events,
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
                events,
                ..ContextOptions::default()
            },
        )
        .await
        .unwrap();
    (
        N {
            node,
            app,
            node_events: Arc::new(tokio::sync::Mutex::new(node_events)),
        },
        app_events,
    )
}

/// Each node knows the other's direct address.
async fn hints(a: &N, b: &N) {
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    b.set_hint(a.address().peer_id(), a.local_addr())
        .await
        .unwrap();
}

async fn reachable(node: &N) {
    node.set_reachable(true).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while node.stats().await.unwrap().keepalives_received == 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a link within two seconds");
}

/// The next message, reset or close, within `within`.
async fn next(receiver: &Receiver, within: Duration) -> Received {
    timeout(within, receiver.recv())
        .await
        .expect("something from the receiver")
}

async fn message(receiver: &Receiver) -> Vec<u8> {
    match next(receiver, Duration::from_secs(5)).await {
        Received::Message(data) => data,
        other => panic!("{other:?} instead of a message"),
    }
}

// --- 3.1 ---------------------------------------------------------------------------------

/// Scenario: a message budget too small is refused when the context opens,
/// naming both sizes, and the context is not served.
#[tokio::test]
async fn a_message_budget_too_small_is_refused_when_the_context_opens() {
    let (node, _events) = convesso_tokio::start(
        identity(1),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let result = node
        .context(
            b"app",
            ContextOptions {
                delivery: Delivery::PerPeer {
                    messages: 262_144,
                    datagrams: 64_000,
                },
                ..ContextOptions::default()
            },
        )
        .await;
    let Err(error) = result else { panic!("opened") };
    assert_eq!(
        error,
        NodeError::Budget {
            budget: 262_144,
            needed: 262_208
        }
    );
    let text = error.to_string();
    assert!(text.contains("262144") && text.contains("262208"), "{text}");
    assert_eq!(262_144 + ELEMENT_COST, 262_208);
    // Not open: the name opens now, with a budget that fits.
    node.context(
        b"app",
        ContextOptions {
            delivery: PER_PEER,
            ..ContextOptions::default()
        },
    )
    .await
    .unwrap();
}

// --- 3.2 ---------------------------------------------------------------------------------

/// Scenario: a receiver yields the reset and the close in order: three
/// messages, the reset of a peer that restarted, its fourth message, then the
/// close made by this side, and the close again afterwards.
#[tokio::test]
async fn a_receiver_yields_the_reset_and_the_close_in_order() {
    let (r, _r_events) = node(1, None, 64, PER_PEER).await;
    // S's first process, on a runtime of its own, killed below.
    let process = tokio::runtime::Runtime::new().unwrap();
    let (s, s_events) = process
        .spawn(async { node(2, None, 64, Delivery::Events).await })
        .await
        .unwrap();
    hints(&r, &s).await;
    let s_peer = s.address().peer_id();
    let receiver = r.receiver(s_peer).await.unwrap();
    for m in [b"one".as_slice(), b"two", b"three"] {
        s.send_message(r.address(), m.to_vec()).await.unwrap();
    }
    for m in [b"one".as_slice(), b"two", b"three"] {
        assert_eq!(message(&receiver).await, m);
    }
    // S restarts: the same key, a new process, a new incarnation. The old
    // one ends without closing anything, as a process killed does.
    process.shutdown_background();
    // Its handles never drop: a dropped context would close its sessions.
    std::mem::forget((s, s_events));
    let (s, _s_events) = node(2, None, 64, Delivery::Events).await;
    hints(&r, &s).await;
    s.send_message(r.address(), b"four".to_vec()).await.unwrap();
    assert_eq!(
        next(&receiver, Duration::from_secs(5)).await,
        Received::Reset(Reason::PeerRestarted)
    );
    assert_eq!(message(&receiver).await, b"four");
    r.close(s_peer, 9).await.unwrap();
    let closed = Received::Closed(SessionClosed {
        code: 9,
        by_peer: false,
    });
    assert_eq!(next(&receiver, Duration::from_secs(5)).await, closed);
    assert_eq!(next(&receiver, Duration::from_millis(100)).await, closed);
    assert!(
        timeout(Duration::from_millis(100), receiver.recv_datagram())
            .await
            .unwrap()
            .is_err()
    );
}

/// Scenario: before a receiver opens, a peer's messages wait in its channel
/// and its datagrams are dropped and counted; once it opens, every message
/// arrives, whole and in order.
#[tokio::test]
async fn before_a_receiver_opens_messages_wait_and_datagrams_are_dropped() {
    let (r, mut r_events) = node(3, None, 64, PER_PEER).await;
    let (s, _s_events) = node(4, None, 64, Delivery::Events).await;
    hints(&r, &s).await;
    let s_peer = s.address().peer_id();
    let sent: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 1000]).collect();
    for m in &sent {
        s.send_message(r.address(), m.clone()).await.unwrap();
    }
    for i in 0..5u8 {
        s.send(r.address(), vec![i; 100]).await.unwrap();
    }
    // The connection is announced on the event stream.
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(ContextEvent::Connected { peer }) = r_events.next().await
                && peer == s_peer
            {
                return;
            }
        }
    })
    .await
    .expect("the connection");
    sleep(Duration::from_millis(500)).await;
    assert!(r.stats().await.unwrap().datagrams_dropped >= 5);
    let receiver = r.receiver(s_peer).await.unwrap();
    for m in &sent {
        assert_eq!(&message(&receiver).await, m);
    }
}

/// Scenario: a second receiver for the same peer is refused, and the first
/// keeps receiving; a receiver in the event-stream mode is refused.
#[tokio::test]
async fn a_second_receiver_for_the_same_peer_is_refused() {
    let (r, _r_events) = node(5, None, 64, PER_PEER).await;
    let (s, _s_events) = node(6, None, 64, Delivery::Events).await;
    hints(&r, &s).await;
    let s_peer = s.address().peer_id();
    let first = r.receiver(s_peer).await.unwrap();
    assert_eq!(
        r.receiver(s_peer).await.unwrap_err(),
        NodeError::ReceiverOpen
    );
    s.send_message(r.address(), b"still".to_vec())
        .await
        .unwrap();
    assert_eq!(message(&first).await, b"still");
    assert_eq!(
        s.receiver(r.address().peer_id()).await.unwrap_err(),
        NodeError::NotPerPeer
    );
}

/// Scenario: in the per-peer mode, a slow event reader does not stop the
/// datagrams: the event stream, of one place, is never read, and a peer's
/// datagrams keep arriving at its receiver.
#[tokio::test]
async fn in_the_per_peer_mode_a_slow_event_reader_does_not_stop_the_datagrams() {
    let (r, _r_events) = node(7, None, 1, PER_PEER).await;
    let (s, _s_events) = node(8, None, 64, Delivery::Events).await;
    hints(&r, &s).await;
    let receiver = r.receiver(s.address().peer_id()).await.unwrap();
    for i in 0..200u32 {
        s.send(r.address(), i.to_le_bytes().to_vec()).await.unwrap();
        let (data, _) = timeout(Duration::from_secs(2), receiver.recv_datagram())
            .await
            .expect("the datagram")
            .unwrap();
        assert_eq!(data, i.to_le_bytes());
    }
    assert!(timeout(Duration::from_millis(200), r.stats()).await.is_ok());
}

/// Scenario: a dropped receiver tells the sender: its channel is reset with
/// "reset by peer", its waiting sends end, and its next message waits in a
/// new incarnation until a receiver opens.
#[tokio::test]
async fn a_dropped_receiver_tells_the_sender() {
    let (r, _r_events) = node(9, None, 64, PER_PEER).await;
    let (s, mut s_events) = node(10, None, 64, Delivery::Events).await;
    hints(&r, &s).await;
    let s_peer = s.address().peer_id();
    let receiver = r.receiver(s_peer).await.unwrap();
    s.send_message(r.address(), b"first".to_vec())
        .await
        .unwrap();
    assert_eq!(message(&receiver).await, b"first");
    // S fills R's budget and its own buffer: its sends wait.
    let (s2, r_address) = (s.clone(), r.address());
    let sent = Arc::new(AtomicU64::new(0));
    let sent2 = sent.clone();
    let sender = tokio::spawn(async move {
        for i in 0..2000u32 {
            s2.send_message(r_address, vec![i as u8; 4000])
                .await
                .unwrap();
            sent2.fetch_add(1, Ordering::Relaxed);
        }
    });
    // Until R's budget and S's buffers are full, and the sends wait.
    let mut waiting = sent.load(Ordering::Relaxed);
    timeout(Duration::from_secs(20), async {
        loop {
            sleep(Duration::from_millis(500)).await;
            let now = sent.load(Ordering::Relaxed);
            if now == waiting {
                return;
            }
            waiting = now;
        }
    })
    .await
    .expect("the sends wait");
    drop(receiver);
    let reason = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(ContextEvent::ChannelReset { reason, .. }) = s_events.next().await {
                return reason;
            }
        }
    })
    .await
    .expect("the sender is told");
    assert_eq!(reason, Reason::ResetByPeer);
    sleep(Duration::from_millis(300)).await;
    assert!(
        sent.load(Ordering::Relaxed) > waiting,
        "the sends that waited go on"
    );
    sender.abort();
    let (s3, r_address) = (s.clone(), r.address());
    tokio::spawn(async move { s3.send_message(r_address, b"after".to_vec()).await });
    let receiver = r.receiver(s_peer).await.unwrap();
    // What S sent after the reset arrives, the new incarnation's first
    // message among it, after messages of the loop that went out after it.
    let got = timeout(Duration::from_secs(10), async {
        loop {
            if let Received::Message(data) = receiver.recv().await
                && data == b"after"
            {
                return;
            }
        }
    })
    .await;
    assert!(got.is_ok(), "the message after the reset arrives");
}

/// The invariant of the receivers: reads, pauses and drops in a random
/// order never leave a message waiting for room that never comes. Once the
/// application reads again, a last message always arrives.
#[tokio::test]
async fn reads_pauses_and_drops_never_strand_a_message() {
    let (r, _r_events) = node(11, None, 64, PER_PEER).await;
    let (s, _s_events) = node(12, None, 64, Delivery::Events).await;
    hints(&r, &s).await;
    let s_peer = s.address().peer_id();
    let (s2, r_address) = (s.clone(), r.address());
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let sender = tokio::spawn(async move {
        let mut seed = 7u64;
        while !stop2.load(Ordering::Relaxed) {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let len = 1 + (seed >> 33) as usize % 30_000;
            if timeout(
                Duration::from_millis(200),
                s2.send_message(r_address, vec![1; len]),
            )
            .await
            .is_err()
            {
                continue;
            }
        }
    });
    let mut seed = 11u64;
    let mut receiver = Some(r.receiver(s_peer).await.unwrap());
    for _ in 0..40 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        match (seed >> 33) % 4 {
            0 => sleep(Duration::from_millis(150)).await,
            1 => receiver = None,
            _ => {
                let open = match receiver.take() {
                    Some(open) => open,
                    None => r.receiver(s_peer).await.unwrap(),
                };
                for _ in 0..(seed >> 40) % 20 {
                    if timeout(Duration::from_millis(50), open.recv())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                receiver = Some(open);
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = timeout(Duration::from_secs(2), sender).await;
    let receiver = match receiver {
        Some(open) => open,
        None => r.receiver(s_peer).await.unwrap(),
    };
    let (s3, r_address) = (s.clone(), r.address());
    tokio::spawn(async move { s3.send_message(r_address, b"last".to_vec()).await });
    let got = timeout(Duration::from_secs(10), async {
        loop {
            if let Received::Message(data) = receiver.recv().await
                && data == b"last"
            {
                return;
            }
        }
    })
    .await;
    assert!(got.is_ok(), "the last message arrives");
}

// --- 3.3 ---------------------------------------------------------------------------------

/// Sends a 1,000-byte message and a 200-byte datagram every 10 ms, counting
/// the messages accepted.
fn pace(sender: N, to: convesso_core::identity::Address, sent: Arc<AtomicU64>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        loop {
            tick.tick().await;
            let _ = sender.send(to, vec![2; 200]).await;
            if sender.send_message(to, vec![1; 1000]).await.is_err() {
                return;
            }
            sent.fetch_add(1, Ordering::Relaxed);
        }
    })
}

/// Reads a receiver while `reading`, counting messages and datagrams.
fn read(
    receiver: Arc<Receiver>,
    reading: Arc<AtomicBool>,
    counts: Arc<[AtomicU64; 2]>,
) -> [JoinHandle<()>; 2] {
    let datagrams = receiver.clone();
    let (reading2, counts2) = (reading.clone(), counts.clone());
    let messages = tokio::spawn(async move {
        loop {
            if !reading.load(Ordering::Relaxed) {
                sleep(Duration::from_millis(20)).await;
                continue;
            }
            if let Ok(Received::Message(_)) =
                timeout(Duration::from_millis(50), receiver.recv()).await
            {
                counts[0].fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    let datagrams = tokio::spawn(async move {
        loop {
            if !reading2.load(Ordering::Relaxed) {
                sleep(Duration::from_millis(20)).await;
                continue;
            }
            if let Ok(Ok(_)) = timeout(Duration::from_millis(50), datagrams.recv_datagram()).await {
                counts2[1].fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    [messages, datagrams]
}

fn counted(counts: &[AtomicU64; 2]) -> [u64; 2] {
    [
        counts[0].load(Ordering::Relaxed),
        counts[1].load(Ordering::Relaxed),
    ]
}

/// Scenario: a stopped reader holds back only its own peer. Two peers send
/// messages and datagrams at a steady rate through a relay; the reader of
/// one stops. For 5 s after the stopped peer's sends wait, the other's rates
/// stay within 10%, the node answers its commands and its relay stays
/// available; a send to the other peer completes, the stopped peer's
/// datagrams are dropped, and its receiver holds no more than its budget
/// allows. The relay keep-alives themselves, one a minute, are counted by
/// the long version, run on demand.
#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_reader_holds_back_only_its_own_peer() {
    // A wait that never ends fails here, in CI, rather than holding the job.
    timeout(
        Duration::from_secs(120),
        stopped_reader(Duration::from_secs(5), false),
    )
    .await
    .expect("the scenario ends within two minutes");
}

/// The same for 60 s, long enough for a relay keep-alive, which are counted.
/// Run on demand: `cargo test -p convesso-tokio --all-features --test per_peer
/// the_relay_keepalives_go_on -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "over a minute of real time, for one relay keep-alive"]
async fn the_relay_keepalives_go_on_while_a_reader_is_stopped() {
    timeout(
        Duration::from_secs(300),
        stopped_reader(Duration::from_secs(60), true),
    )
    .await
    .expect("the scenario ends within five minutes");
}

/// The stopped-reader scenario, the other peer measured for `window` once the
/// stopped peer's sends wait; the relay keep-alives counted when
/// `keepalives`.
async fn stopped_reader(window: Duration, keepalives: bool) {
    let relay = relay().await;
    let (r, _r_events) = node(13, Some(&relay), 64, PER_PEER).await;
    let (s1, _s1_events) = node(14, Some(&relay), 64, Delivery::Events).await;
    let (s2, mut s2_events) = node(15, Some(&relay), 64, Delivery::Events).await;
    for node in [&r, &s1, &s2] {
        reachable(node).await;
    }
    let peers: [PeerId; 2] = [s1.address().peer_id(), s2.address().peer_id()];
    let receivers = [
        Arc::new(r.receiver(peers[0]).await.unwrap()),
        Arc::new(r.receiver(peers[1]).await.unwrap()),
    ];
    let reading = [
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicBool::new(true)),
    ];
    let counts: [Arc<[AtomicU64; 2]>; 2] = [Arc::default(), Arc::default()];
    let sent = [Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0))];
    // The scenario's own tasks, ended before it returns: left running, they
    // would meet the runtime's shutdown, where every timer fires at once, and
    // loop on their timeouts without ever yielding, holding the test.
    let mut tasks = Vec::new();
    for i in 0..2 {
        tasks.extend(read(
            receivers[i].clone(),
            reading[i].clone(),
            counts[i].clone(),
        ));
    }
    tasks.push(pace(s1.clone(), r.address(), sent[0].clone()));
    tasks.push(pace(s2.clone(), r.address(), sent[1].clone()));

    sleep(Duration::from_secs(2)).await;
    let start = counted(&counts[1]);
    let begun = Instant::now();
    sleep(Duration::from_secs(5)).await;
    let both = counted(&counts[1]);
    let rate = |a: [u64; 2], b: [u64; 2], secs: f64| {
        [(b[0] - a[0]) as f64 / secs, (b[1] - a[1]) as f64 / secs]
    };
    let before = rate(start, both, begun.elapsed().as_secs_f64());

    reading[0].store(false, Ordering::Relaxed);
    let keepalives_before = r.stats().await.unwrap().keepalives_sent;
    // The stopped peer's sends go on until R's budget, its channel's buffer
    // and S1's send buffer are full, and then wait.
    let mut s1_sent = sent[0].load(Ordering::Relaxed);
    timeout(Duration::from_secs(40), async {
        loop {
            sleep(Duration::from_secs(1)).await;
            let now = sent[0].load(Ordering::Relaxed);
            if now == s1_sent {
                return;
            }
            s1_sent = now;
        }
    })
    .await
    .expect("the stopped peer's sends wait");
    let from = counted(&counts[1]);
    let begun = Instant::now();
    sleep(window).await;
    let after = rate(from, counted(&counts[1]), begun.elapsed().as_secs_f64());
    std::println!("the other peer: before {before:?}/s, while one is stopped {after:?}/s");
    for k in 0..2 {
        let ratio = after[k] / before[k];
        assert!((0.9..=1.1).contains(&ratio), "{after:?} against {before:?}");
    }
    let stats = r.stats().await.unwrap();
    if keepalives {
        assert!(
            stats.keepalives_sent > keepalives_before,
            "the keep-alives go on"
        );
    }
    // The relay never went unavailable: the link and its keep-alives were
    // kept whatever the application read.
    let mut node_events = r.node_events.lock().await;
    while let Ok(Some(event)) = timeout(Duration::from_millis(100), node_events.next()).await {
        assert!(
            !matches!(event, NodeEvent::RelayUnavailable { .. }),
            "{event:?}"
        );
    }
    drop(node_events);
    assert!(stats.datagrams_dropped > 0, "the stopped peer's datagrams");
    assert_eq!(
        sent[0].load(Ordering::Relaxed),
        s1_sent,
        "the stopped peer's sends wait"
    );
    r.send(s2.address(), b"to the other".to_vec())
        .await
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(ContextEvent::Datagram { data, .. }) = s2_events.next().await
                && data == b"to the other"
            {
                return;
            }
        }
    })
    .await
    .expect("a send to the other peer completes");
    // What the stopped peer's receiver holds is within its budgets, and its
    // budget for messages is full: the credit, not the reader, stopped it.
    let (messages, datagrams) = receivers[0].held();
    let Delivery::PerPeer {
        messages: budget,
        datagrams: datagram_budget,
    } = PER_PEER
    else {
        unreachable!()
    };
    std::println!("the stopped peer's receiver holds {messages} and {datagrams} bytes");
    assert!(messages <= budget && datagrams <= datagram_budget);
    assert!(budget - messages < 1000 + ELEMENT_COST, "a full budget");
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
}

// --- 3.4 ---------------------------------------------------------------------------------

/// Scenario: a full event stream stops nothing: while the application reads
/// none of its context's events, the node keeps reading, its sends complete
/// and its commands are answered; the datagrams beyond the stream's room are
/// dropped and counted, and those it held arrive, in order.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_event_stream_stops_nothing() {
    let relay = relay().await;
    let (r, mut r_events) = node(16, Some(&relay), 4, Delivery::Events).await;
    let (s, mut s_events) = node(17, Some(&relay), 64, Delivery::Events).await;
    reachable(&r).await;
    reachable(&s).await;
    hints(&r, &s).await;
    for i in 0..30u32 {
        s.send(r.address(), i.to_le_bytes().to_vec()).await.unwrap();
        sleep(Duration::from_millis(20)).await;
    }
    sleep(Duration::from_millis(300)).await;
    let stats = timeout(Duration::from_millis(500), r.stats())
        .await
        .expect("commands go on")
        .unwrap();
    assert!(stats.datagrams_dropped >= 26, "{stats:?}");
    r.send(s.address(), b"meanwhile".to_vec()).await.unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(ContextEvent::Datagram { data, .. }) = s_events.next().await
                && data == b"meanwhile"
            {
                return;
            }
        }
    })
    .await
    .expect("a send completes");
    let mut got = Vec::new();
    while let Ok(Some(event)) = timeout(Duration::from_millis(300), r_events.next()).await {
        if let ContextEvent::Datagram { data, .. } = event {
            got.push(data);
        }
    }
    assert_eq!(
        got,
        (0..4u32)
            .map(|i| i.to_le_bytes().to_vec())
            .collect::<Vec<_>>(),
        "the first ones, in order"
    );
}

/// Scenario: an application that reads late sees the latest state. Its
/// relay refuses it, and it reads none of the node's events while the node
/// tries again and again, with its backoff: it then finds the first, which
/// found room, and one more, the latest, rather than one per attempt.
#[tokio::test]
async fn an_application_that_reads_late_sees_the_latest_state() {
    let refusing = relay_with(RefuseAll).await;
    // The per-peer mode reads its socket throughout, so the refusals keep
    // coming while the application reads nothing.
    let (r, mut r_events) = node(18, Some(&refusing), 1, PER_PEER).await;
    let (s, _s_events) = node(19, None, 64, Delivery::Events).await;
    hints(&r, &s).await;
    // The connection fills R's one place, then the relay refuses it again
    // and again.
    s.send(r.address(), b"fill".to_vec()).await.unwrap();
    sleep(Duration::from_millis(300)).await;
    r.set_reachable(true).await.unwrap();
    sleep(Duration::from_secs(5)).await;
    // No more attempts, so that what is read is what waited.
    r.set_reachable(false).await.unwrap();
    sleep(Duration::from_millis(500)).await;
    let mut got = Vec::new();
    let mut node_events = r.node_events.lock().await;
    while let Ok(Some(event)) = timeout(Duration::from_millis(300), node_events.next()).await {
        got.push(event);
    }
    std::println!("{got:?}");
    let unavailable = got
        .iter()
        .filter(|e| matches!(e, NodeEvent::RelayUnavailable { .. }))
        .count();
    assert_eq!(unavailable, 2, "{got:?}");
    // A peer that connects with a datagram, before its receiver opens, is
    // still announced.
    let mut in_app = Vec::new();
    while let Ok(Some(event)) = timeout(Duration::from_millis(300), r_events.next()).await {
        in_app.push(event);
    }
    assert!(
        in_app
            .iter()
            .any(|e| matches!(e, ContextEvent::Connected { .. })),
        "{in_app:?}"
    );
}
