//! Recovery from a session that one side lost while the other still holds
//! its keys: an eviction whose close is lost, a restart, and a board that
//! keeps peers by dialling them back while others ping it (`PROTOCOL.md §5`).
//! Each case prints how long the peer stayed without contact, measured in
//! virtual time (`cargo test -p convesso-relay --lib recovery -- --nocapture`),
//! and checks that the session lost reopens within three round trips of the
//! first packet that met it.
//!
//! Each peer was without contact for, with a ping a second:
//!
//! | Case | Without the signal | With it |
//! |---|---|---|
//! | an eviction whose close is lost | 78.1 s, until its keys turned 120 s old | 1.1 s: the first ping is lost, the next arrives |
//! | a restart, the peer having dialled | 111.1 s, likewise | 1.1 s |
//! | a restart, the board having dialled, the peer sending by `PeerId` | never: `AddressUnknown` once its keys expired | 1.1 s, with the address it was told |
//! | the rounds, datagrams or messages, close lost or not | at most 32.1 s, the 30 s an evictable session had to be silent | at most 1.2 s |

use convesso_core::endpoint::CLOSE_TO_MAKE_ROOM;
use convesso_core::identity::PeerId;

use super::world::*;
use crate::{Config, Open};

/// The simulation's step, in ms.
const STEP: u64 = 100;

fn index_of(world: &World<Open>, peer: PeerId) -> usize {
    world
        .clients
        .iter()
        .position(|c| c.peer_id() == peer)
        .expect("a client of the world")
}

/// How many datagrams starting with `prefix` client `to` received from `from`.
fn received(world: &World<Open>, to: usize, from: usize, prefix: &[u8]) -> usize {
    let peer = world.clients[from].peer_id();
    world.clients[to]
        .events
        .iter()
        .filter(|ev| matches!(ev, Ev::Datagram { peer: p, data, .. } if *p == peer && data.starts_with(prefix)))
        .count()
}

/// Client `from` sends `to` a datagram every second, by address or by
/// `PeerId`, until `to` receives one or `limit` ms pass. Returns the ms from
/// the first send to the first delivery, and the send errors met.
fn ping(
    world: &mut World<Open>,
    from: usize,
    to: usize,
    by_peer: bool,
    limit: u64,
) -> (Option<u64>, Vec<String>) {
    let before = received(world, to, from, b"ping");
    let start = world.now;
    let mut errors = Vec::new();
    while world.now < start + limit {
        let sent = if by_peer {
            world.send_by_peer(from, to, b"ping")
        } else {
            world.send(from, to, b"ping")
        };
        if let Err(error) = sent {
            let error = format!("{error:?}");
            if errors.last() != Some(&error) {
                errors.push(error);
            }
        }
        for _ in 0..10 {
            world.run_for(STEP);
            if received(world, to, from, b"ping") > before {
                return (Some(world.now - start), errors);
            }
        }
    }
    (None, errors)
}

/// When client `peer` was told, at or after `since`, of a session with client
/// `other` that opened: ms after `since`.
fn reopened_after(world: &World<Open>, peer: usize, other: usize, since: u64) -> Option<u64> {
    let other = world.clients[other].peer_id();
    let client = &world.clients[peer];
    client
        .events
        .iter()
        .zip(&client.event_at)
        .find(|(event, at)| **at >= since && **event == Ev::Connected(other))
        .map(|(_, at)| at - since)
}

/// The session lost reopened within three round trips of the first packet
/// that met it, sent at `since`.
fn assert_reopened_in_three_round_trips(world: &World<Open>, peer: usize, since: u64) {
    let took = reopened_after(world, peer, 0, since).expect("the session reopened");
    assert!(
        took <= 3 * 2 * world.delay,
        "reopened {took} ms after the first packet lost"
    );
}

fn report(case: &str, (delay, errors): &(Option<u64>, Vec<String>)) {
    match delay {
        Some(ms) => eprintln!("[recovery] {case}: delivered after {ms} ms; errors {errors:?}"),
        None => eprintln!("[recovery] {case}: NOT delivered; errors {errors:?}"),
    }
}

/// A board (client 0, `Mcu`: 4 sessions with the relay's) holds sessions with
/// three peers; a fourth makes it evict the least recently active, whose
/// close is lost. That peer then sends every second under its keys.
#[test]
fn an_eviction_whose_close_is_lost() {
    let mut world = World::new(Open, Config::default(), 5);
    world.open_link(0);
    for peer in 1..5 {
        world.hint(peer, 0);
    }
    world.run_for(2000);
    for peer in 1..4 {
        world.send(peer, 0, b"hello").unwrap();
        world.run_for(1000);
    }
    world.run_for(40_000);
    world.clients[1].deaf = true;
    world.send(4, 0, b"newcomer").unwrap();
    world.run_for(1000);
    world.clients[1].deaf = false;
    let evicted = world.clients[1].peer_id();
    assert!(
        world.clients[0]
            .events
            .contains(&Ev::Closed(evicted, CLOSE_TO_MAKE_ROOM)),
        "the board evicted the least recently active peer"
    );
    assert!(
        !world.clients[1]
            .events
            .iter()
            .any(|ev| matches!(ev, Ev::Closed(..))),
        "its close was lost"
    );
    let since = world.now;
    let result = ping(&mut world, 1, 0, false, 300_000);
    report("eviction, close lost", &result);
    assert_reopened_in_three_round_trips(&world, 1, since);
}

/// A peer that dialled a board keeps sending to it every second, by address,
/// after the board restarts with the same identity.
#[test]
fn a_restart_under_a_session_the_peer_opened() {
    let mut world = World::new(Open, Config::default(), 2);
    world.open_link(0);
    world.hint(1, 0);
    world.run_for(2000);
    world.send(1, 0, b"hello").unwrap();
    world.run_for(10_000);
    world.restart(0);
    world.open_link(0);
    world.run_for(1000);
    let since = world.now;
    let result = ping(&mut world, 1, 0, false, 300_000);
    report("restart, the peer dialled", &result);
    assert_reopened_in_three_round_trips(&world, 1, since);
}

/// A board dials a peer, then restarts with the same identity; the peer,
/// which knows the board only by `PeerId`, sends to it every second.
#[test]
fn a_restart_under_a_session_the_board_opened() {
    let mut world = World::new(Open, Config::default(), 2);
    world.open_link(0);
    world.hint(0, 1);
    world.run_for(2000);
    world.send(0, 1, b"hello").unwrap();
    world.run_for(10_000);
    world.restart(0);
    world.open_link(0);
    world.run_for(1000);
    let since = world.now;
    let result = ping(&mut world, 1, 0, true, 300_000);
    report(
        "restart, the board dialled, the peer replies by PeerId",
        &result,
    );
    assert_reopened_in_three_round_trips(&world, 1, since);
}

/// The board's application, as a light member of peerfectly's runs it:
/// it keeps `kept` connected by dialling them again a second after their
/// session ends, retrying every 5 seconds when the dial is refused, and it
/// answers every ping with a pong.
struct Board {
    kept: Vec<usize>,
    cursor: usize,
    dial_at: Vec<(usize, u64)>,
    log: Vec<String>,
    /// Whether the pings are reliable messages rather than datagrams; a ping
    /// then counts once the board's application receives it.
    messages: bool,
}

const NAMES: [&str; 5] = ["board", "a", "b", "d", "e"];

impl Board {
    fn step(&mut self, world: &mut World<Open>) {
        world.run_for(STEP);
        let now = world.now;
        let events: Vec<Ev> = world.clients[0].events[self.cursor..].to_vec();
        self.cursor = world.clients[0].events.len();
        for event in events {
            let (peer, what) = match &event {
                Ev::Connected(p) => (*p, "connected".to_string()),
                Ev::Idle(p) => (*p, "idle".to_string()),
                Ev::Closed(p, code) => (*p, format!("closed {code:#06x}")),
                Ev::ReopenFailed(p) => (*p, "reopen failed".to_string()),
                Ev::Datagram { peer, data, .. } if data.starts_with(b"ping") => {
                    let from = index_of(world, *peer);
                    if let Err(error) = world.send(0, from, b"pong") {
                        self.log.push(format!(
                            "{now:>7} pong to {} refused: {error:?}",
                            NAMES[from]
                        ));
                    }
                    continue;
                }
                _ => continue,
            };
            let i = index_of(world, peer);
            self.log.push(format!("{now:>7} {} {what}", NAMES[i]));
            if self.kept.contains(&i) && !matches!(event, Ev::Connected(_)) {
                self.dial_at.push((i, now + 1000));
            }
        }
        let due: Vec<(usize, u64)> = self
            .dial_at
            .iter()
            .copied()
            .filter(|(_, at)| *at <= now)
            .collect();
        self.dial_at.retain(|(_, at)| *at > now);
        for (i, _) in due {
            if let Err(error) = world.connect(0, i) {
                self.log
                    .push(format!("{now:>7} dial {} refused: {error:?}", NAMES[i]));
                self.dial_at.push((i, now + 5000));
            }
        }
    }

    fn run_for(&mut self, world: &mut World<Open>, ms: u64) {
        let until = world.now + ms;
        while world.now < until {
            self.step(world);
        }
    }

    /// Client `from` pings the board every second until a pong arrives, for
    /// at most `limit` ms; returns the ms it took.
    fn ping(&mut self, world: &mut World<Open>, from: usize, limit: u64) -> Option<u64> {
        let tag = format!("ping-{}", NAMES[from]).into_bytes();
        let messages = self.messages;
        let wanted = tag.clone();
        let arrived = move |world: &World<Open>| {
            if messages {
                world.clients[0]
                    .messages
                    .iter()
                    .filter(|m| **m == wanted)
                    .count()
            } else {
                received(world, from, 0, b"pong")
            }
        };
        let before = arrived(world);
        let start = world.now;
        while world.now < start + limit {
            let sent = if messages {
                world
                    .send_message(from, 0, &tag)
                    .map_err(|e| format!("{e:?}"))
            } else {
                world.send(from, 0, b"ping").map_err(|e| format!("{e:?}"))
            };
            if let Err(error) = sent {
                let now = world.now;
                self.log.push(format!(
                    "{now:>7} ping from {} refused: {error}",
                    NAMES[from]
                ));
            }
            for _ in 0..10 {
                self.step(world);
                if arrived(world) > before {
                    return Some(world.now - start);
                }
            }
        }
        None
    }
}

/// The testbed's rounds: a board keeping a and b connected; after `silence`
/// ms of silence, b, e, d and a ping it in turn until it answers, for at most
/// three minutes each. With `close_lost`, a hears nothing while d pings, so
/// that the close of an eviction then is lost.
fn rounds(silence: u64, close_lost: bool, messages: bool) {
    let mut world = World::new(Open, Config::default(), 5);
    if messages {
        world.with_streams();
    }
    world.open_link(0);
    for peer in 1..5 {
        world.hint(peer, 0);
        world.hint(0, peer);
    }
    world.run_for(2000);
    let mut board = Board {
        kept: vec![1, 2],
        cursor: 0,
        dial_at: vec![(1, world.now), (2, world.now)],
        log: Vec::new(),
        messages,
    };
    board.run_for(&mut world, silence);
    let rounds_start = world.now;
    let mut results = Vec::new();
    for peer in [2, 4, 3, 1] {
        world.clients[1].deaf = close_lost && peer == 3;
        let took = board.ping(&mut world, peer, 180_000);
        world.clients[1].deaf = false;
        results.push((NAMES[peer], took));
    }
    eprintln!(
        "[recovery] rounds after {silence} ms of silence, close lost: {close_lost}, messages: {messages}; from {rounds_start} ms: {results:?}"
    );
    for (name, took) in &results {
        assert!(
            took.is_some_and(|ms| ms <= 1500),
            "{name} served within a ping or two: {took:?}"
        );
    }
    for line in board.log.iter().filter(|line| {
        line.split_whitespace()
            .next()
            .and_then(|at| at.parse::<u64>().ok())
            .is_some_and(|at| at >= rounds_start)
    }) {
        eprintln!("[recovery]   {line}");
    }
}

#[test]
fn a_board_that_keeps_two_peers_while_four_ping_it() {
    for messages in [false, true] {
        for silence in [185_000, 250_000, 360_000] {
            for close_lost in [false, true] {
                rounds(silence, close_lost, messages);
            }
        }
    }
}

/// More peers active at once than a board has slots: a board with four
/// sessions, its relay's among them, and six peers each sending it a datagram
/// every 500 ms for 30 seconds. Each eviction costs its peer a signal and a
/// handshake. Measured over a minute: each peer had 93 to 97% of its
/// datagrams delivered, never more than 2.5 s apart, for 340 evictions.
#[test]
fn six_peers_active_at_once_on_a_board_of_four() {
    let mut world = World::new(Open, Config::default(), 7);
    world.open_link(0);
    for peer in 1..7 {
        world.hint(peer, 0);
    }
    world.run_for(2000);
    let start = world.now;
    let mut sent = [0usize; 7];
    let mut last_delivered = [start; 7];
    let mut longest_gap = [0u64; 7];
    let mut delivered_before = [0usize; 7];
    while world.now < start + 30_000 {
        for peer in 1..7 {
            if world.send(peer, 0, b"tick").is_ok() {
                sent[peer] += 1;
            }
            world.run_for(500 / 6);
            let delivered = received(&world, 0, peer, b"tick");
            if delivered > delivered_before[peer] {
                delivered_before[peer] = delivered;
                longest_gap[peer] = longest_gap[peer].max(world.now - last_delivered[peer]);
                last_delivered[peer] = world.now;
            }
        }
    }
    let evictions = world.clients[0]
        .events
        .iter()
        .filter(|ev| matches!(ev, Ev::Closed(_, code) if *code == CLOSE_TO_MAKE_ROOM))
        .count();
    for peer in 1..7 {
        eprintln!(
            "[recovery] six on four: peer {peer} sent {}, delivered {}, longest gap {} ms",
            sent[peer], delivered_before[peer], longest_gap[peer]
        );
    }
    eprintln!("[recovery] six on four: {evictions} evictions in 30 s");
    for peer in 1..7 {
        assert!(
            delivered_before[peer] * 10 >= sent[peer] * 9,
            "peer {peer}: 90% delivered"
        );
        assert!(longest_gap[peer] <= 3000, "peer {peer}: never 3 s without");
    }
}

/// The testbed's report: a board resting on its TCP link, its relay session
/// gone idle after six minutes of silence, is woken by the relay when a member
/// sends to it through the relay, the member knowing no direct path.
#[test]
fn the_relay_wakes_a_board_resting_on_its_link() {
    let mut world = World::new(Open, Config::default(), 3);
    world.direct = false;
    world.open_link(0);
    world.run_for(2000);
    world.send(1, 0, b"before").unwrap();
    world.run_for(2000);
    assert_eq!(
        received(&world, 0, 1, b"before"),
        1,
        "reached before the silence"
    );
    world.run_for(360_000);
    let result = ping(&mut world, 1, 0, false, 30_000);
    report("the relay wakes a board resting on its link", &result);
    assert!(result.0.is_some(), "the member reached the board");
}

/// The testbed's second report: UDP between the board and the relay works, and
/// its TCP link is slower than UDP. The relay must still hold the link as the
/// board's, so that after six minutes of silence it wakes the board there.
#[test]
fn the_relay_wakes_a_board_whose_link_is_slower_than_udp() {
    for lag in [0, 5, 30, 200] {
        let mut world = World::new(Open, Config::default(), 3);
        world.direct = false;
        world.link_lag = lag;
        world.open_link(0);
        world.run_for(2000);
        world.send(1, 0, b"before").unwrap();
        world.run_for(2000);
        assert_eq!(
            received(&world, 0, 1, b"before"),
            1,
            "lag {lag}: reached before"
        );
        world.run_for(360_000);
        let result = ping(&mut world, 1, 0, false, 30_000);
        report(&format!("link {lag} ms slower than UDP"), &result);
        assert!(
            result.0.is_some(),
            "lag {lag}: the member reached the board"
        );
    }
}

/// The testbed's setup more closely: the board holds its session with a and
/// sends to it by address; b and d have sessions with it too; after six
/// minutes of silence, a, b, d and e ping it through the relay, one after the
/// other, then all at once.
#[test]
fn the_relay_wakes_a_board_holding_a_session() {
    for (together, lag) in [(false, 0), (true, 0), (false, 30), (true, 30)] {
        let mut world = World::new(Open, Config::default(), 5);
        world.direct = false;
        world.link_lag = lag;
        world.open_link(0);
        world.run_for(2000);
        world.send(0, 1, b"to a").unwrap();
        world.run_for(1000);
        let a = world.clients[1].peer_id();
        world.clients[0].endpoint.hold(a, SESSION, true).unwrap();
        for member in [2, 3] {
            world.send(member, 0, b"hello").unwrap();
            world.run_for(1000);
        }
        world.run_for(360_000);
        if together {
            for member in 1..5 {
                world.send(member, 0, b"ping").unwrap();
            }
            world.run_for(3000);
            for member in 1..5 {
                let got = received(&world, 0, member, b"ping");
                eprintln!("[wake] together, link {lag} ms slower: member {member} reached: {got}");
                assert!(got >= 1, "member {member} reached the board");
            }
        } else {
            for member in 1..5 {
                let result = ping(&mut world, member, 0, false, 30_000);
                report(
                    &format!("one after the other, link {lag} ms slower, member {member}"),
                    &result,
                );
                assert!(result.0.is_some());
            }
        }
    }
}

// --- connecting at once ------------------------------------------------------------------

/// A member dials a board through the relay while the board is away, and the
/// board comes to the relay `back` ms into the dial: the ms from its arrival
/// to the member's datagram reaching it, if it does before the dial ends.
fn reached_after_arrival(back: u64) -> Option<u64> {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.open_link(1);
    world.run_for(2000);
    let start = world.now;
    world.send(1, 0, b"ping").unwrap();
    world.run_until(start + back);
    world.open_link(0);
    let arrived = world.now;
    while world.now < start + 20_000 {
        world.run_for(10);
        if received(&world, 0, 1, b"ping") > 0 {
            return Some(world.now - arrived);
        }
    }
    None
}

/// A board that comes to the relay during a member's dial, at each second of
/// the dial: how long after its arrival the member's datagram reaches it.
///
/// | Board back at | Attempts at 0, 1, 3, 7 s | 0 to 13 s every 2, and arrivals |
/// |---|---|---|
/// | 0.5 to 6.5 s | 0.6 to 3.6 s after | 0.2 s after |
/// | 7.5 to 12.5 s | never: no attempt left | 0.2 s after |
/// | 13.5, 14.5 s | never | never: the last attempt went at 13 s |
///
/// A board back after the last attempt is reached by the application's next
/// dial.
#[test]
fn a_board_that_arrives_during_a_dial() {
    let mut reached = Vec::new();
    for second in 0..15 {
        let took = reached_after_arrival(second * 1000 + 500);
        eprintln!(
            "[connect] board back {second}.5 s into the dial: {}",
            took.map_or("NOT reached".to_string(), |ms| format!(
                "reached {ms} ms after"
            ))
        );
        reached.push(took);
    }
    for (second, took) in reached.iter().enumerate().take(13) {
        assert!(
            took.is_some_and(|ms| ms <= 300),
            "back at {second}.5 s: {took:?}"
        );
    }
}

/// The relay is down for `down` ms, its host restarting; then a member pings
/// a board resting on its link: the ms from the relay's return to the ping
/// reaching the board.
fn reached_after_relay_outage(down: u64) -> Option<u64> {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.open_link(0);
    world.open_link(1);
    world.run_for(2000);
    world.send(1, 0, b"before").unwrap();
    world.run_for(2000);
    assert_eq!(received(&world, 0, 1, b"before"), 1);
    for client in &mut world.clients {
        client.udp_blocked = true;
        client.tcp_refused = true;
    }
    let relay = crate::Relay::new(
        identity(0),
        Open,
        TestEntropy(7),
        Config::default(),
        world.instant(),
    )
    .unwrap();
    world.replace_relay(relay);
    world.run_for(down);
    for client in &mut world.clients {
        client.udp_blocked = false;
        client.tcp_refused = false;
    }
    ping(&mut world, 1, 0, false, 150_000).0
}

/// A board resting on its link while the relay is down for 30 seconds, 2
/// minutes and 10 minutes: how long after the relay's return a member reaches
/// it. With link attempts up to 60 to 90 s apart: 12.1, 40.1 and 1.2 s (the
/// last as the jitter fell); up to 15 to 22.5 s apart: 11.1, 14.1 and 4.7 s,
/// never more than the longest wait and a ping's second.
#[test]
fn a_board_after_a_relay_outage() {
    for down in [30_000, 120_000, 600_000] {
        let took = reached_after_relay_outage(down);
        assert!(
            took.is_some_and(|ms| ms <= 22_500 + 1_500),
            "down {down} ms: {took:?}"
        );
        eprintln!(
            "[connect] relay down {} s: {}",
            down / 1000,
            took.map_or("board NOT reached".to_string(), |ms| format!(
                "board reached {ms} ms after its return"
            ))
        );
    }
}
