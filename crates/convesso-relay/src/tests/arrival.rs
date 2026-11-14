//! The arrived frame (`PROTOCOL.md §6`): the relay tells a client that sought
//! a recipient not connected when that recipient comes, and the client's dial
//! tries again at once.

use convesso_core::endpoint::{Output, To};
use convesso_core::identity::PeerId;

use super::world::*;
use crate::{Config, Open};

/// The arrived frames the relay sent naming `peer`: to whom, and when (ms).
fn arrivals_naming(world: &World<Open>, peer: PeerId) -> Vec<(PeerId, u64)> {
    let peer = *peer.as_bytes();
    world
        .relay
        .arrivals_sent
        .iter()
        .filter(|(_, named, _)| *named == peer)
        .map(|(to, _, at)| {
            let to = world
                .clients
                .iter()
                .map(Client::peer_id)
                .find(|id| id.as_bytes() == to)
                .expect("a client of the world");
            (to, *at)
        })
        .collect()
}

/// A world of `n` clients, all on the relay but client 0, which is away.
fn board_away(n: usize) -> World<Open> {
    let mut world = World::new(Open, Config::default(), n);
    world.direct = false;
    for i in 1..n {
        world.open_link(i);
    }
    world.run_for(2000);
    world
}

/// Scenario: a peer that arrives during a call is reached in one round trip.
#[test]
fn a_peer_that_arrives_during_a_call_is_reached_in_one_round_trip() {
    let mut world = board_away(2);
    let (a, b) = (world.clients[1].peer_id(), world.clients[0].peer_id());
    let start = world.now;
    world.send(1, 0, b"call").unwrap();
    world.run_until(start + 4000);
    assert!(world.clients[1].events.contains(&Ev::NotAtRelay(b)));
    world.open_link(0);
    world.run_for(1000);
    let arrivals = arrivals_naming(&world, b);
    assert_eq!(arrivals.len(), 1, "{arrivals:?}");
    assert_eq!(arrivals[0].0, a);
    let connected = world.when(1, &Ev::Connected(b)).expect("A connected");
    // The relay to A, A's attempt to the relay, to B, B's response back the
    // same way: three round trips of the world's hops at most.
    assert!(
        connected - arrivals[0].1 <= 6 * world.delay,
        "connected {} ms after the arrival",
        connected - arrivals[0].1
    );
    assert!(connected < start + 5000, "before A's attempt at 5 s");
}

/// Scenario: several callers are told, each once.
#[test]
fn several_callers_are_told() {
    let mut world = board_away(4);
    let b = world.clients[0].peer_id();
    for caller in 1..4 {
        world.send(caller, 0, b"call").unwrap();
        world.run_for(300);
    }
    world.run_for(2000);
    world.open_link(0);
    world.run_for(2000);
    let mut told: Vec<PeerId> = arrivals_naming(&world, b)
        .into_iter()
        .map(|(to, _)| to)
        .collect();
    told.sort_unstable_by_key(|id| *id.as_bytes());
    let mut callers: Vec<PeerId> = (1..4).map(|i| world.clients[i].peer_id()).collect();
    callers.sort_unstable_by_key(|id| *id.as_bytes());
    assert_eq!(told, callers);
    for caller in 1..4 {
        assert!(
            world.when(caller, &Ev::Connected(b)).is_some(),
            "caller {caller}"
        );
    }
}

/// Scenario: a caller that gave up is not told: B comes 16 s after A's last
/// forward to it, the attempt A's dial sent at 13 s.
#[test]
fn a_caller_that_gave_up_is_not_told() {
    let mut world = board_away(2);
    let b = world.clients[0].peer_id();
    let start = world.now;
    world.send(1, 0, b"call").unwrap();
    world.run_until(start + 13_000 + 16_000);
    assert!(world.clients[1].events.contains(&Ev::ReopenFailed(b)));
    world.open_link(0);
    world.run_for(2000);
    assert!(arrivals_naming(&world, b).is_empty());
}

/// Scenario: a client that never sought the peer is not told.
#[test]
fn a_client_that_never_sought_the_peer_is_not_told() {
    let mut world = board_away(3);
    let (b, c) = (world.clients[0].peer_id(), world.clients[2].peer_id());
    world.send(1, 0, b"call").unwrap();
    world.run_for(2000);
    world.open_link(0);
    world.run_for(2000);
    let told: Vec<PeerId> = arrivals_naming(&world, b)
        .into_iter()
        .map(|(to, _)| to)
        .collect();
    assert_eq!(told, vec![world.clients[1].peer_id()]);
    assert!(!told.contains(&c));
    assert!(
        world
            .relay
            .arrivals_sent
            .iter()
            .all(|(to, _, _)| to != c.as_bytes())
    );
}

/// Scenario: an arrival with no dial changes nothing: A's dial has sent all
/// its attempts when B comes, so A sends nothing more and is told nothing
/// until the dial gives up.
#[test]
fn an_arrival_with_no_dial_left_changes_nothing() {
    let mut world = board_away(2);
    let b = world.clients[0].peer_id();
    let start = world.now;
    world.send(1, 0, b"call").unwrap();
    world.run_until(start + 13_500);
    let (transmitted, events) = (world.clients[1].transmitted, world.clients[1].events.len());
    world.open_link(0);
    world.run_until(start + 14_900);
    assert_eq!(arrivals_naming(&world, b).len(), 1, "A was told");
    assert_eq!(world.clients[1].transmitted, transmitted, "A sent nothing");
    assert_eq!(
        world.clients[1].events.len(),
        events,
        "A's application was told nothing"
    );
    assert!(world.when(1, &Ev::Connected(b)).is_none());
}

/// Scenario: an arrived frame from another session is ignored: D sends A, in
/// their own session, a datagram that reads as an arrived frame naming B, while
/// A dials B; A's application gets it as data, and A's dial keeps its times.
#[test]
fn an_arrived_frame_from_another_session_is_ignored() {
    let mut world = board_away(3);
    let b = world.clients[0].peer_id();
    world.send(2, 1, b"hello").unwrap();
    world.run_for(1000);
    let start = world.now;
    world.send(1, 0, b"call").unwrap();
    world.run_until(start + 1500);
    let logs = (
        world.clients[1].udp_log.len(),
        world.clients[1].tcp_log.len(),
    );
    let mut forged = vec![0x06, 0x01];
    forged.extend_from_slice(b.as_bytes());
    world.send(2, 1, &forged).unwrap();
    world.run_until(start + 2900);
    let d = world.clients[2].peer_id();
    assert!(
        world.clients[1]
            .events
            .iter()
            .any(|e| matches!(e, Ev::Datagram { peer, data, .. } if *peer == d && *data == forged))
    );
    // A forward of a first contact: the relay session's 35 bytes, the
    // forward's 34 and the first contact's 138.
    let attempts = world.clients[1].udp_log[logs.0..]
        .iter()
        .chain(&world.clients[1].tcp_log[logs.1..])
        .filter(|packet| packet.len() >= 35 + 34 + 138)
        .count();
    assert_eq!(attempts, 0, "no attempt before 3 s");
}

/// Scenario: the seekers kept are bounded: of 40 callers, the 32 that sought
/// the recipient last are told.
#[test]
fn the_seekers_kept_are_bounded() {
    let mut world = board_away(41);
    let b = world.clients[0].peer_id();
    // All within the first second of the dials, before their second attempts
    // seek again.
    for caller in 1..41 {
        world.send(caller, 0, b"call").unwrap();
        world.run_for(10);
    }
    world.run_for(100);
    world.open_link(0);
    world.run_for(300);
    let mut told: Vec<PeerId> = arrivals_naming(&world, b)
        .into_iter()
        .map(|(to, _)| to)
        .collect();
    told.sort_unstable_by_key(|id| *id.as_bytes());
    let mut last: Vec<PeerId> = (9..41).map(|i| world.clients[i].peer_id()).collect();
    last.sort_unstable_by_key(|id| *id.as_bytes());
    assert_eq!(told, last);
}

// --- what the relay remembers is bounded -------------------------------------------------

/// Client `i` forwards, through its live relay session, a packet of 60 bytes
/// to `peer`: shaped as a first contact (`01 01`), or as a transport packet
/// (`01 04`).
fn forward_raw(world: &mut World<Open>, i: usize, peer: PeerId, first_contact: bool) {
    let now = world.instant();
    let client = &mut world.clients[i];
    let mut out = [0x01u8; 2048];
    if !first_contact {
        out[1] = 0x04;
    }
    let output = client
        .endpoint
        .through_relay(
            peer,
            60,
            now,
            &mut client.policy,
            &mut client.entropy,
            &mut out,
        )
        .unwrap();
    let Output::Transmit {
        to: To::Relay(_),
        len,
    } = output
    else {
        panic!("the relay session is live");
    };
    world.inject_from(i, &out[..len]);
}

/// How many made-up recipients a client forwards to: well over the 64 the
/// relay keeps per sender. The module's own tests take 10,000.
const MADE_UP: usize = 200;

/// A recipient that never connects; derived once, a key costing a scalar
/// multiplication.
fn made_up(i: usize) -> PeerId {
    static KEYS: std::sync::OnceLock<Vec<PeerId>> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        (0..MADE_UP)
            .map(|i| identity(10_000 + i).peer_id())
            .collect()
    })[i]
}

fn bounds(config: &Config) -> crate::asked::Bounds {
    crate::asked::Bounds {
        per_sender: config.asked_per_sender,
        total: config.asked_total,
        seekers_per_recipient: config.seekers_per_recipient,
    }
}

/// Scenario: one client cannot fill the relay: first contacts to 200
/// made-up recipients leave at most 64 pairs for it, and at most one notice
/// per forward.
#[test]
fn one_client_cannot_fill_the_relay() {
    let mut world = board_away(2);
    let sender = world.clients[1].peer_id();
    let notices = |world: &World<Open>| {
        world.clients[1]
            .events
            .iter()
            .filter(|e| matches!(e, Ev::NotAtRelay(_)))
            .count()
    };
    let before = notices(&world);
    for i in 0..MADE_UP {
        forward_raw(&mut world, 1, made_up(i), true);
        world.relay.asked.check(bounds(&Config::default()));
        assert!(world.relay.asked.of_sender(&sender) <= 64);
    }
    world.run_for(500);
    assert_eq!(world.relay.asked.len(), 64);
    assert!(notices(&world) - before <= MADE_UP);
}

/// Scenario: many clients stay within the total, the newest kept; and
/// nothing outlives its time.
#[test]
fn many_clients_stay_within_the_total() {
    let config = Config {
        asked_total: 100,
        ..Config::default()
    };
    let mut world = World::new(Open, config, 10);
    world.direct = false;
    for i in 0..10 {
        world.open_link(i);
    }
    world.run_for(2000);
    for i in 0..10 {
        for r in 0..64 {
            forward_raw(&mut world, i, made_up(r), true);
            world.relay.asked.check(bounds(&config));
        }
        world.run_for(10);
    }
    world.run_for(100);
    world.relay.asked.check(bounds(&config));
    assert_eq!(world.relay.asked.len(), 100);
    assert_eq!(world.relay.asked.of_sender(&world.clients[9].peer_id()), 64);
    assert_eq!(world.relay.asked.of_sender(&world.clients[8].peer_id()), 36);
    world.run_for(15_000);
    assert!(world.relay.asked.is_empty(), "nothing after 15 s");
    assert_eq!(world.relay.table_sizes().3, 0);
}

/// Scenario: a client asking for a few peers is unaffected while another
/// fills its bound: its arrivals, and its notices.
#[test]
fn a_client_asking_for_a_few_peers_is_unaffected() {
    let mut world = World::new(Open, Config::default(), 5);
    world.direct = false;
    for i in 3..5 {
        world.open_link(i);
    }
    world.run_for(2000);
    // Two: a board, as every client here, dials two peers at once.
    for peer in 0..2 {
        world.send(3, peer, b"call").unwrap();
    }
    for r in 0..MADE_UP {
        forward_raw(&mut world, 4, made_up(r), true);
        if r % 20 == 19 {
            world.run_for(5);
        }
    }
    world.run_for(500);
    assert_eq!(world.relay.asked.of_sender(&world.clients[4].peer_id()), 64);
    for peer in 0..2 {
        let id = world.clients[peer].peer_id();
        assert!(world.clients[3].events.contains(&Ev::NotAtRelay(id)));
        world.open_link(peer);
    }
    world.run_for(1000);
    let legit = world.clients[3].peer_id();
    for peer in 0..2 {
        let id = world.clients[peer].peer_id();
        let told: Vec<PeerId> = arrivals_naming(&world, id)
            .into_iter()
            .map(|(to, _)| to)
            .collect();
        assert_eq!(told, vec![legit], "peer {peer}");
        assert!(world.when(3, &Ev::Connected(id)).is_some(), "peer {peer}");
    }
}

/// Scenario: a forward of data makes no seeker: its sender is told the
/// recipient is not connected, and nothing of its arrival.
#[test]
fn a_forward_of_data_makes_no_seeker() {
    let mut world = board_away(2);
    let b = world.clients[0].peer_id();
    forward_raw(&mut world, 1, b, false);
    world.run_for(500);
    assert!(world.clients[1].events.contains(&Ev::NotAtRelay(b)));
    world.open_link(0);
    world.run_for(1000);
    assert!(arrivals_naming(&world, b).is_empty());
}

/// Scenario: a seeker dropped by a bound still reaches the peer: A dials B,
/// then seeks 64 other recipients, which push B out of what the relay keeps
/// for A; B comes at 2 s; A is not told, and its attempt at 3 s reaches B.
#[test]
fn a_seeker_dropped_by_a_bound_still_reaches_the_peer() {
    let mut world = board_away(2);
    let b = world.clients[0].peer_id();
    let start = world.now;
    world.send(1, 0, b"call").unwrap();
    world.run_until(start + 1500);
    for r in 0..64 {
        forward_raw(&mut world, 1, made_up(r), true);
    }
    world.run_until(start + 2000);
    world.open_link(0);
    world.run_until(start + 5000);
    assert!(arrivals_naming(&world, b).is_empty(), "A was not told");
    let connected = world.when(1, &Ev::Connected(b)).expect("A reached B");
    assert!(
        (start + 3000..start + 3500).contains(&connected),
        "at its attempt at 3 s: {}",
        connected - start
    );
}
