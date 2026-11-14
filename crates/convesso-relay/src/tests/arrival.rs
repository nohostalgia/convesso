//! The arrived frame (`PROTOCOL.md §6`): the relay tells a client that sought
//! a recipient not connected when that recipient comes, and the client's dial
//! tries again at once.

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
