//! A microcontroller's bounded tables in the simulated world: more peers
//! than session slots, the relay's reserved room, and evictions told by a
//! close (`PROTOCOL.md §5`, `§6`).

use convesso_core::endpoint::CLOSE_TO_MAKE_ROOM;

use super::world::*;
use crate::{Config, Open};

/// Whether client `to` received `tag` from client `from`.
fn got(world: &World<Open>, to: usize, from: usize, tag: &[u8]) -> bool {
    let peer = world.clients[from].peer_id();
    world.clients[to]
        .events
        .iter()
        .any(|ev| matches!(ev, Ev::Datagram { peer: p, data, .. } if *p == peer && data == tag))
}

/// The closes client `i` was told of with the eviction's code.
fn evictions(world: &World<Open>, i: usize) -> usize {
    world.clients[i]
        .events
        .iter()
        .filter(|ev| matches!(ev, Ev::Closed(_, code) if *code == CLOSE_TO_MAKE_ROOM))
        .count()
}

/// A board (client 0, the `Mcu` profile: 4 sessions) reachable through the
/// relay, keeping sessions with clients 1 and 2, which it sends to every 20
/// seconds; clients 3, 4 and 5 send it a datagram in turn, 40 seconds apart,
/// for six minutes. Every datagram arrives: each newcomer takes the place of
/// the one before, idle 40 seconds, which is closed with the eviction's code;
/// the kept sessions are never evicted; and the relay session stays usable,
/// so that a peer reaching the board only through the relay gets through at
/// the end, once the last newcomer is idle.
#[test]
fn a_board_serves_more_peers_than_its_slots() {
    let mut world = World::new(Open, Config::default(), 7);
    world.open_link(0);
    for kept in [1, 2] {
        world.open_link(kept);
    }
    for peer in [3, 4, 5] {
        world.hint(peer, 0);
    }
    world.run_for(2000);
    let mut n = 0u32;
    let mut turn = 0;
    for _ in 0..9 {
        for _ in 0..2 {
            for kept in [1usize, 2] {
                n += 1;
                let tag = n.to_le_bytes();
                world.send(0, kept, &tag).unwrap();
                world.run_for(1000);
                assert!(got(&world, kept, 0, &tag), "kept peer {kept} reached");
            }
            world.run_for(18_000);
        }
        let peer = 3 + turn % 3;
        turn += 1;
        n += 1;
        let tag = n.to_le_bytes();
        world.send(peer, 0, &tag).unwrap();
        world.run_for(2000);
        assert!(
            got(&world, 0, peer, &tag),
            "peer {peer} reached the board at turn {turn}"
        );
    }
    assert!(
        evictions(&world, 0) >= 6,
        "each newcomer took the place of the one before"
    );
    for kept in [1, 2] {
        let peer = world.clients[kept].peer_id();
        assert!(
            !world.clients[0]
                .events
                .iter()
                .any(|ev| matches!(ev, Ev::Closed(p, _) if *p == peer)),
            "kept peer {kept} never evicted"
        );
    }
    // A peer that knows the board only through the relay, once the last
    // newcomer has been idle long enough to make room.
    for kept in [1usize, 2] {
        world.send(0, kept, b"still here").unwrap();
    }
    world.run_for(35_000);
    world.send(6, 0, b"through the relay").unwrap();
    world.run_for(5000);
    assert!(
        got(&world, 0, 6, b"through the relay"),
        "the relay still reaches the board"
    );
}

/// When every session of a full board is held by its application, a
/// newcomer is refused by name, and nothing the board holds is closed.
#[test]
fn a_held_board_refuses_by_name() {
    let mut world = World::new(Open, Config::default(), 5);
    world.open_link(0);
    for peer in 1..5 {
        world.hint(peer, 0);
    }
    world.run_for(2000);
    // Three peers keep the board's other slots busy; the fourth comes.
    for round in 0..3u8 {
        for peer in 1..4 {
            world.send(peer, 0, &[round, peer as u8]).unwrap();
            world.run_for(1000);
        }
    }
    for peer in 1..4 {
        let id = world.clients[peer].peer_id();
        world.clients[0].endpoint.hold(id, SESSION, true).unwrap();
    }
    world.send(4, 0, b"no room").unwrap();
    world.run_for(20_000);
    assert!(!got(&world, 0, 4, b"no room"));
    assert_eq!(evictions(&world, 0), 0, "held sessions are never evicted");
    let board = world.clients[0].peer_id();
    assert!(
        world.clients[4].events.contains(&Ev::ReopenFailed(board)),
        "the newcomer's dial ends, refused"
    );
}

/// Scenario: a board dials two peers at once while its relay session has
/// keys: the dial kept for the relay is kept only while the relay needs one.
#[test]
fn a_board_dials_two_peers_at_once_while_its_relay_session_has_keys() {
    let mut world = World::new(Open, Config::default(), 3);
    world.open_link(0);
    world.hint(0, 1);
    world.hint(0, 2);
    world.run_for(2000);
    world.connect(0, 1).unwrap();
    world.connect(0, 2).unwrap();
    world.run_for(2000);
    for peer in [1, 2] {
        let id = world.clients[peer].peer_id();
        assert!(world.clients[0].events.contains(&Ev::Connected(id)));
    }
}
