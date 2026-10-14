//! The exchange of candidates, inside the session and only there
//! (`PROTOCOL.md §7`), through the relay.

use std::net::SocketAddr;

use convesso_core::paths::{Candidate, CandidateKind};

use super::world::*;
use crate::{Config, Open};

fn local(i: usize) -> SocketAddr {
    SocketAddr::from(([10, 0, u8::try_from(i).unwrap(), 2], 40000))
}

fn peer_list(world: &World<Open>, i: usize, j: usize) -> Vec<Candidate> {
    let peer = world.clients[j].peer_id();
    world.clients[i]
        .endpoint
        .peer_candidates(&peer, SESSION)
        .to_vec()
}

/// Scenario: candidates travel end-to-end encrypted. Each side receives the
/// other's list, its public address included once the relay observed it, and
/// no packet either sent carries an address of the list in the clear.
#[test]
fn candidates_travel_end_to_end_encrypted() {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    for i in 0..2 {
        world.clients[i].endpoint.set_local_addresses(&[local(i)]);
    }
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"through the relay").unwrap();
    world.run_for(2000);
    world.send(1, 0, b"and back").unwrap();
    world.run_for(2000);

    for (i, j) in [(0, 1), (1, 0)] {
        let own = world.clients[j].endpoint.candidates().to_vec();
        assert_eq!(peer_list(&world, i, j), own, "{i} has {j}'s list");
        assert_eq!(own[0].kind, CandidateKind::Local);
        assert!(
            own.iter().any(|c| c.kind == CandidateKind::Public),
            "{j}'s public address, as the relay saw it"
        );
    }
    for (i, client) in world.clients.iter().enumerate() {
        let mut clear = vec![0x04];
        clear.extend_from_slice(&[10, 0, u8::try_from(i).unwrap(), 2]);
        clear.extend_from_slice(&40000u16.to_le_bytes());
        for packet in client.udp_log.iter().chain(&client.tcp_log) {
            assert!(
                !packet.windows(clear.len()).any(|w| w == clear),
                "client {i}'s local address in the clear"
            );
        }
    }
}

/// Lists go only while sessions are used: once both sides know each other's,
/// 50 quiet seconds send nothing, and a new address sends one list.
#[test]
fn lists_go_on_change_and_never_periodically() {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.clients[0].endpoint.set_local_addresses(&[local(0)]);
    world.clients[1].endpoint.set_local_addresses(&[local(1)]);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"hello").unwrap();
    // Past the end of the attempt (no direct path in this world), after
    // which each side sends its list once more: no probe came from the peer.
    world.run_for(4000);
    assert_eq!(
        peer_list(&world, 0, 1),
        world.clients[1].endpoint.candidates()
    );
    assert_eq!(
        peer_list(&world, 1, 0),
        world.clients[0].endpoint.candidates()
    );
    let packets = |world: &World<Open>| -> Vec<usize> {
        world
            .clients
            .iter()
            .map(|c| c.sent.udp + c.sent.tcp)
            .collect()
    };
    let sent = packets(&world);
    world.run_for(50_000);
    assert_eq!(packets(&world), sent, "nothing in a quiet 50 s");

    // While the keys live, a new interface address reaches the peer in one
    // packet through the relay.
    world.clients[0]
        .endpoint
        .set_local_addresses(&[local(0), SocketAddr::from(([192, 168, 7, 2], 40000))]);
    world.run_for(1000);
    assert_eq!(packets(&world)[0], sent[0] + 1, "one list");
    let list = peer_list(&world, 1, 0);
    assert_eq!(list, world.clients[0].endpoint.candidates());
    assert_eq!(list[1].address, SocketAddr::from(([192, 168, 7, 2], 40000)));
}
