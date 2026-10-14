//! Attempts (`PROTOCOL.md §7`): both sides probe at once, a path is proven
//! both ways and the best one is used, a symmetric NAT is left on the relay,
//! and a session reports its path; between clients behind the simulator's
//! NATs.

use std::net::SocketAddr;

use convesso_core::paths::PathKind;

use super::world::*;
use crate::{Config, Open};

/// Two clients behind the NATs given, the second reachable through the
/// relay; the first sends to the second and they exchange a datagram each way.
fn pair(a: (Mapping, Filtering), b: (Mapping, Filtering)) -> World<Open> {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.behind(0, a.0, a.1);
    world.behind(1, b.0, b.1);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"first").unwrap();
    world.run_for(3000);
    world.send(1, 0, b"back").unwrap();
    world.run_for(1000);
    world
}

const EIM: (Mapping, Filtering) = (Mapping::Independent, Filtering::AddressAndPort);
const FULL_CONE: (Mapping, Filtering) = (Mapping::Independent, Filtering::None);
const SYMMETRIC: (Mapping, Filtering) = (Mapping::Dependent, Filtering::AddressAndPort);

fn path_changes(world: &World<Open>, i: usize) -> Vec<PathKind> {
    world.clients[i]
        .events
        .iter()
        .filter_map(|event| match event {
            Ev::PathChanged(_, path) => Some(*path),
            _ => None,
        })
        .collect()
}

fn info(world: &World<Open>, i: usize, j: usize) -> convesso_core::paths::PathInfo {
    let peer = world.clients[j].peer_id();
    world.clients[i]
        .endpoint
        .path_info(&peer, SESSION)
        .expect("a session")
}

/// Scenario: a session moves to a punched path and says so. Behind two NATs
/// that keep their port and filter by address and port, both sides probe at
/// once; the next datagrams go directly, and arrive marked direct.
#[test]
fn a_session_moves_to_a_punched_path_and_says_so() {
    let mut world = pair(EIM, EIM);
    let public = |i: usize| world.clients[i].nat;
    assert_eq!(path_changes(&world, 0), [PathKind::Direct(public(1))]);
    assert_eq!(path_changes(&world, 1), [PathKind::Direct(public(0))]);

    let relayed_before = world.clients[0].udp_log.len();
    world.send(0, 1, b"direct now").unwrap();
    world.run_for(1000);
    assert_eq!(
        world.clients[1].datagrams().last(),
        Some(&(b"direct now".to_vec(), false))
    );
    assert_eq!(
        world.clients[0].udp_log.len(),
        relayed_before,
        "not relayed"
    );

    // Probes stop at the first path that answers: well under the 40 allowed.
    for i in 0..2 {
        let stats = info(&world, i, 1 - i);
        assert!(
            stats.probes_sent >= 1 && stats.probes_sent <= 10,
            "{stats:?}"
        );
        assert!(!stats.own_symmetric && !stats.peer_symmetric);
        std::println!(
            "client {i}: direct after {:?}, {} probes",
            stats.validated_after.unwrap(),
            stats.probes_sent
        );
    }
}

/// Scenario: the LAN wins over a public path. Both are validated (the NATs
/// hairpin); the session uses the local one.
#[test]
fn the_lan_wins_over_a_public_path() {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.hairpin = true;
    world.behind(0, EIM.0, EIM.1);
    world.behind(1, EIM.0, EIM.1);
    world.same_lan(0, 1);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"first").unwrap();
    world.run_for(3000);
    let lan = |i: usize| world.clients[i].lan;
    assert_eq!(
        info(&world, 0, 1).path,
        PathKind::Direct(lan(1)),
        "{:?}",
        path_changes(&world, 0)
    );
    assert_eq!(info(&world, 1, 0).path, PathKind::Direct(lan(0)));
    let sent = world.sent_direct(0);
    assert!(
        sent.contains(&world.clients[1].nat),
        "the public path was probed too: {sent:?}"
    );
}

/// Scenario: a probe nobody can answer costs at most 40 packets. The peer
/// offers 8 candidates and none is reachable: 5 rounds over 2 s, then
/// nothing, and the session stays on the relay.
#[test]
fn an_unreachable_peer_costs_at_most_40_probes() {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.behind(0, EIM.0, EIM.1);
    world.behind(1, SYMMETRIC.0, SYMMETRIC.1);
    let unreachable: Vec<SocketAddr> = (1..=7)
        .map(|i| SocketAddr::from(([192, 168, 77, i], 40000)))
        .collect();
    world.clients[1].endpoint.set_local_addresses(&unreachable);
    world.open_link(1);
    world.run_for(1000);
    let start = world.now;
    world.send(0, 1, b"first").unwrap();
    world.run_for(10_000);

    let peer = world.clients[1].peer_id();
    assert_eq!(
        world.clients[0]
            .endpoint
            .peer_candidates(&peer, SESSION)
            .len(),
        8
    );
    assert_eq!(world.sent_direct(0).len(), 40);
    assert_eq!(info(&world, 0, 1).probes_sent, 40);
    assert_eq!(info(&world, 0, 1).path, PathKind::Relayed);
    assert!(path_changes(&world, 0).is_empty());
    assert!(
        world.clients[0]
            .deadline
            .is_none_or(|d| d.as_millis() > start + 2500)
    );

    world.send(0, 1, b"still relayed").unwrap();
    world.run_for(1000);
    assert_eq!(
        world.clients[1].datagrams().last(),
        Some(&(b"still relayed".to_vec(), true))
    );
    assert_eq!(world.sent_direct(0).len(), 40, "no attempt within 30 s");
}

/// Scenario: a symmetric NAT is reported, and the relay keeps working. Facing
/// a full cone, the symmetric side's probe gets through from a new port: the
/// full cone sees another port than the relay saw, and the symmetric side
/// learns from the answer that it was seen at another port.
#[test]
fn a_symmetric_nat_is_reported_by_both_sides() {
    let world = pair(SYMMETRIC, FULL_CONE);
    assert!(info(&world, 0, 1).own_symmetric);
    assert!(info(&world, 1, 0).peer_symmetric);
    // The full cone lets the symmetric side's probes in: a direct path.
    assert!(matches!(info(&world, 0, 1).path, PathKind::Direct(_)));
}

/// Facing a NAT that filters by address and port, a symmetric NAT leaves no
/// hole either side can use: the session stays on the relay, and its datagrams
/// keep flowing. Nothing crosses directly, so neither side can tell the NAT
/// is symmetric.
#[test]
fn a_symmetric_nat_facing_a_port_filter_stays_on_the_relay() {
    let mut world = pair(SYMMETRIC, EIM);
    for i in 0..2 {
        assert_eq!(info(&world, i, 1 - i).path, PathKind::Relayed);
        assert!(path_changes(&world, i).is_empty());
    }
    world.send(0, 1, b"through the relay").unwrap();
    world.run_for(1000);
    assert_eq!(
        world.clients[1].datagrams().last(),
        Some(&(b"through the relay".to_vec(), true))
    );
}

/// Scenario: statistics tell a direct session from a relayed one.
#[test]
fn statistics_tell_a_direct_session_from_a_relayed_one() {
    let direct = pair(EIM, EIM);
    let relayed = pair(SYMMETRIC, EIM);
    let symmetric = pair(SYMMETRIC, FULL_CONE);

    let stats = info(&direct, 0, 1);
    assert!(matches!(stats.path, PathKind::Direct(address) if address.is_ipv4()));
    let after = stats.validated_after.expect("validated");
    assert!(after.as_millis() <= 500, "{after:?}");
    assert!(stats.changed_at.is_some());

    let stats = info(&relayed, 0, 1);
    assert_eq!(stats.path, PathKind::Relayed);
    assert_eq!(stats.validated_after, None);
    assert_eq!(stats.changed_at, None);
    assert!(stats.probes_sent > 0);

    let stats = info(&symmetric, 0, 1);
    assert!(stats.own_symmetric);
}

/// A NAT that filters by address only lets a symmetric peer's probe in from
/// its new port, once it probed that peer's address: the symmetric side
/// validates the path, and both sides see the symmetric NAT.
#[test]
fn a_restricted_cone_lets_a_symmetric_peer_through() {
    let restricted = (Mapping::Independent, Filtering::Address);
    let world = pair(SYMMETRIC, restricted);
    assert!(matches!(info(&world, 0, 1).path, PathKind::Direct(_)));
    assert!(info(&world, 0, 1).own_symmetric);
    assert!(info(&world, 1, 0).peer_symmetric);
}
