//! Re-validation on use (`PROTOCOL.md §7`, and the path rule of
//! `PROTOCOL.md §6`), with NATs that forget idle flows after 30 seconds.

use convesso_core::paths::PathKind;

use super::world::*;
use crate::{Config, Open};

const EIM: (Mapping, Filtering) = (Mapping::Independent, Filtering::AddressAndPort);

/// Two clients behind port-keeping NATs, gone direct.
fn direct_pair() -> World<Open> {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.behind(0, EIM.0, EIM.1);
    world.behind(1, EIM.0, EIM.1);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"first").unwrap();
    world.run_for(3000);
    world.send(1, 0, b"back").unwrap();
    world.run_for(1000);
    for i in 0..2 {
        assert!(matches!(path(&world, i), PathKind::Direct(_)), "{i}");
    }
    world
}

fn path(world: &World<Open>, i: usize) -> PathKind {
    let peer = world.clients[1 - i].peer_id();
    world.clients[i]
        .endpoint
        .path_info(&peer, SESSION)
        .expect("a session")
        .path
}

fn probes(world: &World<Open>, i: usize) -> u32 {
    let peer = world.clients[1 - i].peer_id();
    world.clients[i]
        .endpoint
        .path_info(&peer, SESSION)
        .map_or(0, |info| info.probes_sent)
}

fn last_datagram(world: &World<Open>, i: usize) -> (Vec<u8>, bool) {
    world.clients[i]
        .datagrams()
        .last()
        .cloned()
        .expect("a datagram")
}

/// Scenario: a path stale after a pause is checked by use. After 60 idle
/// seconds both NATs forgot the hole: the datagram goes through the relay and
/// arrives, the probe on the direct path gets no answer, the session goes
/// back to the relay, and a new attempt starts.
#[test]
fn a_path_stale_after_a_pause_is_checked_by_use() {
    let mut world = direct_pair();
    world.run_for(60_000);
    let probes_before = probes(&world, 0);
    let direct_before = world.sent_direct(0).len();

    world.send(0, 1, b"after a minute").unwrap();
    world.run_for(100);
    assert_eq!(
        last_datagram(&world, 1),
        (b"after a minute".to_vec(), true),
        "through the relay"
    );
    assert_eq!(world.sent_direct(0).len(), direct_before + 1, "one probe");

    world.run_for(5000);
    assert_eq!(path(&world, 0), PathKind::Relayed);
    assert_eq!(
        world.clients[0].events.iter().rev().find_map(|e| match e {
            Ev::PathChanged(_, path) => Some(*path),
            _ => None,
        }),
        Some(PathKind::Relayed),
        "the application is told"
    );
    assert!(
        probes(&world, 0) > probes_before + 1,
        "a new attempt after the lost check"
    );

    world.send(0, 1, b"still relayed").unwrap();
    world.run_for(1000);
    assert_eq!(last_datagram(&world, 1), (b"still relayed".to_vec(), true));
}

/// Scenario: a path stale after a pause but still open comes back at once.
/// After 20 idle seconds the NATs still hold the hole: the datagram goes
/// through the relay, the probe's answer comes back on the direct path, and
/// the next datagram goes directly.
#[test]
fn a_path_stale_but_still_open_comes_back_at_once() {
    let mut world = direct_pair();
    world.run_for(20_000);
    let changes = world.clients[0].events.len();

    world.send(0, 1, b"after 20 s").unwrap();
    world.run_for(200);
    assert_eq!(last_datagram(&world, 1), (b"after 20 s".to_vec(), true));
    world.send(0, 1, b"direct again").unwrap();
    world.run_for(200);
    assert_eq!(last_datagram(&world, 1), (b"direct again".to_vec(), false));
    assert!(matches!(path(&world, 0), PathKind::Direct(_)));
    assert!(
        !world.clients[0].events[changes..]
            .iter()
            .any(|e| matches!(e, Ev::PathChanged(..))),
        "no change to tell"
    );
}

/// Scenario: a late relayed packet does not undo a direct path. A datagram
/// that took the relay arrives after the session went direct: it is
/// accepted, and the session stays direct.
#[test]
fn a_late_relayed_packet_does_not_undo_a_direct_path() {
    let mut world = direct_pair();
    world.send_through_relay(1, 0, b"late, through the relay");
    world.run_for(500);
    assert_eq!(
        last_datagram(&world, 0),
        (b"late, through the relay".to_vec(), true)
    );
    assert!(matches!(path(&world, 0), PathKind::Direct(_)));
    let relayed = world.clients[0].udp_log.len();
    world.send(0, 1, b"still direct").unwrap();
    world.run_for(500);
    assert_eq!(last_datagram(&world, 1), (b"still direct".to_vec(), false));
    assert_eq!(world.clients[0].udp_log.len(), relayed);
}

/// Scenario: an idle month with a direct session costs nothing more. After
/// the session goes dormant neither client sends anything, directly or to
/// the relay, but the reachable one's keep-alives; and the dormant session
/// forgot its path.
#[test]
fn an_idle_month_with_a_direct_session_costs_nothing_more() {
    const MONTH: u64 = 30 * 24 * 3600 * 1000;
    let mut world = direct_pair();
    world.run_for(200_000);
    let sent: Vec<Sent> = world.clients.iter().map(|c| c.sent).collect();
    let direct: Vec<usize> = (0..2).map(|i| world.sent_direct(i).len()).collect();
    world.run_for(MONTH);
    for i in 0..2 {
        let now = world.clients[i].sent;
        assert_eq!((now.udp, now.tcp), (sent[i].udp, sent[i].tcp), "client {i}");
        assert_eq!(world.sent_direct(i).len(), direct[i], "client {i}");
        assert_eq!(path(&world, i), PathKind::Relayed, "forgotten");
    }
    assert_eq!(world.clients[0].deadline, None);
    assert_eq!(
        world.clients[1].sent.keepalives - sent[1].keepalives,
        43_200,
        "only the link's keep-alives"
    );

    // Used again, the session reopens through the relay, and goes direct.
    world.send(0, 1, b"a month later").unwrap();
    world.run_for(3000);
    assert_eq!(last_datagram(&world, 1), (b"a month later".to_vec(), true));
    world.send(0, 1, b"direct again").unwrap();
    world.run_for(500);
    assert_eq!(last_datagram(&world, 1), (b"direct again".to_vec(), false));
}
