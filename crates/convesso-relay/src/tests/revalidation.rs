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
/// that took the relay arrives after one sent later went directly: it is
/// accepted, and the session stays direct.
#[test]
fn a_late_relayed_packet_does_not_undo_a_direct_path() {
    let mut world = direct_pair();
    world.send_through_relay(1, 0, b"late, through the relay");
    world.send(1, 0, b"sent after it, directly").unwrap();
    world.run_for(500);
    let got = world.clients[0].datagrams();
    let late = got
        .iter()
        .position(|d| *d == (b"late, through the relay".to_vec(), true));
    let direct = got
        .iter()
        .position(|d| *d == (b"sent after it, directly".to_vec(), false));
    assert!(
        matches!((direct, late), (Some(d), Some(l)) if d < l),
        "the relayed one last: {got:?}"
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

/// Scenario: the peer of a client that moved is not sent to at its old
/// address. B moves, and its packets reach A through the relay: from then on
/// A sends B's old address one probe at most, and every datagram arrives,
/// through the relay or at B's new address once an attempt finds it.
#[test]
fn the_peer_of_a_client_that_moved_is_not_sent_to_at_its_old_address() {
    let mut world = direct_pair();
    let old = world.clients[1].nat;
    let before = world.sent_direct(0).iter().filter(|to| **to == old).count();
    world.move_network(1, std::net::Ipv4Addr::new(203, 0, 113, 77));
    world.send(1, 0, b"from elsewhere").unwrap();
    world.run_for(300);
    assert_eq!(last_datagram(&world, 0), (b"from elsewhere".to_vec(), true));

    for i in 0..10u8 {
        world.send(0, 1, &[i]).unwrap();
        world.run_for(100);
    }
    let after = world.sent_direct(0).iter().filter(|to| **to == old).count();
    assert!(after - before <= 1, "one probe to the old address at most");
    let got = world.clients[1].datagrams();
    for i in 0..10u8 {
        assert!(
            got.iter().any(|(data, _)| *data == [i]),
            "datagram {i} arrived"
        );
    }
}

/// Scenario: a peer heard through the relay but still reachable directly is
/// direct again after one probe. B sends one packet through the relay; A's
/// next datagram takes the relay with one probe, whose answer brings A back
/// to the direct path.
#[test]
fn a_peer_heard_through_the_relay_but_reachable_is_direct_again_after_one_probe() {
    let mut world = direct_pair();
    let probes_before = probes(&world, 0);
    world.send_through_relay(1, 0, b"a bounce through the relay");
    world.run_for(300);
    world.send(0, 1, b"after it").unwrap();
    world.run_for(300);
    assert_eq!(last_datagram(&world, 1), (b"after it".to_vec(), true));
    assert_eq!(probes(&world, 0) - probes_before, 1);
    world.send(0, 1, b"direct again").unwrap();
    world.run_for(300);
    assert_eq!(last_datagram(&world, 1), (b"direct again".to_vec(), false));
    assert!(matches!(path(&world, 0), PathKind::Direct(_)));
}

/// Scenario: a peer that moved and has nothing to send is found too. B's NAT
/// forgets its flows and maps it anew, its interfaces unchanged, so its list
/// is the same; B is told the network changed and sends nothing of its own.
/// Its one packet through the relay tells A: every datagram A sends after it
/// arrives.
#[test]
fn a_silent_peer_that_moved_is_found() {
    let mut world = direct_pair();
    for nat in &mut world.clients[1].nats {
        *nat = Nat::new(Mapping::Dependent, Filtering::AddressAndPort);
    }
    world.run_for(1000);
    let now = world.instant();
    world.clients[1].endpoint.network_changed(now);
    world.run_for(500);
    let before = world.clients[1].datagrams().len();
    for i in 0..20u8 {
        world.send(0, 1, &[i]).unwrap();
        world.run_for(100);
    }
    assert_eq!(world.clients[1].datagrams().len(), before + 20);
}

/// B changes network: its NAT maps it anew, and the world's delay makes its
/// relay session and link take a few hundred milliseconds to come back.
fn change_network(world: &mut World<Open>, i: usize, udp_lost: bool) {
    world.delay = 100;
    for nat in &mut world.clients[i].nats {
        *nat = Nat::new(Mapping::Dependent, Filtering::AddressAndPort);
    }
    world.clients[i].udp_blocked = udp_lost;
    let now = world.instant();
    world.clients[i].endpoint.network_changed(now);
}

/// Scenario: the packet that tells the peer waits for the new link. B, with
/// a link and a direct session, changes network, and none of its UDP gets
/// through, to the relay or to A. Its packet goes on the new link once the
/// relay has it again, so A's datagrams take the relay and arrive.
#[test]
fn the_packet_that_tells_the_peer_waits_for_the_new_link() {
    let mut world = direct_pair();
    change_network(&mut world, 1, true);
    world.run_for(2000);
    assert!(
        world.when(1, &Ev::RelayAvailable).is_some(),
        "B registered again"
    );
    let before = world.clients[1].datagrams().len();
    for i in 0..10u8 {
        world.send(0, 1, &[i]).unwrap();
        world.run_for(100);
    }
    world.run_for(500);
    let got = &world.clients[1].datagrams()[before..];
    assert_eq!(got.len(), 10, "every datagram after the change: {got:?}");
    assert!(got.iter().all(|(_, relayed)| *relayed));
}

/// Scenario: a client without a link tells its peer at once. A keeps no link
/// to the relay; it changes network, its UDP working, and its packet goes
/// over UDP at once: B's datagrams take the relay and arrive.
#[test]
fn a_client_without_a_link_tells_its_peer_at_once() {
    let mut world = direct_pair();
    // A's data on the direct path: B's path is one A uses.
    world.send(0, 1, b"direct").unwrap();
    world.run_for(300);
    assert_eq!(last_datagram(&world, 1), (b"direct".to_vec(), false));
    change_network(&mut world, 0, false);
    world.run_for(500);
    let before = world.clients[0].datagrams().len();
    for i in 0..10u8 {
        world.send(1, 0, &[i]).unwrap();
        world.run_for(100);
    }
    world.run_for(500);
    assert_eq!(world.clients[0].datagrams().len(), before + 10);
}

/// Scenario: a change of network ends the proof of UDP: what B proved to the
/// relay from its old network no longer counts, and its first packet for the
/// relay after the change goes over both.
#[test]
fn a_change_of_network_ends_the_proof_of_udp() {
    let mut world = direct_pair();
    world.send_through_relay(1, 0, b"over UDP to the relay");
    world.run_for(500);
    let now = world.instant();
    assert!(world.clients[1].endpoint.relay_udp_proven(now));
    let before = world.clients[1].sent;
    world.clients[1].endpoint.network_changed(now);
    assert!(!world.clients[1].endpoint.relay_udp_proven(now));
    // Once the relay has B again, B's first packet for it, the one that tells
    // A, goes over the link and over UDP at once, whenever the last UDP copy
    // went; the relay's answer over UDP proves UDP again.
    world.run_for(1000);
    let after = world.clients[1].sent;
    assert!(
        after.tcp > before.tcp,
        "over the link: {before:?} -> {after:?}"
    );
    assert!(
        after.udp > before.udp,
        "and over UDP: {before:?} -> {after:?}"
    );
    let now = world.instant();
    assert!(world.clients[1].endpoint.relay_udp_proven(now));
}
