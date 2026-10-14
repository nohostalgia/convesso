//! The relay's side.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use convesso_core::endpoint::{Output, To};
use convesso_core::relay::framing::{PREAMBLE, frame};
use convesso_core::relay::{self, Frame};

use super::world::*;
use crate::{Config, Dest, Limits, Open, Policy};

fn attacker() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 66)), 6666)
}

/// B keeps a link, A only sends; they have exchanged a datagram each way.
fn connected(config: Config, clients: usize) -> World<Open> {
    let mut world = World::new(Open, config, clients);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"hello from a").unwrap();
    world.run_for(2000);
    world.send(1, 0, b"hello from b").unwrap();
    world.run_for(2000);
    assert_eq!(world.clients[0].datagrams().len(), 1);
    world
}

/// Has client `i` seal `packet` as a forward to `to` and put it on UDP.
fn forward_raw<P: Policy>(
    world: &mut World<P>,
    i: usize,
    to: convesso_core::identity::PeerId,
    packet: &[u8],
) {
    let now = world.instant();
    let client = &mut world.clients[i];
    let mut out = [0u8; 2048];
    out[..packet.len()].copy_from_slice(packet);
    let output = client
        .endpoint
        .through_relay(
            to,
            packet.len(),
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
        panic!("the relay session is live: {output:?}");
    };
    world.inject_from(i, &out[..len]);
}

fn actions_count<P: Policy>(world: &World<P>) -> usize {
    world.relay_udp_sent.len() + world.relay_link_types.values().map(Vec::len).sum::<usize>()
}

// --- forwarding -----------------------------------------------------------------------

/// Scenario: a forward to oneself is ignored.
#[test]
fn a_forward_to_oneself_is_ignored() {
    let mut world = connected(Config::default(), 2);
    world.run_for(1000);
    let before = actions_count(&world);
    let a = world.clients[0].peer_id();
    forward_raw(&mut world, 0, a, &[0x01; 60]);
    world.run_for(500);
    assert_eq!(actions_count(&world), before);
}

/// Scenario: a client cannot claim another sender: what A forwards, built to
/// look like C's, reaches B as A's and is dropped by B's end-to-end checks.
#[test]
fn a_client_cannot_claim_another_sender() {
    let mut world = connected(Config::default(), 3);
    let b = world.clients[1].peer_id();
    let events = world.clients[1].events.len();
    let mut fake = vec![0x01, 0x04];
    fake.extend_from_slice(&[0x5a; 60]);
    forward_raw(&mut world, 0, b, &fake);
    // A first contact claiming to be from C, which C never sent.
    let mut first = vec![0x01, 0x01];
    first.extend_from_slice(&[0x33; 132]);
    forward_raw(&mut world, 0, b, &first);
    world.run_for(1000);
    assert_eq!(world.clients[1].events.len(), events);
}

/// Scenario: a relay cannot forge a peer's packet.
#[test]
fn a_relay_cannot_forge_a_peers_packet() {
    let mut world = connected(Config::default(), 2);
    let a = world.clients[0].peer_id();
    let b = *world.clients[1].peer_id().as_bytes();
    let events = world.clients[1].events.len();
    let now = world.instant();
    let mut forged = vec![0x01, 0x04];
    forged.extend_from_slice(&[0x77; 80]);
    world.relay.forward(a, b, &forged, now);
    world.relay_actions();
    world.run_for(1000);
    assert_eq!(world.clients[1].events.len(), events);
}

/// Scenario: an unauthenticated sender learns nothing.
#[test]
fn an_unauthenticated_sender_learns_nothing() {
    let mut world = connected(Config::default(), 2);
    world.run_for(1000);
    let before = world.relay_udp_sent.len();
    let mut transport = vec![0x01, 0x04];
    transport.extend_from_slice(&[0x10; 80]);
    for packet in [vec![0xAA; 50], transport, vec![0x01, 0x01, 0x02], vec![]] {
        world.inject_udp(attacker(), &packet);
    }
    world.run_for(500);
    assert_eq!(world.relay_udp_sent.len(), before);
}

// --- addresses and links --------------------------------------------------------------

/// Scenario: a replayed packet from another address moves nothing.
#[test]
fn a_replayed_packet_from_another_address_moves_nothing() {
    let mut world = connected(Config::default(), 2);
    let a = world.clients[0].peer_id();
    let transport = world.clients[0]
        .udp_log
        .iter()
        .rev()
        .find(|p| p[1] == 0x04)
        .unwrap()
        .clone();
    world.inject_udp(attacker(), &transport);
    world.run_for(100);
    assert_eq!(
        world.relay.clients[a.as_bytes()]
            .udp4
            .map(|udp| udp.address),
        Some(world.clients[0].nat)
    );
    world.send(1, 0, b"still to a").unwrap();
    world.run_for(1000);
    assert!(
        world.clients[0]
            .datagrams()
            .contains(&(b"still to a".to_vec(), true))
    );
    assert!(!world.relay_udp_sent.iter().any(|(to, _)| *to == attacker()));
}

/// Scenario: a genuine move is followed.
#[test]
fn a_genuine_move_is_followed() {
    let mut world = connected(Config::default(), 2);
    let moved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99)), 41000);
    world.clients[0].nat = moved;
    world.send(0, 1, b"from my new address").unwrap();
    world.run_for(1000);
    world.send(1, 0, b"to your new address").unwrap();
    world.run_for(1000);
    assert!(
        world.clients[0]
            .datagrams()
            .contains(&(b"to your new address".to_vec(), true))
    );
    assert!(world.relay_udp_sent.iter().any(|(to, _)| *to == moved));
    assert!(
        world.clients[0]
            .events
            .contains(&Ev::Observed(relay_link_udp(), moved))
    );
}

fn relay_link_udp() -> relay::Link {
    relay::Link::Udp
}

/// Scenario: a spoofed first contact cannot make the relay amplify: a wake
/// replayed from a victim's address gets no more bytes there than it carried.
#[test]
fn a_spoofed_wake_cannot_amplify() {
    let mut world = connected(Config::default(), 2);
    world.run_for(6000);
    let wake = world.clients[0].udp_log[0].clone();
    for _ in 0..3 {
        world.inject_udp(attacker(), &wake);
        world.run_for(6000);
    }
    let (sent, received) = world.relay.unconfirmed[&Dest::Udp(attacker())];
    assert_eq!(received, 3 * wake.len());
    assert!(
        sent <= received,
        "{sent} bytes sent for {received} received"
    );
}

/// Scenario: a device that moves keeps one registration: a second link
/// replaces the first.
#[test]
fn a_second_link_replaces_the_first() {
    let mut world = connected(Config::default(), 2);
    let b = world.clients[1].peer_id();
    let first = world.relay.clients[b.as_bytes()].link.unwrap();
    // B's network changes; the old link's close never reaches the relay.
    world.clients[1].link_blackhole = true;
    let now = world.instant();
    world.clients[1].endpoint.network_changed(now);
    world.run_for(1000);
    let second = world.clients[1].link.unwrap();
    assert_ne!(second, first);
    assert_eq!(world.relay.clients[b.as_bytes()].link, Some(second));
    assert!(!world.relay.links.contains_key(&first));
    world.send(0, 1, b"on the new link").unwrap();
    world.run_for(1000);
    assert!(
        world.clients[1]
            .datagrams()
            .contains(&(b"on the new link".to_vec(), true))
    );
}

/// Scenario: a link cannot be borrowed: a packet of B's session on A's link
/// is dropped, and neither changes.
#[test]
fn a_link_cannot_be_borrowed() {
    let mut world = connected(Config::default(), 2);
    let a_link = world.open_link(0);
    world.run_for(1000);
    let (a, b) = (world.clients[0].peer_id(), world.clients[1].peer_id());
    world.send(1, 0, b"fresh from b").unwrap();
    world.run_for(500);
    let packet = world.clients[1]
        .udp_log
        .iter()
        .chain(world.clients[1].tcp_log.iter())
        .rev()
        .find(|p| p[1] == 0x04)
        .unwrap()
        .clone();
    let (a_state, b_state) = (
        world.relay.clients[a.as_bytes()].link,
        world.relay.clients[b.as_bytes()].link,
    );
    let mut bytes = vec![0u8; packet.len() + 2];
    let n = frame(&packet, &mut bytes).unwrap();
    let now = world.instant();
    world.relay.link_bytes(a_link, &bytes[..n], now);
    world.relay_actions();
    assert_eq!(world.relay.clients[a.as_bytes()].link, a_state);
    assert_eq!(world.relay.clients[b.as_bytes()].link, b_state);
    assert_eq!(
        world.relay.clients[b.as_bytes()]
            .udp4
            .map(|udp| udp.address),
        Some(world.clients[1].nat)
    );
}

/// Scenario: a register for another key is refused.
#[test]
fn a_register_for_another_key_is_refused() {
    let mut world = connected(Config::default(), 2);
    let a = world.clients[0].peer_id();
    let b_address = world.clients[1].address();
    let mut bytes = [0u8; 33];
    let len = relay::encode(
        &Frame::Register {
            address: *b_address.as_bytes(),
        },
        &mut bytes,
    )
    .unwrap();
    let now = world.instant();
    let from = crate::Dest::Udp(world.clients[0].nat);
    world.relay.frame(a, &bytes[..len], false, from, now);
    assert_eq!(world.relay.clients[a.as_bytes()].address, None);
}

// --- wakes ----------------------------------------------------------------------------

/// Scenario: a replayed wake spends no key's budget: a thousand replays, five
/// seconds apart, from one address, and A's own traffic is unaffected.
#[test]
fn a_thousand_replayed_wakes_spend_no_key_budget() {
    let config = Config {
        limits: Limits {
            bytes_per_second: 2_000,
            bytes_burst: 4_000,
            packets_per_second: 10,
            packets_burst: 20,
        },
        ..Config::default()
    };
    let mut world = connected(config, 2);
    let wake = world.clients[0].udp_log[0].clone();
    let a = world.clients[0].peer_id();
    let budget = |world: &World<Open>| {
        let client = &world.relay.clients[a.as_bytes()];
        (client.bytes.level, client.packets.level)
    };
    let before = budget(&world);
    for _ in 0..1000 {
        world.inject_udp(attacker(), &wake);
        world.run_for(5_100);
    }
    assert_eq!(budget(&world), before, "no replay was charged to the key");
    let delivered = world.clients[1].datagrams().len();
    for i in 0u8..10 {
        world.send(0, 1, &[i; 20]).unwrap();
        world.run_for(500);
    }
    assert_eq!(world.clients[1].datagrams().len(), delivered + 10);
}

// --- limits ---------------------------------------------------------------------------

/// Scenario: a key over its rate is held to it.
#[test]
fn a_key_over_its_rate_is_held_to_it() {
    let config = Config {
        limits: Limits {
            bytes_per_second: 25_000,
            bytes_burst: 25_000,
            packets_per_second: 10_000,
            packets_burst: 10_000,
        },
        ..Config::default()
    };
    let mut world = connected(config, 2);
    world.run_for(5000);
    let before = world.clients[1].datagrams().len();
    for i in 0u32..500 {
        world.send(0, 1, &[(i % 251) as u8; 1000]).unwrap();
        world.run_for(20);
    }
    world.run_for(2000);
    let delivered = world.clients[1].datagrams().len() - before;
    // Each forward is 34 + 31 + 1,000 bytes: the rate and burst allow
    // (25,000 * 10 + 25,000) / 1,065 of them in these 10 seconds.
    assert!(delivered <= 259, "{delivered} delivered");
    assert!(delivered >= 200, "{delivered} delivered");
}

/// Scenario: a slow recipient slows no one else.
#[test]
fn a_slow_recipient_slows_no_one_else() {
    let mut world = World::new(Open, Config::default(), 3);
    for i in [1, 2] {
        world.clients[i].udp_blocked = true;
        world.open_link(i);
    }
    world.run_for(1000);
    // One dial at a time: an MCU endpoint holds two, and one is the relay's.
    world.send(0, 1, b"warm b").unwrap();
    world.run_for(2000);
    world.send(0, 2, b"warm c").unwrap();
    world.run_for(2000);
    let b = world.clients[1].peer_id();
    let b_link = world.relay.clients[b.as_bytes()].link.unwrap();
    world
        .relay
        .set_link_backlog(b_link, Config::default().queue_per_recipient);
    let (before_b, before_c) = (
        world.clients[1].datagrams().len(),
        world.clients[2].datagrams().len(),
    );
    for i in 0u8..10 {
        world.send(0, 1, &[i; 50]).unwrap();
        world.send(0, 2, &[i; 50]).unwrap();
        world.run_for(50);
    }
    world.run_for(1000);
    assert_eq!(world.clients[1].datagrams().len(), before_b);
    assert_eq!(world.clients[2].datagrams().len(), before_c + 10);
}

/// Scenario: a recipient is shielded from a handshake flood, and transport
/// packets still reach it.
#[test]
fn a_recipient_is_shielded_from_a_handshake_flood() {
    let mut world = connected(Config::default(), 2);
    world.run_for(5000);
    let b = world.clients[1].peer_id();
    let b_link = world.relay.clients[b.as_bytes()].link.unwrap();
    let before = world.relay_link_types.get(&b_link).map_or(0, Vec::len)
        + world
            .relay_udp_sent
            .iter()
            .filter(|(to, _)| *to == world.clients[1].nat)
            .count();
    let mut first = vec![0x01, 0x01];
    first.extend_from_slice(&[0x44; 132]);
    for _ in 0..30 {
        forward_raw(&mut world, 0, b, &first);
    }
    world.run_for(100);
    let after = world.relay_link_types.get(&b_link).map_or(0, Vec::len)
        + world
            .relay_udp_sent
            .iter()
            .filter(|(to, _)| *to == world.clients[1].nat)
            .count();
    assert!(
        after - before <= 5,
        "{} first contacts carried",
        after - before
    );
    world.send(0, 1, b"still a datagram").unwrap();
    world.run_for(1000);
    assert!(
        world.clients[1]
            .datagrams()
            .contains(&(b"still a datagram".to_vec(), true))
    );
}

/// Scenario: a silent link is closed after 180 seconds; and links keep their
/// preamble rule.
#[test]
fn a_silent_link_is_closed() {
    let mut world = World::new(Open, Config::default(), 1);
    let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 1234);
    assert!(world.relay.link_opened(77, from, world.instant()));
    world.relay.link_bytes(77, &PREAMBLE, world.instant());
    world.run_for(179_000);
    assert!(world.relay.links.contains_key(&77));
    world.run_for(1_500);
    assert!(!world.relay.links.contains_key(&77));
    assert!(world.relay.link_opened(78, from, world.instant()));
    world
        .relay
        .link_bytes(78, b"GET / HTTP/1.1\r\n", world.instant());
    assert!(
        !world.relay.links.contains_key(&78),
        "a wrong preamble closes the link"
    );
}

/// Per-IP and global link limits refuse, with a close.
#[test]
fn link_limits_refuse() {
    let config = Config {
        links_per_ip: 2,
        ..Config::default()
    };
    let mut world = World::new(Open, config, 1);
    let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 1234);
    let now = world.instant();
    assert!(world.relay.link_opened(1, from, now));
    assert!(world.relay.link_opened(2, from, now));
    assert!(!world.relay.link_opened(3, from, now));
    let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 1234);
    let mut opened = 0;
    for id in 10..100 {
        if world.relay.link_opened(id, other, now) {
            opened += 1;
        }
        world.relay.link_closed(id);
    }
    assert_eq!(opened, 48, "the global burst of 50, two of it used above");
}

/// A client that comes back over a new link (a restart, or a new network)
/// while the relay still holds its old UDP address as proven: the relay
/// delivers on the new link at once, not to an address no one listens at.
/// The sender is a third client, which never talked to it: nothing of the
/// old process is in the way, and B sends nothing over UDP before.
#[test]
fn a_client_back_on_a_new_link_is_reached_there_at_once() {
    let mut world = connected(Config::default(), 3);
    let b = world.clients[1].peer_id();
    assert!(
        world.relay.clients[b.as_bytes()].udp4.is_some(),
        "B's UDP is proven"
    );
    world.restart(1);
    world.open_link(1);
    world.run_for(200);
    world.send(2, 1, b"to the new process").unwrap();
    world.run_for(500);
    assert!(
        world.clients[1]
            .datagrams()
            .contains(&(b"to the new process".to_vec(), true)),
        "{:?}",
        world.clients[1].events
    );
}

/// A client asking where the relay sees it is told, on the path it asked
/// on, and only about itself; a question that already brought a report is
/// not answered twice.
#[test]
fn a_question_about_the_observed_address_is_answered() {
    let mut world = connected(Config::default(), 2);
    let observed = |world: &World<Open>| {
        world.clients[0]
            .events
            .iter()
            .filter(|e| matches!(e, Ev::Observed(relay::Link::Udp, _)))
            .count()
    };
    let before = observed(&world);
    let a = world.clients[0].peer_id();
    let from = crate::Dest::Udp(world.clients[0].nat);
    let mut bytes = [0u8; 21];
    let question = Frame::Observed {
        link: relay::Link::Udp,
        address: "[::]:0".parse().unwrap(),
    };
    let len = relay::encode(&question, &mut bytes).unwrap();
    world.relay.reported = false;
    world
        .relay
        .frame(a, &bytes[..len], false, from, world.instant());
    world.relay_actions();
    world.run_for(500);
    assert_eq!(observed(&world), before + 1);
    assert_eq!(
        world.clients[0].events.last(),
        Some(&Ev::Observed(relay::Link::Udp, world.clients[0].nat))
    );
}
