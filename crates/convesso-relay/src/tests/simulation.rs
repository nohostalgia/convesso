//! The simulations: lossy links, the wakes, the
//! idle months.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use convesso_core::relay::framing::KEEPALIVE;

use super::world::*;
use crate::{Config, Open};

// --- lossy links ----------------------------------------------------------------------

/// Two clients exchange datagrams through the relay for ten minutes, both
/// directions, across several rekeys of every session, over UDP that loses,
/// duplicates and reorders: nothing is delivered that was not sent, nothing
/// twice, most of it arrives; traffic runs over UDP; and a NAT rebinding
/// halfway through is followed.
#[test]
fn datagrams_cross_a_lossy_relay() {
    for seed in [1u64, 2, 3] {
        let mut world = World::new(Open, Config::default(), 2);
        world.chaos = Some(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        world.open_link(1);
        world.run_for(1000);
        let mut sent_ab = BTreeSet::new();
        let mut sent_ba = BTreeSet::new();
        for i in 0u32..6000 {
            if i == 3000 {
                world.clients[0].nat =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)), 45000);
            }
            let ab = [b"a".as_slice(), &i.to_le_bytes()].concat();
            if world.send(0, 1, &ab).is_ok() {
                sent_ab.insert(ab);
            }
            let ba = [b"b".as_slice(), &i.to_le_bytes()].concat();
            if world.send(1, 0, &ba).is_ok() {
                sent_ba.insert(ba);
            }
            world.run_for(100);
        }
        world.run_for(5000);
        for (side, received, sent) in [
            ("B", world.clients[1].datagrams(), &sent_ab),
            ("A", world.clients[0].datagrams(), &sent_ba),
        ] {
            let unique: BTreeSet<Vec<u8>> = received.iter().map(|(d, _)| d.clone()).collect();
            assert_eq!(
                unique.len(),
                received.len(),
                "seed {seed}: {side} got a datagram twice"
            );
            assert!(
                unique.is_subset(sent),
                "seed {seed}: {side} got a datagram never sent"
            );
            assert!(received.iter().all(|(_, relayed)| *relayed));
            assert!(
                unique.len() * 100 >= sent.len() * 70,
                "seed {seed}: {side} received {} of {}",
                unique.len(),
                sent.len()
            );
            // After the rebinding too.
            let late = unique
                .iter()
                .filter(|d| u32::from_le_bytes(d[1..5].try_into().unwrap()) > 3100)
                .count();
            assert!(
                late > 2000,
                "seed {seed}: {side} received {late} after the rebinding"
            );
        }
        let b = world.clients[1].sent;
        assert!(
            b.udp > 5 * b.tcp,
            "seed {seed}: B's traffic moved to UDP: {b:?}"
        );
    }
}

/// With every UDP datagram dropped on B's network, the same exchange runs over
/// TCP, losing nothing.
#[test]
fn datagrams_cross_the_relay_over_tcp_when_udp_is_blocked() {
    let mut world = World::new(Open, Config::default(), 2);
    world.clients[1].udp_blocked = true;
    world.open_link(0);
    world.open_link(1);
    world.run_for(1000);
    for i in 0u32..1200 {
        world.send(0, 1, &i.to_le_bytes()).unwrap();
        world.send(1, 0, &i.to_le_bytes()).unwrap();
        world.run_for(100);
    }
    world.run_for(2000);
    assert_eq!(world.clients[1].datagrams().len(), 1200);
    assert_eq!(world.clients[0].datagrams().len(), 1200);
    let b = world.clients[1].sent;
    // A copy every 10 s, and the questions about its public address (at most
    // 4) when its session with A opened.
    let questions = convesso_core::endpoint::ASK_ADDRESS_AT.len();
    assert!(
        b.udp <= 120 / 10 + 2 + questions,
        "UDP copies only every 10 s: {b:?}"
    );
}

// --- the wakes -------------------------------------------------------------------------

/// Scenario: a wake reaches the peer in one round trip: with 20 ms on every
/// hop, the peer's response reaches the sleeping client 80 ms (client, relay,
/// peer, relay, client) after its first datagram left.
#[test]
fn a_wake_reaches_the_peer_in_one_round_trip() {
    let mut world = World::new(Open, Config::default(), 2);
    world.open_link(1);
    world.run_for(1000);
    let start = world.now;
    world.send(0, 1, b"wake").unwrap();
    world.run_for(1000);
    let b = world.clients[1].peer_id();
    let connected = world.when(0, &Ev::Connected(b)).unwrap();
    assert_eq!(connected - start, 4 * world.delay);
    assert_eq!(world.clients[0].udp_log[0].len(), 302);
    std::println!(
        "wake through the relay: the peer's response after {} ms, {} hops of {} ms",
        connected - start,
        (connected - start) / world.delay,
        world.delay
    );
}

/// Scenario: a dormant client receives a first contact in one round trip: the
/// relay's first packet to it after the wake is a first contact carrying the
/// peer's first contact.
#[test]
fn a_dormant_client_is_woken_by_the_relay() {
    let mut world = World::new(Open, Config::default(), 2);
    world.open_link(1);
    world.run_for(1000);
    // Long enough for every relay session to go dormant; the link stays up.
    world.run_for(200_000);
    let relay = world.relay.address().peer_id();
    assert!(!world.clients[1].endpoint.is_live(
        &relay,
        convesso_core::relay::CONTEXT,
        world.instant()
    ));
    let b = world.relay.clients[world.clients[1].peer_id().as_bytes()]
        .link
        .unwrap();
    let before = world.relay_link_types.get(&b).map_or(0, Vec::len);
    let start = world.now;
    world.send(0, 1, b"wake up").unwrap();
    world.run_for(2000);
    let types = &world.relay_link_types[&b];
    assert_eq!(
        types[before], 0x05,
        "a first contact with a payload, nothing before it"
    );
    assert_eq!(
        world.clients[1].datagrams(),
        vec![(b"wake up".to_vec(), true)]
    );
    let a = world.clients[0].peer_id();
    let delivered = world
        .when(
            1,
            &Ev::Datagram {
                peer: a,
                data: b"wake up".to_vec(),
                relayed: true,
            },
        )
        .unwrap();
    std::println!(
        "relay's wake of a dormant client: the datagram arrives {} ms after it left ({} hops of {} ms)",
        delivered - start,
        (delivered - start) / world.delay,
        world.delay
    );
}

// --- the idle months ------------------------------------------------------------------

const MONTH: u64 = 30 * 24 * 3600 * 1000;

/// Scenario: an idle month with a TCP link costs only keep-alives: one every
/// 60 seconds, the relay's answer to each, nothing else either way, and the
/// link stays bound.
#[test]
fn an_idle_month_with_a_link_costs_only_keepalives() {
    let mut world = World::new(Open, Config::default(), 1);
    world.open_link(0);
    world.run_for(60_000);
    let start = world.clients[0].sent;
    let answers = world.clients[0].keepalive_answers;
    let link = world.clients[0].link.unwrap();
    let relay_sent = world.relay_link_sent[&link];
    world.run_for(MONTH);
    let end = world.clients[0].sent;
    assert_eq!(end.keepalives - start.keepalives, 43_200);
    assert_eq!(
        (end.udp, end.tcp),
        (start.udp, start.tcp),
        "nothing but keep-alives"
    );
    assert_eq!(world.clients[0].keepalive_answers - answers, 43_200);
    assert_eq!(
        world.relay_link_sent[&link] - relay_sent,
        43_200 * KEEPALIVE.len(),
        "the relay sent nothing but the answers"
    );
    assert_eq!(world.clients[0].opens.len(), 1, "one link, never replaced");
    let peer = world.clients[0].peer_id();
    assert_eq!(world.relay.clients[peer.as_bytes()].link, Some(link));
    // On the wire: 2 bytes of TCP payload each way; with IPv4, TCP and
    // timestamps (52 bytes of headers), the answer riding in the relay's ACK:
    // about 108 bytes a minute.
    let keepalives = end.keepalives - start.keepalives;
    let per_keepalive = 2 * KEEPALIVE.len() + 52 + 52;
    std::println!(
        "idle month with a link: {keepalives} keep-alives and as many answers, {} bytes of payload, about {:.1} MB with headers and ACKs",
        2 * keepalives * KEEPALIVE.len(),
        (keepalives * per_keepalive) as f64 / 1e6
    );
}

/// What two clients send in an idle month after an exchange of datagrams in
/// each of `contexts`, through the relay, client 1 keeping a link: the
/// packets each sent, and client 1's keep-alives.
fn an_idle_month_after_contexts(contexts: &[&[u8]]) -> (u64, u64, u64) {
    let mut world = World::new(Open, Config::default(), 2);
    for client in &mut world.clients {
        for context in contexts {
            if *context != SESSION {
                client
                    .endpoint
                    .serve(context, convesso_core::handshake::Access::Policy)
                    .unwrap();
            }
        }
    }
    world.open_link(1);
    world.run_for(60_000);
    for context in contexts {
        world.send_in(0, 1, context, b"there").unwrap();
        world.run_for(1000);
        world.send_in(1, 0, context, b"and back").unwrap();
        world.run_for(1000);
    }
    let got = world.clients[0].datagrams().len() + world.clients[1].datagrams().len();
    assert_eq!(got, 2 * contexts.len(), "an exchange in each context");
    // Past the keys' life: every session dormant.
    world.run_for(200_000);
    let start: Vec<_> = world.clients.iter().map(|c| c.sent).collect();
    world.run_for(MONTH);
    let end: Vec<_> = world.clients.iter().map(|c| c.sent).collect();
    let packets = |i: usize| (end[i].udp + end[i].tcp - start[i].udp - start[i].tcp) as u64;
    (
        packets(0),
        packets(1),
        (end[1].keepalives - start[1].keepalives) as u64,
    )
}

/// Scenario: an idle month with three contexts open costs what one costs:
/// after an exchange in each, keep-alives only, one a minute, on the link of
/// the client that keeps one; nothing from the other.
#[test]
fn an_idle_month_with_three_contexts_costs_what_one_costs() {
    let one = an_idle_month_after_contexts(&[SESSION]);
    let three = an_idle_month_after_contexts(&[SESSION, b"example/files/1", b"example/chat/1"]);
    std::println!("an idle month: one context {one:?}, three {three:?}");
    assert_eq!(three, one);
    assert_eq!(three, (0, 0, 43_200), "keep-alives only, one a minute");
}

/// Scenario: an idle month without a link costs nothing: after one datagram
/// through the relay over UDP, nothing is sent and no deadline is returned.
#[test]
fn an_idle_month_without_a_link_costs_nothing() {
    let mut world = World::new(Open, Config::default(), 2);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"one reading").unwrap();
    world.run_for(200_000);
    let start = world.clients[0].sent;
    world.run_for(MONTH);
    assert_eq!(world.clients[0].sent, start);
    assert_eq!(world.clients[0].deadline, None);
    std::println!(
        "idle month without a link: {} packets, {} bytes in all (the first exchange only)",
        start.udp,
        start.udp_bytes
    );
}

// --- attacks --------------------------------------------------------------------------
//
// The attacks run in the same simulator, each in its own test with the
// scenario it checks: a replayed wake from a forged address
// (`relay::a_spoofed_wake_cannot_amplify`, and a thousand of them in
// `relay::a_thousand_replayed_wakes_spend_no_key_budget`); a replayed
// transport packet from another address
// (`relay::a_replayed_packet_from_another_address_moves_nothing`); a client
// claiming another sender (`relay::a_client_cannot_claim_another_sender`); a
// relay delivering a forged packet (`relay::a_relay_cannot_forge_a_peers_packet`);
// a packet of one key on another key's link (`relay::a_link_cannot_be_borrowed`);
// a scanner dialling a client in the relay context
// (`client::another_key_cannot_pose_as_the_relay`).
