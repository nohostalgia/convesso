//! The client's side.

use std::time::Duration;

use convesso_core::dos::Source;
use convesso_core::endpoint::{Endpoint, Output, RelayError, SendError, Target, To};
use convesso_core::handshake::{DialError, RefusalCode};
use convesso_core::identity::PeerId;
use convesso_core::relay::{CONTEXT, Link, MAX_CARRIED};
use convesso_core::storage::Mcu;

use super::world::*;
use crate::{Admit, Config, Open, Policy};

/// B keeps a link; A only sends. After this, both have relay sessions and a
/// session with each other.
fn connected() -> World<Open> {
    let mut world = World::new(Open, Config::default(), 3);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"hello from a").unwrap();
    world.run_for(2000);
    world
}

fn relay_peer<P: Policy>(world: &World<P>) -> PeerId {
    world.relay.address().peer_id()
}

/// A reachable client B (TCP link) and a client A that only sends: A's first
/// datagram reaches B through the relay, marked relayed, and B's reply comes
/// back the same way.
#[test]
fn a_datagram_crosses_the_relay_both_ways() {
    let mut world = connected();
    assert_eq!(
        world.clients[1].datagrams(),
        vec![(b"hello from a".to_vec(), true)]
    );
    world.send(1, 0, b"hello from b").unwrap();
    world.run_for(2000);
    assert_eq!(
        world.clients[0].datagrams(),
        vec![(b"hello from b".to_vec(), true)]
    );
}

// --- the relay session ----------------------------------------------------------------

/// Scenario: a client opens a session with its pinned relay, in the relay
/// context, and no connection event reaches the application.
#[test]
fn a_client_opens_a_session_with_its_pinned_relay() {
    let world = connected();
    let relay = relay_peer(&world);
    assert!(
        world.clients[0]
            .endpoint
            .is_live(&relay, CONTEXT, world.instant())
    );
    for client in &world.clients {
        assert!(!client.events.contains(&Ev::Connected(relay)));
        assert!(!client.events.contains(&Ev::Payload));
    }
    // A's application saw B, never the relay.
    assert!(
        world.clients[0]
            .events
            .contains(&Ev::Connected(world.clients[1].peer_id()))
    );
}

/// Scenario: another key cannot pose as the relay: its first contacts in the
/// relay context, with or without a payload, meet silence.
#[test]
fn another_key_cannot_pose_as_the_relay() {
    let mut world = connected();
    let mut imposter: Endpoint<Mcu> = Endpoint::new(identity(4), &[SESSION]).unwrap();
    let mut entropy = TestEntropy(999);
    let a = world.clients[0].address();
    let now = world.instant();
    let mut out = [0u8; 2048];
    imposter.set_hints(a.peer_id(), &[&[0]], now).unwrap();
    let Ok(Output::Transmit { len, .. }) =
        imposter.connect(&a, CONTEXT, now, &mut AcceptAll, &mut entropy, &mut out)
    else {
        panic!("an endpoint without a pinned relay dials in the relay context");
    };
    let plain = out[..len].to_vec();
    let mut imposter: Endpoint<Mcu> = Endpoint::new(identity(4), &[SESSION]).unwrap();
    imposter.set_hints(a.peer_id(), &[&[0]], now).unwrap();
    let Ok(Output::Transmit { len, .. }) = imposter.send(
        Target::Address(&a),
        CONTEXT,
        &[0x02; 60],
        1500,
        now,
        &mut AcceptAll,
        &mut entropy,
        &mut out,
    ) else {
        panic!("a dial in the relay context");
    };
    let with_payload = out[..len].to_vec();
    assert_eq!(
        with_payload[1], 0x05,
        "a dial in the relay context carries its queue"
    );

    let events = world.clients[0].events.len();
    let sent = world.clients[0].sent;
    for packet in [&plain, &with_payload] {
        let client = &mut world.clients[0];
        for link in [Link::Udp, Link::Tcp] {
            let mut buffer = packet.clone();
            let output = client.endpoint.handle_relay_packet(
                &mut buffer,
                link,
                now,
                &mut client.policy,
                &mut client.entropy,
                &mut out,
            );
            assert_eq!(output, Output::Nothing);
        }
        let mut buffer = packet.clone();
        world.handle_direct(0, &mut buffer, Source::Direct(&[9, 9]));
    }
    world.run_for(100);
    assert_eq!(world.clients[0].events.len(), events);
    assert_eq!(world.clients[0].sent, sent);
}

/// Scenario: relay frames never reach the application as data; and the relay
/// context is the endpoint's own.
#[test]
fn relay_frames_never_reach_the_application() {
    let mut world = connected();
    for client in &world.clients {
        for event in &client.events {
            assert!(
                !matches!(event, Ev::Datagram { peer, .. } if *peer == world.relay.address().peer_id())
            );
        }
    }
    let now = world.instant();
    let b = world.clients[1].address();
    let client = &mut world.clients[0];
    let mut out = [0u8; 2048];
    assert_eq!(
        client.endpoint.send(
            Target::Address(&b),
            CONTEXT,
            b"x",
            1500,
            now,
            &mut client.policy,
            &mut client.entropy,
            &mut out
        ),
        Err(SendError::ReservedContext)
    );
    assert_eq!(
        client.endpoint.connect(
            &b,
            CONTEXT,
            now,
            &mut client.policy,
            &mut client.entropy,
            &mut out
        ),
        Err(SendError::ReservedContext)
    );
}

// --- the wake -------------------------------------------------------------------------

/// The wake is one datagram: the relay's first contact, 302 bytes, carrying
/// the forward of A's first contact to B.
#[test]
fn a_wake_is_one_datagram_of_302_bytes() {
    let world = connected();
    let wake = &world.clients[0].udp_log[0];
    assert_eq!(wake.len(), 302);
    assert_eq!(&wake[..2], &[0x01, 0x05]);
}

/// Scenario: a datagram too large for the relay is refused, naming the sizes.
#[test]
fn a_datagram_too_large_for_the_relay_is_refused() {
    let mut world = connected();
    assert_eq!(
        world.send(0, 1, &[7; MAX_CARRIED + 1 - 31]),
        Err(SendError::TooLarge {
            packet: 1381,
            path: 1380
        })
    );
    let b = world.clients[1].peer_id();
    let now = world.instant();
    let client = &mut world.clients[0];
    let mut out = [1u8; 2048];
    assert_eq!(
        client.endpoint.through_relay(
            b,
            MAX_CARRIED + 1,
            now,
            &mut client.policy,
            &mut client.entropy,
            &mut out
        ),
        Err(SendError::TooLarge {
            packet: 1381,
            path: 1380
        })
    );
}

/// A forward is built around the packet in place: an output buffer of the
/// packet plus 65 bytes is enough, one byte less is not.
#[test]
fn a_forward_needs_no_second_buffer() {
    let mut world = connected();
    let b = world.clients[1].peer_id();
    let now = world.instant();
    let client = &mut world.clients[0];
    let packet = [0x01u8; 100];
    let mut tight = [0u8; 165];
    tight[..100].copy_from_slice(&packet);
    assert!(matches!(
        client.endpoint.through_relay(
            b,
            100,
            now,
            &mut client.policy,
            &mut client.entropy,
            &mut tight
        ),
        Ok(Output::Transmit {
            to: To::Relay(_),
            len: 165
        })
    ));
    let mut short = [0u8; 164];
    short[..100].copy_from_slice(&packet);
    assert!(matches!(
        client.endpoint.through_relay(
            b,
            100,
            now,
            &mut client.policy,
            &mut client.entropy,
            &mut short
        ),
        Err(SendError::TooLarge { .. })
    ));
}

// --- a peer not at the relay ----------------------------------------------------------

/// Scenario: a sender learns that its peer is not at the relay, and its dial
/// continues on its schedule.
#[test]
fn a_sender_learns_its_peer_is_not_at_the_relay() {
    let mut world = connected();
    let c = world.clients[2].peer_id();
    world.send(0, 2, b"anyone there?").unwrap();
    world.run_for(1000);
    let notices = |world: &World<Open>| {
        world.clients[0]
            .events
            .iter()
            .filter(|e| **e == Ev::NotAtRelay(c))
            .count()
    };
    assert_eq!(notices(&world), 1);
    assert!(!world.clients[0].events.contains(&Ev::ReopenFailed(c)));
    world.run_for(16_000);
    assert!(world.clients[0].events.contains(&Ev::ReopenFailed(c)));
    assert!(
        notices(&world) >= 2,
        "each retry is answered, at most once a second"
    );
}

/// Scenario: not-connected notices are rate-limited: ten forwards in one
/// second to an absent key get one notice.
#[test]
fn not_connected_notices_are_rate_limited() {
    let mut world = connected();
    let c = world.clients[2].peer_id();
    let now = world.instant();
    for _ in 0..10 {
        let client = &mut world.clients[0];
        let mut out = [0x01u8; 2048];
        let output = client
            .endpoint
            .through_relay(
                c,
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
        world.inject_from(0, &out[..len]);
    }
    world.run_for(500);
    let notices = world.clients[0]
        .events
        .iter()
        .filter(|e| **e == Ev::NotAtRelay(c))
        .count();
    assert_eq!(notices, 1);
}

/// Scenario: a client learns its public address, for UDP and for its TCP link.
#[test]
fn a_client_learns_its_public_address() {
    let world = connected();
    assert!(
        world.clients[0]
            .events
            .contains(&Ev::Observed(Link::Udp, world.clients[0].nat))
    );
    assert!(
        world.clients[1]
            .events
            .contains(&Ev::Observed(Link::Tcp, world.clients[1].tcp_from))
    );
}

/// Scenario: nothing is reported while the address does not change, over an
/// hour of traffic, rekeys included.
#[test]
fn an_unchanged_address_is_reported_once() {
    let mut world = connected();
    let observed = |world: &World<Open>| {
        world.clients[0]
            .events
            .iter()
            .filter(|e| matches!(e, Ev::Observed(Link::Udp, _)))
            .count()
    };
    assert_eq!(observed(&world), 1);
    for i in 0..360 {
        world.send(0, 1, &u32::to_le_bytes(i)).unwrap();
        world.run_for(10_000);
    }
    assert_eq!(observed(&world), 1);
    assert_eq!(world.clients[1].datagrams().len(), 361);
}

/// Scenario: a relayed datagram is marked relayed, a direct one direct: A
/// reaches B through the relay, C, which has B's address, directly.
#[test]
fn datagrams_say_how_they_came() {
    let mut world = World::new(Open, Config::default(), 3);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"relayed").unwrap();
    world.run_for(1000);
    world.hint(2, 1);
    world.send(2, 1, b"direct").unwrap();
    world.run_for(1000);
    assert_eq!(
        world.clients[1].datagrams(),
        vec![(b"relayed".to_vec(), true), (b"direct".to_vec(), false)]
    );
}

struct RefuseAll;

impl Policy for RefuseAll {
    fn admit(&mut self, _peer: &PeerId) -> Admit {
        Admit::Refuse(RefusalCode::application(0x0100).unwrap())
    }
}

/// Scenario: a refused client learns why, from the relay only.
#[test]
fn a_refused_client_learns_why() {
    let mut world = World::new(RefuseAll, Config::default(), 2);
    world.send(0, 1, b"let me in").unwrap();
    world.run_for(1000);
    let code = RefusalCode::application(0x0100).unwrap();
    assert!(
        world.clients[0]
            .events
            .contains(&Ev::RelayUnavailable(RelayError::Dial(DialError::Refused(
                code
            ))))
    );
}

// --- UDP and TCP ----------------------------------------------------------------------

/// Scenario: a session in use moves to UDP: B, on its link, sends over TCP
/// with a UDP copy until the relay answers over UDP, then over UDP only; and
/// the relay delivers to B over UDP. A copy arriving twice is delivered once.
#[test]
fn a_session_in_use_moves_to_udp() {
    let mut world = connected();
    world.send(1, 0, b"first reply").unwrap();
    // Past the end of the attempt the candidates started (no direct path in
    // this world): its one list sent again is not counted below.
    world.run_for(4000);
    assert!(world.clients[1].endpoint.relay_udp_proven(world.instant()));
    let before = world.clients[1].sent;
    for i in 0u8..5 {
        world.send(1, 0, &[i; 10]).unwrap();
        world.run_for(100);
    }
    let after = world.clients[1].sent;
    assert_eq!(after.tcp, before.tcp, "nothing more over TCP");
    assert_eq!(after.udp, before.udp + 5);
    let b_nat = world.clients[1].nat;
    let to_b = world
        .relay_udp_sent
        .iter()
        .filter(|(to, _)| *to == b_nat)
        .count();
    world.send(0, 1, b"to b").unwrap();
    world.run_for(200);
    assert!(
        world
            .relay_udp_sent
            .iter()
            .filter(|(to, _)| *to == b_nat)
            .count()
            > to_b
    );
    let received = world.clients[0].datagrams();
    assert_eq!(received.len(), 6, "every datagram once: {received:?}");
}

/// Scenario: blocked UDP falls back to TCP: over 60 seconds of traffic every
/// packet arrives, and at most 6 copies go over UDP.
#[test]
fn blocked_udp_falls_back_to_tcp() {
    let mut world = connected();
    // The receiver stays reachable on its own link; the sender's network
    // drops every UDP datagram.
    world.open_link(0);
    world.clients[1].udp_blocked = true;
    world.run_for(20_000);
    let before = world.clients[1].sent;
    for i in 0u32..600 {
        world.send(1, 0, &i.to_le_bytes()).unwrap();
        world.run_for(100);
    }
    let after = world.clients[1].sent;
    assert!(
        after.udp - before.udp <= 6,
        "{} UDP copies",
        after.udp - before.udp
    );
    assert_eq!(world.clients[0].datagrams().len(), 600);
}

/// The keep-alive: one a minute on an idle link, lengthenable, never shorter.
#[test]
fn the_keepalive_runs_once_a_minute_and_never_faster() {
    let mut world = World::new(Open, Config::default(), 1);
    world.open_link(0);
    world.run_for(1000);
    let start = world.clients[0].sent.keepalives;
    world.run_for(600_000);
    assert_eq!(world.clients[0].sent.keepalives - start, 10);
    assert!(
        world.clients[0]
            .endpoint
            .set_relay_keepalive(Duration::from_secs(30))
            .is_err()
    );
    world.run_for(600_000);
    assert_eq!(
        world.clients[0].sent.keepalives - start,
        20,
        "unchanged at a minute"
    );
    world.clients[0]
        .endpoint
        .set_relay_keepalive(Duration::from_secs(120))
        .unwrap();
    world.run_for(1_200_000);
    assert_eq!(world.clients[0].sent.keepalives - start, 30);
}

/// A client keeping a link registers after each relay handshake.
#[test]
fn a_linked_client_registers() {
    let world = connected();
    let b = world.clients[1].peer_id();
    assert_eq!(
        world.relay.clients[b.as_bytes()].address,
        Some(world.clients[1].address())
    );
    let a = world.clients[0].peer_id();
    assert_eq!(
        world.relay.clients[a.as_bytes()].address,
        None,
        "A keeps no link"
    );
}

/// A forward too large for a first contact's payload (over 1,166 bytes of
/// packet): a client whose queue can hold it dials the relay with a plain
/// first contact and forwards once the session is open; an MCU client, whose
/// 1 KB queue cannot, is told so by name and nothing is sent.
#[test]
fn a_forward_too_large_to_carry_dials_first() {
    use convesso_core::endpoint::Poll;
    use convesso_core::session::QueueFull;
    use convesso_core::storage::Server;

    let mut world = connected();
    let b = world.clients[1].peer_id();
    let now = world.instant();

    // The MCU client: its relay session dormant, a 1,300-byte packet.
    world.run_for(200_000);
    let now_later = world.instant();
    let client = &mut world.clients[0];
    let mut out = [0x01u8; 2048];
    assert_eq!(
        client.endpoint.through_relay(
            b,
            1300,
            now_later,
            &mut client.policy,
            &mut client.entropy,
            &mut out
        ),
        Err(SendError::QueueFull(QueueFull { limit: 1024 }))
    );

    // A server client.
    let mut server: Endpoint<Server> = Endpoint::new(identity(4), &[SESSION]).unwrap();
    server.pin_relay(world.relay.address(), now).unwrap();
    let mut entropy = TestEntropy(4242);
    let from = std::net::SocketAddr::from(([192, 0, 2, 44], 4444));
    let now = world.instant();
    let mut out = [0x01u8; 2048];
    let Ok(Output::Transmit {
        to: To::Relay(_),
        len,
    }) = server.through_relay(b, 1300, now, &mut AcceptAll, &mut entropy, &mut out)
    else {
        panic!("a dial to the relay");
    };
    assert_eq!(len, 134, "a plain first contact");
    assert_eq!(out[1], 0x01);
    let mut to_relay = vec![out[..len].to_vec()];
    let mut forwarded = false;
    for _ in 0..4 {
        for packet in to_relay.drain(..) {
            world.relay.udp(&packet, from, now);
        }
        let mut to_client = Vec::new();
        while let Some(action) = world.relay.next_action() {
            if let crate::Action::Udp { to, packet } = action
                && to == from
            {
                to_client.push(packet);
            }
        }
        for mut packet in to_client {
            let _ = server.handle_relay_packet(
                &mut packet,
                Link::Udp,
                now,
                &mut AcceptAll,
                &mut entropy,
                &mut out,
            );
        }
        while let Poll::Transmit { len, .. } =
            server.poll(now, &mut AcceptAll, &mut entropy, &mut out)
        {
            forwarded |= len == 31 + 34 + 1300;
            to_relay.push(out[..len].to_vec());
        }
    }
    assert!(forwarded, "the forward follows the handshake");
}
