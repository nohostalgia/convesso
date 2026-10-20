//! The core's choice of path (`PROTOCOL.md §6`). No output can leave the choice to
//! the driver: the public `To` names a direct address or the relay, nothing
//! else, so that half of the requirement is held by the type.

use convesso_core::endpoint::{Endpoint, SendError, Target};
use convesso_core::storage::Mcu;

use super::world::*;
use crate::{Config, Open};

/// Scenario: a hinted peer is dialled directly, and once it answers from
/// there, the session stays direct: nothing goes to the relay.
#[test]
fn a_hinted_peer_is_dialled_directly() {
    let mut world = World::new(Open, Config::default(), 2);
    world.hint(0, 1);
    world.send(0, 1, b"over the LAN").unwrap();
    world.run_for(1000);
    world.send(1, 0, b"and back").unwrap();
    world.run_for(1000);
    assert_eq!(
        world.clients[1].datagrams(),
        vec![(b"over the LAN".to_vec(), false)]
    );
    assert_eq!(
        world.clients[0].datagrams(),
        vec![(b"and back".to_vec(), false)]
    );
    assert!(world.clients[0].udp_log.is_empty(), "nothing to the relay");
    assert!(world.clients[1].udp_log.is_empty(), "nothing to the relay");
}

/// Scenario: a hint that does not answer falls back to the relay: the same
/// first contact goes through it 250 ms after the hint, and the session opens
/// there.
#[test]
fn a_hint_that_does_not_answer_falls_back_to_the_relay() {
    let mut world = World::new(Open, Config::default(), 2);
    world.open_link(1);
    world.run_for(1000);
    world.direct = false;
    world.hint(0, 1);
    let start = world.now;
    world.send(0, 1, b"anyone home?").unwrap();
    world.run_for(3000);
    assert_eq!(
        world.clients[1].datagrams(),
        vec![(b"anyone home?".to_vec(), true)]
    );
    let first_to_relay = world.clients[0].udp_log.len();
    assert!(first_to_relay > 0, "the retry went through the relay");
    let connected = world
        .when(0, &Ev::Connected(world.clients[1].peer_id()))
        .unwrap();
    std::println!(
        "a dead hint costs {} ms before the relay answers",
        connected - start
    );
    // The relay joins the first attempt 250 ms after the hint, not at the
    // second attempt, a second in.
    assert!(connected - start >= 250 && connected - start <= 250 + 4 * world.delay);
}

/// Scenario: a peer heard through the relay is answered through the relay,
/// even once a hint for it is known.
#[test]
fn a_peer_heard_through_the_relay_is_answered_through_it() {
    let mut world = World::new(Open, Config::default(), 2);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"through the relay").unwrap();
    world.run_for(1000);
    world.hint(1, 0);
    world.send(1, 0, b"still through it").unwrap();
    world.run_for(1000);
    assert_eq!(
        world.clients[0].datagrams(),
        vec![(b"still through it".to_vec(), true)]
    );
}

/// Scenario: no path is an error, not a guess.
#[test]
fn no_path_is_an_error() {
    let mut endpoint: Endpoint<Mcu> = Endpoint::new(identity(1), &[SESSION]).unwrap();
    let peer = *identity(2).address();
    let mut out = [0u8; 2048];
    let now = convesso_core::time::Instant::from_millis(0);
    assert_eq!(
        endpoint.send(
            Target::Address(&peer),
            SESSION,
            b"to whom?",
            1400,
            now,
            &mut AcceptAll,
            &mut TestEntropy(5),
            &mut out,
        ),
        Err(SendError::NoPath)
    );
    assert_eq!(
        endpoint.connect(
            &peer,
            SESSION,
            now,
            &mut AcceptAll,
            &mut TestEntropy(5),
            &mut out
        ),
        Err(SendError::NoPath)
    );
    // A hint is a path.
    endpoint.set_hints(peer.peer_id(), &[&[2]], now).unwrap();
    assert!(
        endpoint
            .connect(
                &peer,
                SESSION,
                now,
                &mut AcceptAll,
                &mut TestEntropy(5),
                &mut out
            )
            .is_ok()
    );
}

/// A full hint table (4 on a microcontroller) forgets the hint used least
/// recently, and a hint longer than a direct source is refused.
#[test]
fn hints_are_bounded() {
    let mut endpoint: Endpoint<Mcu> = Endpoint::new(identity(0), &[SESSION]).unwrap();
    let t = convesso_core::time::Instant::from_millis;
    for i in 1..=4u8 {
        let peer = identity(usize::from(i)).peer_id();
        endpoint.set_hints(peer, &[&[i]], t(u64::from(i))).unwrap();
    }
    // A fifth hint: the one set at t(1), for identity 1, goes.
    endpoint
        .set_hints(identity(0).peer_id(), &[&[0]], t(5))
        .unwrap();
    let mut out = [0u8; 2048];
    let one = *identity(1).address();
    let two = *identity(2).address();
    assert_eq!(
        endpoint.connect(
            &one,
            SESSION,
            t(6),
            &mut AcceptAll,
            &mut TestEntropy(5),
            &mut out
        ),
        Err(SendError::NoPath)
    );
    assert!(
        endpoint
            .connect(
                &two,
                SESSION,
                t(6),
                &mut AcceptAll,
                &mut TestEntropy(5),
                &mut out
            )
            .is_ok()
    );
    assert!(
        endpoint
            .set_hints(identity(1).peer_id(), &[&[0; 33]], t(9))
            .is_err()
    );
}

/// A client whose relay cannot be reached: it refuses the client's link, and
/// never answers its handshakes.
fn relay_out_of_reach(world: &mut World<Open>, i: usize) {
    world.clients[i].tcp_refused = true;
    world.clients[i].handshakes_ignored = true;
}

/// Scenario: a hint given mid-dial is used, as an integrator found it: two
/// peers one hop apart, their relay out of reach, the peer's address learned
/// 2 s into the dial. The next attempt goes to it at once, and the session
/// opens then, not after the dial gives up at 15 s.
#[test]
fn a_hint_given_mid_dial_is_used() {
    let mut world = World::new(Open, Config::default(), 2);
    relay_out_of_reach(&mut world, 0);
    let start = world.now;
    world.send(0, 1, b"found you").unwrap();
    world.run_for(2000);
    assert!(world.clients[1].datagrams().is_empty(), "no way to B yet");
    world.hint(0, 1);
    world.run_for(500);
    assert_eq!(
        world.clients[1].datagrams(),
        vec![(b"found you".to_vec(), false)]
    );
    let connected = world
        .when(0, &Ev::Connected(world.clients[1].peer_id()))
        .unwrap();
    assert!(
        connected - start < 2000 + 4 * world.delay.max(1),
        "{}",
        connected - start
    );
}

/// Scenario: an unreachable relay does not take the hints' attempts: the
/// first contact to the hint is lost, the relay is out of reach, and the next
/// attempt, a second in, goes to the hint again and opens the session.
#[test]
fn an_unreachable_relay_does_not_take_the_hints_attempts() {
    let mut world = World::new(Open, Config::default(), 2);
    relay_out_of_reach(&mut world, 0);
    world.hint(0, 1);
    // The first attempt's packet to the hint is lost.
    world.direct = false;
    let start = world.now;
    world.send(0, 1, b"second time lucky").unwrap();
    world.run_for(500);
    world.direct = true;
    world.run_for(1500);
    assert_eq!(
        world.clients[1].datagrams(),
        vec![(b"second time lucky".to_vec(), false)]
    );
    let connected = world
        .when(0, &Ev::Connected(world.clients[1].peer_id()))
        .unwrap();
    assert!(
        (1000..1500).contains(&(connected - start)),
        "{}",
        connected - start
    );
}
