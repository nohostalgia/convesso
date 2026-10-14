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

/// Scenario: a hint that does not answer falls back to the relay: the dial's
/// next attempt, one second later, goes through it, and the session opens
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
    assert!(connected - start >= 1000 && connected - start <= 1000 + 4 * world.delay);
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
    endpoint.set_hint(peer.peer_id(), &[2], now).unwrap();
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
        endpoint.set_hint(peer, &[i], t(u64::from(i))).unwrap();
    }
    // A fifth hint: the one set at t(1), for identity 1, goes.
    endpoint
        .set_hint(identity(0).peer_id(), &[0], t(5))
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
            .set_hint(identity(1).peer_id(), &[0; 33], t(9))
            .is_err()
    );
}
