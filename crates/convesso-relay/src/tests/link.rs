//! The relay link's lifecycle, decided by the core, and the relay's
//! answer to keep-alives.

use convesso_core::relay::framing::PREAMBLE;

use super::world::*;
use crate::{Config, Open};
use convesso_core::endpoint::{LinkFailure, RelayError};
use convesso_core::handshake::DialError;

const HOUR: u64 = 3_600_000;

/// Scenario: a closed link is reopened at once.
#[test]
fn a_closed_link_is_reopened_at_once() {
    let mut world = World::new(Open, Config::default(), 1);
    let first = world.open_link(0);
    world.run_for(5_000);
    let at = world.now;
    world.relay.link_closed(first);
    world.clients[0].link = None;
    let now = world.instant();
    world.clients[0].endpoint.relay_link_closed(now);
    world.run_for(1);
    assert_eq!(world.clients[0].opens.last(), Some(&at));
    assert_ne!(world.clients[0].link, Some(first));
    assert!(world.clients[0].link.is_some());
}

/// Scenario: an unreachable relay is retried at most once a minute: the
/// backoff grows from about a second to the cap, never waits more than 90
/// seconds, and once capped never less than 60.
#[test]
fn an_unreachable_relay_is_retried_at_most_once_a_minute() {
    let mut world = World::new(Open, Config::default(), 1);
    world.clients[0].tcp_refused = true;
    let now = world.instant();
    world.clients[0].endpoint.set_reachable(true, now);
    world.run_for(HOUR);
    let opens = &world.clients[0].opens;
    let gaps: Vec<u64> = opens.windows(2).map(|w| w[1] - w[0]).collect();
    std::println!("attempts: {}, gaps (ms): {gaps:?}", opens.len());
    assert!(gaps[0] >= 1_000 && gaps[0] <= 1_500, "{gaps:?}");
    assert!(gaps.iter().all(|&gap| gap <= 90_000), "{gaps:?}");
    let capped = gaps.iter().position(|&gap| gap >= 60_000).unwrap();
    assert!(gaps[capped..].iter().all(|&gap| gap >= 60_000), "{gaps:?}");
    assert!(opens.len() <= 7 + 60, "at most one a minute once capped");
    // The relay comes back: the next attempt succeeds.
    world.clients[0].tcp_refused = false;
    world.run_for(91_000);
    assert!(world.clients[0].link.is_some());
}

/// Scenario: a link that dies silently is noticed within 80 seconds, and
/// replaced at once.
#[test]
fn a_link_that_dies_silently_is_noticed_within_80_seconds() {
    let mut world = World::new(Open, Config::default(), 1);
    let first = world.open_link(0);
    world.run_for(10_000);
    let died = world.now;
    world.clients[0].link_blackhole = true;
    world.run_for(100_000);
    let closed = *world.clients[0].closes.first().unwrap();
    assert!(
        closed - died <= 80_000,
        "noticed after {} ms",
        closed - died
    );
    let reopened = world.clients[0]
        .opens
        .iter()
        .find(|&&at| at >= closed)
        .unwrap();
    assert_eq!(*reopened, closed, "a new link at once");
    assert_ne!(world.clients[0].link, Some(first));
}

/// Scenario: a client that need not be reachable keeps no link, and one that
/// stops being reachable closes its link and opens no other.
#[test]
fn a_client_that_need_not_be_reachable_keeps_no_link() {
    let mut world = World::new(Open, Config::default(), 1);
    world.run_for(HOUR);
    assert!(world.clients[0].opens.is_empty());
    assert_eq!(world.clients[0].sent, Sent::default());
    world.open_link(0);
    world.run_for(1_000);
    let now = world.instant();
    world.clients[0].endpoint.set_reachable(false, now);
    world.run_for(HOUR);
    assert_eq!(world.clients[0].closes.len(), 1);
    assert_eq!(world.clients[0].opens.len(), 1);
    assert_eq!(world.clients[0].link, None);
    assert_eq!(
        world.clients[0].deadline, None,
        "nothing left to do at rest"
    );
}

/// Scenario: a link opened beside a proven UDP path is established by the
/// answer to its first keep-alive, and lives.
#[test]
fn a_link_beside_proven_udp_is_established() {
    let mut world = World::new(Open, Config::default(), 2);
    world.open_link(1);
    world.run_for(1_000);
    world.send(0, 1, b"proves the UDP path").unwrap();
    world.run_for(1_000);
    assert!(world.clients[0].endpoint.relay_udp_proven(world.instant()));
    world.open_link(0);
    world.run_for(300_000);
    assert_eq!(world.clients[0].opens.len(), 1);
    assert!(world.clients[0].closes.is_empty());
    assert!(world.clients[0].keepalive_answers >= 1);
}

/// Scenario: the relay never starts a keep-alive: a link silent for 179
/// seconds gets nothing but the preamble.
#[test]
fn the_relay_never_starts_a_keepalive() {
    let mut world = World::new(Open, Config::default(), 1);
    let from = std::net::SocketAddr::from(([192, 0, 2, 9], 1234));
    assert!(world.relay.link_opened(55, from, world.instant()));
    world.relay.link_bytes(55, &PREAMBLE, world.instant());
    world.relay_actions();
    world.run_for(179_000);
    assert_eq!(world.relay_link_sent[&55], PREAMBLE.len());
}

/// Scenario: an opening that hangs is a failed attempt: 20 seconds without
/// the driver reporting opened or closed, the core asks to close it, and
/// asks again after the backoff.
#[test]
fn an_opening_that_hangs_is_a_failed_attempt() {
    let mut world = World::new(Open, Config::default(), 1);
    world.clients[0].tcp_hangs = true;
    let now = world.instant();
    world.clients[0].endpoint.set_reachable(true, now);
    world.run_for(30_000);
    let client = &world.clients[0];
    assert_eq!(client.closes.first(), Some(&20_000));
    assert!(client.opens.len() >= 2);
    assert!(
        client.opens[1] >= 21_000,
        "after the backoff: {:?}",
        client.opens
    );
}

// --- refusals, and what the application is told ---------------------------------------

/// A relay shedding load: it refuses everyone, as busy.
struct Busy;

impl crate::Policy for Busy {
    fn admit(&mut self, _peer: &convesso_core::identity::PeerId) -> crate::Admit {
        crate::Admit::Refuse(convesso_core::handshake::RefusalCode::BUSY)
    }
}

fn refused() -> Ev {
    Ev::RelayUnavailable(RelayError::Dial(DialError::Refused(
        convesso_core::handshake::RefusalCode::BUSY,
    )))
}

fn count(world: &World<impl crate::Policy>, ev: &Ev) -> usize {
    world.clients[0].events.iter().filter(|e| *e == ev).count()
}

/// Scenario: a relay that refuses the client is tried at most once a
/// minute: after each refusal the link is closed and nothing more is dialled
/// on it, and the attempts follow the backoff.
#[test]
fn a_relay_that_refuses_the_client_is_tried_at_most_once_a_minute() {
    let mut world = World::new(Busy, Config::default(), 1);
    let now = world.instant();
    world.clients[0].endpoint.set_reachable(true, now);
    world.run_for(HOUR);
    let client = &world.clients[0];
    // The delay between an attempt's end (its close) and the next one.
    let delays: Vec<u64> = client
        .closes
        .iter()
        .zip(client.opens.iter().skip(1))
        .map(|(closed, opened)| opened - closed)
        .collect();
    let gaps: Vec<u64> = client.opens.windows(2).map(|w| w[1] - w[0]).collect();
    std::println!("attempts: {}, delays (ms): {delays:?}", client.opens.len());
    assert!(
        client.keepalive_answers > 0,
        "the relay answers on the link"
    );
    assert!(
        delays.iter().all(|&d| (1_000..=90_000).contains(&d)),
        "{delays:?}"
    );
    let capped = delays.iter().position(|&d| d >= 60_000).unwrap();
    assert!(gaps[capped..].iter().all(|&gap| gap >= 60_000), "{gaps:?}");
    assert!(
        client.opens.len() <= 7 + 60,
        "at most one a minute once capped"
    );
    // One outcome per link, never a second dial on it: refused, or, once
    // the relay's limit on handshakes per address drops them, unanswered.
    let refusals = count(&world, &refused());
    let unanswered = count(
        &world,
        &Ev::RelayUnavailable(RelayError::Dial(DialError::NoResponse)),
    );
    std::println!("{refusals} refused, {unanswered} unanswered");
    assert!(refusals >= 1);
    assert_eq!(refusals + unanswered, client.closes.len());
}

/// Scenario: a relay session never answered is a failed attempt: once the
/// dial gives up, the link is closed, and the next attempt waits for the
/// backoff.
#[test]
fn a_relay_session_never_answered_is_a_failed_attempt() {
    let mut world = World::new(Open, Config::default(), 1);
    world.clients[0].handshakes_ignored = true;
    let now = world.instant();
    world.clients[0].endpoint.set_reachable(true, now);
    world.run_for(10 * 60_000);
    let client = &world.clients[0];
    assert!(
        client.keepalive_answers > 0,
        "the relay answers on the link"
    );
    let delays: Vec<u64> = client
        .closes
        .iter()
        .zip(client.opens.iter().skip(1))
        .map(|(closed, opened)| opened - closed)
        .collect();
    std::println!("attempts: {}, delays (ms): {delays:?}", client.opens.len());
    assert!(!client.closes.is_empty(), "the link is closed");
    assert!(
        delays.iter().all(|&d| d >= 1_000),
        "after the backoff: {delays:?}"
    );
    assert!(client.opens.len() <= 12, "{} attempts", client.opens.len());
    assert!(
        client
            .events
            .contains(&Ev::RelayUnavailable(RelayError::Dial(
                DialError::NoResponse
            )))
    );
}

/// Scenario: a client is told when it is registered, once, and nothing
/// before.
#[test]
fn a_client_is_told_when_it_is_registered() {
    let mut world = World::new(Open, Config::default(), 1);
    world.open_link(0);
    world.run_for(5_000);
    let events = &world.clients[0].events;
    assert_eq!(count(&world, &Ev::RelayAvailable), 1, "{events:?}");
    assert!(
        !events.iter().any(|e| matches!(e, Ev::RelayUnavailable(_))),
        "{events:?}"
    );
}

/// Scenario: a refused client is told once per attempt, with the relay's
/// code, and is never told the relay is available.
#[test]
fn a_refused_client_is_told_once_per_attempt() {
    let mut world = World::new(Busy, Config::default(), 1);
    let now = world.instant();
    world.clients[0].endpoint.set_reachable(true, now);
    world.run_for(10 * 60_000);
    // The attempts that ended.
    let ended = world.clients[0].closes.len();
    assert!(ended >= 5, "{ended}");
    assert_eq!(count(&world, &Ev::RelayAvailable), 0);
    let unavailable = world.clients[0]
        .events
        .iter()
        .filter(|e| matches!(e, Ev::RelayUnavailable(_)))
        .count();
    assert_eq!(unavailable, ended, "one event per attempt");
    assert!(count(&world, &refused()) >= 1, "naming the refusal");
}

/// Scenario: a link that cannot be opened is told, once per attempt, and
/// the next attempt follows the backoff.
#[test]
fn a_link_that_cannot_be_opened_is_told() {
    let mut world = World::new(Open, Config::default(), 1);
    world.clients[0].tcp_refused = true;
    let now = world.instant();
    world.clients[0].endpoint.set_reachable(true, now);
    world.run_for(10_000);
    let attempts = world.clients[0].opens.len();
    assert!((2..=5).contains(&attempts), "{attempts}");
    assert_eq!(
        count(
            &world,
            &Ev::RelayUnavailable(RelayError::Link(LinkFailure::NotOpened))
        ),
        attempts
    );
}

/// Scenario: a lost link is told, and its return: a link the client was
/// registered on closes, the next one is registered.
#[test]
fn a_lost_link_is_told_and_its_return() {
    let mut world = World::new(Open, Config::default(), 1);
    let first = world.open_link(0);
    world.run_for(5_000);
    world.relay.link_closed(first);
    world.clients[0].link = None;
    let now = world.instant();
    world.clients[0].endpoint.relay_link_closed(now);
    world.run_for(5_000);
    let events: Vec<&Ev> = world.clients[0]
        .events
        .iter()
        .filter(|e| matches!(e, Ev::RelayAvailable | Ev::RelayUnavailable(_)))
        .collect();
    assert_eq!(
        events,
        [
            &Ev::RelayAvailable,
            &Ev::RelayUnavailable(RelayError::Link(LinkFailure::Lost)),
            &Ev::RelayAvailable
        ]
    );
}

/// Scenario: stopping is not unavailability: a registered client asked to
/// stop being reachable closes its link, and is told nothing.
#[test]
fn stopping_is_not_unavailability() {
    let mut world = World::new(Open, Config::default(), 1);
    world.open_link(0);
    world.run_for(5_000);
    let now = world.instant();
    world.clients[0].endpoint.set_reachable(false, now);
    world.run_for(5_000);
    assert!(!world.clients[0].closes.is_empty(), "the link is closed");
    assert!(
        !world.clients[0]
            .events
            .iter()
            .any(|e| matches!(e, Ev::RelayUnavailable(_))),
        "{:?}",
        world.clients[0].events
    );
}
