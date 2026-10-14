//! The relay link's lifecycle, decided by the core, and the relay's
//! answer to keep-alives.

use convesso_core::relay::framing::PREAMBLE;

use super::world::*;
use crate::{Config, Open};

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
