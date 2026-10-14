//! The NAT matrix in the simulator (`PROTOCOL.md §7`): every row of
//! `nat-matrix.toml`, the outcome expected of each pair of NAT behaviours, run
//! as a probing application would; and the behaviours the table does not
//! cover: a client that moves to another network in the middle of a session.

use std::net::Ipv4Addr;

use convesso_core::paths::PathKind;

use super::world::*;
use crate::{Config, Open};

const TABLE: &str = include_str!("nat-matrix.toml");

/// Puts client `i` behind a NAT profile.
fn profile(world: &mut World<Open>, i: usize, name: &str) {
    let eim = (Mapping::Independent, Filtering::AddressAndPort);
    match name {
        "eim" => world.behind(i, eim.0, eim.1),
        "full-cone" => world.behind(i, Mapping::Independent, Filtering::None),
        "symmetric" => world.behind(i, Mapping::Dependent, Filtering::AddressAndPort),
        "cgnat" => world.behind_chain(i, &[eim, eim]),
        "no-udp" => {
            world.behind(i, eim.0, eim.1);
            world.clients[i].udp_blocked = true;
        }
        "v6-firewall" => {
            world.behind(i, eim.0, eim.1);
            world.firewalled_v6(i);
        }
        other => panic!("no profile {other} in the simulator"),
    }
}

/// One run: both sides reachable; the first sends a
/// datagram every 100 ms for 6 s, the second echoes. Returns the first's
/// path, and when it went direct.
fn run(a: &str, b: &str) -> (String, Option<u64>) {
    run_on(a, b, 20, None)
}

/// [`run`] with `delay` ms one way per hop, and `loss` percent of UDP lost.
fn run_on(a: &str, b: &str, delay: u64, loss: Option<u64>) -> (String, Option<u64>) {
    run_seeded(
        a,
        b,
        delay,
        loss.map(|percent| (0x9e37_79b9_7f4a_7c15, percent)),
    )
}

/// [`run_on`] with the loss drawn from `seed`.
fn run_seeded(a: &str, b: &str, delay: u64, loss: Option<(u64, u64)>) -> (String, Option<u64>) {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.delay = delay;
    world.loss = loss;
    profile(&mut world, 0, a);
    profile(&mut world, 1, b);
    world.open_link(0);
    world.open_link(1);
    world.run_for(1000);
    let start = world.now;
    for _ in 0..60 {
        world.send(0, 1, b"probe").unwrap();
        world.run_for(50);
        world.send(1, 0, b"echo").unwrap();
        world.run_for(50);
    }
    let peer = world.clients[1].peer_id();
    let info = world.clients[0].endpoint.path_info(&peer, SESSION).unwrap();
    let direct_at = world.clients[0]
        .events
        .iter()
        .zip(&world.clients[0].event_at)
        .find_map(|(event, at)| {
            matches!(event, Ev::PathChanged(_, PathKind::Direct(_))).then(|| at - start)
        });
    let udp = world.clients[0].endpoint.relay_udp_proven(world.instant());
    let path = match info.path {
        PathKind::Direct(at) if at.is_ipv4() => "direct ipv4",
        PathKind::Direct(_) => "direct ipv6",
        PathKind::Relayed if udp => "relayed",
        PathKind::Relayed => "relayed-tcp",
    };
    let received = world.clients[1]
        .datagrams()
        .iter()
        .filter(|(data, _)| data == b"probe")
        .count();
    let least = if loss.is_some() { 48 } else { 55 };
    assert!(
        received >= least,
        "{a} {b}: only {received} of 60 datagrams arrived"
    );
    (path.to_owned(), direct_at)
}

/// Scenario: the matrix holds in the simulator. Every row of the table
/// gives the path it expects, and its family for a direct one.
#[test]
fn every_pair_of_profiles_gives_the_expected_path() {
    check_table(20, None);
}

/// The same table over bad networks: 50 ms one way per hop, and 2% of UDP lost.
#[test]
fn the_matrix_holds_with_50_ms_and_2_percent_loss() {
    check_table(50, Some(2));
}

fn check_table(delay: u64, loss: Option<u64>) {
    let mut failures = Vec::new();
    for line in TABLE.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [a, b, family, expected] = fields[..] else {
            continue;
        };
        if a.starts_with('#') {
            continue;
        }
        let expected = if expected == "direct" {
            format!("direct {family}")
        } else {
            expected.to_owned()
        };
        let (path, direct_at) = run_on(a, b, delay, loss);
        std::println!(
            "{a:<12} {b:<12} {path:<12} {}",
            direct_at.map_or_else(String::new, |ms| format!("direct after {ms} ms"))
        );
        if path != expected {
            failures.push(format!("{a} {b}: {path}, expected {expected}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

const EIM: (Mapping, Filtering) = (Mapping::Independent, Filtering::AddressAndPort);

fn last_datagram(world: &World<Open>, i: usize) -> (Vec<u8>, bool) {
    world.clients[i]
        .datagrams()
        .last()
        .cloned()
        .expect("a datagram")
}

/// A client that moves to another network while its session is direct: its
/// next datagram takes the relay and arrives, both sides find the new path,
/// and the datagrams after it go directly again.
#[test]
fn a_client_that_moves_keeps_its_session_and_finds_a_new_path() {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.behind(0, EIM.0, EIM.1);
    world.behind(1, EIM.0, EIM.1);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"first").unwrap();
    world.run_for(2000);
    world.send(1, 0, b"back").unwrap();
    world.run_for(1000);
    let peer = world.clients[1].peer_id();
    let path = |world: &World<Open>| {
        world.clients[0]
            .endpoint
            .path_info(&peer, SESSION)
            .unwrap()
            .path
    };
    assert!(matches!(path(&world), PathKind::Direct(_)));

    world.move_network(0, Ipv4Addr::new(203, 0, 113, 101));
    world.send(0, 1, b"from the new network").unwrap();
    world.run_for(500);
    assert_eq!(
        last_datagram(&world, 1),
        (b"from the new network".to_vec(), true),
        "the first packet after the move takes the relay"
    );
    // Traffic both ways, as an application's would be.
    for i in 0..30u8 {
        world.send(0, 1, &[i]).unwrap();
        world.run_for(50);
        world.send(1, 0, &[i]).unwrap();
        world.run_for(50);
    }
    assert!(matches!(path(&world), PathKind::Direct(_)));
    assert_eq!(last_datagram(&world, 1), (vec![29], false), "direct again");
    assert_eq!(last_datagram(&world, 0), (vec![29], false), "both ways");
    assert_eq!(world.clients[1].datagrams().len(), 32, "nothing lost");
}

/// The other side of a move: the peer that stayed learns the new candidates,
/// drops the path to the old address at once rather than after 15 s of
/// losses, and finds the new one.
#[test]
fn the_peer_of_a_client_that_moved_loses_nothing() {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.behind(0, EIM.0, EIM.1);
    world.behind(1, EIM.0, EIM.1);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"first").unwrap();
    world.run_for(2000);
    world.send(1, 0, b"back").unwrap();
    world.run_for(1000);

    world.move_network(0, Ipv4Addr::new(203, 0, 113, 101));
    // The mover's new list reaches the peer; then the peer sends first.
    world.send(0, 1, b"moved").unwrap();
    world.run_for(500);
    let before = world.clients[0].datagrams().len();
    for i in 0..20u8 {
        world.send(1, 0, &[i]).unwrap();
        world.run_for(100);
    }
    assert_eq!(
        world.clients[0].datagrams().len(),
        before + 20,
        "every datagram from the peer arrived"
    );
}

/// The firewall in front of a global IPv6 address lets a session in only once
/// the inside side has sent to the peer: both sides probe at once, and the
/// path is direct over IPv6, preferred to IPv4.
#[test]
fn two_ipv6_firewalls_give_a_direct_ipv6_path() {
    let (path, _) = run("v6-firewall", "v6-firewall");
    assert_eq!(path, "direct ipv6");
}

/// Every row, over many draws of a 2% loss at 50 ms: how often each fails.
/// Run on demand: `cargo test -p convesso-relay loss_sweep -- --ignored --nocapture`.
#[test]
#[ignore = "a sweep of 40 seeds, for diagnosis"]
fn loss_sweep() {
    let mut failures = Vec::new();
    for seed in 1..=40u64 {
        for line in TABLE.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [a, b, family, expected] = fields[..] else {
                continue;
            };
            if a.starts_with('#') {
                continue;
            }
            let expected = if expected == "direct" {
                format!("direct {family}")
            } else {
                expected.to_owned()
            };
            let (path, _) = run_seeded(a, b, 50, Some((seed * 0x9e37_79b9, 2)));
            if path != expected {
                failures.push(format!("seed {seed}: {a} {b}: {path}, expected {expected}"));
            }
        }
    }
    std::println!("{} failures: {failures:#?}", failures.len());
}

/// The two ways a client could miss its public address under loss, each
/// pinned by a seed that hits it: the relay's report lost (7), and the
/// client's only early UDP packet to the relay lost (20). The client asks the
/// relay until it is told, and the session goes direct.
#[test]
fn a_public_address_lost_on_the_way_is_asked_for_again() {
    for seed in [7u64, 20] {
        let (path, direct_at) = run_seeded("eim", "eim", 50, Some((seed * 0x9e37_79b9, 2)));
        assert_eq!(path, "direct ipv4", "seed {seed}");
        std::println!("seed {seed}: direct after {direct_at:?} ms");
    }
}
