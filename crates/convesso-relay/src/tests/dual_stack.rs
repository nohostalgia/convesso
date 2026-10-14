//! A dual-stack client and the relay: the relay reports the address it
//! observes, in each family, and to no one else (`PROTOCOL.md §6`).

use std::net::SocketAddr;

use convesso_core::paths::CandidateKind;
use convesso_core::relay::Link;

use super::world::*;
use crate::{Config, Open};

fn observed(world: &World<Open>, i: usize) -> Vec<SocketAddr> {
    world.clients[i]
        .events
        .iter()
        .filter_map(|event| match event {
            Ev::Observed(Link::Udp, address) => Some(*address),
            _ => None,
        })
        .collect()
}

/// Scenario: a dual-stack client learns both public addresses. Opening a
/// session with a peer, it sends one packet of its relay session over IPv6,
/// and receives one observed-address frame per family; both become public
/// candidates, IPv6 first.
#[test]
fn a_dual_stack_client_learns_both_public_addresses() {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.dual_stack(0);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"hello").unwrap();
    world.run_for(3000);

    let (v4, v6) = (world.clients[0].nat, world.clients[0].nat6.unwrap());
    let mut frames = observed(&world, 0);
    frames.sort();
    assert_eq!(frames, [v4, v6], "one frame per family");
    let publics: Vec<SocketAddr> = world.clients[0]
        .endpoint
        .candidates()
        .iter()
        .filter(|c| c.kind == CandidateKind::Public)
        .map(|c| c.address)
        .collect();
    assert_eq!(publics, [v6, v4]);
    assert_eq!(
        world.clients[1].datagrams(),
        [(b"hello".to_vec(), true)],
        "the datagram crossed"
    );
}

/// Scenario: alternating between the families afterwards raises no further
/// frame: each family's address is proven, and stays the same.
#[test]
fn alternating_families_raises_no_further_frame() {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.dual_stack(0);
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"hello").unwrap();
    world.run_for(3000);
    assert_eq!(observed(&world, 0).len(), 2);

    world.clients[0].alternate = true;
    for i in 0..20u8 {
        world.send(0, 1, &[i]).unwrap();
        world.run_for(500);
    }
    assert_eq!(observed(&world, 0).len(), 2, "{:?}", observed(&world, 0));
    assert_eq!(world.clients[1].datagrams().len(), 21);
}

/// A client with the relay in one family sends nothing more: its driver
/// drops the packet for the other family.
#[test]
fn a_single_stack_client_learns_one_address() {
    let mut world = World::new(Open, Config::default(), 2);
    world.direct = false;
    world.open_link(1);
    world.run_for(1000);
    world.send(0, 1, b"hello").unwrap();
    world.run_for(3000);
    assert_eq!(observed(&world, 0), [world.clients[0].nat]);
}
