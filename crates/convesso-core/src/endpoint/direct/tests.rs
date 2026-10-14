//! This endpoint's candidates and exclusions (`PROTOCOL.md §7`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::vec::Vec;

use serde_json::Value;

use super::*;
use crate::identity::{Address, Identity};
use crate::storage::Mcu;

fn endpoint() -> Endpoint<Mcu> {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../vectors/identity.json")).unwrap();
    let key = &vectors["keys"][1];
    let bytes = |v: &Value| -> [u8; 32] {
        let text = v.as_str().unwrap();
        (0..32)
            .map(|j| u8::from_str_radix(&text[2 * j..2 * j + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    };
    let identity = Identity::from_parts(
        bytes(&key["x25519_scalar"]),
        Address::parse(bytes(&key["address"])).unwrap(),
    )
    .unwrap();
    Endpoint::new(identity, &[b"session"]).unwrap()
}

fn a(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn listed(endpoint: &Endpoint<Mcu>) -> Vec<(CandidateKind, SocketAddr)> {
    endpoint
        .candidates()
        .iter()
        .map(|c| (c.kind, c.address))
        .collect()
}

/// Scenario: a dual-stack endpoint offers both families, local first.
#[test]
fn a_dual_stack_endpoint_offers_both_families_local_first() {
    let mut endpoint = endpoint();
    endpoint.set_local_addresses(&[a("192.168.1.20:7500"), a("[2a01:db8::20]:7500")]);
    endpoint.observed_public(a("203.0.113.7:41641"));
    endpoint.observed_public(a("[2a01:db8::99]:7500"));
    assert_eq!(
        listed(&endpoint),
        [
            (CandidateKind::Local, a("192.168.1.20:7500")),
            (CandidateKind::Local, a("[2a01:db8::20]:7500")),
            (CandidateKind::Public, a("[2a01:db8::99]:7500")),
            (CandidateKind::Public, a("203.0.113.7:41641")),
        ]
    );
}

/// Scenario: an excluded prefix is never offered (its other half, never
/// probed nor used, is in the endpoint's tests).
#[test]
fn an_excluded_interface_is_never_offered() {
    let mut endpoint = endpoint();
    endpoint
        .exclude_prefix("100.64.0.0".parse().unwrap(), 10)
        .unwrap();
    endpoint.set_local_addresses(&[a("100.64.1.2:7500"), a("192.168.1.20:7500")]);
    assert_eq!(
        listed(&endpoint),
        [(CandidateKind::Local, a("192.168.1.20:7500"))]
    );

    // Excluded afterwards, it leaves the list too; so does a public address.
    endpoint.observed_public(a("100.100.0.1:9"));
    endpoint
        .exclude_prefix("192.168.0.0".parse().unwrap(), 16)
        .unwrap();
    assert!(endpoint.candidates().is_empty());
}

#[test]
fn unusable_and_repeated_addresses_are_not_candidates() {
    let mut endpoint = endpoint();
    endpoint.set_local_addresses(&[
        a("127.0.0.1:7500"),
        a("[::1]:7500"),
        a("0.0.0.0:7500"),
        a("[fe80::1]:7500"),
        a("224.0.0.1:7500"),
        a("10.0.0.1:0"),
        a("[::ffff:10.0.0.2]:7500"),
        a("10.0.0.2:7500"),
    ]);
    // The IPv4-mapped address is the IPv4 one: listed once.
    assert_eq!(
        listed(&endpoint),
        [(CandidateKind::Local, a("10.0.0.2:7500"))]
    );
    // A public address equal to a local one is the local one.
    endpoint.observed_public(a("10.0.0.2:7500"));
    assert_eq!(endpoint.candidates().len(), 1);
}

#[test]
fn at_most_eight_candidates_and_locals_make_room_for_public_ones() {
    let mut endpoint = endpoint();
    let locals: Vec<SocketAddr> = (1..=10)
        .map(|i| SocketAddr::from(([10, 0, 0, i], 7500)))
        .collect();
    endpoint.set_local_addresses(&locals);
    assert_eq!(endpoint.candidates().len(), 8);
    endpoint.observed_public(a("203.0.113.7:41641"));
    endpoint.observed_public(a("[2001:db8::7]:41641"));
    let list = listed(&endpoint);
    assert_eq!(list.len(), 8);
    assert!(
        list[..6]
            .iter()
            .all(|(kind, _)| *kind == CandidateKind::Local)
    );
    assert_eq!(list[6], (CandidateKind::Public, a("[2001:db8::7]:41641")));
    assert_eq!(list[7], (CandidateKind::Public, a("203.0.113.7:41641")));
}

#[test]
fn every_change_and_only_a_change_makes_a_new_generation() {
    let mut endpoint = endpoint();
    assert_eq!(endpoint.own.owed_generation(), None, "nothing to tell");
    endpoint.set_local_addresses(&[a("10.0.0.2:7500")]);
    let first = endpoint.own.owed_generation().unwrap();
    endpoint.set_local_addresses(&[a("10.0.0.2:7500")]);
    endpoint.observed_public(a("10.0.0.2:7500"));
    assert_eq!(endpoint.own.owed_generation(), Some(first), "the same list");
    endpoint.observed_public(a("203.0.113.7:41641"));
    assert_eq!(endpoint.own.owed_generation(), Some(first + 1));
    endpoint.observed_public(a("203.0.113.7:41642"));
    assert_eq!(endpoint.own.owed_generation(), Some(first + 2));
}

#[test]
fn prefixes_are_bounded_and_checked() {
    let mut endpoint = endpoint();
    assert_eq!(
        endpoint.exclude_prefix("10.0.0.0".parse().unwrap(), 33),
        Err(ExcludeError::TooLong { len: 33 })
    );
    for i in 0..4 {
        endpoint
            .exclude_prefix(IpAddr::from([10, i, 0, 0]), 16)
            .unwrap();
    }
    // The same prefix again takes no room; a fifth does not fit an Mcu.
    endpoint
        .exclude_prefix("10.0.255.255".parse().unwrap(), 16)
        .unwrap();
    assert_eq!(
        endpoint.exclude_prefix("10.9.0.0".parse().unwrap(), 16),
        Err(ExcludeError::Full { bound: 4 })
    );
    assert!(endpoint.is_excluded("10.3.200.1".parse().unwrap()));
    assert!(!endpoint.is_excluded("10.4.0.1".parse().unwrap()));
    // A /0 of a family covers that family only.
    let mut endpoint = self::endpoint();
    endpoint.exclude_prefix("::".parse().unwrap(), 0).unwrap();
    assert!(endpoint.is_excluded("2001:db8::1".parse().unwrap()));
    assert!(!endpoint.is_excluded("192.0.2.1".parse().unwrap()));
    // IPv4-mapped addresses are their IPv4 address.
    endpoint
        .exclude_prefix("::ffff:192.0.2.0".parse().unwrap(), 120)
        .unwrap();
    assert!(endpoint.is_excluded("192.0.2.1".parse().unwrap()));
}

/// Scenario: the core receives every interface address. A
/// private IPv4 address, a global IPv6 one and a tunnel's all become
/// candidates; the tunnel's, only until the application excludes its prefix.
#[test]
fn a_tunnel_address_is_a_candidate_until_excluded() {
    let mut endpoint = endpoint();
    let reported = [
        a("192.168.1.20:7500"),
        a("[2a01:db8::20]:7500"),
        a("100.64.3.7:7500"),
    ];
    endpoint.set_local_addresses(&reported);
    let addresses = |e: &Endpoint<Mcu>| -> Vec<SocketAddr> {
        e.candidates().iter().map(|c| c.address).collect()
    };
    assert_eq!(addresses(&endpoint), reported);
    endpoint
        .exclude_prefix("100.64.0.0".parse().unwrap(), 10)
        .unwrap();
    assert_eq!(addresses(&endpoint), reported[..2]);
}

/// Scenario: a replaced set lets a prefix in again.
#[test]
fn a_replaced_set_lets_a_prefix_in_again() {
    let mut endpoint = endpoint();
    let reported = [a("192.168.1.20:7500"), a("100.64.3.7:7500")];
    endpoint
        .set_excluded(&[("100.64.0.0".parse().unwrap(), 10)])
        .unwrap();
    endpoint.set_local_addresses(&reported);
    assert_eq!(
        listed(&endpoint),
        [(CandidateKind::Local, a("192.168.1.20:7500"))]
    );

    // The tunnel went down and another came up: its prefix replaces the old.
    endpoint
        .set_excluded(&[("10.8.0.0".parse().unwrap(), 24)])
        .unwrap();
    assert!(!endpoint.is_excluded("100.64.3.7".parse().unwrap()));
    assert!(endpoint.is_excluded("10.8.0.9".parse().unwrap()));
    endpoint.set_local_addresses(&reported);
    assert_eq!(
        listed(&endpoint),
        [
            (CandidateKind::Local, a("192.168.1.20:7500")),
            (CandidateKind::Local, a("100.64.3.7:7500")),
        ]
    );

    // A set that covers what is listed takes it out at once; an empty one
    // excludes nothing.
    endpoint
        .set_excluded(&[("192.168.0.0".parse().unwrap(), 16)])
        .unwrap();
    assert_eq!(
        listed(&endpoint),
        [(CandidateKind::Local, a("100.64.3.7:7500"))]
    );
    endpoint.set_excluded(&[]).unwrap();
    assert!(!endpoint.is_excluded("192.168.1.20".parse().unwrap()));
}

/// Scenario: a set over the bound is refused whole, and so is a set with one
/// prefix longer than its address.
#[test]
fn a_set_over_the_bound_is_refused_whole() {
    let mut endpoint = endpoint();
    endpoint
        .set_excluded(&[("100.64.0.0".parse().unwrap(), 10)])
        .unwrap();
    let five: Vec<(IpAddr, u8)> = (0..5).map(|i| (IpAddr::from([10, i, 0, 0]), 16)).collect();
    assert_eq!(
        endpoint.set_excluded(&five),
        Err(ExcludeError::Full { bound: 4 })
    );
    assert_eq!(
        endpoint.set_excluded(&[
            ("10.0.0.0".parse().unwrap(), 8),
            ("10.0.0.0".parse().unwrap(), 33),
        ]),
        Err(ExcludeError::TooLong { len: 33 })
    );
    assert!(endpoint.is_excluded("100.64.1.1".parse().unwrap()));
    assert!(!endpoint.is_excluded("10.0.0.1".parse().unwrap()));

    // The same prefix written twice, or as its IPv4-mapped form, counts once.
    let mut four = five[..4].to_vec();
    four.push(("10.0.255.255".parse().unwrap(), 16));
    four.push(("::ffff:10.1.0.0".parse().unwrap(), 112));
    endpoint.set_excluded(&four).unwrap();
    assert!(endpoint.is_excluded("10.3.0.1".parse().unwrap()));
    assert!(!endpoint.is_excluded("100.64.1.1".parse().unwrap()));
}
