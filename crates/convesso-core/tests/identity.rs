//! The identity scenarios (`PROTOCOL.md §2`), against the vectors in
//! `vectors/identity.json`, which an implementation independent of the dalek
//! crates computed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use convesso_core::identity::{Address, Identity, IdentityMismatch, PeerId};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/identity.json")).unwrap()
}

fn bytes32(value: &Value) -> [u8; 32] {
    let text = value.as_str().unwrap();
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

/// Scenario: conversion matches the committed vectors; an address and its
/// negation are one identity; a provisioned scalar matches its address.
#[test]
fn keys_convert_as_the_vectors_say() {
    for key in vectors()["keys"].as_array().unwrap() {
        let name = key["name"].as_str().unwrap();
        let address = Address::parse(bytes32(&key["address"])).unwrap();
        let negated = Address::parse(bytes32(&key["negated_address"])).unwrap();
        let peer_id = bytes32(&key["peer_id"]);

        assert_eq!(address.peer_id().as_bytes(), &peer_id, "{name}");
        assert_eq!(negated.peer_id(), address.peer_id(), "{name}");
        assert_ne!(negated.as_bytes(), address.as_bytes(), "{name}");
        assert_eq!(
            PeerId::from_static(peer_id),
            Ok(address.peer_id()),
            "{name}"
        );

        let identity = Identity::from_parts(bytes32(&key["x25519_scalar"]), address).unwrap();
        assert_eq!(identity.peer_id(), address.peer_id(), "{name}");
    }
}

/// Scenario: a defective address is refused, with its defect named.
#[test]
fn defective_addresses_are_refused() {
    for vector in vectors()["invalid_addresses"].as_array().unwrap() {
        let error = Address::parse(bytes32(&vector["address"])).unwrap_err();
        assert_eq!(
            format!("{error:?}"),
            vector["defect"].as_str().unwrap(),
            "{}",
            vector["name"]
        );
    }
}

/// Every encoding X25519 would treat as equal to a valid key, and every static
/// key that is no key at all, is refused with its defect named.
#[test]
fn non_canonical_static_keys_are_refused() {
    let statics = vectors()["invalid_statics"].as_array().unwrap().clone();
    assert!(statics.iter().filter(|s| s["equivalent"] == true).count() >= 8);
    for vector in statics {
        let error = PeerId::from_static(bytes32(&vector["static"])).unwrap_err();
        assert_eq!(
            format!("{error:?}"),
            vector["defect"].as_str().unwrap(),
            "{}",
            vector["name"]
        );
    }
}

/// Scenario: a provisioned scalar must match its address.
#[test]
fn a_mismatched_scalar_is_refused() {
    let keys = vectors()["keys"].as_array().unwrap().clone();
    let address = Address::parse(bytes32(&keys[0]["address"])).unwrap();
    let other_scalar = bytes32(&keys[1]["x25519_scalar"]);
    assert!(matches!(
        Identity::from_parts(other_scalar, address),
        Err(IdentityMismatch)
    ));
}

/// The seed path derives the same identity as the vectors.
#[cfg(feature = "ed25519-seed")]
#[test]
fn a_seed_derives_the_vector_identity() {
    for key in vectors()["keys"].as_array().unwrap() {
        let identity = Identity::from_ed25519_seed(&bytes32(&key["seed"])).unwrap();
        assert_eq!(identity.address().as_bytes(), &bytes32(&key["address"]));
        assert_eq!(identity.peer_id().as_bytes(), &bytes32(&key["peer_id"]));
    }
}
