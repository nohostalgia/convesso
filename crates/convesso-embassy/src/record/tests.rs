//! The provisioning record against `vectors/identity.json`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::vec::Vec;

use proptest::prelude::*;
use serde_json::Value;

use super::*;

fn hex32(value: &Value) -> [u8; 32] {
    let text = value.as_str().unwrap();
    (0..32)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn keys() -> Vec<([u8; 32], [u8; 32])> {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../convesso-core/vectors/identity.json")).unwrap();
    vectors["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| (hex32(&key["x25519_scalar"]), hex32(&key["address"])))
        .collect()
}

/// The record of each key of `identity.json` is its scalar, then its
/// address, and gives that key's identity.
#[test]
fn each_key_of_the_vectors_gives_its_identity() {
    for (scalar, address) in keys() {
        let mut record = [0u8; RECORD_LEN];
        record[..32].copy_from_slice(&scalar);
        record[32..].copy_from_slice(&address);
        let identity = identity(&record).unwrap();
        assert_eq!(identity.address().as_bytes(), &address);
        assert_eq!(write(&scalar, identity.address()), record);
    }
}

/// Scenario: a record that does not match is refused.
#[test]
fn a_record_of_two_keys_is_refused() {
    let keys = keys();
    let mut record = [0u8; RECORD_LEN];
    record[..32].copy_from_slice(&keys[0].0);
    record[32..].copy_from_slice(&keys[1].1);
    assert!(matches!(identity(&record), Err(InvalidRecord)));
}

proptest! {
    /// Any 64 bytes are accepted or refused, never a panic.
    #[test]
    fn any_record_is_read_without_panic(bytes in proptest::collection::vec(any::<u8>(), 64)) {
        let record: [u8; RECORD_LEN] = bytes.try_into().unwrap();
        let _ = identity(&record);
    }
}
