//! The wire invariants' scenarios (`PROTOCOL.md §1`), against the vectors in
//! `vectors/wire-format.json`, which an independent implementation computed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use convesso_core::wire::{
    Classified, DecodeError, MAC_LEN, MACS_LEN, MIN_FIRST_CONTACT_LEN, Mac1Key,
    PendingFirstContact, Version, VersionNotSupported, answer_unknown_version, carried_mac1,
    classify, match_answer,
};
use proptest::prelude::*;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/wire-format.json")).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn address(i: u8) -> [u8; 32] {
    [i; 32]
}

/// A first contact of `version`: a body, then a `mac1` valid for `address`, then `mac2`.
fn first_contact(version: u8, body_len: usize, address: &[u8; 32], mac2: [u8; 16]) -> Vec<u8> {
    let mut packet = vec![version];
    packet.extend((0..body_len).map(|i| i as u8));
    let mac1 = Mac1Key::for_address(address).compute(&packet);
    packet.extend_from_slice(&mac1);
    packet.extend_from_slice(&mac2);
    packet
}

// --- mac1 ------------------------------------------------------------------

/// Scenario: mac1 matches the committed vectors.
#[test]
fn mac1_matches_the_committed_vectors() {
    let vectors = vectors();
    assert_eq!(hex(&vectors["mac1_label"]), b"convesso-mac1");
    for vector in vectors["mac1"].as_array().unwrap() {
        let address: [u8; 32] = hex(&vector["address"]).try_into().unwrap();
        let prefix = hex(&vector["prefix"]);
        let expected = hex(&vector["mac1"]);
        let key = Mac1Key::for_address(&address);

        assert_eq!(key.compute(&prefix).as_slice(), expected.as_slice());

        // A packet carrying that mac1 after a non-empty prefix verifies.
        if !prefix.is_empty() {
            let mut packet = prefix.clone();
            packet.extend_from_slice(&expected);
            packet.extend_from_slice(&[0u8; MAC_LEN]);
            assert!(key.verify(&packet));
        }
    }
}

/// Scenario: a packet with a wrong mac1 is met with silence — including one
/// valid for a different address.
#[test]
fn a_mac1_for_another_address_is_not_valid() {
    let packet = first_contact(1, 40, &address(1), [0; 16]);

    assert!(Mac1Key::for_address(&address(1)).verify(&packet));
    assert!(!Mac1Key::for_address(&address(2)).verify(&packet));
}

/// Scenario: mac2 does not affect mac1.
#[test]
fn mac2_does_not_affect_mac1() {
    let key = Mac1Key::for_address(&address(1));
    let mut packet = first_contact(1, 40, &address(1), [0; 16]);
    let len = packet.len();
    for byte in &mut packet[len - MAC_LEN..] {
        *byte ^= 0xA5;
    }
    assert!(key.verify(&packet));
}

/// A packet too short to carry the MACs is never valid.
#[test]
fn a_packet_too_short_is_never_valid() {
    let key = Mac1Key::for_address(&address(1));
    for len in 0..MIN_FIRST_CONTACT_LEN {
        assert!(!key.verify(&vec![1u8; len]));
        assert_eq!(carried_mac1(&vec![1u8; len]), None);
    }
}

proptest! {
    /// Scenario: any change before mac1 invalidates it.
    #[test]
    fn flipping_any_bit_before_mac1_invalidates_it(
        body_len in 0usize..200,
        position in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let key = Mac1Key::for_address(&address(7));
        let mut packet = first_contact(1, body_len, &address(7), [0; 16]);
        let covered = packet.len() - MACS_LEN;
        packet[position.index(covered)] ^= 1 << bit;
        prop_assert!(!key.verify(&packet));
    }
}

// --- byte 0 ----------------------------------------------------------------

/// Scenarios: a known version is handed to that version; a reserved or empty
/// packet is dropped.
#[test]
fn byte_zero_classifies_the_packet() {
    assert_eq!(classify(&[]), Classified::Drop);
    assert_eq!(classify(&[0xFF, 1, 2]), Classified::Drop);
    assert_eq!(classify(&[0x00, 1]), Classified::VersionNotSupported);
    assert_eq!(classify(&[0x01]), Classified::Version(Version::V1));
    assert_eq!(
        classify(&[0xFE]),
        Classified::Version(Version::new(0xFE).unwrap())
    );
    assert_eq!(Version::new(0x00), None);
    assert_eq!(Version::new(0xFF), None);
}

// --- answering an unknown version -----------------------------------------

const SPOKEN: &[Version] = &[Version::V1];

/// Scenario: an unknown version with a valid mac1 is answered with
/// `00 01 01 || mac1`.
#[test]
fn an_unknown_version_with_a_valid_mac1_is_answered() {
    let key = Mac1Key::for_address(&address(1));
    let packet = first_contact(0x02, 0, &address(1), [0; 16]);
    assert_eq!(packet.len(), MIN_FIRST_CONTACT_LEN);
    let mut out = [0u8; 64];

    let len = answer_unknown_version(&packet, &key, SPOKEN, &mut out).unwrap();

    let mut expected = vec![0x00, 0x01, 0x01];
    expected.extend_from_slice(&carried_mac1(&packet).unwrap());
    assert_eq!(&out[..len], expected.as_slice());
}

/// Scenario: an unknown version with an invalid mac1 is met with silence.
#[test]
fn an_unknown_version_with_an_invalid_mac1_is_not_answered() {
    let key = Mac1Key::for_address(&address(1));
    let packet = first_contact(0x02, 10, &address(2), [0; 16]);
    assert_eq!(
        answer_unknown_version(&packet, &key, SPOKEN, &mut [0u8; 64]),
        None
    );
}

/// A known version, a reserved or empty packet, a version-not-supported message
/// and a packet too short to be a first contact are never answered.
#[test]
fn nothing_else_is_answered() {
    let key = Mac1Key::for_address(&address(1));
    let mut out = [0u8; 64];
    let known = first_contact(0x01, 10, &address(1), [0; 16]);
    let mut reserved = first_contact(0x02, 10, &address(1), [0; 16]);
    reserved[0] = 0xFF;

    assert_eq!(answer_unknown_version(&known, &key, SPOKEN, &mut out), None);
    assert_eq!(
        answer_unknown_version(&reserved, &key, SPOKEN, &mut out),
        None
    );
    assert_eq!(answer_unknown_version(&[], &key, SPOKEN, &mut out), None);
    for len in 1..MIN_FIRST_CONTACT_LEN {
        let short = vec![0x02; len];
        assert_eq!(answer_unknown_version(&short, &key, SPOKEN, &mut out), None);
    }
}

/// Scenario: the answer is never larger than the question.
#[test]
fn the_answer_is_never_larger_than_the_question() {
    let key = Mac1Key::for_address(&address(1));
    let packet = first_contact(0x20, 0, &address(1), [0; 16]);
    let many: Vec<Version> = (1..=15).map(|b| Version::new(b).unwrap()).collect();
    let mut out = [0u8; 64];

    // 15 versions make a 33-byte answer: exactly the 33-byte packet's size.
    assert_eq!(
        answer_unknown_version(&packet, &key, &many, &mut out),
        Some(33)
    );

    // A spoken list the message cannot carry is not answered at all.
    let too_many: Vec<Version> = (1..=16).map(|b| Version::new(b).unwrap()).collect();
    let longer = first_contact(0x20, 100, &address(1), [0; 16]);
    assert_eq!(
        answer_unknown_version(&longer, &key, &too_many, &mut out),
        None
    );

    // An answer that does not fit the caller's buffer is not sent truncated.
    assert_eq!(
        answer_unknown_version(&packet, &key, SPOKEN, &mut [0u8; 10]),
        None
    );
}

// --- decoding "version not supported" ---------------------------------------

/// Scenario: a well-formed message is decoded.
#[test]
fn well_formed_messages_decode() {
    let vectors = vectors();
    for vector in vectors["version_not_supported"]["valid"]
        .as_array()
        .unwrap()
    {
        let encoding = hex(&vector["encoding"]);
        let decoded = VersionNotSupported::decode(&encoding).unwrap();
        let versions: Vec<u64> = decoded
            .versions()
            .iter()
            .map(|v| u64::from(v.get()))
            .collect();
        let expected: Vec<u64> = vector["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();

        assert_eq!(versions, expected, "{}", vector["name"]);
        assert_eq!(decoded.echo().as_slice(), hex(&vector["echo"]).as_slice());

        let mut out = [0u8; 64];
        let len = decoded.encode(&mut out).unwrap();
        assert_eq!(&out[..len], encoding.as_slice());
    }
}

/// Scenario: malformed messages are rejected with a named defect.
#[test]
fn malformed_messages_are_rejected_with_their_defect() {
    let vectors = vectors();
    for vector in vectors["version_not_supported"]["invalid"]
        .as_array()
        .unwrap()
    {
        let error = VersionNotSupported::decode(&hex(&vector["encoding"])).unwrap_err();
        let defect = vector["defect"].as_str().unwrap();
        assert!(
            format!("{error:?}").starts_with(defect),
            "{}: expected {defect}, got {error:?}",
            vector["name"]
        );
    }
    assert_eq!(
        VersionNotSupported::decode(&[0x00, 16]),
        Err(DecodeError::TooManyVersions { count: 16 })
    );
}

proptest! {
    /// Decoding inverts encoding.
    #[test]
    fn decode_inverts_encode(
        set in prop::collection::btree_set(1u8..=0xFE, 1..=15),
        echo in any::<[u8; 16]>(),
    ) {
        let versions: Vec<Version> = set.into_iter().map(|b| Version::new(b).unwrap()).collect();
        let message = VersionNotSupported::new(&versions, echo).unwrap();
        let mut out = [0u8; 64];
        let len = message.encode(&mut out).unwrap();

        prop_assert_eq!(len, 18 + versions.len());
        prop_assert_eq!(VersionNotSupported::decode(&out[..len]), Ok(message));
    }

    /// Arbitrary input never panics (the fuzz target explores further).
    #[test]
    fn decoding_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let _ = VersionNotSupported::decode(&bytes);
        let _ = classify(&bytes);
    }
}

// --- the initiator's side -----------------------------------------------------

fn answer(versions: &[u8], echo: [u8; 16]) -> VersionNotSupported {
    let versions: Vec<Version> = versions.iter().map(|&b| Version::new(b).unwrap()).collect();
    VersionNotSupported::new(&versions, echo).unwrap()
}

/// Scenario: a matching message ends the attempt with a named error.
#[test]
fn a_matching_answer_ends_the_attempt_with_a_named_error() {
    let v2 = Version::new(2).unwrap();
    let pending = [
        PendingFirstContact {
            version: v2,
            mac1: [9; 16],
        },
        PendingFirstContact {
            version: v2,
            mac1: [5; 16],
        },
    ];

    let (index, error) = match_answer(&answer(&[1], [5; 16]), &pending).unwrap();

    assert_eq!(index, 1);
    assert_eq!(error.attempted, v2);
    assert_eq!(error.peer_versions(), &[Version::V1]);
    assert_eq!(
        error.to_string(),
        "peer does not speak version 2; it speaks 1"
    );
}

/// Scenario: a message that matches no attempt is ignored.
#[test]
fn an_answer_matching_no_attempt_is_ignored() {
    let pending = [PendingFirstContact {
        version: Version::new(2).unwrap(),
        mac1: [9; 16],
    }];
    assert_eq!(match_answer(&answer(&[1], [5; 16]), &pending), None);
    assert_eq!(match_answer(&answer(&[1], [5; 16]), &[]), None);
}

/// Scenario: a message contradicting the attempt is ignored.
#[test]
fn an_answer_listing_the_attempted_version_is_ignored() {
    let pending = [PendingFirstContact {
        version: Version::V1,
        mac1: [5; 16],
    }];
    assert_eq!(match_answer(&answer(&[1, 3], [5; 16]), &pending), None);
}
