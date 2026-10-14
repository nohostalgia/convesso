//! The packet and anti-replay scenarios (`PROTOCOL.md §5`),
//! against `vectors/transport-v1.json`, which an implementation independent of
//! the RustCrypto crates computed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::collections::BTreeSet;
use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use serde_json::Value;

use super::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../vectors/transport-v1.json")).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

// --- packets --------------------------------------------------------------------

/// Scenario: packets match the committed vectors.
#[test]
fn packets_match_the_vectors() {
    for vector in vectors()["packets"].as_array().unwrap() {
        let key: [u8; 32] = hex(&vector["key"]).try_into().unwrap();
        let index = u32::try_from(vector["index"].as_u64().unwrap()).unwrap();
        let counter = vector["counter"].as_u64().unwrap();
        let inner_type = u8::try_from(vector["inner_type"].as_u64().unwrap()).unwrap();
        let data = hex(&vector["data"]);
        let expected = hex(&vector["packet"]);

        let mut out = vec![0u8; OVERHEAD + data.len()];
        let len = seal(&key, index, counter, inner_type, &data, &mut out).unwrap();
        assert_eq!(&out[..len], expected.as_slice(), "{}", vector["name"]);

        let mut received = expected.clone();
        let opened = open(&key, &mut received).unwrap();
        assert_eq!(
            opened.header,
            Header {
                receiver_index: index,
                counter
            }
        );
        assert_eq!(opened.inner_type, inner_type);
        assert_eq!(opened.data, data.as_slice());
    }
}

/// Scenario: a change to any header byte fails authentication (the index too:
/// it is authenticated, though a changed index usually just finds no session).
#[test]
fn every_header_bit_is_authenticated() {
    let key = [9; 32];
    let mut out = [0u8; 64];
    let len = seal(&key, 0x0a0b_0c0d, 42, inner::DATAGRAM, b"hello", &mut out).unwrap();
    for byte in 0..HEADER_LEN {
        for bit in 0..8 {
            let mut packet = out[..len].to_vec();
            packet[byte] ^= 1 << bit;
            assert!(open(&key, &mut packet).is_err(), "byte {byte} bit {bit}");
        }
    }
    let mut packet = out[..len].to_vec();
    packet[len - 1] ^= 1;
    assert_eq!(open(&key, &mut packet), Err(TransportError::Decrypt));
    let mut packet = out[..len].to_vec();
    assert!(open(&[8; 32], &mut packet).is_err());
}

/// Scenario: a packet shorter than its smallest form is dropped.
#[test]
fn short_packets_are_malformed() {
    for len in 0..OVERHEAD {
        let mut packet = vec![0u8; len];
        if len >= 2 {
            packet[..2].copy_from_slice(&[0x01, TYPE_TRANSPORT]);
        }
        assert!(matches!(
            open(&[0; 32], &mut packet),
            Err(TransportError::Malformed(_))
        ));
    }
    let mut packet = [0u8; 40];
    packet[..2].copy_from_slice(&[0x01, 0x02]);
    assert_eq!(parse_header(&packet), Err(MessageError::WrongType));
}

#[test]
fn the_counter_cap_holds_both_ways() {
    let mut out = [0u8; 64];
    assert_eq!(
        seal(&[1; 32], 1, MAX_COUNTER, inner::KEEPALIVE, &[], &mut out),
        Err(TransportError::CounterExhausted)
    );
    let len = seal(
        &[1; 32],
        1,
        MAX_COUNTER - 1,
        inner::KEEPALIVE,
        &[],
        &mut out,
    )
    .unwrap();
    out[6..14].copy_from_slice(&MAX_COUNTER.to_le_bytes());
    assert_eq!(
        open(&[1; 32], &mut out[..len]),
        Err(TransportError::CounterExhausted)
    );
    assert_eq!(
        seal(&[1; 32], 1, 0, inner::DATAGRAM, &[0; 10], &mut [0u8; 40]),
        Err(TransportError::BufferTooSmall { needed: 41 })
    );
}

// --- anti-replay ----------------------------------------------------------------

type Mcu = Window<5>;
type Server = Window<129>;

#[test]
fn the_configured_windows_have_the_stated_sizes() {
    assert_eq!(Mcu::WINDOW, 256);
    assert_eq!(Server::WINDOW, 8192);
}

/// Scenario: a late packet within the window is accepted.
#[test]
fn late_packets_within_the_window_are_accepted_once() {
    let mut window = Mcu::default();
    for counter in [0, 1, 2, 3, 4, 6, 7, 8, 9, 5] {
        assert!(window.may_accept(counter), "{counter}");
        window.accept(counter);
    }
    // Scenario: a duplicate is refused.
    for counter in 0..10 {
        assert!(!window.may_accept(counter), "{counter} again");
    }
}

/// Scenario: a packet older than the window is refused.
#[test]
fn packets_older_than_the_window_are_refused() {
    let mut window = Mcu::default();
    window.accept(1000);
    assert!(window.may_accept(1000 - 255));
    assert!(!window.may_accept(1000 - 256));
    assert!(!window.may_accept(0));
}

/// Scenario: a forged packet moves nothing. The window is only told about a
/// counter after the packet opened, so a forgery never reaches `accept`; this
/// checks that asking about it changes nothing either.
#[test]
fn asking_never_moves_the_window() {
    let mut window = Mcu::default();
    window.accept(10);
    assert!(window.may_accept(u64::MAX >> 4));
    assert!(window.may_accept(9));
    window.accept(9);
    assert!(!window.may_accept(9));
}

proptest! {
    /// The window agrees with a model that remembers every counter accepted,
    /// for any sequence, within its stated window.
    #[test]
    fn agrees_with_a_set_based_model(
        steps in prop::collection::vec((0u64..3, 0u64..700), 1..400),
    ) {
        let mut window = Mcu::default();
        let mut accepted = BTreeSet::new();
        let mut highest: Option<u64> = None;
        let mut position = 0u64;
        for (kind, amount) in steps {
            // Mostly forward, sometimes back, sometimes far ahead.
            let counter = match kind {
                0 => { position += amount % 3; position }
                1 => position.saturating_sub(amount % 300),
                _ => { position += amount; position }
            };
            let expected = match highest {
                None => true,
                Some(h) if counter > h => true,
                Some(h) => h - counter < Mcu::WINDOW && !accepted.contains(&counter),
            };
            prop_assert_eq!(window.may_accept(counter), expected, "counter {}", counter);
            if expected {
                window.accept(counter);
                accepted.insert(counter);
                highest = Some(highest.map_or(counter, |h| h.max(counter)));
            }
        }
    }
}
