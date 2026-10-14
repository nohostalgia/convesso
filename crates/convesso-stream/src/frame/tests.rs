//! The frames against `vectors/stream-v1.json`, which `generate_stream.py`
//! built with Python's `struct`, independently of this encoder; and the
//! frames' rules (`PROTOCOL.md §8`) one by one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::string::String;
use std::vec::Vec;

use proptest::prelude::*;
use serde_json::Value;

use super::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../vectors/stream-v1.json")).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn incarnation(v: &Value) -> Incarnation {
    hex(v.as_str().unwrap()).try_into().unwrap()
}

fn u32_of(v: &Value) -> u32 {
    u32::try_from(v.as_u64().unwrap()).unwrap()
}

fn name(v: &Value) -> String {
    v["description"].as_str().unwrap().into()
}

/// Scenario: frames match the committed vectors, both ways.
#[test]
fn data_frames_match_the_vectors() {
    for v in vectors()["data"].as_array().unwrap() {
        let frame = hex(v["frame"].as_str().unwrap());
        let bytes = hex(v["bytes"].as_str().unwrap());
        let expected = Data {
            incarnation: incarnation(&v["incarnation"]),
            sequence: u32_of(&v["sequence"]),
            length: v["length"].as_u64().map(|n| u32::try_from(n).unwrap()),
            last: v["last"].as_bool().unwrap(),
            start: v["start"].as_bool().unwrap(),
            bytes: &bytes,
        };
        assert_eq!(Data::decode(&frame), Ok(expected), "{}", name(v));
        let mut out = [0u8; MAX_DATA_LEN];
        let len = expected.encode(&mut out).unwrap();
        assert_eq!(&out[..len], &frame[..], "{}", name(v));
    }
}

/// Scenario: frames match the committed vectors, both ways.
#[test]
fn acknowledgements_match_the_vectors() {
    for v in vectors()["acks"].as_array().unwrap() {
        let frame = hex(v["frame"].as_str().unwrap());
        let mut expected = Ack::new(
            incarnation(&v["incarnation"]),
            v["reset"].as_bool().unwrap(),
            u32_of(&v["cumulative"]),
            u32_of(&v["window"]),
            u32_of(&v["max_message"]),
        );
        for range in v["ranges"].as_array().unwrap() {
            assert!(expected.push_range(Range {
                start: u32_of(&range[0]),
                end: u32_of(&range[1]),
            }));
        }
        assert_eq!(Ack::decode(&frame), Ok(expected), "{}", name(v));
        let mut out = [0u8; MAX_ACK_LEN];
        let len = expected.encode(&mut out).unwrap();
        assert_eq!(&out[..len], &frame[..], "{}", name(v));
    }
}

/// Scenario: a malformed frame changes nothing: each is refused whole.
#[test]
fn malformed_frames_are_refused() {
    let v = vectors();
    for m in v["malformed_data"].as_array().unwrap() {
        let frame = hex(m["frame"].as_str().unwrap());
        assert_eq!(
            Data::decode(&frame),
            Err(FrameError::Malformed),
            "{}",
            name(m)
        );
    }
    for m in v["malformed_acks"].as_array().unwrap() {
        let frame = hex(m["frame"].as_str().unwrap());
        assert_eq!(
            Ack::decode(&frame),
            Err(FrameError::Malformed),
            "{}",
            name(m)
        );
    }
}

/// The encoders refuse to write what the decoders would refuse.
#[test]
fn encoders_refuse_malformed_frames() {
    let mut out = [0u8; MAX_DATA_LEN + 1];
    let data = |length, bytes| Data {
        incarnation: [1; 8],
        sequence: 0,
        length,
        last: false,
        start: false,
        bytes,
    };
    assert_eq!(data(None, &[]).encode(&mut out), Err(FrameError::Malformed));
    assert_eq!(
        data(Some(0), b"x").encode(&mut out),
        Err(FrameError::Malformed)
    );
    assert_eq!(
        data(None, &[0; MAX_FRAGMENT + 1]).encode(&mut out),
        Err(FrameError::Malformed)
    );
    assert_eq!(
        data(Some(3), b"abc").encode(&mut [0u8; 19]),
        Err(FrameError::BufferTooSmall)
    );
    let mut ack = Ack::new([1; 8], false, 100, 0, 0);
    assert!(ack.push_range(Range {
        start: 100,
        end: 101
    }));
    assert_eq!(ack.encode(&mut out), Err(FrameError::Malformed));
    let mut full = Ack::new([1; 8], false, 0, 0, 0);
    for i in 0..4 {
        assert!(full.push_range(Range {
            start: 2 * i + 1,
            end: 2 * i + 2
        }));
    }
    assert!(
        !full.push_range(Range { start: 9, end: 10 }),
        "no fifth range"
    );
}

/// Serial-number arithmetic (RFC 1982): order across the wrap.
#[test]
fn sequences_compare_across_the_wrap() {
    assert!(after(1, 0));
    assert!(!after(0, 0));
    assert!(!after(0, 1));
    assert!(after(0, u32::MAX));
    assert!(after(5, u32::MAX - 5));
    assert!(!after(1 << 31, 0), "2^31 apart: unordered");
    assert!(!after(0, 1 << 31), "2^31 apart: unordered");
}

proptest! {
    /// Any bytes decode or are refused, never a panic; what decodes encodes
    /// back to the same bytes.
    #[test]
    fn any_bytes_decode_or_are_refused(frame in proptest::collection::vec(any::<u8>(), 0..1400)) {
        if let Ok(data) = Data::decode(&frame) {
            let mut out = [0u8; MAX_DATA_LEN];
            let len = data.encode(&mut out).unwrap();
            prop_assert_eq!(&out[..len], &frame[..]);
        }
        if let Ok(ack) = Ack::decode(&frame) {
            let mut out = [0u8; MAX_ACK_LEN];
            let len = ack.encode(&mut out).unwrap();
            prop_assert_eq!(&out[..len], &frame[..]);
        }
    }
}
