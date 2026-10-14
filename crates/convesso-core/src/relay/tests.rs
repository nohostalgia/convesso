//! The relay's frame and framing scenarios (`PROTOCOL.md §6`), against
//! `vectors/relay-v1.json`, which `generate_relay.py` built with Python's
//! `struct`, independently of this encoder.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use serde_json::Value;

use super::framing::{CloseReason, Deframed, Deframer, KEEPALIVE, MAX_FRAME, PREAMBLE, frame};
use super::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../vectors/relay-v1.json")).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn key(value: &Value) -> [u8; 32] {
    hex(value).try_into().unwrap()
}

/// The frame a vector describes, from its fields.
fn expected<'a>(vector: &Value, packet: &'a [u8]) -> Frame<'a> {
    match vector["type"].as_str().unwrap() {
        "forward" => Frame::Forward {
            recipient: key(&vector["peer"]),
            packet,
        },
        "deliver" => Frame::Deliver {
            sender: key(&vector["peer"]),
            packet,
        },
        "not_connected" => Frame::NotConnected {
            recipient: key(&vector["peer"]),
        },
        "register" => Frame::Register {
            address: key(&vector["address"]),
        },
        "observed" => Frame::Observed {
            link: match vector["link"].as_str().unwrap() {
                "udp" => Link::Udp,
                _ => Link::Tcp,
            },
            address: SocketAddr::new(
                vector["ip"].as_str().unwrap().parse().unwrap(),
                u16::try_from(vector["port"].as_u64().unwrap()).unwrap(),
            ),
        },
        other => panic!("unknown vector type {other}"),
    }
}

// --- frames ---------------------------------------------------------------------------

/// Scenario: frames match the committed vectors.
#[test]
fn frames_match_the_vectors() {
    let vectors = vectors();
    let frames = vectors["frames"].as_array().unwrap();
    assert!(frames.len() >= 12);
    for vector in frames {
        let bytes = hex(&vector["bytes"]);
        let packet = vector.get("packet").map(hex).unwrap_or_default();
        let frame = expected(vector, &packet);
        let mut out = [0u8; 2048];
        let len = encode(&frame, &mut out).unwrap();
        assert_eq!(&out[..len], bytes.as_slice(), "{}", vector["name"]);
        assert_eq!(decode(&bytes), Ok(frame), "{}", vector["name"]);
    }
}

/// Scenario: a malformed or unknown frame is refused, with the defect named.
#[test]
fn malformed_frames_are_refused() {
    for vector in vectors()["malformed"].as_array().unwrap() {
        let bytes = hex(&vector["bytes"]);
        let defect = match vector["defect"].as_str().unwrap() {
            "empty" => FrameError::Empty,
            "unknown type" => FrameError::UnknownType,
            "reserved kind" => FrameError::ReservedKind,
            "wrong length" => FrameError::WrongLength,
            "packet length" => FrameError::PacketLength,
            "reserved version" => FrameError::ReservedVersion,
            "unknown link" => FrameError::UnknownLink,
            "unknown family" => FrameError::UnknownFamily,
            other => panic!("unknown defect {other}"),
        };
        assert_eq!(decode(&bytes), Err(defect), "{}", vector["name"]);
    }
}

/// The encoder refuses what the decoder would, and a buffer too small.
#[test]
fn the_encoder_refuses_what_the_decoder_would() {
    let mut out = [0u8; 2048];
    for packet in [&[][..], &[0xFF, 1, 2][..], &[1u8; MAX_CARRIED + 1][..]] {
        assert!(
            encode(
                &Frame::Forward {
                    recipient: [1; 32],
                    packet
                },
                &mut out
            )
            .is_err()
        );
    }
    let frame = Frame::Deliver {
        sender: [2; 32],
        packet: &[1; 10],
    };
    assert_eq!(
        encode(&frame, &mut [0u8; 43]),
        Err(FrameError::BufferTooSmall)
    );
    assert_eq!(encode(&frame, &mut [0u8; 44]), Ok(44));
}

proptest! {
    /// Arbitrary bytes decode or are refused, and what decodes encodes back to
    /// the same bytes.
    #[test]
    fn decoding_is_strict_and_canonical(bytes in prop::collection::vec(any::<u8>(), 0..1500)) {
        if let Ok(frame) = decode(&bytes) {
            let mut out = [0u8; 2048];
            let len = encode(&frame, &mut out).unwrap();
            prop_assert_eq!(&out[..len], bytes.as_slice());
        }
    }
}

// --- the TCP link's framing -----------------------------------------------------------

/// What a stream produced: its packets, its keep-alives, and why it closed.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    packets: Vec<Vec<u8>>,
    keepalives: usize,
    closed: Option<CloseReason>,
}

/// Feeds `pieces` to one deframer in turn.
fn deframe<'a>(pieces: impl IntoIterator<Item = &'a [u8]>) -> Outcome {
    let mut deframer = Deframer::default();
    let mut outcome = Outcome {
        packets: Vec::new(),
        keepalives: 0,
        closed: None,
    };
    'pieces: for piece in pieces {
        let mut at = 0;
        loop {
            let (used, result) = deframer.feed(&piece[at..]);
            at += used;
            match result {
                Deframed::NeedMore => {
                    assert_eq!(at, piece.len(), "NeedMore consumes its input");
                    break;
                }
                Deframed::KeepAlive => outcome.keepalives += 1,
                Deframed::Packet(packet) => outcome.packets.push(packet.to_vec()),
                Deframed::Closed(reason) => {
                    outcome.closed = Some(reason);
                    break 'pieces;
                }
            }
        }
    }
    outcome
}

fn expected_outcome(vector: &Value) -> Outcome {
    Outcome {
        packets: vector["packets"]
            .as_array()
            .unwrap()
            .iter()
            .map(hex)
            .collect(),
        keepalives: usize::try_from(vector["keepalives"].as_u64().unwrap()).unwrap(),
        closed: match vector["closed"].as_str() {
            None => None,
            Some("wrong preamble") => Some(CloseReason::WrongPreamble),
            Some("length") => Some(CloseReason::Length(1501)),
            Some(other) => panic!("unknown close {other}"),
        },
    }
}

/// Scenario: packets survive any segmentation — whole, byte by byte, and cut
/// in two at every boundary; and the wrong-preamble and oversized-length
/// scenarios close the link.
#[test]
fn streams_match_the_vectors_however_they_are_cut() {
    let vectors = vectors();
    assert_eq!(hex(&vectors["preamble"]), PREAMBLE);
    for vector in vectors["streams"].as_array().unwrap() {
        let stream = hex(&vector["bytes"]);
        let want = expected_outcome(vector);
        let name = vector["name"].as_str().unwrap();
        assert_eq!(deframe([stream.as_slice()]), want, "{name}: whole");
        assert_eq!(deframe(stream.chunks(1)), want, "{name}: byte by byte");
        for cut in 0..=stream.len() {
            let (a, b) = stream.split_at(cut);
            assert_eq!(deframe([a, b]), want, "{name}: cut at {cut}");
        }
    }
}

/// The framer writes what the deframer reads, and refuses what it would not.
#[test]
fn framing_round_trips() {
    let mut stream = PREAMBLE.to_vec();
    let packets: Vec<Vec<u8>> = [1, 31, 134, MAX_FRAME]
        .iter()
        .map(|&n| (0..n).map(|i| (i % 251) as u8 + 1).collect())
        .collect();
    for packet in &packets {
        let mut out = vec![0u8; packet.len() + 2];
        let len = frame(packet, &mut out).unwrap();
        stream.extend_from_slice(&out[..len]);
        stream.extend_from_slice(&KEEPALIVE);
    }
    let outcome = deframe([stream.as_slice()]);
    assert_eq!(outcome.packets, packets);
    assert_eq!(outcome.keepalives, packets.len());
    assert_eq!(outcome.closed, None);
    assert_eq!(frame(&[], &mut [0u8; 8]), None);
    assert_eq!(frame(&[1; MAX_FRAME + 1], &mut [0u8; 2000]), None);
    assert_eq!(frame(&[1; 10], &mut [0u8; 11]), None);
}

/// Scenario: an oversized length closes the link without reading further, and
/// a closed deframer stays closed.
#[test]
fn a_closed_deframer_reads_nothing_more() {
    let mut deframer = Deframer::default();
    let mut stream = PREAMBLE.to_vec();
    stream.extend_from_slice(&1501u16.to_le_bytes());
    stream.extend_from_slice(&[7; 40]);
    let (used, result) = deframer.feed(&stream);
    assert_eq!(result, Deframed::Closed(CloseReason::Length(1501)));
    assert_eq!(used, PREAMBLE.len() + 2);
    assert_eq!(
        deframer.feed(&[0, 0]),
        (0, Deframed::Closed(CloseReason::Length(1501)))
    );
    assert_eq!(deframer.closed(), Some(CloseReason::Length(1501)));
}

proptest! {
    /// Any sequence of packets and keep-alives, framed and cut into pieces of
    /// random sizes, comes out the same.
    #[test]
    fn random_streams_survive_random_cuts(
        packets in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..300), 0..12),
        cuts in prop::collection::vec(1usize..64, 1..40),
    ) {
        let mut stream = PREAMBLE.to_vec();
        let mut want = Vec::new();
        let mut keepalives = 0;
        for packet in &packets {
            if packet.is_empty() {
                stream.extend_from_slice(&KEEPALIVE);
                keepalives += 1;
            } else {
                let mut out = vec![0u8; packet.len() + 2];
                let len = frame(packet, &mut out).unwrap();
                stream.extend_from_slice(&out[..len]);
                want.push(packet.clone());
            }
        }
        let mut pieces = Vec::new();
        let mut at = 0;
        for cut in cuts.iter().cycle() {
            if at >= stream.len() {
                break;
            }
            let end = (at + cut).min(stream.len());
            pieces.push(&stream[at..end]);
            at = end;
        }
        let outcome = deframe(pieces);
        prop_assert_eq!(outcome.packets, want);
        prop_assert_eq!(outcome.keepalives, keepalives);
        prop_assert_eq!(outcome.closed, None);
    }
}

#[test]
fn the_preamble_is_never_a_tls_record() {
    assert_ne!(PREAMBLE[0], 0x16);
    assert_eq!(&PREAMBLE[..8], b"convesso");
}
