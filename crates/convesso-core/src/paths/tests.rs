//! The path messages' encodings (`PROTOCOL.md §7`), against
//! `vectors/paths-v1.json`, which `generate_paths.py` built with Python's
//! `struct` and `ipaddress`, independently of these codecs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::string::{String, ToString};
use std::vec::Vec;

use proptest::prelude::*;
use serde_json::Value;

use super::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../vectors/paths-v1.json")).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn address(entry: &Value) -> SocketAddr {
    let ip: IpAddr = entry["address"].as_str().unwrap().parse().unwrap();
    SocketAddr::new(ip, u16::try_from(entry["port"].as_u64().unwrap()).unwrap())
}

fn kind(entry: &Value) -> CandidateKind {
    match entry["kind"].as_str().unwrap() {
        "local" => CandidateKind::Local,
        "public" => CandidateKind::Public,
        "seen" => CandidateKind::SeenByPeer,
        other => panic!("unknown kind {other}"),
    }
}

#[test]
fn candidate_lists_match_the_vectors_both_ways() {
    let vectors = vectors();
    for vector in vectors["candidates"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let bytes = hex(&vector["bytes"]);
        let generation = u16::try_from(vector["generation"].as_u64().unwrap()).unwrap();
        let candidates: Vec<Candidate> = vector["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| Candidate {
                kind: kind(entry),
                address: address(entry),
            })
            .collect();

        let list = decode_candidates(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(list.generation, generation, "{name}");
        assert_eq!(list.as_slice(), candidates.as_slice(), "{name}");

        let mut out = [0u8; MAX_CANDIDATES_LEN];
        let len = encode_candidates(generation, &candidates, &mut out).unwrap();
        assert_eq!(&out[..len], bytes.as_slice(), "{name}");
    }
}

#[test]
fn probes_and_answers_match_the_vectors_both_ways() {
    let vectors = vectors();
    let probe = &vectors["probe"];
    assert_eq!(
        decode_probe(&hex(&probe["bytes"])).unwrap().as_slice(),
        hex(&probe["nonce"])
    );

    for vector in vectors["answers"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let bytes = hex(&vector["bytes"]);
        let nonce: Nonce = hex(&vector["nonce"]).try_into().unwrap();
        assert_eq!(
            decode_answer(&bytes),
            Ok((nonce, address(vector))),
            "{name}"
        );

        let mut out = [0u8; 27];
        let len = encode_answer(&nonce, address(vector), &mut out).unwrap();
        assert_eq!(&out[..len], bytes.as_slice(), "{name}");
    }
}

#[test]
fn malformed_messages_are_refused_with_their_defect() {
    let vectors = vectors();
    for vector in vectors["malformed_candidates"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let expected = match vector["defect"].as_str().unwrap() {
            "length" => PathError::Length,
            "count" => PathError::Count,
            "kind" => PathError::Kind,
            "family" => PathError::Family,
            other => panic!("unknown defect {other}"),
        };
        assert_eq!(
            decode_candidates(&hex(&vector["bytes"])),
            Err(expected),
            "{name}"
        );
    }
    for vector in vectors["malformed_probes"].as_array().unwrap() {
        assert!(
            decode_probe(&hex(&vector["bytes"])).is_err(),
            "{}",
            vector["name"]
        );
    }
    for vector in vectors["malformed_answers"].as_array().unwrap() {
        assert!(
            decode_answer(&hex(&vector["bytes"])).is_err(),
            "{}",
            vector["name"]
        );
    }
}

#[test]
fn an_ipv4_mapped_address_is_written_as_ipv4() {
    let mapped: SocketAddr = "[::ffff:203.0.113.7]:41641".parse().unwrap();
    let mut out = [0u8; 27];
    let len = encode_answer(&[7; 8], mapped, &mut out).unwrap();
    assert_eq!(len, 8 + 7);
    assert_eq!(
        decode_answer(&out[..len]).unwrap().1,
        "203.0.113.7:41641".parse().unwrap()
    );
}

#[test]
fn encoders_refuse_too_many_candidates_and_short_buffers() {
    let nine = [Candidate::NONE; MAX_CANDIDATES + 1];
    let mut out = [0u8; 512];
    assert_eq!(encode_candidates(1, &nine, &mut out), Err(PathError::Count));
    assert_eq!(
        encode_candidates(1, &nine[..1], &mut out[..9]),
        Err(PathError::BufferTooSmall)
    );
    assert_eq!(
        encode_answer(&[0; 8], Candidate::NONE.address, &mut out[..14]),
        Err(PathError::BufferTooSmall)
    );
    assert_eq!(
        PathError::Count.to_string(),
        String::from("more than 8 candidates")
    );
}

fn any_address() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (any::<[u8; 4]>(), any::<u16>()).prop_map(|(ip, port)| SocketAddr::from((ip, port))),
        (any::<[u8; 16]>(), any::<u16>())
            .prop_map(|(ip, port)| { SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port) }),
    ]
}

fn any_candidate() -> impl Strategy<Value = Candidate> {
    let kind = prop_oneof![
        Just(CandidateKind::Local),
        Just(CandidateKind::Public),
        Just(CandidateKind::SeenByPeer)
    ];
    (kind, any_address()).prop_map(|(kind, address)| Candidate {
        kind,
        address: canonical(address),
    })
}

proptest! {
    #[test]
    fn every_list_round_trips(
        generation in any::<u16>(),
        candidates in proptest::collection::vec(any_candidate(), 0..=MAX_CANDIDATES),
    ) {
        let mut out = [0u8; MAX_CANDIDATES_LEN];
        let len = encode_candidates(generation, &candidates, &mut out).unwrap();
        let list = decode_candidates(&out[..len]).unwrap();
        prop_assert_eq!(list.generation, generation);
        prop_assert_eq!(list.as_slice(), candidates.as_slice());
    }

    #[test]
    fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        let _ = decode_candidates(&bytes);
        let _ = decode_probe(&bytes);
        let _ = decode_answer(&bytes);
    }
}

#[test]
fn an_ipv4_mapped_address_is_read_as_ipv4() {
    let mut bytes = Vec::from([1, 0, 1, 0x00, 0x06]);
    bytes.extend_from_slice(&"::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap().octets());
    bytes.extend_from_slice(&7500u16.to_le_bytes());
    let list = decode_candidates(&bytes).unwrap();
    assert_eq!(list.as_slice()[0].address, "10.0.0.1:7500".parse().unwrap());
}
