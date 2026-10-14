//! The cookie, mac2, cookie-reply and state scenarios of protection under
//! load (`PROTOCOL.md §4`), against `vectors/dos-v1.json`, which an
//! implementation independent of the RustCrypto crates computed.

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
use crate::storage::FixedTable;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../vectors/dos-v1.json")).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn source_from(tag: u64, bytes: &[u8]) -> SourceKey {
    match tag {
        1 => Source::Direct(bytes).key().unwrap(),
        2 => Source::Relayed(PeerId::from_static(bytes.try_into().unwrap()).unwrap())
            .key()
            .unwrap(),
        _ => panic!("unknown tag"),
    }
}

fn t(millis: u64) -> Instant {
    Instant::from_millis(millis)
}

struct Counter(u8);
impl Entropy for Counter {
    fn fill(&mut self, dest: &mut [u8]) {
        self.0 = self.0.wrapping_add(1);
        dest.fill(self.0);
    }
}

// --- cookies, mac2 and the cookie reply -----------------------------------------

/// Scenario: cookies match the committed vectors.
#[test]
fn cookies_match_the_vectors() {
    for vector in vectors()["cookies"].as_array().unwrap() {
        let secret: [u8; 32] = hex(&vector["secret"]).try_into().unwrap();
        let source = source_from(vector["tag"].as_u64().unwrap(), &hex(&vector["source"]));
        assert_eq!(
            cookie(&secret, &source).as_slice(),
            hex(&vector["cookie"]).as_slice(),
            "{}",
            vector["name"]
        );
    }
}

/// Scenario: mac2 matches the committed vectors, and verifies in place.
#[test]
fn mac2_matches_the_vectors() {
    for vector in vectors()["mac2"].as_array().unwrap() {
        let cookie: Cookie = hex(&vector["cookie"]).try_into().unwrap();
        let prefix = hex(&vector["prefix"]);
        let expected = hex(&vector["mac2"]);
        assert_eq!(mac2(&cookie, &prefix).as_slice(), expected.as_slice());
        let mut packet = prefix.clone();
        packet.extend_from_slice(&expected);
        assert!(verify_mac2(&cookie, &packet));
        let last = packet.len() - 1;
        packet[last] ^= 1;
        assert!(!verify_mac2(&cookie, &packet));
    }
}

/// Scenario: a cookie reply matches the committed vectors, and opens only for
/// the dialled address and the first contact's mac1.
#[test]
fn cookie_replies_match_the_vectors() {
    for vector in vectors()["cookie_replies"].as_array().unwrap() {
        let address: [u8; 32] = hex(&vector["address"]).try_into().unwrap();
        let nonce: [u8; 24] = hex(&vector["nonce"]).try_into().unwrap();
        let cookie_value: Cookie = hex(&vector["cookie"]).try_into().unwrap();
        let mac1: Mac = hex(&vector["mac1"]).try_into().unwrap();
        let index = u32::try_from(vector["initiator_index"].as_u64().unwrap()).unwrap();
        let packet = write_cookie_reply(&address, index, &nonce, &cookie_value, &mac1).unwrap();
        assert_eq!(packet.as_slice(), hex(&vector["packet"]).as_slice());

        let reply = parse_cookie_reply(&packet).unwrap();
        assert_eq!(reply.initiator_index, index);
        assert_eq!(
            open_cookie_reply(&reply, &address, &mac1),
            Some(cookie_value)
        );
        let mut other_mac1 = mac1;
        other_mac1[0] ^= 1;
        assert_eq!(open_cookie_reply(&reply, &address, &other_mac1), None);
        let mut other_address = address;
        other_address[0] ^= 1;
        assert_eq!(open_cookie_reply(&reply, &other_address, &mac1), None);
    }
}

/// Scenario: a cookie for one source is worth nothing from another, including
/// the same bytes under the other tag.
#[test]
fn a_cookie_is_bound_to_its_source() {
    let secret = [7; 32];
    let peer =
        PeerId::from_static(hex(&vectors()["cookies"][4]["source"]).try_into().unwrap()).unwrap();
    let relayed = Source::Relayed(peer).key().unwrap();
    let direct_same_bytes = Source::Direct(peer.as_bytes()).key().unwrap();
    let ipv4 = Source::Direct(&[192, 0, 2, 1, 0xCA, 0x6C]).key().unwrap();
    let ipv4_other_port = Source::Direct(&[192, 0, 2, 1, 0xCA, 0x6D]).key().unwrap();

    let cookies = [
        cookie(&secret, &relayed),
        cookie(&secret, &direct_same_bytes),
        cookie(&secret, &ipv4),
        cookie(&secret, &ipv4_other_port),
    ];
    for (i, a) in cookies.iter().enumerate() {
        for b in &cookies[i + 1..] {
            assert_ne!(a, b);
        }
    }
    let packet = [0x5a; 134];
    let mut with_mac2 = packet;
    with_mac2[118..].copy_from_slice(&mac2(&cookies[0], &packet[..118]));
    assert!(verify_mac2(&cookies[0], &with_mac2));
    assert!(!verify_mac2(&cookies[1], &with_mac2));

    // A direct source longer than 32 bytes is no source at all.
    assert_eq!(Source::Direct(&[0; 33]).key(), None);
}

/// Scenario: a cookie expires with its secret.
#[test]
fn the_secret_rotates_after_120_seconds() {
    let mut secret = CookieSecret::default();
    let mut entropy = Counter(0);
    let first = *secret.at(t(1000), &mut entropy);
    assert_eq!(*secret.at(t(1000 + 119_999), &mut entropy), first);
    let second = *secret.at(t(1000 + 120_000), &mut entropy);
    assert_ne!(second, first);

    let source = Source::Direct(&[1, 2, 3]).key().unwrap();
    let old_cookie = cookie(&first, &source);
    let mut packet = [0x11; 134];
    packet[118..].copy_from_slice(&mac2(&old_cookie, &[0x11; 118]));
    assert!(verify_mac2(&cookie(&first, &source), &packet));
    assert!(!verify_mac2(&cookie(&second, &source), &packet));
}

/// Scenario: a cookie reply of any other length or type is not acted on.
#[test]
fn only_62_byte_cookie_replies_parse() {
    let packet = write_cookie_reply(&[1; 32], 9, &[2; 24], &[3; 16], &[4; 16]).unwrap();
    assert!(parse_cookie_reply(&packet).is_ok());
    for len in [0, 1, 2, 61, 63, 134] {
        let mut bytes = packet.to_vec();
        bytes.resize(len, 0);
        if len >= 2 {
            bytes[..2].copy_from_slice(&[0x01, 0x03]);
        }
        assert!(parse_cookie_reply(&bytes).is_err(), "length {len}");
    }
    let mut wrong_type = packet;
    wrong_type[1] = 0x02;
    assert_eq!(
        parse_cookie_reply(&wrong_type),
        Err(MessageError::WrongType)
    );
    let mut wrong_version = packet;
    wrong_version[0] = 0x02;
    assert_eq!(
        parse_cookie_reply(&wrong_version),
        Err(MessageError::WrongVersion)
    );
}

// --- load and rates -------------------------------------------------------------

#[test]
fn a_bucket_refills_from_caller_time() {
    let mut bucket = Bucket::full(5, t(0));
    for _ in 0..5 {
        assert!(bucket.take(5, 5, t(0)));
    }
    assert!(!bucket.take(5, 5, t(0)));
    // 5 a second: one token every 200 ms.
    assert!(!bucket.take(5, 5, t(199)));
    assert!(bucket.take(5, 5, t(200)));
    assert!(!bucket.take(5, 5, t(200)));
    // Never more than the burst, however long the wait.
    let mut taken = 0;
    while bucket.take(5, 5, t(1_000_000)) {
        taken += 1;
    }
    assert_eq!(taken, 5);
}

/// Scenarios: a burst beyond the rate is dropped; other sources are unaffected.
#[test]
fn each_source_has_its_rate() {
    let mut table: FixedTable<SourceKey, Bucket, 8> = FixedTable::new();
    let a = Source::Direct(&[1]).key().unwrap();
    let b = Source::Direct(&[2]).key().unwrap();
    let results: Vec<bool> = (0..6)
        .map(|_| take_source_token(&mut table, a, t(0)))
        .collect();
    assert_eq!(results, [true, true, true, true, true, false]);
    assert!(take_source_token(&mut table, b, t(0)));
    // 20 a second: one token every 50 ms.
    assert!(take_source_token(&mut table, a, t(50)));
}

#[test]
fn a_full_rate_table_forgets_the_source_seen_least_recently() {
    let mut table: FixedTable<SourceKey, Bucket, 2> = FixedTable::new();
    let a = Source::Direct(&[1]).key().unwrap();
    let b = Source::Direct(&[2]).key().unwrap();
    let c = Source::Direct(&[3]).key().unwrap();
    take_source_token(&mut table, a, t(0));
    take_source_token(&mut table, b, t(10));
    assert!(take_source_token(&mut table, c, t(20)));
    assert!(table.get(&a).is_none());
    assert!(table.get(&b).is_some());
    assert!(table.get(&c).is_some());
}

#[test]
fn ephemerals_are_remembered_for_5_seconds() {
    let mut table: FixedTable<[u8; 32], Instant, 2> = FixedTable::new();
    remember(&mut table, [1; 32], t(0));
    assert!(seen_recently(&table, &[1; 32], t(4_999)));
    assert!(!seen_recently(&table, &[1; 32], t(5_000)));
    assert!(!seen_recently(&table, &[2; 32], t(0)));

    // When full, the entry expiring first is forgotten.
    remember(&mut table, [2; 32], t(100));
    remember(&mut table, [3; 32], t(200));
    assert!(!seen_recently(&table, &[1; 32], t(300)));
    assert!(seen_recently(&table, &[2; 32], t(300)));
    assert!(seen_recently(&table, &[3; 32], t(300)));
}

// --- IP sources -------------------------------------------------------------------------

#[test]
fn ip_sources_round_trip_in_both_families() {
    for text in [
        "192.0.2.1:7400",
        "0.0.0.0:0",
        "255.255.255.255:65535",
        "[2001:db8::1]:443",
        "[::1]:1",
        "[fe80::1234:5678:9abc:def0]:65535",
    ] {
        let address: core::net::SocketAddr = text.parse().unwrap();
        let (bytes, len) = encode_ip(address);
        assert_eq!(len, if address.is_ipv4() { 6 } else { 18 });
        assert_eq!(decode_ip(&bytes[..len]), Some(address), "{text}");
        assert_eq!(SourceKey::from_ip(address).as_ip(), Some(address));
    }
}

/// Scenario: one peer, one source.
#[test]
fn an_ipv4_mapped_address_is_encoded_as_ipv4() {
    let mapped: core::net::SocketAddr = "[::ffff:192.0.2.1]:7400".parse().unwrap();
    let plain: core::net::SocketAddr = "192.0.2.1:7400".parse().unwrap();
    assert_eq!(encode_ip(mapped), encode_ip(plain));
    assert_eq!(SourceKey::from_ip(mapped), SourceKey::from_ip(plain));
    assert_eq!(SourceKey::from_ip(mapped).as_ip(), Some(plain));
}

/// Scenario: other lengths name no address.
#[test]
fn other_lengths_name_no_address() {
    for len in [0, 1, 5, 7, 17, 19, 32] {
        assert_eq!(decode_ip(&[1u8; 32][..len]), None, "{len}");
    }
    let seven = Source::Direct(&[1; 7]).key().unwrap();
    assert_eq!(seven.as_ip(), None);
}
