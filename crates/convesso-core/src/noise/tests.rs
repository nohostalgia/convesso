//! Our Noise instance against the official vectors and against `snow`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_arguments
)]

extern crate std;

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use serde_json::Value;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    Completed, DHLEN, TAGLEN, initiation_es, read_initiation, read_response, write_initiation,
    write_response,
};

const NAME: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn key32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().unwrap()
}

/// One full handshake through our implementation, returning the two messages
/// and both sides' results.
struct Run {
    first: Vec<u8>,
    second: Vec<u8>,
    first_payload: Vec<u8>,
    second_payload: Vec<u8>,
    initiator: Completed,
    responder: Completed,
}

#[allow(clippy::too_many_arguments)]
fn run(
    init_static: [u8; 32],
    init_ephemeral: [u8; 32],
    resp_static: [u8; 32],
    resp_ephemeral: [u8; 32],
    prologue: &[u8],
    psk: [u8; 32],
    payload1: &[u8],
    payload2: &[u8],
) -> Run {
    let is = StaticSecret::from(init_static);
    let rs_secret = StaticSecret::from(resp_static);
    let rs = PublicKey::from(&rs_secret).to_bytes();

    let mut first = vec![0u8; 2 * DHLEN + 2 * TAGLEN + payload1.len()];
    let (awaiting, len) = write_initiation(
        &is,
        &rs,
        StaticSecret::from(init_ephemeral),
        prologue,
        payload1,
        &mut first,
    )
    .unwrap();
    first.truncate(len);

    let mut received = first.clone();
    let (re, es) = initiation_es(&rs_secret, &received).unwrap();
    let (read, p1_len) = read_initiation(&rs_secret, prologue, &re, &es, &mut received).unwrap();
    assert_eq!(read.remote_static(), PublicKey::from(&is).as_bytes());
    let first_payload = received[2 * DHLEN + TAGLEN..2 * DHLEN + TAGLEN + p1_len].to_vec();

    let mut second = vec![0u8; DHLEN + TAGLEN + payload2.len()];
    let (responder, len) = write_response(
        read,
        &StaticSecret::from(resp_ephemeral),
        &psk,
        payload2,
        &mut second,
    )
    .unwrap();
    second.truncate(len);

    let mut received = second.clone();
    let (initiator, p2_len) = read_response(&awaiting, &is, &psk, &mut received).unwrap();
    let second_payload = received[DHLEN..DHLEN + p2_len].to_vec();

    Run {
        first,
        second,
        first_payload,
        second_payload,
        initiator,
        responder,
    }
}

/// Encrypts one transport message with our cipher.
fn seal(cipher: &mut super::CipherState, payload: &[u8]) -> Vec<u8> {
    let mut buffer = payload.to_vec();
    buffer.resize(payload.len() + TAGLEN, 0);
    let len = cipher
        .encrypt_with_ad(&[], &mut buffer, payload.len())
        .unwrap();
    buffer.truncate(len);
    buffer
}

/// Decrypts one transport message with our cipher.
fn open(cipher: &mut super::CipherState, message: &[u8]) -> Vec<u8> {
    let mut buffer = message.to_vec();
    let len = cipher.decrypt_with_ad(&[], &mut buffer).unwrap();
    buffer.truncate(len);
    buffer
}

/// Every official vector for this protocol name: both handshake messages, the
/// handshake hash, and the transport messages that follow, alternating from
/// the initiator.
#[test]
fn the_official_vectors_pass() {
    let document: Value =
        serde_json::from_str(include_str!("../../vectors/cacophony-ikpsk2.json")).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for vector in vectors {
        assert_eq!(vector["protocol_name"], NAME);
        assert_eq!(vector["init_prologue"], vector["resp_prologue"]);
        let messages = vector["messages"].as_array().unwrap();
        let mut result = run(
            key32(&hex(&vector["init_static"])),
            key32(&hex(&vector["init_ephemeral"])),
            key32(&hex(&vector["resp_static"])),
            key32(&hex(&vector["resp_ephemeral"])),
            &hex(&vector["init_prologue"]),
            key32(&hex(&vector["init_psks"][0])),
            &hex(&messages[0]["payload"]),
            &hex(&messages[1]["payload"]),
        );
        assert_eq!(
            hex(&vector["init_remote_static"]),
            PublicKey::from(&StaticSecret::from(key32(&hex(&vector["resp_static"])))).as_bytes()
        );
        assert_eq!(result.first, hex(&messages[0]["ciphertext"]));
        assert_eq!(result.second, hex(&messages[1]["ciphertext"]));
        assert_eq!(result.first_payload, hex(&messages[0]["payload"]));
        assert_eq!(result.second_payload, hex(&messages[1]["payload"]));
        let hash = hex(&vector["handshake_hash"]);
        assert_eq!(result.initiator.handshake_hash.as_slice(), hash.as_slice());
        assert_eq!(result.responder.handshake_hash.as_slice(), hash.as_slice());

        for (i, message) in messages.iter().enumerate().skip(2) {
            let payload = hex(&message["payload"]);
            let expected = hex(&message["ciphertext"]);
            let (sender, receiver) = if i % 2 == 0 {
                (&mut result.initiator, &mut result.responder)
            } else {
                (&mut result.responder, &mut result.initiator)
            };
            let sealed = seal(&mut sender.transport.send, &payload);
            assert_eq!(sealed, expected, "transport message {i}");
            assert_eq!(open(&mut receiver.transport.recv, &sealed), payload);
        }
    }
}

fn snow_builder<'a>(
    params: &snow::params::NoiseParams,
    local: &'a [u8; 32],
    ephemeral: &'a [u8; 32],
    prologue: &'a [u8],
    psk: &'a [u8; 32],
) -> snow::Builder<'a> {
    snow::Builder::new(params.clone())
        .local_private_key(local)
        .unwrap()
        .prologue(prologue)
        .unwrap()
        .psk(2, psk)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(ephemeral)
}

/// Byte-for-byte equality with `snow`, given the same keys: both handshake
/// messages, the handshake hash, and transport messages in both directions.
fn equal_to_snow(
    init_static: [u8; 32],
    init_ephemeral: [u8; 32],
    resp_static: [u8; 32],
    resp_ephemeral: [u8; 32],
    prologue: &[u8],
    psk: [u8; 32],
    payload1: &[u8],
    payload2: &[u8],
) {
    let params: snow::params::NoiseParams = NAME.parse().unwrap();
    let resp_public = PublicKey::from(&StaticSecret::from(resp_static)).to_bytes();
    let mut snow_init = snow_builder(&params, &init_static, &init_ephemeral, prologue, &psk)
        .remote_public_key(&resp_public)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut snow_resp = snow_builder(&params, &resp_static, &resp_ephemeral, prologue, &psk)
        .build_responder()
        .unwrap();

    let mut ours = run(
        init_static,
        init_ephemeral,
        resp_static,
        resp_ephemeral,
        prologue,
        psk,
        payload1,
        payload2,
    );

    let mut buffer = [0u8; 1024];
    let len = snow_init.write_message(payload1, &mut buffer).unwrap();
    assert_eq!(&buffer[..len], ours.first.as_slice(), "first message");
    let mut payload = [0u8; 1024];
    snow_resp
        .read_message(&buffer[..len], &mut payload)
        .unwrap();
    let len = snow_resp.write_message(payload2, &mut buffer).unwrap();
    assert_eq!(&buffer[..len], ours.second.as_slice(), "second message");
    snow_init
        .read_message(&buffer[..len], &mut payload)
        .unwrap();
    assert_eq!(
        snow_init.get_handshake_hash(),
        ours.initiator.handshake_hash
    );
    assert_eq!(
        snow_resp.get_handshake_hash(),
        ours.responder.handshake_hash
    );

    let mut snow_init = snow_init.into_transport_mode().unwrap();
    let mut snow_resp = snow_resp.into_transport_mode().unwrap();
    for round in 0u8..3 {
        let message = [round; 40];
        let len = snow_init.write_message(&message, &mut buffer).unwrap();
        assert_eq!(
            seal(&mut ours.initiator.transport.send, &message),
            &buffer[..len]
        );
        assert_eq!(
            open(&mut ours.responder.transport.recv, &buffer[..len]),
            message
        );
        let len = snow_resp.write_message(&message, &mut buffer).unwrap();
        assert_eq!(
            seal(&mut ours.responder.transport.send, &message),
            &buffer[..len]
        );
        assert_eq!(
            open(&mut ours.initiator.transport.recv, &buffer[..len]),
            message
        );
    }
}

#[test]
fn equal_to_snow_on_fixed_keys() {
    equal_to_snow(
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        b"convesso\x01\x00",
        [0; 32],
        &[],
        &[0, 0, 0],
    );
    equal_to_snow(
        [9; 32],
        [8; 32],
        [7; 32],
        [6; 32],
        b"convesso\x01\x07session",
        [5; 32],
        b"payload",
        &[1, 0x00, 0x01],
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The same with random keys, prologues, PSKs and payloads.
    #[test]
    fn equal_to_snow_on_random_keys(
        keys in any::<[[u8; 32]; 4]>(),
        prologue in prop::collection::vec(any::<u8>(), 0..64),
        psk in any::<[u8; 32]>(),
        payload1 in prop::collection::vec(any::<u8>(), 0..64),
        payload2 in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        equal_to_snow(keys[0], keys[1], keys[2], keys[3], &prologue, psk, &payload1, &payload2);
    }
}

/// A Diffie-Hellman with a small-order key is refused rather than used.
#[test]
fn an_all_zero_diffie_hellman_is_refused() {
    let s = StaticSecret::from([1; 32]);
    let mut out = [0u8; 128];
    let zero = [0u8; 32];
    assert!(matches!(
        write_initiation(&s, &zero, StaticSecret::from([2; 32]), &[], &[], &mut out),
        Err(super::NoiseError::ZeroDh)
    ));
}

/// A tampered first message is refused, and a responder's decryption failure
/// is not an error that leaks which part failed beyond "does not decrypt".
#[test]
fn a_tampered_message_does_not_decrypt() {
    let result = run(
        [1; 32], [2; 32], [3; 32], [4; 32], b"p", [0; 32], b"x", b"y",
    );
    let rs_secret = StaticSecret::from([3; 32]);
    for position in DHLEN..result.first.len() {
        let mut tampered = result.first.clone();
        tampered[position] ^= 1;
        let (re, es) = initiation_es(&rs_secret, &tampered).unwrap();
        assert!(read_initiation(&rs_secret, b"p", &re, &es, &mut tampered).is_err());
    }
}

/// Our initiator against `snow`'s responder, then `snow`'s initiator against our
/// responder, with `snow` drawing its own ephemerals: each side reads the other's
/// handshake messages and transport messages in both directions.
fn interoperates_with_snow(
    init_static: [u8; 32],
    our_ephemeral: [u8; 32],
    resp_static: [u8; 32],
    prologue: &[u8],
    psk: [u8; 32],
) {
    let params: snow::params::NoiseParams = NAME.parse().unwrap();
    let init_secret = StaticSecret::from(init_static);
    let resp_secret = StaticSecret::from(resp_static);
    let resp_public = PublicKey::from(&resp_secret).to_bytes();
    let mut buffer = [0u8; 1024];
    let mut payload = [0u8; 1024];

    // Ours initiating, snow responding.
    let mut snow_resp = snow::Builder::new(params.clone())
        .local_private_key(&resp_static)
        .unwrap()
        .prologue(prologue)
        .unwrap()
        .psk(2, &psk)
        .unwrap()
        .build_responder()
        .unwrap();
    let (awaiting, len) = write_initiation(
        &init_secret,
        &resp_public,
        StaticSecret::from(our_ephemeral),
        prologue,
        b"hello",
        &mut buffer,
    )
    .unwrap();
    let n = snow_resp
        .read_message(&buffer[..len], &mut payload)
        .unwrap();
    assert_eq!(&payload[..n], b"hello");
    let len = snow_resp.write_message(b"hi", &mut buffer).unwrap();
    let (mut ours, n) = read_response(&awaiting, &init_secret, &psk, &mut buffer[..len]).unwrap();
    assert_eq!(&buffer[DHLEN..DHLEN + n], b"hi");
    let mut snow_resp = snow_resp.into_transport_mode().unwrap();
    let sealed = seal(&mut ours.transport.send, b"to snow");
    let n = snow_resp.read_message(&sealed, &mut payload).unwrap();
    assert_eq!(&payload[..n], b"to snow");
    let len = snow_resp.write_message(b"to us", &mut buffer).unwrap();
    assert_eq!(open(&mut ours.transport.recv, &buffer[..len]), b"to us");

    // Snow initiating, ours responding.
    let mut snow_init = snow::Builder::new(params)
        .local_private_key(&init_static)
        .unwrap()
        .remote_public_key(&resp_public)
        .unwrap()
        .prologue(prologue)
        .unwrap()
        .psk(2, &psk)
        .unwrap()
        .build_initiator()
        .unwrap();
    let len = snow_init.write_message(b"hello", &mut buffer).unwrap();
    let mut received = buffer[..len].to_vec();
    let (re, es) = initiation_es(&resp_secret, &received).unwrap();
    let (read, n) = read_initiation(&resp_secret, prologue, &re, &es, &mut received).unwrap();
    assert_eq!(
        &received[2 * DHLEN + TAGLEN..2 * DHLEN + TAGLEN + n],
        b"hello"
    );
    assert_eq!(
        read.remote_static(),
        PublicKey::from(&init_secret).as_bytes()
    );
    let mut out = [0u8; 128];
    let (mut ours, len) = write_response(
        read,
        &StaticSecret::from(our_ephemeral),
        &psk,
        b"hi",
        &mut out,
    )
    .unwrap();
    let n = snow_init.read_message(&out[..len], &mut payload).unwrap();
    assert_eq!(&payload[..n], b"hi");
    assert_eq!(snow_init.get_handshake_hash(), ours.handshake_hash);
    let mut snow_init = snow_init.into_transport_mode().unwrap();
    let len = snow_init.write_message(b"to us", &mut buffer).unwrap();
    assert_eq!(open(&mut ours.transport.recv, &buffer[..len]), b"to us");
    let sealed = seal(&mut ours.transport.send, b"to snow");
    let n = snow_init.read_message(&sealed, &mut payload).unwrap();
    assert_eq!(&payload[..n], b"to snow");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn interoperates_with_snow_both_ways(
        keys in any::<[[u8; 32]; 3]>(),
        prologue in prop::collection::vec(any::<u8>(), 0..64),
        psk in any::<[u8; 32]>(),
    ) {
        interoperates_with_snow(keys[0], keys[1], keys[2], &prologue, psk);
    }
}
