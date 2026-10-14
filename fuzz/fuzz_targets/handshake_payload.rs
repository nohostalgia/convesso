//! First contacts with a payload (type `0x05`) never make a responder panic,
//! answer with more than a response, hand over more than the payload limit, or
//! ask admission more than once; and a genuine one hands over exactly its
//! payload.
//!
//! The first input byte picks the mode. Even: the rest is a payload, dialled
//! for real, which the responder must hand back unchanged. Odd: the rest is a
//! packet, relabelled as a first contact with a payload half the time, with a
//! correct mac1 grafted in, so that the fuzzer reaches decryption.

#![no_main]

use convesso_core::dos::Source;
use convesso_core::handshake::messages;
use convesso_core::handshake::{
    Admission, Decision, Dial, Entropy, MAX_FIRST_CONTACT_LEN, MAX_PAYLOAD, RESPONSE_LEN,
    Responder, ResponderOutput,
};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::storage::Mcu;
use convesso_core::time::Instant;
use convesso_core::wire::Mac1Key;
use libfuzzer_sys::fuzz_target;

const SCALAR: [u8; 32] = hex32("357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f");
const ADDRESS: [u8; 32] = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const A_SCALAR: [u8; 32] =
    hex32("6ebd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e11");
const A_ADDRESS: [u8; 32] =
    hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
const SOURCE: Source<'static> = Source::Direct(&[192, 0, 2, 1, 0xCA, 0x6C]);
const RELAY: &[u8] = b"convesso-relay";

const fn hex32(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(bytes[2 * i]) << 4 | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

struct Counter(u64);
impl Entropy for Counter {
    fn fill(&mut self, dest: &mut [u8]) {
        for byte in dest {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (self.0 >> 56) as u8;
        }
    }
}

struct Count(usize);
impl Admission for Count {
    fn admit(&mut self, _peer: &PeerId, _context: &[u8]) -> Decision {
        self.0 += 1;
        Decision::Accept { psk: None }
    }
}

fn identity(scalar: [u8; 32], address: [u8; 32]) -> Identity {
    Identity::from_parts(scalar, Address::parse(address).expect("valid")).expect("matching")
}

/// Hands `packet` to a responder accepting payloads in the relay context;
/// returns the payload it handed over, if any.
fn run(packet: &[u8]) -> Option<Vec<u8>> {
    let mut responder: Responder<Mcu> =
        Responder::new(identity(SCALAR, ADDRESS), &[b"session", RELAY]).expect("contexts");
    responder.accept_payload(RELAY).expect("served");
    let mut admission = Count(0);
    let mut out = vec![0u8; RESPONSE_LEN + MAX_PAYLOAD];
    let result = match responder.handle(
        packet,
        SOURCE,
        Instant::from_millis(0),
        &mut admission,
        &mut Counter(7),
        &mut out,
    ) {
        ResponderOutput::Silent => None,
        ResponderOutput::Send(len) => {
            assert!(len <= 62);
            None
        }
        ResponderOutput::Payload { len, payload, .. } => {
            assert_eq!(len, RESPONSE_LEN);
            assert!((1..=MAX_PAYLOAD).contains(&payload));
            Some(out[len..len + payload].to_vec())
        }
    };
    assert!(admission.0 <= 1);
    result
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let _ = messages::parse_payload_first_contact(rest);
    if mode & 1 == 0 {
        let payload = &rest[..rest.len().min(MAX_PAYLOAD)];
        let mut out = vec![0u8; MAX_FIRST_CONTACT_LEN];
        let Ok((_, len)) = Dial::start_with_payload(
            &identity(A_SCALAR, A_ADDRESS),
            &Address::parse(ADDRESS).expect("valid"),
            RELAY,
            None,
            payload,
            Instant::from_millis(0),
            &mut Counter(u64::from(mode)),
            &mut out,
        ) else {
            panic!("a payload within the limit is always dialled");
        };
        let handed = run(&out[..len]);
        if payload.is_empty() {
            assert_eq!(handed, None);
        } else {
            assert_eq!(handed.as_deref(), Some(payload));
        }
        return;
    }
    let mut packet = rest.to_vec();
    if mode & 2 == 2 && packet.len() >= 2 {
        packet[0] = 0x01;
        packet[1] = 0x05;
    }
    if mode & 4 == 4 && packet.len() >= 33 {
        let at = packet.len() - 32;
        let mac1 = Mac1Key::for_address(&ADDRESS).compute(&packet[..at]);
        packet[at..at + 16].copy_from_slice(&mac1);
    }
    let _ = run(&packet);
});
