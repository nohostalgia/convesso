//! An endpoint with a live session, fed arbitrary packets, never panics.
//!
//! Each run completes a real handshake between two endpoints first. Half the
//! inputs then get the live session's receiver index grafted in, so that the
//! fuzzer reaches decryption and anti-replay rather than stopping at the index
//! lookup.

#![no_main]

use convesso_core::dos::Source;
use convesso_core::endpoint::{Endpoint, Output, Poll};
use convesso_core::handshake::{Admission, Decision, Entropy};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::storage::Mcu;
use convesso_core::time::Instant;
use libfuzzer_sys::fuzz_target;

const B_SCALAR: [u8; 32] =
    hex32("357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f");
const B_ADDRESS: [u8; 32] =
    hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const A_SCALAR: [u8; 32] =
    hex32("6ebd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e11");
const A_ADDRESS: [u8; 32] =
    hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
const A_SOURCE: [u8; 6] = [10, 0, 0, 1, 0, 1];
const B_SOURCE: [u8; 6] = [10, 0, 0, 2, 0, 2];

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

struct Accept;
impl Admission for Accept {
    fn admit(&mut self, _peer: &PeerId, _context: &[u8]) -> Decision {
        Decision::Accept { psk: None }
    }
}

fn endpoint(scalar: [u8; 32], address: [u8; 32]) -> Endpoint<Mcu> {
    let identity =
        Identity::from_parts(scalar, Address::parse(address).expect("valid")).expect("matching");
    Endpoint::new(identity, &[b"session"]).expect("a context")
}

fuzz_target!(|data: &[u8]| {
    let now = Instant::from_millis(0);
    let mut a = endpoint(A_SCALAR, A_ADDRESS);
    let mut b = endpoint(B_SCALAR, B_ADDRESS);
    let (mut ea, mut eb) = (Counter(1), Counter(2));
    let b_address = Address::parse(B_ADDRESS).expect("valid");
    a.set_hint(b_address.peer_id(), &B_SOURCE, now)
        .expect("a direct source");

    // A connects; B answers; A confirms with a keepalive.
    let mut out = [0u8; 256];
    let Ok(Output::Transmit { len, .. }) =
        a.connect(&b_address, b"session", now, &mut Accept, &mut ea, &mut out)
    else {
        return;
    };
    let mut first = out[..len].to_vec();
    let mut answer = [0u8; 256];
    let Output::Transmit { len, .. } = b.handle_packet(
        &mut first,
        Source::Direct(&A_SOURCE),
        now,
        &mut Accept,
        &mut eb,
        &mut answer,
    ) else {
        return;
    };
    let mut response = answer[..len].to_vec();
    let _ = a.handle_packet(
        &mut response,
        Source::Direct(&B_SOURCE),
        now,
        &mut Accept,
        &mut ea,
        &mut out,
    );
    let Poll::Transmit { len, .. } = a.poll(now, &mut Accept, &mut ea, &mut out) else {
        return;
    };
    let keepalive = out[..len].to_vec();
    let mut confirm = keepalive.clone();
    let _ = b.handle_packet(
        &mut confirm,
        Source::Direct(&A_SOURCE),
        now,
        &mut Accept,
        &mut eb,
        &mut answer,
    );

    // The fuzzed packet, with the live session's index grafted in half the time.
    let mut packet = data.to_vec();
    if packet.len() >= 31 && packet[0] == 0x01 && packet[1] == 0x04 && packet[2] & 1 == 1 {
        packet[2..6].copy_from_slice(&keepalive[2..6]);
    }
    let _ = b.handle_packet(
        &mut packet,
        Source::Direct(&A_SOURCE),
        now,
        &mut Accept,
        &mut eb,
        &mut answer,
    );
    let _ = b.poll(now, &mut Accept, &mut eb, &mut answer);
});
