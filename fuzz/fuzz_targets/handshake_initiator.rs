//! A dial with an attempt in progress, fed arbitrary packets, never panics, and
//! never completes on bytes it did not get from the responder.

#![no_main]

use convesso_core::handshake::{Dial, DialEvent, Entropy};
use convesso_core::identity::{Address, Identity};
use convesso_core::time::Instant;
use libfuzzer_sys::fuzz_target;

const SCALAR: [u8; 32] = hex32("6ebd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e11");
const ADDRESS: [u8; 32] = hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
const REMOTE: [u8; 32] = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

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

fuzz_target!(|data: &[u8]| {
    let identity = Identity::from_parts(SCALAR, Address::parse(ADDRESS).expect("valid"))
        .expect("a matching scalar");
    let remote = Address::parse(REMOTE).expect("valid");
    let mut out = [0u8; 256];
    let (mut dial, first) = Dial::start(
        &identity,
        &remote,
        b"session",
        None,
        Instant::from_millis(0),
        &mut Counter(7),
        &mut out,
    )
    .expect("a dial");
    // Graft the attempt's index into the fuzzed bytes half the time, so that
    // the fuzzer reaches the Noise layer behind the index lookup.
    let mut packet = data.to_vec();
    if packet.len() == 61 && packet[0] == 0x01 && packet[1] == 0x02 && packet[2] & 1 == 1 {
        packet[6..10].copy_from_slice(&out[2..6]);
    }
    // The same for cookie replies, whose index is at bytes 2..6.
    if packet.len() == 62 && packet[0] == 0x01 && packet[1] == 0x03 && packet[6] & 1 == 1 {
        packet[2..6].copy_from_slice(&out[2..6]);
    }
    let _ = first;
    match dial.handle(&identity, &packet, Instant::from_millis(1)) {
        DialEvent::Established(_) => panic!("completed on fuzzed bytes"),
        DialEvent::Ignored | DialEvent::Failed(_) => {}
    }
});
