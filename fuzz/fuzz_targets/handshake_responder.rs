//! A responder fed arbitrary packets never panics, never answers with more than
//! its largest answer, and never asks admission for a packet it could not
//! decrypt.
//!
//! Random bytes almost never carry a valid mac1, so the harness appends the
//! correct mac1 to most inputs: that is what lets the fuzzer reach the checks
//! behind it. A quarter of the inputs go to a responder that is always under
//! load (a configuration with no burst); for half of those, the harness first
//! obtains the cookie for its source from a cookie reply and recomputes mac2,
//! so that the fuzzer also reaches the Diffie-Hellman path under load.

#![no_main]

use convesso_core::dos::{self, Source};
use convesso_core::handshake::{
    Admission, Decision, Entropy, MAX_RESPONDER_OUTPUT, Responder, ResponderOutput,
};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::storage::{Config, FixedTable, Mcu};
use convesso_core::time::Instant;
use convesso_core::wire::{self, Mac1Key};
use libfuzzer_sys::fuzz_target;

const SCALAR: [u8; 32] = hex32("357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f");
const ADDRESS: [u8; 32] = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const SOURCE: Source<'static> = Source::Direct(&[192, 0, 2, 1, 0xCA, 0x6C]);

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

/// The microcontroller configuration, except that it is always under load.
struct UnderLoad;

impl Config for UnderLoad {
    type Sessions<K: Ord, V> = FixedTable<K, V, 4>;
    type Peers<K: Ord, V> = FixedTable<K, V, 16>;
    type Pending<K: Ord, V> = FixedTable<K, V, 4>;
    type RecentEphemerals<K: Ord, V> = FixedTable<K, V, 8>;
    type SourceRates<K: Ord, V> = FixedTable<K, V, 8>;
    type ReplayWindow = convesso_core::transport::Window<5>;
    type Queue = convesso_core::session::FixedQueue<1024>;
    type Dials<K: Ord, V> = FixedTable<K, V, 2>;
    type Indices<K: Ord, V> = FixedTable<K, V, 12>;
    type Hints<K: Ord, V> = FixedTable<K, V, 4>;
    type Excluded<K: Ord, V> = FixedTable<K, V, 4>;
    const LOAD_RATE_PER_SECOND: u32 = 0;
    const LOAD_BURST: u32 = 0;
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

fn identity() -> Identity {
    Identity::from_parts(SCALAR, Address::parse(ADDRESS).expect("a valid address"))
        .expect("a matching scalar")
}

fn run<C: Config>(
    responder: &mut Responder<C>,
    packet: &[u8],
    entropy: &mut Counter,
) -> Option<Vec<u8>> {
    let mut admission = Count(0);
    let mut out = [0u8; 256];
    let result = match responder.handle(
        packet,
        SOURCE,
        Instant::from_millis(0),
        &mut admission,
        entropy,
        &mut out,
    ) {
        ResponderOutput::Silent => None,
        ResponderOutput::Send(len) => {
            assert!(len <= MAX_RESPONDER_OUTPUT);
            Some(out[..len].to_vec())
        }
        ResponderOutput::Payload { .. } => panic!("no context here accepts a payload"),
    };
    assert!(admission.0 <= 1);
    result
}

fuzz_target!(|data: &[u8]| {
    let mode = data.first().copied().unwrap_or(0);
    let mut packet = data.to_vec();
    if mode & 1 == 1 && packet.len() >= 33 {
        let at = packet.len() - 32;
        let mac1 = Mac1Key::for_address(&ADDRESS).compute(&packet[..at]);
        packet[at..at + 16].copy_from_slice(&mac1);
    }
    let mut entropy = Counter(1);
    if mode & 6 != 6 {
        let mut responder: Responder<Mcu> =
            Responder::new(identity(), &[b"session"]).expect("a context");
        let _ = run(&mut responder, &packet, &mut entropy);
        return;
    }
    let mut responder: Responder<UnderLoad> =
        Responder::new(identity(), &[b"session"]).expect("a context");
    let answer = run(&mut responder, &packet, &mut entropy);
    // Under load, take the cookie the responder gave and present it, if any.
    if let (Some(reply), Some(mac1)) = (answer, wire::carried_mac1(&packet)) {
        if let Ok(reply) = dos::parse_cookie_reply(&reply) {
            if let Some(cookie) = dos::open_cookie_reply(&reply, &ADDRESS, &mac1) {
                let at = packet.len() - 16;
                let mac2 = dos::mac2(&cookie, &packet[..at]);
                packet[at..].copy_from_slice(&mac2);
                let _ = run(&mut responder, &packet, &mut entropy);
            }
        }
    }
});
