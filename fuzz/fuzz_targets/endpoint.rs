//! An endpoint with a live session, fed arbitrary packets, never panics.
//!
//! Each run completes a real handshake between two endpoints first. Half the
//! inputs then get the live session's receiver index grafted in, so that the
//! fuzzer reaches decryption and anti-replay rather than stopping at the index
//! lookup. The first four bytes are changes to the contexts B serves (serving,
//! a change of access, closing), two before the packet and two between it and
//! its replay, so that the packet meets every state a context can be in.

#![no_main]

use convesso_core::dos::Source;
use convesso_core::endpoint::{Endpoint, Output, Poll, Settings};
use convesso_core::handshake::{Access, Admission, Decision, Entropy, RefusalCode};
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

/// Refuses everyone, with an application's code.
struct Refuse;
impl Admission for Refuse {
    fn admit(&mut self, _peer: &PeerId, _context: &[u8]) -> Decision {
        Decision::Refuse {
            code: RefusalCode::application(0x0100).expect("an application's code"),
            psk: None,
        }
    }
}

const CONTEXTS: [&[u8]; 3] = [b"session", b"other", b"third"];

/// Applies the change to B's contexts that `op` names; a refusal is fine.
fn change(b: &mut Endpoint<Mcu>, op: u8, a: PeerId) {
    let context = CONTEXTS[usize::from(op / 8) % CONTEXTS.len()];
    let _ = match op % 8 {
        0 => b.serve(context, Access::Policy),
        1 => b.serve(context, Access::Bound(a)),
        2 => b.set_access(context, None, 0x0200, &mut Accept),
        3 => b.set_access(context, Some(Access::Policy), 0x0200, &mut Refuse),
        4 => b.set_access(context, Some(Access::Policy), 0x0200, &mut Accept),
        5 => b.set_access(context, Some(Access::Bound(a)), 0x0200, &mut Accept),
        6 => b.close_context(context, 0x0201),
        _ => b.set_context_settings(
            context,
            Settings {
                early_data: true,
                ..Settings::default()
            },
        ),
    };
    assert!(b.contexts_served() <= 4, "the profile's table holds 4");
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
    a.set_hints(b_address.peer_id(), &[&B_SOURCE], now)
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

    let a_peer = Address::parse(A_ADDRESS).expect("valid").peer_id();
    let (ops, data) = data.split_at(data.len().min(4));
    let op = |i: usize| ops.get(i).copied();

    // The fuzzed packet, with the live session's index grafted in half the time.
    let mut packet = data.to_vec();
    if packet.len() >= 31 && packet[0] == 0x01 && packet[1] == 0x04 && packet[2] & 1 == 1 {
        packet[2..6].copy_from_slice(&keepalive[2..6]);
    }
    for round in 0..2 {
        for i in [2 * round, 2 * round + 1] {
            if let Some(op) = op(i) {
                change(&mut b, op, a_peer);
            }
        }
        let mut copy = packet.clone();
        let _ = b.handle_packet(
            &mut copy,
            Source::Direct(&A_SOURCE),
            now,
            &mut Accept,
            &mut eb,
            &mut answer,
        );
        for _ in 0..8 {
            if !matches!(
                b.poll(now, &mut Accept, &mut eb, &mut answer),
                Poll::Transmit { .. } | Poll::Event(_)
            ) {
                break;
            }
        }
    }
});
