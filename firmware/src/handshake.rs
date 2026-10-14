//! One complete version 1 handshake, in memory, shared by the reference and
//! the vectors firmware.

use core::hint::black_box;

use convesso_core::dos::Source;
use convesso_core::handshake::{
    Admission, Decision, Dial, DialEvent, Entropy, Responder, ResponderOutput,
};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::storage::Mcu;
use convesso_core::time::Instant;

/// RFC 8032 §7.1 TEST 1 and TEST 2: X25519 scalar and Ed25519 address.
const RESPONDER_SCALAR: [u8; 32] =
    hex32("357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f");
const RESPONDER_ADDRESS: [u8; 32] =
    hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const INITIATOR_SCALAR: [u8; 32] =
    hex32("6ebd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e11");
const INITIATOR_ADDRESS: [u8; 32] =
    hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

pub(crate) const fn hex32(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
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

/// Not a source of randomness: a fixed sequence, so the firmware is
/// deterministic. A real driver uses the hardware generator.
pub(crate) struct Sequence(pub(crate) u64);

impl Entropy for Sequence {
    fn fill(&mut self, dest: &mut [u8]) {
        for byte in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (self.0 >> 56) as u8;
        }
    }
}

pub(crate) struct AcceptAll;

impl Admission for AcceptAll {
    fn admit(&mut self, _peer: &PeerId, _context: &[u8]) -> Decision {
        Decision::Accept { psk: None }
    }
}

/// Runs a dial against a responder, both on this device. Returns whether the
/// handshake completed with equal channel bindings on both sides.
pub fn run() -> bool {
    let (Ok(responder_address), Ok(initiator_address)) = (
        Address::parse(black_box(RESPONDER_ADDRESS)),
        Address::parse(black_box(INITIATOR_ADDRESS)),
    ) else {
        return false;
    };
    let (Ok(responder_identity), Ok(initiator)) = (
        Identity::from_parts(black_box(RESPONDER_SCALAR), responder_address),
        Identity::from_parts(black_box(INITIATOR_SCALAR), initiator_address),
    ) else {
        return false;
    };
    let Ok(mut responder) = Responder::<Mcu>::new(responder_identity, &[b"session"]) else {
        return false;
    };
    let mut entropy = Sequence(black_box(1));
    let now = Instant::from_millis(black_box(0));

    let mut first = [0u8; 160];
    let Ok((mut dial, len)) = Dial::start(
        &initiator,
        &responder_address,
        b"session",
        None,
        now,
        &mut entropy,
        &mut first,
    ) else {
        return false;
    };
    let mut response = [0u8; 64];
    let ResponderOutput::Send(response_len) = responder.handle(
        black_box(&first[..len]),
        Source::Direct(black_box(&[192, 0, 2, 1, 0xCA, 0x6C])),
        now,
        &mut AcceptAll,
        &mut entropy,
        &mut response,
    ) else {
        return false;
    };
    let DialEvent::Established(established) =
        dial.handle(&initiator, black_box(&response[..response_len]), now)
    else {
        return false;
    };
    responder
        .pending(established.remote_index())
        .is_some_and(|pending| pending.channel_binding() == established.channel_binding())
}

/// Drives a responder past its load bucket: five dials take its burst, the
/// sixth meets a cookie reply, and that dial keeps the cookie. Returns whether
/// all of that happened.
pub fn under_load() -> bool {
    let (Ok(responder_address), Ok(initiator_address)) = (
        Address::parse(black_box(RESPONDER_ADDRESS)),
        Address::parse(black_box(INITIATOR_ADDRESS)),
    ) else {
        return false;
    };
    let (Ok(responder_identity), Ok(initiator)) = (
        Identity::from_parts(black_box(RESPONDER_SCALAR), responder_address),
        Identity::from_parts(black_box(INITIATOR_SCALAR), initiator_address),
    ) else {
        return false;
    };
    let Ok(mut responder) = Responder::<Mcu>::new(responder_identity, &[b"session"]) else {
        return false;
    };
    let mut entropy = Sequence(black_box(2));
    let now = Instant::from_millis(black_box(0));
    let source = Source::Direct(black_box(&[192, 0, 2, 1, 0xCA, 0x6C]));

    for attempt in 0..6 {
        let mut first = [0u8; 160];
        let Ok((mut dial, len)) = Dial::start(
            &initiator,
            &responder_address,
            b"session",
            None,
            now,
            &mut entropy,
            &mut first,
        ) else {
            return false;
        };
        let mut answer = [0u8; 64];
        let ResponderOutput::Send(answer_len) = responder.handle(
            black_box(&first[..len]),
            source,
            now,
            &mut AcceptAll,
            &mut entropy,
            &mut answer,
        ) else {
            return false;
        };
        let expected = if attempt < 5 { 61 } else { 62 };
        if answer_len != expected {
            return false;
        }
        if attempt == 5 {
            let _ = dial.handle(&initiator, black_box(&answer[..answer_len]), now);
            return dial.cookie_at(now).is_some();
        }
    }
    false
}

/// Two endpoints on this device: a handshake through `connect`, a datagram each
/// way, and an authenticated close. Returns whether each step did what the
/// spec says.
pub fn endpoints() -> bool {
    use convesso_core::endpoint::{Endpoint, Event, Output, Poll, Target};

    let (Ok(b_address), Ok(a_address)) = (
        Address::parse(black_box(RESPONDER_ADDRESS)),
        Address::parse(black_box(INITIATOR_ADDRESS)),
    ) else {
        return false;
    };
    let (Ok(b_identity), Ok(a_identity)) = (
        Identity::from_parts(black_box(RESPONDER_SCALAR), b_address),
        Identity::from_parts(black_box(INITIATOR_SCALAR), a_address),
    ) else {
        return false;
    };
    let (Ok(mut a), Ok(mut b)) = (
        Endpoint::<Mcu>::new(a_identity, &[b"session"]),
        Endpoint::<Mcu>::new(b_identity, &[b"session"]),
    ) else {
        return false;
    };
    let (mut ea, mut eb) = (Sequence(black_box(3)), Sequence(black_box(4)));
    let now = Instant::from_millis(black_box(0));
    let a_source = Source::Direct(black_box(&[10, 0, 0, 1, 0, 1]));
    let b_source = Source::Direct(black_box(&[10, 0, 0, 2, 0, 2]));
    // No relay: each is given where the other is.
    if a.set_hint(b_address.peer_id(), &[10, 0, 0, 2, 0, 2], now)
        .is_err()
    {
        return false;
    }
    let mut out = [0u8; 256];
    let mut answer = [0u8; 256];

    // Handshake: first contact, response, confirming keepalive.
    let Ok(Output::Transmit { len, .. }) = a.connect(
        &b_address,
        b"session",
        now,
        &mut AcceptAll,
        &mut ea,
        &mut out,
    ) else {
        return false;
    };
    let mut packet = [0u8; 256];
    packet[..len].copy_from_slice(&out[..len]);
    let Output::Transmit { len, .. } = b.handle_packet(
        &mut packet[..len],
        a_source,
        now,
        &mut AcceptAll,
        &mut eb,
        &mut answer,
    ) else {
        return false;
    };
    packet[..len].copy_from_slice(&answer[..len]);
    if !matches!(
        a.handle_packet(
            &mut packet[..len],
            b_source,
            now,
            &mut AcceptAll,
            &mut ea,
            &mut out
        ),
        Output::Event(Event::Connected { .. })
    ) {
        return false;
    }
    let Poll::Transmit { len, .. } = a.poll(now, &mut AcceptAll, &mut ea, &mut out) else {
        return false;
    };
    packet[..len].copy_from_slice(&out[..len]);
    if !matches!(
        b.handle_packet(
            &mut packet[..len],
            a_source,
            now,
            &mut AcceptAll,
            &mut eb,
            &mut answer
        ),
        Output::Event(Event::Connected { .. })
    ) {
        return false;
    }

    // A datagram from A to B.
    let Ok(Output::Transmit { len, .. }) = a.send(
        Target::Address(&b_address),
        b"session",
        black_box(b"reading"),
        1400,
        now,
        &mut AcceptAll,
        &mut ea,
        &mut out,
    ) else {
        return false;
    };
    packet[..len].copy_from_slice(&out[..len]);
    if !matches!(
        b.handle_packet(
            &mut packet[..len],
            a_source,
            now,
            &mut AcceptAll,
            &mut eb,
            &mut answer
        ),
        Output::Event(Event::Datagram {
            data: b"reading",
            ..
        })
    ) {
        return false;
    }

    // A reply from B, by PeerId.
    let Ok(Output::Transmit { len, .. }) = b.send(
        Target::Peer(a_address.peer_id()),
        b"session",
        black_box(b"ack"),
        1400,
        now,
        &mut AcceptAll,
        &mut eb,
        &mut answer,
    ) else {
        return false;
    };
    packet[..len].copy_from_slice(&answer[..len]);
    if !matches!(
        a.handle_packet(
            &mut packet[..len],
            b_source,
            now,
            &mut AcceptAll,
            &mut ea,
            &mut out
        ),
        Output::Event(Event::Datagram { data: b"ack", .. })
    ) {
        return false;
    }

    // An authenticated close.
    let Output::Transmit { len, .. } =
        a.close(b_address.peer_id(), b"session", 0x0101, now, &mut out)
    else {
        return false;
    };
    packet[..len].copy_from_slice(&out[..len]);
    matches!(
        b.handle_packet(
            &mut packet[..len],
            a_source,
            now,
            &mut AcceptAll,
            &mut eb,
            &mut answer
        ),
        Output::Event(Event::Closed {
            code: 0x0101,
            by_peer: true,
            ..
        })
    )
}
