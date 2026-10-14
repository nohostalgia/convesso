//! A client with a live relay session, fed arbitrary frames inside valid relay
//! datagrams (and arbitrary packets on the relay's links), never panics.
//!
//! Each run opens a real relay session first: the client wakes the relay with
//! a forward, the relay (a core endpoint serving the relay context) answers,
//! and the client confirms. Then the relay seals the fuzzed bytes as a datagram
//! of that session, which is how a relay frame reaches a client; half the time
//! the bytes start with the deliver header, so that the fuzzer reaches the
//! packet a deliver carries.

#![no_main]

use convesso_core::dos::Source;
use convesso_core::endpoint::{Endpoint, Event, Output, Poll, Target, To};
use convesso_core::handshake::{Admission, Decision, Entropy};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::relay::{self, Link};
use convesso_core::storage::Mcu;
use convesso_core::time::Instant;
use libfuzzer_sys::fuzz_target;

const RELAY_SCALAR: [u8; 32] =
    hex32("357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f");
const RELAY_ADDRESS: [u8; 32] =
    hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const CLIENT_SCALAR: [u8; 32] =
    hex32("6ebd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e11");
const CLIENT_ADDRESS: [u8; 32] =
    hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
const CLIENT_SOURCE: [u8; 6] = [10, 0, 0, 1, 0, 1];

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

fn identity(scalar: [u8; 32], address: [u8; 32]) -> Identity {
    Identity::from_parts(scalar, Address::parse(address).expect("valid")).expect("matching")
}

/// Drains `endpoint`, returning the packets it sends.
fn drain(endpoint: &mut Endpoint<Mcu>, now: Instant, entropy: &mut Counter) -> Vec<Vec<u8>> {
    let mut sent = Vec::new();
    for _ in 0..16 {
        let mut out = [0u8; 2048];
        match endpoint.poll(now, &mut Accept, entropy, &mut out) {
            Poll::Transmit { to, len } if !matches!(to, To::RelayKeepAlive) => {
                sent.push(out[..len].to_vec());
            }
            Poll::Transmit { .. } | Poll::Event(_) | Poll::OpenRelayLink | Poll::CloseRelayLink => {
            }
            Poll::Wait(_) | Poll::Idle => break,
        }
    }
    sent
}

fuzz_target!(|data: &[u8]| {
    let now = Instant::from_millis(0);
    let relay_address = Address::parse(RELAY_ADDRESS).expect("valid");
    let mut relay: Endpoint<Mcu> =
        Endpoint::new(identity(RELAY_SCALAR, RELAY_ADDRESS), &[relay::CONTEXT]).expect("context");
    relay.accept_payload(relay::CONTEXT).expect("served");
    let mut client: Endpoint<Mcu> =
        Endpoint::new(identity(CLIENT_SCALAR, CLIENT_ADDRESS), &[b"session"]).expect("context");
    client.pin_relay(relay_address, now).expect("pinned");
    let (mut re, mut ce) = (Counter(1), Counter(2));

    // The wake: a forward of a dummy packet to some peer.
    let mut out = [0u8; 2048];
    out[..40].fill(0x01);
    let Ok(Output::Transmit { len, .. }) = client.through_relay(
        relay_address.peer_id(),
        40,
        now,
        &mut Accept,
        &mut ce,
        &mut out,
    ) else {
        return;
    };
    let mut wake = out[..len].to_vec();
    let client_peer = client.identity().peer_id();
    let _ = relay.handle_packet(
        &mut wake,
        Source::Direct(&CLIENT_SOURCE),
        now,
        &mut Accept,
        &mut re,
        &mut out,
    );
    for mut packet in drain(&mut relay, now, &mut re) {
        let _ =
            client.handle_relay_packet(&mut packet, Link::Udp, now, &mut Accept, &mut ce, &mut out);
    }
    for mut packet in drain(&mut client, now, &mut ce) {
        let _ = relay.handle_packet(
            &mut packet,
            Source::Direct(&CLIENT_SOURCE),
            now,
            &mut Accept,
            &mut re,
            &mut out,
        );
    }
    let _ = drain(&mut relay, now, &mut re);

    // The fuzzed frame, sealed by the relay in the client's session.
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let mut frame = Vec::new();
    if mode & 1 == 1 {
        frame.extend_from_slice(&[relay::frame_type::DELIVER, relay::KIND_PEER_ID]);
        frame.extend_from_slice(&[7u8; 32]);
    }
    frame.extend_from_slice(rest);
    let link = if mode & 2 == 2 { Link::Tcp } else { Link::Udp };
    if let Ok(Output::Transmit { len, .. }) = relay.send(
        Target::Peer(client_peer),
        relay::CONTEXT,
        &frame,
        2048,
        now,
        &mut Accept,
        &mut re,
        &mut out,
    ) {
        let mut packet = out[..len].to_vec();
        let mut answer = [0u8; 2048];
        // A frame can carry a packet that becomes a datagram of another
        // session; never one of the relay session.
        if let Output::Event(Event::Datagram { peer, .. }) =
            client.handle_relay_packet(&mut packet, link, now, &mut Accept, &mut ce, &mut answer)
        {
            assert_ne!(peer, relay_address.peer_id());
        }
        let _ = drain(&mut client, now, &mut ce);
    }
    // And the bytes as they are, on either link.
    let mut raw = rest.to_vec();
    let _ = client.handle_relay_packet(&mut raw, link, now, &mut Accept, &mut ce, &mut out);
    let _ = drain(&mut client, now, &mut ce);
});
