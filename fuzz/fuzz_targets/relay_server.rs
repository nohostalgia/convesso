//! A relay fed arbitrary UDP packets, TCP streams and link events never
//! panics, and its tables stay within bounds.
//!
//! The input is a script of operations. Before it runs, a real client opens a
//! relay session over UDP, so that the script's forwards (packets the client
//! seals for an arbitrary recipient) reach the relay's authenticated paths, not
//! only its decoders.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use convesso_core::endpoint::{Endpoint, Output, Poll};
use convesso_core::handshake::{Admission, Decision, Entropy};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::relay::Link;
use convesso_core::relay::framing::PREAMBLE;
use convesso_core::storage::Mcu;
use convesso_core::time::Instant;
use convesso_relay::{Action, Config, Open, Relay};
use libfuzzer_sys::fuzz_target;

const RELAY_SCALAR: [u8; 32] =
    hex32("357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f");
const RELAY_ADDRESS: [u8; 32] =
    hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const CLIENT_SCALAR: [u8; 32] =
    hex32("6ebd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e11");
const CLIENT_ADDRESS: [u8; 32] =
    hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

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

fn addr(n: u8) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, n % 4, 1)),
        1000 + u16::from(n),
    )
}

const CLIENT_UDP: u8 = 200;

/// Hands the relay's UDP datagrams for the client to it; drops the rest.
fn exchange(
    relay: &mut Relay<Open, Counter>,
    client: &mut Endpoint<Mcu>,
    now: Instant,
    entropy: &mut Counter,
) {
    for _ in 0..8 {
        let mut to_client = Vec::new();
        while let Some(action) = relay.next_action() {
            if let Action::Udp { to, packet } = action
                && to == addr(CLIENT_UDP)
            {
                to_client.push(packet);
            }
        }
        let mut to_relay = Vec::new();
        for mut packet in to_client {
            let mut out = [0u8; 2048];
            if let Output::Transmit { len, .. } = client.handle_relay_packet(
                &mut packet,
                Link::Udp,
                now,
                &mut Accept,
                entropy,
                &mut out,
            ) {
                to_relay.push(out[..len].to_vec());
            }
        }
        loop {
            let mut out = [0u8; 2048];
            match client.poll(now, &mut Accept, entropy, &mut out) {
                Poll::Transmit { len, .. } => to_relay.push(out[..len].to_vec()),
                Poll::Event(_) | Poll::OpenRelayLink | Poll::CloseRelayLink => {}
                Poll::Wait(_) | Poll::Idle => break,
            }
        }
        if to_relay.is_empty() {
            return;
        }
        for packet in to_relay {
            relay.udp(&packet, addr(CLIENT_UDP), now);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut now = Instant::from_millis(0);
    let mut relay = Relay::new(
        identity(RELAY_SCALAR, RELAY_ADDRESS),
        Open,
        Counter(1),
        Config::default(),
        now,
    )
    .expect("a relay");
    let mut client: Endpoint<Mcu> =
        Endpoint::new(identity(CLIENT_SCALAR, CLIENT_ADDRESS), &[b"session"]).expect("context");
    client
        .pin_relay(Address::parse(RELAY_ADDRESS).expect("valid"), now)
        .expect("pinned");
    let mut entropy = Counter(2);

    let mut ops = data;
    let mut opened = 0usize;
    while let [op, arg, rest @ ..] = ops {
        let len = usize::from(*arg).min(rest.len());
        let (bytes, tail) = rest.split_at(len);
        ops = tail;
        match op % 6 {
            0 => relay.udp(bytes, addr(*arg), now),
            1 => {
                opened += 1;
                if relay.link_opened(u64::from(*arg % 8), addr(*arg), now) && arg % 2 == 0 {
                    relay.link_bytes(u64::from(*arg % 8), &PREAMBLE, now);
                }
            }
            2 => relay.link_bytes(u64::from(*arg % 8), bytes, now),
            3 => relay.link_closed(u64::from(*arg % 8)),
            4 => {
                now = now.saturating_add(core::time::Duration::from_millis(u64::from(*arg) * 1000));
                let _ = relay.poll(now);
            }
            _ => {
                // A forward the client seals for the recipient the bytes name.
                let mut recipient = [0u8; 32];
                for (slot, byte) in recipient.iter_mut().zip(bytes) {
                    *slot = *byte;
                }
                let packet = if bytes.is_empty() { &[1u8][..] } else { bytes };
                let mut out = [0u8; 2048];
                out[..packet.len()].copy_from_slice(packet);
                let peer =
                    Address::parse(recipient).map_or(client.identity().peer_id(), |a| a.peer_id());
                if let Ok(Output::Transmit { len, .. }) = client.through_relay(
                    peer,
                    packet.len(),
                    now,
                    &mut Accept,
                    &mut entropy,
                    &mut out,
                ) {
                    relay.udp(&out[..len], addr(CLIENT_UDP), now);
                }
                exchange(&mut relay, &mut client, now, &mut entropy);
            }
        }
        while relay.next_action().is_some() {}
        let (clients, links, ips, notices) = relay.table_sizes();
        assert!(clients <= 4, "{clients} clients");
        assert!(links <= 8 && links <= opened);
        assert!(ips <= 5, "{ips} addresses");
        assert!(notices <= 64, "{notices} notices");
    }
});
