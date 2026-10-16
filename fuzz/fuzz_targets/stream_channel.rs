//! A channel on the `Mcu` configuration never panics on any sequence of
//! frames, sends, times, refusals, grants of credit and resets asked by the
//! reader, never holds more than
//! its configuration's buffers, and with delivery credit on never hands out a
//! message its credit does not cover (`PROTOCOL.md §8`).
//!
//! Two contexts: `ctx`, with the configuration's limits, and `two`, given a
//! largest message and a credit mode of its own; no message longer than its
//! context's largest is handed out. The input's first byte turns credit on or
//! off in each, the next two give `two`'s largest message; the rest is a list
//! of operations, each on the context its high bit names. Frames are built
//! from fuzzed fields, so that most of them decode, or taken raw.

#![no_main]

use convesso_core::endpoint::FrameKind;
use convesso_core::handshake::{Context, DialError, Entropy};
use convesso_core::identity::{Address, PeerId};
use convesso_core::time::Instant;
use convesso_stream::config::Mcu;
use convesso_stream::frame::{Ack, Data, MAX_DATA_LEN, Range};
use convesso_stream::{Channels, ELEMENT_COST, Event, Poll};
use libfuzzer_sys::fuzz_target;

/// The receive buffer and the send buffer of an `Mcu` channel.
const BOUND: usize = 2048 + 2048;

struct Counter(u64);
impl Entropy for Counter {
    fn fill(&mut self, dest: &mut [u8]) {
        for byte in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *byte = (self.0 >> 33) as u8;
        }
    }
}

struct Input<'a>(&'a [u8]);
impl Input<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes([self.byte()?, self.byte()?]))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from(self.u16()?) | (u32::from(self.u16()?) << 16))
    }
    fn take(&mut self, n: usize) -> &[u8] {
        let n = n.min(self.0.len());
        let (taken, rest) = self.0.split_at(n);
        self.0 = rest;
        taken
    }
}

/// The peer: the first key of the core's identity vectors (RFC 8032, 7.1).
fn peer() -> PeerId {
    let bytes: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    Address::parse(bytes).expect("a vector's address").peer_id()
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let modes = input.byte().unwrap_or(0);
    let credit = modes & 1 != 0;
    let credit_two = modes & 2 != 0;
    let max_two = usize::from(input.u16().unwrap_or(0)) % 2049;
    let mut channels: Channels<Mcu> = if credit {
        Channels::with_credit()
    } else {
        Channels::new()
    };
    let max_two = if max_two == 0 { None } else { Some(max_two) };
    channels
        .set_context(b"two", max_two, credit_two)
        .expect("within the configuration");
    let names: [&[u8]; 2] = [b"ctx", b"two"];
    let contexts = names.map(|name| Context::new(name).expect("short"));
    // Each context's credit mode and largest message.
    let limits = |c: &Context| {
        if *c == contexts[1] {
            (credit_two, max_two.unwrap_or(2048))
        } else {
            (credit, 2048)
        }
    };
    let mut entropy = Counter(1);
    let peer = peer();
    let incarnations = [[1u8; 8], [2u8; 8], [3u8; 8]];
    let mut now = 0u64;
    let mut out = [0u8; MAX_DATA_LEN];
    let mut frame = [0u8; MAX_DATA_LEN];
    while let Some(op) = input.byte() {
        let t = Instant::from_millis(now);
        let (name, context) = (names[usize::from(op >> 7)], contexts[usize::from(op >> 7)]);
        match op % 14 {
            0 => {
                let len = usize::from(input.u16().unwrap_or(0)) % 3000;
                let message = vec![op; len];
                let _ = channels.send_message(peer, None, name, &message, t, &mut entropy);
            }
            1 => {
                let incarnation = incarnations[usize::from(input.byte().unwrap_or(0)) % 3];
                let sequence = u32::from(input.u16().unwrap_or(0) % 64);
                let flags = input.byte().unwrap_or(0);
                let length = (flags & 1 != 0).then(|| u32::from(input.u16().unwrap_or(1)).max(1));
                let len = usize::from(input.u16().unwrap_or(1)) % 1400;
                let bytes = vec![flags; len];
                let data = Data {
                    incarnation,
                    sequence,
                    length,
                    last: flags & 2 != 0,
                    start: flags & 4 != 0,
                    bytes: &bytes,
                };
                if let Ok(n) = data.encode(&mut frame) {
                    channels.handle_frame(peer, context, FrameKind::Data, &frame[..n], t);
                }
            }
            2 => {
                let incarnation = if input.byte().unwrap_or(0) % 2 == 0 {
                    incarnations[0]
                } else {
                    // The channel's own, learned from what it sent last.
                    Data::decode(&out).map(|d| d.incarnation).unwrap_or([0; 8])
                };
                let reset = input.byte().unwrap_or(0) % 16 == 0;
                let cumulative = u32::from(input.u16().unwrap_or(0) % 64);
                let window = input.u32().unwrap_or(0);
                let max = input.u32().unwrap_or(0);
                let mut ack = Ack::new(incarnation, reset, cumulative, window, max);
                for _ in 0..usize::from(input.byte().unwrap_or(0) % 5) {
                    let start = cumulative.wrapping_add(u32::from(input.byte().unwrap_or(1)));
                    let end = start.wrapping_add(u32::from(input.byte().unwrap_or(1)));
                    ack.push_range(Range { start, end });
                }
                if let Ok(n) = ack.encode(&mut frame) {
                    channels.handle_frame(peer, context, FrameKind::Ack, &frame[..n], t);
                }
            }
            3 => now += u64::from(input.u16().unwrap_or(0)),
            4 | 5 | 13 => {
                // Deliver in every context, in none, or in `ctx` alone.
                let deliver = |c: &Context| match op % 14 {
                    4 => true,
                    5 => false,
                    _ => *c == contexts[0],
                };
                for _ in 0..64 {
                    let before = contexts.map(|c| channels.inspect(peer, c).and_then(|s| s.credit));
                    match channels.poll_with(t, deliver, &mut out) {
                        Poll::SendFrame { len, .. } => assert!(len <= MAX_DATA_LEN),
                        Poll::Event(Event::Message { data, context, .. }) => {
                            assert!(deliver(&context), "delivered where it may not be");
                            let (credit, max) = limits(&context);
                            assert!(data.len() <= max, "longer than its context takes");
                            let before = before[usize::from(context == contexts[1])];
                            assert_eq!(before.is_some(), credit);
                            if let Some(before) = before {
                                assert!(before >= data.len() + ELEMENT_COST, "beyond the credit");
                            }
                        }
                        Poll::Wait(at) => {
                            assert!(at.as_millis() >= now, "a deadline in the past");
                            break;
                        }
                        Poll::Idle => break,
                        _ => {}
                    }
                }
            }
            6 => channels.frame_refused(t),
            7 => channels.session_closed(peer, context, 1),
            8 => channels.reopen_failed(peer, context, DialError::NoResponse),
            9 => {
                let n = usize::from(input.u16().unwrap_or(0)) % 1400;
                let raw = input.take(n).to_vec();
                channels.handle_frame(peer, context, FrameKind::Data, &raw, t);
            }
            10 => {
                let bytes = input.u32().unwrap_or(0) as usize;
                let _ = channels.grant(peer, name, bytes);
            }
            11 => channels.reset_here(peer, context, t),
            _ => {
                let n = usize::from(input.byte().unwrap_or(0)) % 64;
                let raw = input.take(n).to_vec();
                channels.handle_frame(peer, context, FrameKind::Ack, &raw, t);
            }
        }
        for context in contexts {
            if let Some(held) = channels.memory(peer, context) {
                assert!(held <= BOUND, "{held} bytes held");
            }
        }
    }
});
