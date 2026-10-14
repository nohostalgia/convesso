//! Two channels on a virtual clock, joined by a link that can lose, delay,
//! reorder and duplicate frames.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

extern crate std;

use std::vec;
use std::vec::Vec;

use convesso_core::endpoint::FrameKind;
use convesso_core::handshake::{Context, DialError, Entropy};
use convesso_core::identity::{Address, PeerId};
use convesso_core::storage::Table;
use convesso_core::time::Instant;
use serde_json::Value;

use crate::config::{Mcu, StreamConfig};
use crate::frame::{self, Ack, Data, MAX_DATA_LEN};
use crate::{Channels, Event, Poll, Reason, SendError};

pub(crate) fn address(i: usize) -> Address {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../convesso-core/vectors/identity.json")).unwrap();
    let text = vectors["keys"][i]["address"].as_str().unwrap();
    let bytes: Vec<u8> = (0..32)
        .map(|j| u8::from_str_radix(&text[2 * j..2 * j + 2], 16).unwrap())
        .collect();
    Address::parse(bytes.try_into().unwrap()).unwrap()
}

pub(crate) fn ctx() -> Context {
    Context::new(b"ctx").unwrap()
}

pub(crate) struct Counter(pub(crate) u64);
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Got {
    Message(Vec<u8>),
    Writable,
    Reset(Reason),
}

pub(crate) struct Side<C: StreamConfig> {
    pub(crate) channels: Channels<C>,
    pub(crate) peer: PeerId,
    pub(crate) entropy: Counter,
    pub(crate) got: Vec<Got>,
    pub(crate) deliver: bool,
    /// Every frame this side sent, with when.
    pub(crate) sent: Vec<(u64, FrameKind, Vec<u8>)>,
    pub(crate) dials: usize,
}

impl<C: StreamConfig> Side<C> {
    fn new(i: usize, seed: u64) -> Self {
        Self {
            channels: Channels::new(),
            peer: address(i).peer_id(),
            entropy: Counter(seed),
            got: Vec::new(),
            deliver: true,
            sent: Vec::new(),
            dials: 0,
        }
    }

    pub(crate) fn messages(&self) -> Vec<Vec<u8>> {
        self.got
            .iter()
            .filter_map(|g| match g {
                Got::Message(m) => Some(m.clone()),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn resets(&self) -> Vec<Reason> {
        self.got
            .iter()
            .filter_map(|g| match g {
                Got::Reset(r) => Some(*r),
                _ => None,
            })
            .collect()
    }
}

struct InFlight {
    at: u64,
    to_b: bool,
    kind: FrameKind,
    bytes: Vec<u8>,
}

pub(crate) struct Pair<A: StreamConfig, B: StreamConfig> {
    pub(crate) a: Side<A>,
    pub(crate) b: Side<B>,
    pub(crate) now: u64,
    wire: Vec<InFlight>,
    pub(crate) delay: u64,
    rng: u64,
    pub(crate) loss: u64,
    pub(crate) duplicate: u64,
    pub(crate) jitter: u64,
    pub(crate) cut_to_a: bool,
    pub(crate) cut_to_b: bool,
}

impl<A: StreamConfig, B: StreamConfig> Pair<A, B> {
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            a: Side::new(0, seed),
            b: Side::new(1, seed + 1),
            now: 1000,
            wire: Vec::new(),
            delay: 20,
            rng: seed | 1,
            loss: 0,
            duplicate: 0,
            jitter: 0,
            cut_to_a: false,
            cut_to_b: false,
        }
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng % 100 < percent
    }

    fn random(&mut self, below: u64) -> u64 {
        self.chance(0);
        if below == 0 { 0 } else { self.rng % below }
    }

    pub(crate) fn t(&self) -> Instant {
        Instant::from_millis(self.now)
    }

    pub(crate) fn a_sends(&mut self, message: &[u8]) -> Result<(), SendError> {
        let now = self.t();
        let address = address(1);
        let peer = self.b.peer;
        self.a.channels.send_message(
            peer,
            Some(&address),
            b"ctx",
            message,
            now,
            &mut self.a.entropy,
        )
    }

    pub(crate) fn b_sends(&mut self, message: &[u8]) -> Result<(), SendError> {
        let now = self.t();
        let address = address(0);
        let peer = self.a.peer;
        self.b.channels.send_message(
            peer,
            Some(&address),
            b"ctx",
            message,
            now,
            &mut self.b.entropy,
        )
    }

    /// Drains one side's poll; returns its next deadline.
    fn poll_side(&mut self, from_a: bool) -> Option<u64> {
        let now = self.t();
        let mut out = [0u8; MAX_DATA_LEN];
        let mut launched = Vec::new();
        let deadline = loop {
            let poll = if from_a {
                let deliver = self.a.deliver;
                self.a.channels.poll(now, deliver, &mut out)
            } else {
                let deliver = self.b.deliver;
                self.b.channels.poll(now, deliver, &mut out)
            };
            let got = match poll {
                Poll::SendFrame { kind, len, .. } => {
                    launched.push((kind, out[..len].to_vec()));
                    continue;
                }
                Poll::Event(Event::Message { data, .. }) => Got::Message(data.to_vec()),
                Poll::Event(Event::Writable { .. }) => Got::Writable,
                Poll::Event(Event::Reset { reason, .. }) => Got::Reset(reason),
                Poll::Dial { .. } => {
                    if from_a {
                        self.a.dials += 1;
                    } else {
                        self.b.dials += 1;
                    }
                    continue;
                }
                Poll::Wait(at) => break Some(at.as_millis()),
                Poll::Idle => break None,
            };
            if from_a {
                self.a.got.push(got);
            } else {
                self.b.got.push(got);
            }
        };
        for (kind, bytes) in launched {
            if from_a {
                self.a.sent.push((self.now, kind, bytes.clone()));
            } else {
                self.b.sent.push((self.now, kind, bytes.clone()));
            }
            self.launch(from_a, kind, bytes);
        }
        deadline
    }

    fn launch(&mut self, to_b: bool, kind: FrameKind, bytes: Vec<u8>) {
        if (to_b && self.cut_to_b) || (!to_b && self.cut_to_a) {
            return;
        }
        let loss = self.loss;
        if self.chance(loss) {
            return;
        }
        let copies = if self.chance(self.duplicate) { 2 } else { 1 };
        for _ in 0..copies {
            let jitter = self.random(self.jitter + 1);
            self.wire.push(InFlight {
                at: self.now + self.delay + jitter,
                to_b,
                kind,
                bytes: bytes.clone(),
            });
        }
    }

    /// Hands every frame due now to its side.
    fn deliver_due(&mut self) -> bool {
        let now = self.now;
        let mut due = Vec::new();
        let mut i = 0;
        while i < self.wire.len() {
            if self.wire[i].at <= now {
                due.push(self.wire.remove(i));
            } else {
                i += 1;
            }
        }
        let moved = !due.is_empty();
        for frame in due {
            self.inject(frame.to_b, frame.kind, &frame.bytes);
        }
        moved
    }

    pub(crate) fn inject(&mut self, to_b: bool, kind: FrameKind, bytes: &[u8]) {
        let t = self.t();
        if to_b {
            let peer = self.a.peer;
            self.b.channels.handle_frame(peer, ctx(), kind, bytes, t);
        } else {
            let peer = self.b.peer;
            self.a.channels.handle_frame(peer, ctx(), kind, bytes, t);
        }
    }

    /// Runs until `until` ms, or until nothing is due at all.
    pub(crate) fn run_until(&mut self, until: u64) {
        loop {
            self.deliver_due();
            let a = self.poll_side(true);
            let b = self.poll_side(false);
            if self.deliver_due() {
                continue;
            }
            let next = [a, b, self.wire.iter().map(|f| f.at).min()]
                .into_iter()
                .flatten()
                .filter(|&t| t > self.now)
                .min();
            match next {
                Some(t) if t <= until => self.now = t,
                _ => {
                    self.now = self.now.max(until);
                    self.deliver_due();
                    self.poll_side(true);
                    self.poll_side(false);
                    return;
                }
            }
        }
    }

    pub(crate) fn run_for(&mut self, ms: u64) {
        let until = self.now + ms;
        self.run_until(until);
    }

    /// Whether neither side has a deadline: the channels are at rest.
    pub(crate) fn at_rest(&mut self) -> bool {
        self.poll_side(true).is_none() && self.poll_side(false).is_none()
    }
}

fn message(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| (i * 31 + j * 7) as u8).collect()
}

fn mcu_pair(seed: u64) -> Pair<Mcu, Mcu> {
    Pair::new(seed)
}

// --- 3.1: configurations -------------------------------------------------------------

/// Scenario: a fifth channel on `Mcu` is refused, and the four are untouched.
#[test]
fn a_fifth_channel_on_mcu_is_refused() {
    let mut channels: Channels<Mcu> = Channels::new();
    let mut entropy = Counter(1);
    let now = Instant::from_millis(0);
    for i in 0..4 {
        let peer = address(i).peer_id();
        channels
            .send_message(peer, None, b"ctx", b"hello", now, &mut entropy)
            .unwrap();
    }
    let fifth = address(4).peer_id();
    assert_eq!(
        channels.send_message(fifth, None, b"ctx", b"hello", now, &mut entropy),
        Err(SendError::TableFull)
    );
    for i in 0..4 {
        assert_eq!(channels.memory(address(i).peer_id(), ctx()), Some(5));
    }
    assert_eq!(channels.memory(fifth, ctx()), None);
}

/// A server channel's buffers return to nothing once a 256 KiB message is
/// acknowledged.
#[cfg(feature = "alloc")]
#[test]
fn server_buffers_empty_after_a_large_message() {
    use crate::config::Server;
    let mut pair: Pair<Server, Server> = Pair::new(7);
    let big = message(1, 262_144);
    pair.a_sends(&big).unwrap();
    pair.run_for(10_000);
    assert_eq!(pair.b.messages(), vec![big]);
    let a = pair.a.peer;
    let b = pair.b.peer;
    assert_eq!(pair.a.channels.memory(b, ctx()), Some(0));
    assert_eq!(pair.b.channels.memory(a, ctx()), Some(0));
    assert!(pair.at_rest());
}

// --- 3.2: the sender -----------------------------------------------------------------

/// Scenario: a message over the limit is refused at the sender: over this
/// side's maximum, and over the peer's advertised one.
#[cfg(feature = "alloc")]
#[test]
fn a_message_over_the_limit_is_refused() {
    use crate::config::Server;
    let mut mcu = mcu_pair(3);
    assert_eq!(
        mcu.a_sends(&[0; 2049]),
        Err(SendError::TooLarge {
            size: 2049,
            max: 2048
        })
    );
    assert_eq!(mcu.a_sends(&[]), Err(SendError::Empty));
    assert!(mcu.a.sent.is_empty());

    let mut mixed: Pair<Server, Mcu> = Pair::new(4);
    mixed.a_sends(b"first").unwrap();
    mixed.run_for(1000);
    assert_eq!(mixed.b.messages(), vec![b"first".to_vec()]);
    let sent = mixed.a.sent.len();
    assert_eq!(
        mixed.a_sends(&[0; 10 * 1024]),
        Err(SendError::TooLarge {
            size: 10 * 1024,
            max: 2048
        })
    );
    mixed.run_for(1000);
    assert_eq!(mixed.a.sent.len(), sent, "nothing sent");
}

/// A full send buffer refuses, and room is announced once an acknowledgement
/// frees it.
#[test]
fn a_full_buffer_refuses_then_announces_room() {
    let mut pair = mcu_pair(5);
    pair.a_sends(&message(0, 2000)).unwrap();
    assert_eq!(pair.a_sends(&message(1, 100)), Err(SendError::Full));
    pair.run_for(1000);
    assert!(pair.a.got.contains(&Got::Writable));
    pair.a_sends(&message(1, 100)).unwrap();
    pair.run_for(1000);
    assert_eq!(pair.b.messages(), vec![message(0, 2000), message(1, 100)]);
}

// --- 3.3: the receiver ---------------------------------------------------------------

/// Scenario: a duplicated fragment is not delivered twice.
#[test]
fn a_duplicated_fragment_is_not_delivered_twice() {
    let mut pair = mcu_pair(6);
    pair.duplicate = 100;
    for i in 0..20 {
        pair.a_sends(&message(i, 100 + i)).unwrap();
        pair.run_for(200);
    }
    pair.run_for(2000);
    let expected: Vec<_> = (0..20).map(|i| message(i, 100 + i)).collect();
    assert_eq!(pair.b.messages(), expected);
}

/// Scenario: a fragment outside the window is not held.
#[test]
fn a_fragment_outside_the_window_is_not_held() {
    let mut pair = mcu_pair(7);
    pair.a_sends(b"open").unwrap();
    pair.run_for(1000);
    let a = pair.a.peer;
    let before = pair.b.channels.memory(a, ctx()).unwrap();
    let incarnation = {
        let (_, _, frame) = pair
            .a
            .sent
            .iter()
            .find(|(_, k, _)| *k == FrameKind::Data)
            .unwrap();
        Data::decode(frame).unwrap().incarnation
    };
    let mut out = [0u8; MAX_DATA_LEN];
    for (sequence, bytes) in [
        (70_000u32, &[1u8; 100][..]),
        (5, &[2u8; 1332][..]),
        (6, &[3u8; 1332][..]),
    ] {
        let data = Data {
            incarnation,
            sequence,
            length: None,
            last: false,
            start: false,
            bytes,
        };
        let len = data.encode(&mut out).unwrap();
        pair.inject(true, FrameKind::Data, &out[..len]);
    }
    let after = pair.b.channels.memory(a, ctx()).unwrap();
    assert!(after - before <= 2048, "never beyond the buffer");
    assert_eq!(
        after - before,
        1332,
        "only what the window holds: one of the two"
    );
}

/// The delayed acknowledgement: one fragment alone is acknowledged within
/// 25 ms, not at once.
#[test]
fn a_lone_fragment_is_acknowledged_within_25_ms() {
    let mut pair = mcu_pair(8);
    pair.delay = 0;
    pair.a_sends(b"one").unwrap();
    pair.poll_side(true);
    pair.deliver_due();
    pair.poll_side(false);
    assert!(
        pair.b.sent.iter().all(|(_, k, _)| *k != FrameKind::Ack),
        "not at once"
    );
    pair.run_for(25);
    let acks: Vec<_> = pair
        .b
        .sent
        .iter()
        .filter(|(_, k, _)| *k == FrameKind::Ack)
        .collect();
    assert_eq!(acks.len(), 1);
    assert_eq!(acks[0].0, 1025);
}

// --- 3.4: recovery and congestion ----------------------------------------------------

/// Scenario: a lost fragment is sent again: by three later fragments
/// acknowledged, well before the timeout.
#[test]
fn a_lost_fragment_is_sent_again_by_three_later_ones() {
    let mut pair: Pair<crate::config::Mcu, BigReceiver> = Pair::new(9);
    // Ten fragments' worth, in ten messages; the second fragment is lost.
    for i in 0..10 {
        pair.a_sends(&message(i, 200)).unwrap();
    }
    pair.cut_to_b = true;
    pair.poll_side(true);
    pair.cut_to_b = false;
    let first: Vec<_> = pair.a.sent.clone();
    assert_eq!(first.len(), 10, "ten fragments in the initial window");
    // Deliver all but the second.
    pair.wire.clear();
    for (i, (_, kind, bytes)) in first.iter().enumerate() {
        if i != 1 {
            pair.inject(true, *kind, bytes);
        }
    }
    pair.run_for(150);
    let resent = pair.a.sent.len() - first.len();
    assert!(resent >= 1, "sent again before the 1 s timeout");
    pair.run_for(2000);
    let expected: Vec<_> = (0..10).map(|i| message(i, 200)).collect();
    assert_eq!(pair.b.messages(), expected);
}

/// Scenario: a lost fragment is sent again at the timeout, when nothing
/// after it tells.
#[test]
fn a_lone_lost_fragment_is_sent_again_at_the_timeout() {
    let mut pair = mcu_pair(10);
    pair.cut_to_b = true;
    pair.a_sends(b"lost once").unwrap();
    pair.run_for(10);
    pair.cut_to_b = false;
    pair.run_for(1500);
    assert_eq!(pair.b.messages(), vec![b"lost once".to_vec()]);
    let data: Vec<_> = pair
        .a
        .sent
        .iter()
        .filter(|(_, k, _)| *k == FrameKind::Data)
        .collect();
    assert_eq!(data.len(), 2);
    assert_eq!(data[1].0 - data[0].0, 1000, "at the initial timeout");
}

/// Scenario: an acknowledgement of unsent data is ignored whole.
#[test]
fn an_acknowledgement_of_unsent_data_is_ignored() {
    let mut pair = mcu_pair(11);
    pair.cut_to_b = true;
    pair.a_sends(&message(0, 1000)).unwrap();
    pair.run_for(10);
    let b = pair.b.peer;
    let incarnation = Data::decode(&pair.a.sent[0].2).unwrap().incarnation;
    let before = channel_windows(&pair.a.channels, b);
    let mut out = [0u8; 64];
    let ack = Ack::new(incarnation, false, 5, 1 << 20, 2048);
    let len = ack.encode(&mut out).unwrap();
    pair.inject(false, FrameKind::Ack, &out[..len]);
    let mut ranged = Ack::new(incarnation, false, 0, 1 << 20, 2048);
    assert!(ranged.push_range(frame::Range { start: 3, end: 9 }));
    let len = ranged.encode(&mut out).unwrap();
    pair.inject(false, FrameKind::Ack, &out[..len]);
    assert_eq!(channel_windows(&pair.a.channels, b), before);
    assert_eq!(
        pair.a.channels.memory(b, ctx()),
        Some(1000),
        "nothing released"
    );
}

fn channel_windows<C: StreamConfig>(
    channels: &Channels<C>,
    peer: PeerId,
) -> (usize, usize, usize, usize) {
    channels.table.get(&(peer, ctx())).unwrap().windows()
}

/// Scenario: losses slow the sender down: under 5% loss the congestion
/// window moves, and stays well below where the same transfer takes it
/// without loss. (A new fragment is sent only with room under both windows:
/// that is checked where it is sent.)
#[test]
fn losses_slow_the_sender_down() {
    let average_cwnd = |loss: u64| {
        let mut pair: Pair<BigReceiver, BigReceiver> = Pair::new(12);
        pair.loss = loss;
        let peer = pair.b.peer;
        let (mut sum, mut min, mut max) = (0, usize::MAX, 0);
        for i in 0..60 {
            let _ = pair.a_sends(&message(i, 4000));
            pair.run_for(50);
            let (_, cwnd, _, _) = channel_windows(&pair.a.channels, peer);
            sum += cwnd;
            min = min.min(cwnd);
            max = max.max(cwnd);
        }
        (sum / 60, min, max)
    };
    let (lossless, _, _) = average_cwnd(0);
    let (lossy, min, max) = average_cwnd(5);
    assert!(min < max, "the window moved");
    assert!(lossy < lossless, "{lossy} under loss, {lossless} without");
}

/// A configuration with room to receive many fragments early.
struct BigReceiver;
impl StreamConfig for BigReceiver {
    const MAX_MESSAGE: usize = 4096;
    type SendQueue = crate::config::FixedQueue<16384>;
    type Lengths = crate::config::FixedSlots<u32, 64>;
    type InFlight = crate::config::FixedSlots<crate::Sent, 64>;
    type ReceiveArena = crate::config::FixedArena<16384>;
    type Stored = crate::config::FixedSlots<crate::Stored, 64>;
    type Channels<V> = convesso_core::storage::FixedTable<crate::config::Key, V, 2>;
}

/// A closed window is probed, at most every 15 s once backed off, and a
/// reader paused for ten minutes loses nothing and resets nothing.
#[test]
fn a_paused_reader_closes_the_window_and_loses_nothing() {
    let mut pair = mcu_pair(13);
    pair.b.deliver = false;
    // Two messages: one fills B's buffer, the other waits in A's.
    pair.a_sends(&message(0, 1500)).unwrap();
    pair.run_for(1000);
    pair.a_sends(&message(1, 1500)).unwrap();
    let paused_from = pair.now;
    pair.run_for(600_000);
    assert!(
        pair.a.resets().is_empty() && pair.b.resets().is_empty(),
        "no reset"
    );
    assert!(pair.b.messages().is_empty(), "nothing taken while paused");
    let probes: Vec<u64> = pair
        .a
        .sent
        .iter()
        .filter(|(t, k, _)| *k == FrameKind::Data && *t > paused_from + 120_000)
        .map(|(t, _, _)| *t)
        .collect();
    assert!(!probes.is_empty(), "the closed window is probed");
    for w in probes.windows(2) {
        assert!(w[1] - w[0] >= 15_000, "probes at most every 15 s: {w:?}");
    }
    pair.b.deliver = true;
    pair.run_for(60_000);
    assert_eq!(pair.b.messages(), vec![message(0, 1500), message(1, 1500)]);
    assert!(pair.at_rest());
}

// --- 3.5: resets ---------------------------------------------------------------------

/// Scenario: a peer switched off resets the channel within 30 s, with one
/// event, and nothing more is sent on it.
#[test]
fn a_vanished_peer_resets_the_channel_within_30_s() {
    let mut pair = mcu_pair(14);
    pair.a_sends(b"hello").unwrap();
    pair.run_for(1000);
    pair.cut_to_b = true;
    pair.cut_to_a = true;
    let start = pair.now;
    pair.a_sends(b"into the void").unwrap();
    pair.run_for(31_000);
    assert_eq!(pair.a.resets(), vec![Reason::NoProgress]);
    let after_reset = pair.a.sent.len();
    let packets = pair.a.sent.iter().filter(|(t, _, _)| *t >= start).count();
    assert!(packets <= 8, "a bounded number of packets: {packets}");
    pair.run_for(600_000);
    assert_eq!(pair.a.sent.len(), after_reset, "nothing after the reset");
    assert!(pair.at_rest());
}

/// Scenario: a device that restarted is recognised at once.
#[test]
fn a_restarted_device_is_recognised_at_once() {
    let mut pair = mcu_pair(15);
    pair.a_sends(b"before").unwrap();
    pair.b_sends(b"before, from b").unwrap();
    pair.run_for(1000);
    // B restarts: it keeps nothing.
    pair.b = Side::new(1, 99);
    pair.b_sends(b"after the restart").unwrap();
    pair.run_for(1000);
    assert_eq!(pair.a.resets(), vec![Reason::PeerRestarted]);
    assert_eq!(
        pair.a.messages(),
        vec![b"before, from b".to_vec(), b"after the restart".to_vec()]
    );
}

/// Scenario: a device that restarted tells a sender at once.
#[test]
fn a_restarted_device_tells_a_sender_at_once() {
    let mut pair = mcu_pair(16);
    pair.a_sends(b"before").unwrap();
    pair.run_for(1000);
    pair.b = Side::new(1, 98);
    pair.a_sends(b"to a device that forgot").unwrap();
    pair.run_for(1000);
    assert_eq!(pair.a.resets(), vec![Reason::ResetByPeer]);
    assert!(pair.b.resets().is_empty(), "it had nothing to reset");
    pair.a_sends(b"again").unwrap();
    pair.run_for(1000);
    assert_eq!(pair.b.messages(), vec![b"again".to_vec()]);
}

/// Scenario: frames of a reset channel change nothing.
#[test]
fn frames_of_a_reset_channel_change_nothing() {
    let mut pair = mcu_pair(17);
    pair.a_sends(b"one").unwrap();
    pair.b_sends(b"from b").unwrap();
    pair.run_for(1000);
    pair.a_sends(b"two").unwrap();
    pair.run_for(1000);
    let old_data = pair
        .a
        .sent
        .iter()
        .rev()
        .find(|(_, k, _)| *k == FrameKind::Data)
        .unwrap()
        .2
        .clone();
    let old_ack = pair
        .b
        .sent
        .iter()
        .rev()
        .find(|(_, k, _)| *k == FrameKind::Ack)
        .unwrap()
        .2
        .clone();
    // B restarts and sends: A resets.
    pair.b = Side::new(1, 97);
    pair.b_sends(b"new").unwrap();
    pair.run_for(1000);
    assert_eq!(pair.a.resets(), vec![Reason::PeerRestarted]);
    let b_messages = pair.b.messages().len();
    // Late frames of A's old incarnation reach B; B's old ack reaches A.
    pair.inject(true, FrameKind::Data, &old_data);
    pair.inject(false, FrameKind::Ack, &old_ack);
    pair.run_for(1000);
    assert_eq!(
        pair.a.resets(),
        vec![Reason::PeerRestarted],
        "no second reset"
    );
    assert_eq!(pair.b.messages().len(), b_messages, "nothing delivered");
}

/// A message longer than the receiver accepts, sent before it advertised its
/// maximum, resets both sides.
#[cfg(feature = "alloc")]
#[test]
fn a_message_too_large_for_the_peer_resets_both_sides() {
    let mut pair: Pair<crate::config::Server, Mcu> = Pair::new(18);
    pair.a_sends(&message(0, 3000)).unwrap();
    pair.run_for(2000);
    assert_eq!(pair.b.resets(), vec![Reason::MessageTooLarge]);
    assert_eq!(pair.a.resets(), vec![Reason::ResetByPeer]);
    assert!(pair.b.messages().is_empty());
}

/// Scenario: a slow transfer that progresses is not reset: a message every
/// 20 s for 10 minutes, over a link that loses a fifth of the packets.
#[test]
fn a_slow_transfer_that_progresses_is_not_reset() {
    let mut pair = mcu_pair(19);
    pair.loss = 20;
    for i in 0..30 {
        let _ = pair.a_sends(&message(i, 300));
        pair.run_for(20_000);
    }
    pair.loss = 0;
    pair.run_for(60_000);
    assert!(pair.a.resets().is_empty(), "{:?}", pair.a.resets());
    let expected: Vec<_> = (0..30).map(|i| message(i, 300)).collect();
    assert_eq!(pair.b.messages(), expected);
}

/// The session closing, or its reopening failing, resets the channel with
/// that reason.
#[test]
fn a_closed_session_or_a_failed_reopening_resets_the_channel() {
    let mut pair = mcu_pair(20);
    pair.a_sends(b"hello").unwrap();
    pair.run_for(1000);
    let b = pair.b.peer;
    pair.a.channels.session_closed(b, ctx(), 7);
    pair.run_for(10);
    assert_eq!(pair.a.resets(), vec![Reason::SessionClosed { code: 7 }]);
    pair.a_sends(b"again").unwrap();
    pair.run_for(1000);
    // A failed renewal while the session still carries the channel: no reset.
    pair.a
        .channels
        .reopen_failed(b, ctx(), DialError::NoResponse);
    pair.run_for(10);
    assert_eq!(pair.a.resets(), vec![Reason::SessionClosed { code: 7 }]);
    // A channel waiting for the session's keys: the failed dial resets it.
    pair.a_sends(b"waiting").unwrap();
    let now = pair.t();
    let mut out = [0u8; MAX_DATA_LEN];
    assert!(matches!(
        pair.a.channels.poll(now, true, &mut out),
        Poll::SendFrame { .. }
    ));
    pair.a.channels.frame_refused(now);
    pair.a
        .channels
        .reopen_failed(b, ctx(), DialError::NoResponse);
    pair.run_for(10);
    assert_eq!(
        pair.a.resets(),
        vec![
            Reason::SessionClosed { code: 7 },
            Reason::ReopenFailed(DialError::NoResponse)
        ]
    );
}

/// After an exchange, both channels are at rest: no deadline at all.
#[test]
fn channels_are_at_rest_after_an_exchange() {
    let mut pair = mcu_pair(21);
    for i in 0..5 {
        pair.a_sends(&message(i, 500)).unwrap();
        pair.b_sends(&message(i + 10, 700)).unwrap();
        pair.run_for(300);
    }
    pair.run_for(5000);
    assert_eq!(pair.b.messages().len(), 5);
    assert_eq!(pair.a.messages().len(), 5);
    assert!(pair.at_rest());
}

/// An unknown incarnation without START is answered with RESET, at most once
/// a second.
#[test]
fn reset_answers_are_limited_to_one_a_second() {
    let mut pair = mcu_pair(22);
    let mut out = [0u8; MAX_DATA_LEN];
    let data = Data {
        incarnation: [9; 8],
        sequence: 40,
        length: None,
        last: false,
        start: false,
        bytes: b"forgotten",
    };
    let len = data.encode(&mut out).unwrap();
    let frame = out[..len].to_vec();
    let resets = |pair: &Pair<Mcu, Mcu>| {
        pair.b
            .sent
            .iter()
            .filter(|(_, k, f)| *k == FrameKind::Ack && Ack::decode(f).is_ok_and(|a| a.reset))
            .count()
    };
    for _ in 0..5 {
        pair.inject(true, FrameKind::Data, &frame);
        pair.run_for(100);
    }
    assert_eq!(resets(&pair), 1, "once within the second");
    pair.run_for(1000);
    pair.inject(true, FrameKind::Data, &frame);
    pair.run_for(10);
    assert_eq!(resets(&pair), 2, "again after it");
    assert!(pair.b.messages().is_empty() && pair.b.resets().is_empty());
}
