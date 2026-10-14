//! A channel over two real endpoints of the core, on a virtual clock: the
//! reopening of a dormant session (`PROTOCOL.md §8`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use convesso_core::dos::Source;
use convesso_core::endpoint::{Endpoint, Event as CoreEvent, Output, Poll as CorePoll, SendError};
use convesso_core::handshake::{Admission, Decision, DialError, Entropy, Psk};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::storage::Mcu as CoreMcu;
use convesso_core::time::Instant;
use convesso_stream::config::Mcu;
use convesso_stream::frame::MAX_DATA_LEN;
use convesso_stream::{Channels, Event, Poll, Reason};
use serde_json::Value;

fn identity(i: usize) -> Identity {
    let vectors: Value =
        serde_json::from_str(include_str!("../../convesso-core/vectors/identity.json")).unwrap();
    let key = &vectors["keys"][i];
    let bytes = |v: &Value| -> [u8; 32] {
        let text = v.as_str().unwrap();
        (0..32)
            .map(|j| u8::from_str_radix(&text[2 * j..2 * j + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    };
    Identity::from_parts(
        bytes(&key["x25519_scalar"]),
        Address::parse(bytes(&key["address"])).unwrap(),
    )
    .unwrap()
}

struct Open;
impl Admission for Open {
    fn admit(&mut self, _peer: &PeerId, _context: &[u8]) -> Decision {
        Decision::Accept { psk: None }
    }
    fn psk(&mut self, _peer: &PeerId, _context: &[u8]) -> Option<Psk> {
        None
    }
}

struct Counter(u64);
impl Entropy for Counter {
    fn fill(&mut self, dest: &mut [u8]) {
        for byte in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1442695040888963407);
            *byte = (self.0 >> 33) as u8;
        }
    }
}

/// An endpoint, its channels, and what its application saw: the driver's
/// part, written out.
struct Node {
    endpoint: Endpoint<CoreMcu>,
    channels: Channels<Mcu>,
    entropy: Counter,
    source: [u8; 6],
    messages: Vec<Vec<u8>>,
    resets: Vec<Reason>,
    first_contacts: usize,
}

impl Node {
    fn new(i: usize, source: [u8; 6]) -> Self {
        Self {
            endpoint: Endpoint::new(identity(i), &[b"ctx"]).unwrap(),
            channels: Channels::new(),
            entropy: Counter(i as u64 + 7),
            source,
            messages: Vec::new(),
            resets: Vec::new(),
            first_contacts: 0,
        }
    }

    fn core_event(&mut self, event: CoreEvent<'_>, now: Instant) {
        match event {
            CoreEvent::Frame {
                peer,
                context,
                kind,
                data,
                ..
            } => self.channels.handle_frame(peer, context, kind, data, now),
            CoreEvent::Closed {
                peer,
                context,
                code,
                ..
            } => self.channels.session_closed(peer, context, code),
            CoreEvent::ReopenFailed {
                peer,
                context,
                error,
            } => self.channels.reopen_failed(peer, context, error),
            _ => {}
        }
    }
}

struct Net {
    a: Node,
    b: Node,
    now: u64,
    /// Packets towards a node: (due, to b, bytes).
    wire: Vec<(u64, bool, Vec<u8>)>,
    cut: bool,
}

const DELAY: u64 = 10;

impl Net {
    fn new() -> Self {
        let mut net = Self {
            a: Node::new(0, [10, 0, 0, 1, 0, 1]),
            b: Node::new(1, [10, 0, 0, 2, 0, 2]),
            now: 0,
            wire: Vec::new(),
            cut: false,
        };
        let (a, b) = (
            net.a.endpoint.identity().peer_id(),
            net.b.endpoint.identity().peer_id(),
        );
        let (sa, sb) = (net.a.source, net.b.source);
        net.a
            .endpoint
            .set_hint(b, &sb, Instant::from_millis(0))
            .unwrap();
        net.b
            .endpoint
            .set_hint(a, &sa, Instant::from_millis(0))
            .unwrap();
        net
    }

    fn t(&self) -> Instant {
        Instant::from_millis(self.now)
    }

    fn node(&mut self, a: bool) -> &mut Node {
        if a { &mut self.a } else { &mut self.b }
    }

    fn launch(&mut self, from_a: bool, packet: &[u8]) {
        if packet.first() == Some(&0x01) && packet.get(1).is_some_and(|t| *t == 0x01 || *t == 0x05)
        {
            self.node(from_a).first_contacts += 1;
        }
        if !self.cut {
            self.wire.push((self.now + DELAY, from_a, packet.to_vec()));
        }
    }

    /// Drives one node: its core, then its channels; returns its deadline.
    fn drive(&mut self, a: bool) -> Option<u64> {
        let now = self.t();
        let mut out = [0u8; 2048];
        let mut deadline: Option<u64>;
        loop {
            let mut moved = false;
            loop {
                let node = self.node(a);
                let poll = node
                    .endpoint
                    .poll(now, &mut Open, &mut node.entropy, &mut out);
                match poll {
                    CorePoll::Transmit { len, .. } => {
                        let packet = out[..len].to_vec();
                        self.launch(a, &packet);
                        moved = true;
                    }
                    CorePoll::Event(event) => {
                        self.node(a).core_event(event, now);
                        moved = true;
                    }
                    CorePoll::Wait(at) => {
                        deadline = Some(at.as_millis());
                        break;
                    }
                    CorePoll::Idle => {
                        deadline = None;
                        break;
                    }
                    CorePoll::OpenRelayLink | CorePoll::CloseRelayLink => unreachable!(),
                }
            }
            let mut frame = [0u8; MAX_DATA_LEN];
            loop {
                let node = self.node(a);
                match node.channels.poll(now, true, &mut frame) {
                    Poll::SendFrame {
                        peer,
                        context,
                        kind,
                        len,
                    } => {
                        let sent = node.endpoint.send_frame(
                            peer,
                            context.as_bytes(),
                            kind,
                            &frame[..len],
                            now,
                            &mut Open,
                            &mut node.entropy,
                            &mut out,
                        );
                        match sent {
                            Ok(Output::Transmit { len, .. }) => {
                                let packet = out[..len].to_vec();
                                self.launch(a, &packet);
                            }
                            Ok(_) => {}
                            Err(SendError::NoKeys) => self.node(a).channels.frame_refused(now),
                            Err(e) => panic!("{e:?}"),
                        }
                        moved = true;
                    }
                    Poll::Dial { address, context } => {
                        let output = node
                            .endpoint
                            .connect(
                                &address,
                                context.as_bytes(),
                                now,
                                &mut Open,
                                &mut node.entropy,
                                &mut out,
                            )
                            .unwrap();
                        if let Output::Transmit { len, .. } = output {
                            let packet = out[..len].to_vec();
                            self.launch(a, &packet);
                        }
                        moved = true;
                    }
                    Poll::Event(Event::Message { data, .. }) => {
                        let data = data.to_vec();
                        self.node(a).messages.push(data);
                        moved = true;
                    }
                    Poll::Event(Event::Reset { reason, .. }) => {
                        self.node(a).resets.push(reason);
                        moved = true;
                    }
                    Poll::Event(Event::Writable { .. }) => moved = true,
                    Poll::Wait(at) => {
                        let at = at.as_millis();
                        deadline = Some(deadline.map_or(at, |d: u64| d.min(at)));
                        break;
                    }
                    Poll::Idle => break,
                }
            }
            if !moved {
                return deadline;
            }
        }
    }

    fn deliver_due(&mut self) -> bool {
        let now = self.now;
        let due: Vec<_> = self
            .wire
            .iter()
            .filter(|(t, _, _)| *t <= now)
            .cloned()
            .collect();
        self.wire.retain(|(t, _, _)| *t > now);
        for (_, to_b, packet) in &due {
            let from = if *to_b { self.a.source } else { self.b.source };
            let node_is_a = !*to_b;
            let mut buffer = packet.clone();
            let mut out = [0u8; 2048];
            let t = self.t();
            let target = if node_is_a { &mut self.a } else { &mut self.b };
            let output = target.endpoint.handle_packet(
                &mut buffer,
                Source::Direct(&from),
                t,
                &mut Open,
                &mut target.entropy,
                &mut out,
            );
            match output {
                Output::Transmit { len, .. } => {
                    let answer = out[..len].to_vec();
                    self.launch(node_is_a, &answer);
                }
                Output::Event(event) => {
                    let target = if node_is_a { &mut self.a } else { &mut self.b };
                    target.core_event(event, t);
                }
                Output::Nothing => {}
            }
        }
        !due.is_empty()
    }

    fn run_until(&mut self, until: u64) {
        loop {
            while self.deliver_due() {}
            let a = self.drive(true);
            let b = self.drive(false);
            if self.wire.iter().any(|(t, _, _)| *t <= self.now) {
                continue;
            }
            let next = [a, b, self.wire.iter().map(|(t, _, _)| *t).min()]
                .into_iter()
                .flatten()
                .filter(|&t| t > self.now)
                .min();
            match next {
                Some(t) if t <= until => self.now = t,
                _ => {
                    self.now = self.now.max(until);
                    while self.deliver_due() {}
                    self.drive(true);
                    self.drive(false);
                    return;
                }
            }
        }
    }

    fn a_sends(&mut self, message: &[u8]) {
        let now = self.t();
        let address = *self.b.endpoint.identity().address();
        let peer = address.peer_id();
        let node = &mut self.a;
        node.channels
            .send_message(
                peer,
                Some(&address),
                b"ctx",
                message,
                now,
                &mut node.entropy,
            )
            .unwrap();
    }
}

/// Scenario: a message to a dormant session reopens it, is delivered after
/// the fresh handshake, and no reset is raised.
#[test]
fn a_message_to_a_dormant_session_reopens_it() {
    let mut net = Net::new();
    let address = *net.b.endpoint.identity().address();
    let ctx = b"ctx";
    net.a_sends(b"before");
    net.run_until(5_000);
    assert_eq!(net.b.messages, vec![b"before".to_vec()]);

    // Ten minutes: the keys expire and the session falls dormant.
    net.run_until(600_000);
    let peer = address.peer_id();
    assert!(!net.a.endpoint.is_live(&peer, ctx, net.t()), "dormant");
    let contacts = net.a.first_contacts;

    net.a_sends(b"after a sleep");
    net.run_until(605_000);
    assert_eq!(
        net.b.messages,
        vec![b"before".to_vec(), b"after a sleep".to_vec()]
    );
    assert!(net.a.first_contacts > contacts, "a fresh handshake");
    assert!(
        net.a.resets.is_empty() && net.b.resets.is_empty(),
        "no reset"
    );
}

/// Scenario: a reopening that fails resets the channel with the dial's error.
#[test]
fn a_reopening_that_fails_resets_the_channel() {
    let mut net = Net::new();
    net.a_sends(b"before");
    net.run_until(5_000);
    assert_eq!(net.b.messages, vec![b"before".to_vec()]);
    net.run_until(600_000);
    net.cut = true;
    net.a_sends(b"to nobody");
    net.run_until(640_000);
    assert_eq!(
        net.a.resets,
        vec![Reason::ReopenFailed(DialError::NoResponse)]
    );
    assert_eq!(net.b.messages, vec![b"before".to_vec()]);
}
