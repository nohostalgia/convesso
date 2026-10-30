//! Channels with many peers, over real endpoints of the core on a virtual
//! clock: what a server holds for the peers it met, and what a message costs
//! with many channels (`PROTOCOL.md §8`).

#![cfg(feature = "alloc")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use convesso_core::dos::Source;
use convesso_core::endpoint::{Endpoint, Event as CoreEvent, Output, Poll as CorePoll, SendError};
use convesso_core::handshake::{Admission, Decision, Entropy, Psk};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::storage::{Config as CoreConfig, Mcu as CoreMcu};
use convesso_core::time::Instant;
use convesso_stream::config::{Mcu, Server, StreamConfig};
use convesso_stream::frame::MAX_DATA_LEN;
use convesso_stream::{Channels, Event, Poll};

convesso_core::profile! {
    /// The server profile with room for many sessions, admitting handshakes
    /// as fast as a measurement makes them.
    Wide: Server { indices: 100_000, load_rate_per_second: 10_000_000, load_burst: 10_000_000 }
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
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (self.0 >> 33) as u8;
        }
    }
}

fn seeded(i: u32) -> Identity {
    let mut seed = [11u8; 32];
    seed[..4].copy_from_slice(&i.to_le_bytes());
    Identity::from_ed25519_seed(&seed).unwrap()
}

/// An endpoint and its channels, driven as a driver would.
struct Node<C: CoreConfig, S: StreamConfig> {
    endpoint: Endpoint<C>,
    channels: Channels<S>,
    entropy: Counter,
    source: [u8; 6],
    messages: usize,
    resets: usize,
}

impl<C: CoreConfig, S: StreamConfig> Node<C, S> {
    fn new(identity: Identity, source: [u8; 6], seed: u64) -> Self {
        Self {
            endpoint: Endpoint::new(identity, &[b"ctx"]).unwrap(),
            channels: Channels::new(),
            entropy: Counter(seed),
            source,
            messages: 0,
            resets: 0,
        }
    }

    fn address(&self) -> Address {
        *self.endpoint.identity().address()
    }

    fn core_event(&mut self, event: CoreEvent<'_>, now: Instant) {
        match event {
            CoreEvent::Frame {
                peer,
                context,
                kind,
                data,
                connected,
                ..
            } => {
                if connected {
                    self.channels
                        .session_opened(peer, context, &mut self.entropy);
                }
                self.channels.handle_frame(peer, context, kind, data, now);
            }
            CoreEvent::Connected { peer, context }
            | CoreEvent::Datagram {
                peer,
                context,
                connected: true,
                ..
            } => self
                .channels
                .session_opened(peer, context, &mut self.entropy),
            CoreEvent::Idle { peer, context } => {
                self.channels.session_idle(peer, context, &mut self.entropy);
            }
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

    /// Everything the node has to send at `now`, its core and its channels
    /// polled until neither moves.
    fn drive(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut sent = Vec::new();
        let mut out = [0u8; 2048];
        loop {
            let mut moved = false;
            loop {
                match self
                    .endpoint
                    .poll(now, &mut Open, &mut self.entropy, &mut out)
                {
                    CorePoll::Transmit { len, .. } => {
                        sent.push(out[..len].to_vec());
                        moved = true;
                    }
                    CorePoll::Event(event) => {
                        self.core_event(event, now);
                        moved = true;
                    }
                    _ => break,
                }
            }
            let mut frame = [0u8; MAX_DATA_LEN];
            loop {
                match self.channels.poll(now, true, &mut frame) {
                    Poll::SendFrame {
                        peer,
                        context,
                        kind,
                        len,
                    } => {
                        match self.endpoint.send_frame(
                            peer,
                            context.as_bytes(),
                            kind,
                            &frame[..len],
                            now,
                            &mut Open,
                            &mut self.entropy,
                            &mut out,
                        ) {
                            Ok(Output::Transmit { len, .. }) => sent.push(out[..len].to_vec()),
                            Ok(_) => {}
                            Err(SendError::NoKeys) => self.channels.frame_refused(now),
                            Err(e) => panic!("{e:?}"),
                        }
                        moved = true;
                    }
                    Poll::Dial { address, context } => {
                        if let Output::Transmit { len, .. } = self
                            .endpoint
                            .connect(
                                &address,
                                context.as_bytes(),
                                now,
                                &mut Open,
                                &mut self.entropy,
                                &mut out,
                            )
                            .unwrap()
                        {
                            sent.push(out[..len].to_vec());
                        }
                        moved = true;
                    }
                    Poll::Event(Event::Message { .. }) => {
                        self.messages += 1;
                        moved = true;
                    }
                    Poll::Event(Event::Reset { .. }) => {
                        self.resets += 1;
                        moved = true;
                    }
                    Poll::Event(Event::Writable { .. }) => moved = true,
                    Poll::Wait(_) | Poll::Idle => break,
                }
            }
            if !moved {
                return sent;
            }
        }
    }

    /// Hands it `packet` from `from`; returns its answer, if any.
    fn take(&mut self, packet: &[u8], from: [u8; 6], now: Instant) -> Option<Vec<u8>> {
        let mut buffer = packet.to_vec();
        let mut out = [0u8; 2048];
        match self.endpoint.handle_packet(
            &mut buffer,
            Source::Direct(&from),
            now,
            &mut Open,
            &mut self.entropy,
            &mut out,
        ) {
            Output::Transmit { len, .. } => Some(out[..len].to_vec()),
            Output::Event(event) => {
                self.core_event(event, now);
                None
            }
            Output::Nothing => None,
        }
    }

    fn send_message(&mut self, to: &Address, data: &[u8], now: Instant) {
        self.channels
            .send_message(to.peer_id(), Some(to), b"ctx", data, now, &mut self.entropy)
            .unwrap();
    }
}

/// Carries packets between `a` and `b` at `now`, with no delay, until
/// neither sends.
fn pump<A: CoreConfig, SA: StreamConfig, B: CoreConfig, SB: StreamConfig>(
    a: &mut Node<A, SA>,
    b: &mut Node<B, SB>,
    now: Instant,
) {
    for _ in 0..1_000 {
        let mut queue: Vec<(bool, Vec<u8>)> = a.drive(now).into_iter().map(|p| (true, p)).collect();
        queue.extend(b.drive(now).into_iter().map(|p| (false, p)));
        if queue.is_empty() {
            return;
        }
        while let Some((from_a, packet)) = queue.pop() {
            let answer = if from_a {
                b.take(&packet, a.source, now)
            } else {
                a.take(&packet, b.source, now)
            };
            if let Some(answer) = answer {
                queue.push((!from_a, answer));
            }
        }
    }
    panic!("the pair never settled");
}

fn client(i: u32) -> Node<CoreMcu, Mcu> {
    let [_, x, y, z] = i.to_be_bytes();
    Node::new(seeded(i), [10, x, y, z, 0x1f, 0x40], 7 + u64::from(i))
}

/// A server and `n` peers, each having sent it one message, `spacing` ms
/// apart; with a spacing longer than the delayed acknowledgement, every
/// acknowledgement is sent before the next peer comes. Returns the server
/// and the last peer.
fn met(n: u32, spacing: u64) -> (Node<Wide, Server>, Node<CoreMcu, Mcu>) {
    let server_source = [192, 0, 2, 1, 0x1f, 0x40];
    let mut server: Node<Wide, Server> = Node::new(seeded(1_000_000), server_source, 1);
    let server_peer = server.endpoint.identity().peer_id();
    let server_address = server.address();
    let mut last = None;
    for i in 0..n {
        let now = Instant::from_millis(u64::from(i) * spacing);
        let mut c = client(i);
        c.endpoint
            .set_hints(server_peer, &[&server_source], now)
            .unwrap();
        // The session first, so that the message leaves at once rather than
        // after the channel's wait for keys.
        let mut out = [0u8; 2048];
        let opened = c
            .endpoint
            .connect(
                &server_address,
                b"ctx",
                now,
                &mut Open,
                &mut c.entropy,
                &mut out,
            )
            .unwrap();
        if let Output::Transmit { len, .. } = opened {
            let first = out[..len].to_vec();
            if let Some(answer) = server.take(&first, c.source, now) {
                let _ = c.take(&answer, server_source, now);
            }
        }
        pump(&mut c, &mut server, now);
        c.send_message(&server_address, b"hello", now);
        pump(&mut c, &mut server, now);
        if spacing > 25 {
            pump(
                &mut c,
                &mut server,
                Instant::from_millis(u64::from(i) * spacing + 25),
            );
        }
        if i + 1 == n {
            last = Some(c);
        }
    }
    assert_eq!(server.messages, n as usize, "every message arrived");
    (server, last.unwrap())
}

/// Scenario: peers met and gone leave no channel: 100 peers each send the
/// server a message, their sessions go idle, and the server's stream layer
/// holds no channel.
#[test]
fn peers_met_and_gone_leave_no_channel() {
    let (mut server, _) = met(100, 40);
    assert_eq!(server.channels.channel_count(), 100);
    let later = Instant::from_millis(100 * 40 + 181_000);
    let _ = server.drive(later);
    assert_eq!(server.endpoint.session_count(), 0, "sessions gone");
    assert_eq!(server.channels.channel_count(), 0, "channels gone");
}

/// The cost of one message each way between a server and one of N peers it
/// holds a channel with. Ignored by default; run it with
/// `cargo test -p convesso-stream --all-features --release --test many -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, meaningful only in release"]
fn a_message_with_channels_live() {
    for n in [1u32, 1_000, 10_000] {
        let started = std::time::Instant::now();
        let (mut server, mut c) = met(n, 1);
        let opened = started.elapsed();
        let server_address = server.address();
        let c_address = c.address();
        let start = u64::from(n) + 1;
        let rounds = 1_000u64;
        let started = std::time::Instant::now();
        for round in 0..rounds {
            let now = Instant::from_millis(start + round);
            c.send_message(&server_address, b"ping", now);
            pump(&mut c, &mut server, now);
            server.send_message(&c_address, b"pong", now);
            pump(&mut c, &mut server, now);
        }
        let per_round = started.elapsed() / u32::try_from(rounds).unwrap();
        std::println!(
            "{n:>6} channels: {per_round:?} a round; {} channels held; opened in {opened:?}",
            server.channels.channel_count()
        );
    }
}
