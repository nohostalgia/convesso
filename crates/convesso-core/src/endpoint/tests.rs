//! The session scenarios (`PROTOCOL.md §5`): two endpoints
//! over a link the test controls, driven by a virtual clock.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::collections::VecDeque;
use std::vec;
use std::vec::Vec;

use serde_json::Value;

use super::*;
use crate::handshake::{Decision, Psk, RefusalCode};
use crate::storage::Mcu;
use crate::transport::{self, inner};

// --- the harness ------------------------------------------------------------------

fn identity(i: usize) -> Identity {
    let vectors: Value = serde_json::from_str(include_str!("../../vectors/identity.json")).unwrap();
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

struct TestEntropy(u64);
impl Entropy for TestEntropy {
    fn fill(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            self.0 += 1;
            let block = crate::noise::tests_support::hash(&self.0.to_le_bytes());
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

struct Policy {
    decision: Decision,
    asked: usize,
}
impl Admission for Policy {
    fn admit(&mut self, _peer: &PeerId, _context: &[u8]) -> Decision {
        self.asked += 1;
        self.decision
    }
    fn psk(&mut self, _peer: &PeerId, _context: &[u8]) -> Option<Psk> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ev {
    Connected(Vec<u8>),
    Datagram(Vec<u8>, Vec<u8>, bool),
    Closed(Vec<u8>, u16, bool),
    ReopenFailed(Vec<u8>, DialError),
    Payload(Vec<u8>, Vec<u8>),
    /// A datagram that arrived through the relay.
    Relayed(Vec<u8>, Vec<u8>, bool),
    NotAtRelay(PeerId),
    Observed(crate::relay::Link, core::net::SocketAddr),
    RelayUnavailable(RelayError),
    PathChanged(crate::paths::PathKind),
    /// A stream frame: context, kind, data, whether it came through the relay.
    Frame(Vec<u8>, FrameKind, Vec<u8>, bool),
}

fn own(event: Event<'_>) -> Ev {
    match event {
        Event::Connected { context, .. } => Ev::Connected(context.as_bytes().to_vec()),
        Event::Datagram {
            context,
            data,
            connected,
            relayed: false,
            ..
        } => Ev::Datagram(context.as_bytes().to_vec(), data.to_vec(), connected),
        Event::Datagram {
            context,
            data,
            connected,
            relayed: true,
            ..
        } => Ev::Relayed(context.as_bytes().to_vec(), data.to_vec(), connected),
        Event::Closed {
            context,
            code,
            by_peer,
            ..
        } => Ev::Closed(context.as_bytes().to_vec(), code, by_peer),
        Event::ReopenFailed { context, error, .. } => {
            Ev::ReopenFailed(context.as_bytes().to_vec(), error)
        }
        Event::Payload { context, data, .. } => {
            Ev::Payload(context.as_bytes().to_vec(), data.to_vec())
        }
        Event::PeerNotAtRelay { peer } => Ev::NotAtRelay(peer),
        Event::ObservedAddress { link, address } => Ev::Observed(link, address),
        Event::RelayUnavailable { error } => Ev::RelayUnavailable(error),
        Event::PathChanged { path, .. } => Ev::PathChanged(path),
        Event::Frame {
            context,
            kind,
            data,
            relayed,
            ..
        } => Ev::Frame(context.as_bytes().to_vec(), kind, data.to_vec(), relayed),
    }
}

struct Node {
    endpoint: Endpoint<Mcu>,
    policy: Policy,
    entropy: TestEntropy,
    source: [u8; 6],
    events: Vec<Ev>,
    /// Every packet this node transmitted, in order.
    sent: Vec<Vec<u8>>,
}

impl Node {
    fn new(key: usize, source: [u8; 6], seed: u64) -> Self {
        Self {
            endpoint: Endpoint::new(identity(key), &[b"session", b"other"]).unwrap(),
            policy: Policy {
                decision: Decision::Accept { psk: None },
                asked: 0,
            },
            entropy: TestEntropy(seed),
            source,
            events: Vec::new(),
            sent: Vec::new(),
        }
    }

    fn address(&self) -> Address {
        *self.endpoint.identity().address()
    }

    fn peer_id(&self) -> PeerId {
        self.endpoint.identity().peer_id()
    }

    fn first_contacts_sent(&self) -> usize {
        self.sent.iter().filter(|p| p[..2] == [0x01, 0x01]).count()
    }
}

const PATH: usize = 1400;

/// Two endpoints and the link between them: A, the initiator, and B.
struct Net {
    a: Node,
    b: Node,
    now: u64,
    /// Packets towards A or B are dropped while set.
    drop_to_a: bool,
    drop_to_b: bool,
}

impl Net {
    fn new() -> Self {
        let mut net = Self {
            a: Node::new(1, [10, 0, 0, 1, 0, 1], 100),
            b: Node::new(0, [10, 0, 0, 2, 0, 2], 200),
            now: 0,
            drop_to_a: false,
            drop_to_b: false,
        };
        // No relay here: each knows where the other is.
        let (a, b) = (net.a.peer_id(), net.b.peer_id());
        let (a_source, b_source) = (net.a.source, net.b.source);
        net.a
            .endpoint
            .set_hint(b, &b_source, Instant::from_millis(0))
            .unwrap();
        net.b
            .endpoint
            .set_hint(a, &a_source, Instant::from_millis(0))
            .unwrap();
        net
    }

    fn t(&self) -> Instant {
        Instant::from_millis(self.now)
    }

    /// Hands `packet` to the node it is for; returns its answer, if any.
    fn deliver(&mut self, to_b: bool, packet: &[u8]) -> Option<Vec<u8>> {
        let now = self.t();
        let (node, from) = if to_b {
            (&mut self.b, self.a.source)
        } else {
            (&mut self.a, self.b.source)
        };
        let mut buffer = packet.to_vec();
        let mut out = [0u8; 2048];
        match node.endpoint.handle_packet(
            &mut buffer,
            Source::Direct(&from),
            now,
            &mut node.policy,
            &mut node.entropy,
            &mut out,
        ) {
            Output::Transmit { len, .. } => {
                node.sent.push(out[..len].to_vec());
                Some(out[..len].to_vec())
            }
            Output::Event(event) => {
                node.events.push(own(event));
                None
            }
            Output::Nothing => None,
        }
    }

    fn poll_node(&mut self, a: bool, queue: &mut VecDeque<(bool, Vec<u8>)>) -> bool {
        let now = self.t();
        let node = if a { &mut self.a } else { &mut self.b };
        let mut progressed = false;
        loop {
            let mut out = [0u8; 2048];
            match node
                .endpoint
                .poll(now, &mut node.policy, &mut node.entropy, &mut out)
            {
                Poll::Transmit { len, .. } => {
                    node.sent.push(out[..len].to_vec());
                    queue.push_back((a, out[..len].to_vec()));
                    progressed = true;
                }
                Poll::Event(event) => {
                    node.events.push(own(event));
                    progressed = true;
                }
                Poll::OpenRelayLink | Poll::CloseRelayLink => {
                    panic!("no relay is pinned here")
                }
                Poll::Wait(_) | Poll::Idle => return progressed,
            }
        }
    }

    /// Delivers and polls until nothing moves at the current instant.
    fn settle_with(&mut self, mut queue: VecDeque<(bool, Vec<u8>)>) {
        for _ in 0..1000 {
            let mut moved = self.poll_node(true, &mut queue);
            moved |= self.poll_node(false, &mut queue);
            while let Some((from_a, packet)) = queue.pop_front() {
                moved = true;
                let to_b = from_a;
                if (to_b && self.drop_to_b) || (!to_b && self.drop_to_a) {
                    continue;
                }
                if let Some(answer) = self.deliver(to_b, &packet) {
                    queue.push_back((!from_a, answer));
                }
            }
            if !moved {
                return;
            }
        }
        panic!("the link never settled");
    }

    fn settle(&mut self) {
        self.settle_with(VecDeque::new());
    }

    /// A sends to B (by address), then the link settles.
    fn a_sends(&mut self, data: &[u8]) -> Result<(), SendError> {
        let now = self.t();
        let address = self.b.address();
        let mut out = [0u8; 2048];
        let output = self.a.endpoint.send(
            Target::Address(&address),
            b"session",
            data,
            PATH,
            now,
            &mut self.a.policy,
            &mut self.a.entropy,
            &mut out,
        )?;
        let mut queue = VecDeque::new();
        if let Output::Transmit { len, .. } = output {
            self.a.sent.push(out[..len].to_vec());
            queue.push_back((true, out[..len].to_vec()));
        }
        self.settle_with(queue);
        Ok(())
    }

    /// B sends to A by `PeerId`, then the link settles.
    fn b_replies(&mut self, data: &[u8]) -> Result<(), SendError> {
        let now = self.t();
        let peer = self.a.peer_id();
        let mut out = [0u8; 2048];
        let output = self.b.endpoint.send(
            Target::Peer(peer),
            b"session",
            data,
            PATH,
            now,
            &mut self.b.policy,
            &mut self.b.entropy,
            &mut out,
        )?;
        let mut queue = VecDeque::new();
        if let Output::Transmit { len, .. } = output {
            self.b.sent.push(out[..len].to_vec());
            queue.push_back((false, out[..len].to_vec()));
        }
        self.settle_with(queue);
        Ok(())
    }

    fn at(&mut self, seconds: u64) {
        self.now = seconds * 1000;
        self.settle();
    }

    /// A sends B a stream frame, then the link settles.
    fn a_sends_frame(&mut self, kind: FrameKind, frame: &[u8]) -> Result<(), SendError> {
        let now = self.t();
        let peer = self.b.peer_id();
        let mut out = [0u8; 2048];
        let output = self.a.endpoint.send_frame(
            peer,
            b"session",
            kind,
            frame,
            now,
            &mut self.a.policy,
            &mut self.a.entropy,
            &mut out,
        )?;
        let mut queue = VecDeque::new();
        if let Output::Transmit { len, .. } = output {
            self.a.sent.push(out[..len].to_vec());
            queue.push_back((true, out[..len].to_vec()));
        }
        self.settle_with(queue);
        Ok(())
    }

    fn b_frames(&self) -> Vec<(FrameKind, Vec<u8>)> {
        self.b
            .events
            .iter()
            .filter_map(|e| match e {
                Ev::Frame(_, kind, data, _) => Some((*kind, data.clone())),
                _ => None,
            })
            .collect()
    }

    fn connected(&mut self) {
        let now = self.t();
        let address = self.b.address();
        let mut out = [0u8; 2048];
        let output = self
            .a
            .endpoint
            .connect(
                &address,
                b"session",
                now,
                &mut self.a.policy,
                &mut self.a.entropy,
                &mut out,
            )
            .unwrap();
        let mut queue = VecDeque::new();
        if let Output::Transmit { len, .. } = output {
            self.a.sent.push(out[..len].to_vec());
            queue.push_back((true, out[..len].to_vec()));
        }
        self.settle_with(queue);
    }

    fn b_datagrams(&self) -> Vec<Vec<u8>> {
        self.b
            .events
            .iter()
            .filter_map(|e| match e {
                Ev::Datagram(_, data, _) => Some(data.clone()),
                _ => None,
            })
            .collect()
    }

    fn connections(node: &Node) -> usize {
        node.events
            .iter()
            .filter(|e| matches!(e, Ev::Connected(_)) || matches!(e, Ev::Datagram(_, _, true)))
            .count()
    }
}

fn ctx() -> Context {
    Context::new(b"session").unwrap()
}

// --- confirmation ---------------------------------------------------------------------

/// Scenario: a receive-only initiator still connects.
#[test]
fn a_receive_only_initiator_connects_with_a_keepalive() {
    let mut net = Net::new();
    net.connected();
    assert_eq!(net.a.events, vec![Ev::Connected(b"session".to_vec())]);
    assert_eq!(net.b.events, vec![Ev::Connected(b"session".to_vec())]);
    // A sent its first contact and one keepalive: 134 + 31 bytes.
    let lens: Vec<usize> = net.a.sent.iter().map(Vec::len).collect();
    assert_eq!(lens, vec![134, 31]);
    assert!(
        net.b
            .endpoint
            .is_live(&net.a.peer_id(), b"session", net.t())
    );
}

/// The first datagram confirms as a keepalive would, and is delivered.
#[test]
fn the_first_datagram_confirms_and_is_delivered() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    assert_eq!(
        net.b.events,
        vec![Ev::Datagram(b"session".to_vec(), b"hello".to_vec(), true)]
    );
    assert_eq!(net.a.events, vec![Ev::Connected(b"session".to_vec())]);
    assert_eq!(net.a.sent.len(), 2, "first contact, then the datagram");
}

/// Scenario: a replayed first contact never displaces a session.
#[test]
fn a_replayed_first_contact_never_displaces_the_session() {
    let mut net = Net::new();
    net.a_sends(b"one").unwrap();
    let first_contact = net.a.sent[0].clone();
    net.at(10);
    assert!(
        net.deliver(true, &first_contact).is_some(),
        "it pends, after 5 s"
    );
    net.at(16);
    net.a_sends(b"two").unwrap();
    assert_eq!(net.b_datagrams(), vec![b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(Net::connections(&net.b), 1);
}

/// Scenario: a rekey raises no connection event. Scenario: sending past 120 s
/// starts a rekey.
#[test]
fn a_rekey_is_silent() {
    let mut net = Net::new();
    net.a_sends(b"one").unwrap();
    net.at(121);
    let before = net.a.first_contacts_sent();
    net.a_sends(b"two").unwrap();
    assert_eq!(
        net.a.first_contacts_sent(),
        before + 1,
        "the send started a rekey"
    );
    net.at(122);
    net.a_sends(b"three").unwrap();
    assert_eq!(
        net.b_datagrams(),
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );
    assert_eq!(Net::connections(&net.a), 1);
    assert_eq!(Net::connections(&net.b), 1);
}

// --- the channel binding ---------------------------------------------------------------

fn bindings(net: &Net) -> (Option<ChannelBinding>, Option<ChannelBinding>) {
    (
        net.a.endpoint.channel_binding(&net.b.peer_id(), b"session"),
        net.b.endpoint.channel_binding(&net.a.peer_id(), b"session"),
    )
}

/// Scenarios: both ends see the same binding; a key renewal keeps it; no
/// session, no binding.
#[test]
fn both_ends_keep_one_binding_across_a_rekey() {
    let mut net = Net::new();
    assert_eq!(bindings(&net), (None, None), "no session yet");
    net.a_sends(b"one").unwrap();
    let (a, b) = bindings(&net);
    assert!(a.is_some());
    assert_eq!(a, b);

    net.at(121);
    let before = net.a.first_contacts_sent();
    net.a_sends(b"two").unwrap();
    net.at(122);
    net.a_sends(b"three").unwrap();
    assert_eq!(
        net.a.first_contacts_sent(),
        before + 1,
        "the keys were renewed"
    );
    assert_eq!(bindings(&net), (a, a));

    // Another context is another session, with none.
    assert_eq!(
        net.a.endpoint.channel_binding(&net.b.peer_id(), b"other"),
        None
    );
}

/// Scenario: a reopened session has a new binding; a dormant one has none.
#[test]
fn a_reopened_session_has_a_new_binding() {
    let mut net = Net::new();
    net.a_sends(b"zero").unwrap();
    let (old, _) = bindings(&net);
    net.at(300);
    assert_eq!(bindings(&net), (None, None), "dormant");
    net.a_sends(b"one").unwrap();
    let (a, b) = bindings(&net);
    assert!(a.is_some());
    assert_eq!(a, b);
    assert_ne!(a, old);
}

/// A reopening whose old keys expired but were not yet swept away is a new
/// channel too, not a renewal.
#[test]
fn a_reopening_before_the_sweep_has_a_new_binding() {
    let mut net = Net::new();
    net.a_sends(b"zero").unwrap();
    let (old, _) = bindings(&net);
    net.now = 300_000;
    net.a_sends(b"one").unwrap();
    let (a, b) = bindings(&net);
    assert_eq!(a, b);
    assert_ne!(a, old);
}

// --- slots --------------------------------------------------------------------------

/// Scenario: packets in flight across a rekey are delivered.
#[test]
fn packets_in_flight_across_a_rekey_are_delivered() {
    let mut net = Net::new();
    net.a_sends(b"one").unwrap();
    net.at(121);
    // A datagram sealed under the old keys, held back by the link...
    net.drop_to_b = true;
    net.a_sends(b"late").unwrap();
    let late = net
        .a
        .sent
        .iter()
        .rev()
        .find(|p| p[1] == 0x04)
        .unwrap()
        .clone();
    net.drop_to_b = false;
    // ...while the rekey completes on its retry.
    net.at(122);
    net.a_sends(b"new").unwrap();
    // The late one arrives after the new keys took over.
    net.deliver(true, &late);
    let datagrams = net.b_datagrams();
    assert!(datagrams.contains(&b"late".to_vec()), "{datagrams:?}");
    assert!(datagrams.contains(&b"new".to_vec()));
}

/// A packet that arrives late, after a newer one, does not move where the
/// session's packets go: the newest packet decides. Otherwise one packet still
/// in flight on an old path, or reordered between a relay's UDP and its TCP
/// link, takes the session back to a path that may no longer carry anything.
#[test]
fn a_late_packet_does_not_move_the_session_back() {
    let mut net = Net::new();
    net.a_sends(b"open").unwrap();
    // Two datagrams from A, held back by the link.
    net.drop_to_b = true;
    net.a_sends(b"older").unwrap();
    net.a_sends(b"newer").unwrap();
    net.drop_to_b = false;
    let n = net.a.sent.len();
    let (mut older, newer) = (net.a.sent[n - 2].clone(), net.a.sent[n - 1].clone());
    // The newer one arrives from A's address; the older one after it, from
    // another address. Both are accepted: the older is still in the window.
    net.deliver(true, &newer);
    let elsewhere: [u8; 6] = [10, 0, 0, 9, 0, 9];
    let mut out = [0u8; 2048];
    let late = net.b.endpoint.handle_packet(
        &mut older,
        Source::Direct(&elsewhere),
        net.t(),
        &mut net.b.policy,
        &mut net.b.entropy,
        &mut out,
    );
    assert!(matches!(late, Output::Event(Event::Datagram { .. })));
    // B's next packet goes where the newest one came from.
    let peer = net.a.peer_id();
    let now = net.t();
    let output = net
        .b
        .endpoint
        .send(
            Target::Peer(peer),
            b"session",
            b"reply",
            PATH,
            now,
            &mut net.b.policy,
            &mut net.b.entropy,
            &mut out,
        )
        .unwrap();
    let source = net.a.source;
    let Output::Transmit { to, .. } = output else {
        panic!("a packet")
    };
    assert_eq!(to, To::Direct(Source::Direct(&source).key().unwrap()));
}

/// Scenario: a deleted key pair opens nothing (expiry).
#[test]
fn an_expired_key_pair_opens_nothing() {
    let mut net = Net::new();
    net.a_sends(b"one").unwrap();
    let packet = net.a.sent[1].clone();
    net.at(181);
    assert_eq!(net.deliver(true, &packet), None);
    assert_eq!(net.b_datagrams(), vec![b"one".to_vec()]);
}

// --- rekey ------------------------------------------------------------------------------

/// Scenario: without the address, the peer renews the keys.
#[test]
fn a_responder_without_the_address_starts_no_handshake() {
    let mut net = Net::new();
    net.a_sends(b"one").unwrap();
    net.at(121);
    net.b_replies(b"reply").unwrap();
    assert_eq!(net.b.first_contacts_sent(), 0);
    assert!(
        net.a
            .events
            .contains(&Ev::Datagram(b"session".to_vec(), b"reply".to_vec(), false))
    );
}

/// Scenario: receiving past 120 s does not start a handshake.
#[test]
fn receiving_never_starts_a_handshake() {
    let mut net = Net::new();
    net.a_sends(b"0").unwrap();
    for second in (10..=150).step_by(10) {
        net.at(second);
        net.a_sends(b"x").unwrap();
    }
    assert_eq!(net.b.first_contacts_sent(), 0);
    assert_eq!(net.b.sent.iter().filter(|p| p[1] == 0x04).count(), 0);
}

/// Scenario: keys past 180 s are not used.
#[test]
fn keys_past_180_seconds_are_not_used() {
    let mut net = Net::new();
    net.a_sends(b"one").unwrap();
    net.at(181);
    assert_eq!(net.b_replies(b"too late"), Err(SendError::AddressUnknown));
}

// --- dormancy and the queue --------------------------------------------------------------

/// Scenario: a dormant session reopens on the next datagram, without a new
/// connection event; scenario: the queue is sent when the keys arrive.
#[test]
fn a_dormant_session_reopens_and_flushes_its_queue_in_order() {
    let mut net = Net::new();
    net.a_sends(b"zero").unwrap();
    net.now = 300_000;
    net.drop_to_b = true; // hold the reopening until the queue fills
    net.a_sends(b"one").unwrap();
    net.a_sends(b"two").unwrap();
    net.a_sends(b"three").unwrap();
    net.drop_to_b = false;
    net.at(301); // the retry at 1 s goes through
    assert_eq!(
        net.b_datagrams(),
        vec![
            b"zero".to_vec(),
            b"one".to_vec(),
            b"two".to_vec(),
            b"three".to_vec()
        ]
    );
    assert_eq!(Net::connections(&net.a), 1, "{:?}", net.a.events);
    assert_eq!(Net::connections(&net.b), 1, "{:?}", net.b.events);
}

/// Scenario: a full queue refuses with a named error.
#[test]
fn a_full_queue_refuses_and_keeps_what_it_holds() {
    let mut net = Net::new();
    net.drop_to_b = true;
    net.a_sends(&[1; 500]).unwrap();
    net.a_sends(&[2; 500]).unwrap();
    assert_eq!(
        net.a_sends(&[3; 500]),
        Err(SendError::QueueFull(QueueFull { limit: 1024 }))
    );
    net.drop_to_b = false;
    net.at(1);
    assert_eq!(net.b_datagrams(), vec![vec![1; 500], vec![2; 500]]);
}

/// Scenario: a failed reopening reports why (refused).
#[test]
fn a_refused_reopening_reports_the_code() {
    let mut net = Net::new();
    let code = RefusalCode::application(0x0101).unwrap();
    net.b.policy.decision = Decision::Refuse { code, psk: None };
    net.a_sends(b"queued").unwrap();
    assert_eq!(
        net.a.events,
        vec![Ev::ReopenFailed(
            b"session".to_vec(),
            DialError::Refused(code)
        )]
    );
    assert!(net.b_datagrams().is_empty());
}

/// Scenario: a failed reopening reports why (no response).
#[test]
fn an_unanswered_reopening_reports_no_response() {
    let mut net = Net::new();
    net.drop_to_b = true;
    net.a_sends(b"queued").unwrap();
    for second in 1..=16 {
        net.at(second);
    }
    assert_eq!(
        net.a.events,
        vec![Ev::ReopenFailed(b"session".to_vec(), DialError::NoResponse)]
    );
}

// --- path size and targets ----------------------------------------------------------------

/// Scenarios: a datagram that fits is sent; one that does not is refused.
#[test]
fn the_path_size_is_respected() {
    let mut net = Net::new();
    net.a_sends(b"open").unwrap();
    let now = net.t();
    let address = net.b.address();
    let mut out = [0u8; 2048];
    let sent = net.a.endpoint.send(
        Target::Address(&address),
        b"session",
        &[0; 1280],
        1400,
        now,
        &mut net.a.policy,
        &mut net.a.entropy,
        &mut out,
    );
    assert!(matches!(sent, Ok(Output::Transmit { len: 1311, .. })));
    let refused = net.a.endpoint.send(
        Target::Address(&address),
        b"session",
        &[0; 1280],
        1280,
        now,
        &mut net.a.policy,
        &mut net.a.entropy,
        &mut out,
    );
    assert_eq!(
        refused,
        Err(SendError::TooLarge {
            packet: 1311,
            path: 1280
        })
    );
}

/// Scenarios: a reply by `PeerId` works while live; a dormant session cannot be
/// reopened by `PeerId`.
#[test]
fn a_peer_id_reaches_only_a_live_session() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    net.b_replies(b"hi").unwrap();
    assert!(
        net.a
            .events
            .contains(&Ev::Datagram(b"session".to_vec(), b"hi".to_vec(), false))
    );
    net.at(400);
    assert_eq!(net.b_replies(b"later"), Err(SendError::AddressUnknown));
}

/// Scenario (relay change): a send by `PeerId` waits for a pending
/// handshake's confirmation, without a dial, and leaves under the new keys.
#[test]
fn a_send_by_peer_id_waits_for_a_pending_handshake() {
    let mut net = Net::new();
    let now = net.t();
    let address = net.b.address();
    let mut out = [0u8; 2048];
    let Ok(Output::Transmit { len, .. }) = net.a.endpoint.connect(
        &address,
        b"session",
        now,
        &mut net.a.policy,
        &mut net.a.entropy,
        &mut out,
    ) else {
        panic!("a dial");
    };
    let first = out[..len].to_vec();
    // B answers, and holds a pending handshake.
    let response = net.deliver(true, &first).unwrap();
    // B sends by PeerId before A confirms: queued, nothing sent, no dial.
    let sent_before = net.b.sent.len();
    let peer_a = net.a.peer_id();
    let result = net.b.endpoint.send(
        Target::Peer(peer_a),
        b"session",
        b"early",
        PATH,
        now,
        &mut net.b.policy,
        &mut net.b.entropy,
        &mut out,
    );
    assert_eq!(result, Ok(Output::Nothing));
    assert_eq!(net.b.sent.len(), sent_before);
    // A completes and confirms; B's datagram leaves.
    net.deliver(false, &response);
    net.settle();
    assert!(
        net.a
            .events
            .contains(&Ev::Datagram(b"session".to_vec(), b"early".to_vec(), false))
    );
    assert_eq!(net.b.first_contacts_sent(), 0, "B never dialled");
}

/// Scenario (relay change): a pending handshake that is never confirmed sends
/// nothing, and no dial starts.
#[test]
fn an_unconfirmed_pending_handshake_sends_nothing() {
    let mut net = Net::new();
    let now = net.t();
    let address = net.b.address();
    let mut out = [0u8; 2048];
    let Ok(Output::Transmit { len, .. }) = net.a.endpoint.connect(
        &address,
        b"session",
        now,
        &mut net.a.policy,
        &mut net.a.entropy,
        &mut out,
    ) else {
        panic!("a dial");
    };
    let first = out[..len].to_vec();
    net.deliver(true, &first).unwrap();
    let peer_a = net.a.peer_id();
    let result = net.b.endpoint.send(
        Target::Peer(peer_a),
        b"session",
        b"never",
        PATH,
        now,
        &mut net.b.policy,
        &mut net.b.entropy,
        &mut out,
    );
    assert_eq!(result, Ok(Output::Nothing));
    let sent = net.b.sent.len();
    // A never hears the response; B's pending handshake expires.
    net.drop_to_a = true;
    net.at(30);
    assert_eq!(net.b.sent.len(), sent);
    assert_eq!(net.b.first_contacts_sent(), 0);
}

// --- close ------------------------------------------------------------------------------------

/// Scenario: a close is reported with its code.
#[test]
fn a_close_is_reported_with_its_code() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let now = net.t();
    let peer_b = net.b.peer_id();
    let mut out = [0u8; 2048];
    let Output::Transmit { len, .. } = net
        .a
        .endpoint
        .close(peer_b, b"session", 0x0101, now, &mut out)
    else {
        panic!("a close is sent");
    };
    net.deliver(true, &out[..len]);
    assert!(
        net.b
            .events
            .contains(&Ev::Closed(b"session".to_vec(), 0x0101, true))
    );
    assert!(!net.a.endpoint.is_live(&peer_b, b"session", now));
    assert!(!net.b.endpoint.is_live(&net.a.peer_id(), b"session", now));
}

/// Scenario: a forged or replayed close closes nothing.
#[test]
fn a_forged_close_closes_nothing() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let mut forged = net.a.sent[1].clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert_eq!(net.deliver(true, &forged), None);
    assert!(
        net.b
            .endpoint
            .is_live(&net.a.peer_id(), b"session", net.t())
    );
}

/// Scenario: revocation reaches pending handshakes, and every context.
#[test]
fn revocation_closes_everything() {
    let mut net = Net::new();
    net.a_sends(b"one").unwrap();
    // A second context.
    let now = net.t();
    let address = net.b.address();
    let mut out = [0u8; 2048];
    if let Ok(Output::Transmit { len, .. }) = net.a.endpoint.send(
        Target::Address(&address),
        b"other",
        b"two",
        PATH,
        now,
        &mut net.a.policy,
        &mut net.a.entropy,
        &mut out,
    ) {
        let packet = out[..len].to_vec();
        net.settle_with(VecDeque::from([(true, packet)]));
    }
    // A pending handshake: a fresh first contact B answers but nobody confirms.
    net.at(10);
    let pending_contact = {
        let mut probe = Node::new(1, [10, 0, 0, 9, 0, 9], 999);
        let b_source = net.b.source;
        probe
            .endpoint
            .set_hint(address.peer_id(), &b_source, net.t())
            .unwrap();
        let mut out = [0u8; 2048];
        let Output::Transmit { len, .. } = probe
            .endpoint
            .connect(
                &address,
                b"session",
                net.t(),
                &mut probe.policy,
                &mut probe.entropy,
                &mut out,
            )
            .unwrap()
        else {
            panic!();
        };
        out[..len].to_vec()
    };
    assert!(net.deliver(true, &pending_contact).is_some());

    net.b.endpoint.close_peer(net.a.peer_id(), 0x0102);
    net.settle();
    let closes = net
        .a
        .events
        .iter()
        .filter(|e| matches!(e, Ev::Closed(_, 0x0102, true)))
        .count();
    assert_eq!(closes, 2, "{:?}", net.a.events);
    assert!(
        !net.b
            .endpoint
            .is_live(&net.a.peer_id(), b"session", net.t())
    );
    assert!(!net.b.endpoint.is_live(&net.a.peer_id(), b"other", net.t()));
}

// --- the passive keepalive ---------------------------------------------------------------------

/// Scenario: off by default.
#[test]
fn the_passive_keepalive_is_off_by_default() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let sent = net.b.sent.len();
    for second in 1..=60 {
        net.at(second);
    }
    assert_eq!(net.b.sent.len(), sent);
}

/// Scenario: on when enabled: one keepalive 10 s after received data.
#[test]
fn the_passive_keepalive_when_enabled() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    net.b
        .endpoint
        .set_passive_keepalive(net.a.peer_id(), b"session", true);
    let sent = net.b.sent.len();
    for second in 1..=9 {
        net.at(second);
    }
    assert_eq!(net.b.sent.len(), sent);
    net.at(10);
    assert_eq!(net.b.sent.len(), sent + 1);
    assert_eq!(net.b.sent.last().unwrap().len(), 31);
    for second in 11..=60 {
        net.at(second);
    }
    assert_eq!(
        net.b.sent.len(),
        sent + 1,
        "no other until it receives again"
    );
}

// --- inner types and anti-replay ----------------------------------------------------------------

/// Crafts a packet from A to B under A's current keys.
fn crafted(net: &mut Net, inner_type: u8, data: &[u8]) -> Vec<u8> {
    let key = (net.b.peer_id(), ctx());
    let session = net.a.endpoint.sessions.get_mut(&key).unwrap();
    let pair = session.current.as_mut().unwrap();
    let mut out = [0u8; 2048];
    let len = transport::seal(
        &pair.send,
        pair.remote_index,
        pair.next_counter,
        inner_type,
        data,
        &mut out,
    )
    .unwrap();
    pair.next_counter += 1;
    out[..len].to_vec()
}

/// Scenario: a malformed close or keepalive is ignored.
#[test]
fn malformed_closes_and_keepalives_are_ignored() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    for (inner_type, data) in [
        (inner::KEEPALIVE, &b"x"[..]),
        (inner::CLOSE, &[0, 0][..]),
        (inner::CLOSE, &[1][..]),
        (inner::CLOSE, &[1, 0, 0][..]),
    ] {
        let packet = crafted(&mut net, inner_type, data);
        assert_eq!(net.deliver(true, &packet), None);
    }
    assert!(
        net.b
            .endpoint
            .is_live(&net.a.peer_id(), b"session", net.t())
    );
    assert!(!net.b.events.iter().any(|e| matches!(e, Ev::Closed(..))));
}

/// Scenario: a reserved inner type is ignored, and refused as a replay.
#[test]
fn a_reserved_inner_type_is_ignored_and_not_replayable() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let events = net.b.events.len();
    let packet = crafted(&mut net, 0x08, b"later");
    assert_eq!(net.deliver(true, &packet), None);
    assert_eq!(net.deliver(true, &packet), None);
    assert_eq!(net.b.events.len(), events);
    // Scenario: a duplicate is refused (a datagram, delivered once).
    let datagram = crafted(&mut net, inner::DATAGRAM, b"once");
    net.deliver(true, &datagram);
    net.deliver(true, &datagram);
    assert_eq!(
        net.b_datagrams()
            .iter()
            .filter(|d| d.as_slice() == b"once")
            .count(),
        1
    );
}

// --- simulation ------------------------------------------------------------------------

/// A deterministic generator for the link's decisions.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

/// A link that loses, duplicates and delays (so reorders) packets, and knows
/// which datagram each transport packet a sender sealed carries.
struct Lossy {
    net: Net,
    rng: Rng,
    in_flight: Vec<(u64, bool, Vec<u8>)>,
    payload_of: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    /// Datagrams whose packet the link delivered at least once, per direction.
    delivered_to_b: std::collections::BTreeSet<Vec<u8>>,
    delivered_to_a: std::collections::BTreeSet<Vec<u8>>,
}

impl Lossy {
    fn new(seed: u64) -> Self {
        Self {
            net: Net::new(),
            rng: Rng(seed),
            in_flight: Vec::new(),
            payload_of: std::collections::BTreeMap::new(),
            delivered_to_b: std::collections::BTreeSet::new(),
            delivered_to_a: std::collections::BTreeSet::new(),
        }
    }

    fn launch(&mut self, to_b: bool, packet: Vec<u8>) {
        if self.rng.chance(10) {
            return; // lost
        }
        let copies = if self.rng.chance(5) { 2 } else { 1 };
        for _ in 0..copies {
            let delay = 10 + self.rng.next() % 51;
            self.in_flight
                .push((self.net.now + delay, to_b, packet.clone()));
        }
    }

    fn poll_both(&mut self) {
        for a in [true, false] {
            let mut queue = VecDeque::new();
            self.net.poll_node(a, &mut queue);
            for (from_a, packet) in queue {
                self.launch(from_a, packet);
            }
        }
    }

    fn deliver_due(&mut self) {
        let now = self.net.now;
        let mut due: Vec<(u64, bool, Vec<u8>)> = Vec::new();
        self.in_flight.retain(|(at, to_b, packet)| {
            if *at <= now {
                due.push((*at, *to_b, packet.clone()));
                false
            } else {
                true
            }
        });
        due.sort_by_key(|(at, _, _)| *at);
        for (_, to_b, packet) in due {
            if let Some(payload) = self.payload_of.get(&packet) {
                if to_b {
                    self.delivered_to_b.insert(payload.clone());
                } else {
                    self.delivered_to_a.insert(payload.clone());
                }
            }
            if let Some(answer) = self.net.deliver(to_b, &packet) {
                self.launch(!to_b, answer);
            }
        }
    }

    /// A sends by address; B replies by `PeerId`. Returns whether a packet left
    /// at once (live keys), which is the only way datagrams leave in this test.
    fn send(&mut self, from_a: bool, payload: &[u8]) -> bool {
        let now = self.net.t();
        let mut out = [0u8; 2048];
        let b_address = self.net.b.address();
        let a_peer = self.net.a.peer_id();
        let (node, target) = if from_a {
            (&mut self.net.a, Target::Address(&b_address))
        } else {
            (&mut self.net.b, Target::Peer(a_peer))
        };
        let result = node.endpoint.send(
            target,
            b"session",
            payload,
            PATH,
            now,
            &mut node.policy,
            &mut node.entropy,
            &mut out,
        );
        match result {
            Ok(Output::Transmit { len, .. }) if out[1] == 0x04 => {
                let packet = out[..len].to_vec();
                node.sent.push(packet.clone());
                self.payload_of.insert(packet.clone(), payload.to_vec());
                self.launch(from_a, packet);
                true
            }
            _ => false,
        }
    }
}

/// Every datagram delivered was sent, none twice, and the loss seen equals the
/// link's: across several rekeys, over a link that loses 10%, duplicates 5%
/// and reorders by up to 50 ms, each side receives exactly the datagrams whose
/// packet the link delivered.
#[test]
fn datagrams_survive_a_lossy_reordering_duplicating_link() {
    for seed in [1, 2, 3] {
        let mut sim = Lossy::new(seed);
        // Connected over a clean link first.
        sim.net.connected();
        let mut sequence = 0u32;
        let mut sent = 0;
        // Ten minutes: four rekeys' worth.
        while sim.net.now < 600_000 {
            if sim.net.now.is_multiple_of(100) {
                sequence += 1;
                assert!(
                    sim.send(true, &sequence.to_le_bytes()),
                    "seed {seed}: A always has live keys at {} ms",
                    sim.net.now
                );
                sent += 1;
                let mut reply = vec![0xB0];
                reply.extend_from_slice(&sequence.to_le_bytes());
                let _ = sim.send(false, &reply);
            }
            sim.poll_both();
            sim.deliver_due();
            sim.net.now += 5;
        }
        // Let the last packets land.
        for _ in 0..20 {
            sim.deliver_due();
            sim.net.now += 5;
        }
        let received_by_b = sim.net.b_datagrams();
        let received_by_a: Vec<Vec<u8>> = sim
            .net
            .a
            .events
            .iter()
            .filter_map(|e| match e {
                Ev::Datagram(_, data, _) => Some(data.clone()),
                _ => None,
            })
            .collect();
        for (side, received, delivered) in [
            ("B", &received_by_b, &sim.delivered_to_b),
            ("A", &received_by_a, &sim.delivered_to_a),
        ] {
            let unique: std::collections::BTreeSet<_> = received.iter().cloned().collect();
            assert_eq!(
                unique.len(),
                received.len(),
                "seed {seed}: {side} got a datagram twice"
            );
            assert_eq!(
                &unique, delivered,
                "seed {seed}: {side} received other than what the link delivered"
            );
        }
        assert!(sent >= 6000);
        assert!(
            received_by_a.len() > 4000,
            "seed {seed}: B's replies flowed too"
        );
        assert!(
            sim.net.a.first_contacts_sent() >= 5,
            "seed {seed}: rekeys happened"
        );
        assert_eq!(Net::connections(&sim.net.a), 1, "seed {seed}");
        assert_eq!(Net::connections(&sim.net.b), 1, "seed {seed}");
    }
}

/// Simultaneous dials: both sides reopen at the same instant; both handshakes
/// complete, and datagrams flow both ways afterwards.
#[test]
fn simultaneous_dials_converge() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    net.at(400);
    // Both dormant. Both send by address at the same instant.
    let a_address = net.a.address();
    let b_address = net.b.address();
    let now = net.t();
    let mut queue = VecDeque::new();
    for (from_a, address) in [(true, b_address), (false, a_address)] {
        let node = if from_a { &mut net.a } else { &mut net.b };
        let mut out = [0u8; 2048];
        if let Ok(Output::Transmit { len, .. }) = node.endpoint.send(
            Target::Address(&address),
            b"session",
            if from_a { b"from a" } else { b"from b" },
            PATH,
            now,
            &mut node.policy,
            &mut node.entropy,
            &mut out,
        ) {
            node.sent.push(out[..len].to_vec());
            queue.push_back((from_a, out[..len].to_vec()));
        }
    }
    net.settle_with(queue);
    assert!(net.b_datagrams().contains(&b"from a".to_vec()));
    assert!(net.a.events.contains(&Ev::Datagram(
        b"session".to_vec(),
        b"from b".to_vec(),
        false
    )));
    // And afterwards, in both directions.
    net.at(401);
    net.a_sends(b"after a").unwrap();
    net.b_replies(b"after b").unwrap();
    assert!(net.b_datagrams().contains(&b"after a".to_vec()));
    assert!(net.a.events.contains(&Ev::Datagram(
        b"session".to_vec(),
        b"after b".to_vec(),
        false
    )));
}

// --- the idle month ---------------------------------------------------------------------

/// Scenario: an idle month sends nothing. The endpoints are polled at every
/// deadline they return; once the keys expire, neither sends a packet nor
/// returns a deadline.
#[test]
fn an_idle_month_sends_nothing() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let month = 30 * 24 * 3600 * 1000u64;
    let mut wakeups = 0;
    loop {
        let mut next = None;
        for a in [true, false] {
            let now = net.t();
            let node = if a { &mut net.a } else { &mut net.b };
            let mut out = [0u8; 2048];
            match node
                .endpoint
                .poll(now, &mut node.policy, &mut node.entropy, &mut out)
            {
                Poll::Wait(at) => next = Some(next.map_or(at, |n: Instant| n.min(at))),
                Poll::Idle => {}
                other => panic!("nothing is due at rest, got {other:?}"),
            }
        }
        let Some(at) = next else { break };
        assert!(at.as_millis() < month);
        net.now = at.as_millis();
        net.settle();
        wakeups += 1;
    }
    let packets = net.a.sent.len() + net.b.sent.len();
    std::println!(
        "idle month: {packets} packets in all (all in the first exchange), {wakeups} deadlines, last at {} ms",
        net.now
    );
    assert!(net.now <= 181_000, "the last deadline is the keys' expiry");
    // Nothing more for the rest of the month.
    net.now = month;
    net.settle();
    assert_eq!(net.a.sent.len() + net.b.sent.len(), packets);
    for node in [&mut net.a, &mut net.b] {
        let mut out = [0u8; 2048];
        assert_eq!(
            node.endpoint.poll(
                Instant::from_millis(month),
                &mut node.policy,
                &mut node.entropy,
                &mut out
            ),
            Poll::Idle
        );
    }
}

/// The cost of sealing and opening a 1,280-byte datagram, and the throughput of
/// one session in memory. Ignored by default; run it with
/// `cargo test -p convesso-core --release --lib transport_time -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, meaningful only in release"]
fn transport_time() {
    let key = [7u8; 32];
    let data = [0x5a; 1280];
    let mut out = [0u8; 1400];
    let mut seal_times = Vec::with_capacity(10_000);
    let mut open_times = Vec::with_capacity(10_000);
    for counter in 0..10_000u64 {
        let started = std::time::Instant::now();
        let len = transport::seal(&key, 1, counter, inner::DATAGRAM, &data, &mut out).unwrap();
        seal_times.push(started.elapsed());
        let started = std::time::Instant::now();
        let opened = transport::open(&key, &mut out[..len]).unwrap();
        open_times.push(started.elapsed());
        assert_eq!(opened.data.len(), 1280);
    }
    seal_times.sort_unstable();
    open_times.sort_unstable();

    // One session, both directions, through the endpoints.
    let mut net = Net::new();
    net.connected();
    let address = net.b.address();
    let a_peer = net.a.peer_id();
    let started = std::time::Instant::now();
    let rounds = 20_000;
    for i in 0..rounds {
        let now = net.t();
        let mut out = [0u8; 2048];
        let sent = net.a.endpoint.send(
            Target::Address(&address),
            b"session",
            &data,
            PATH,
            now,
            &mut net.a.policy,
            &mut net.a.entropy,
            &mut out,
        );
        let Ok(Output::Transmit { len, .. }) = sent else {
            panic!("round {i}");
        };
        let mut packet = out[..len].to_vec();
        let mut answer = [0u8; 2048];
        let delivered = net.b.endpoint.handle_packet(
            &mut packet,
            Source::Direct(&net.a.source),
            now,
            &mut net.b.policy,
            &mut net.b.entropy,
            &mut answer,
        );
        assert!(matches!(delivered, Output::Event(Event::Datagram { .. })));
        let sent = net.b.endpoint.send(
            Target::Peer(a_peer),
            b"session",
            &data,
            PATH,
            now,
            &mut net.b.policy,
            &mut net.b.entropy,
            &mut answer,
        );
        let Ok(Output::Transmit { len, .. }) = sent else {
            panic!("reply {i}");
        };
        let mut packet = answer[..len].to_vec();
        let delivered = net.a.endpoint.handle_packet(
            &mut packet,
            Source::Direct(&net.b.source),
            now,
            &mut net.a.policy,
            &mut net.a.entropy,
            &mut out,
        );
        assert!(matches!(delivered, Output::Event(Event::Datagram { .. })));
    }
    let elapsed = started.elapsed();
    let datagrams = 2.0 * f64::from(rounds);
    std::println!(
        "1,280-byte datagram, median of 10,000: seal {:?}, open {:?}; one session, both directions: {:.0} datagrams/s ({:.0} Mbit/s of data)",
        seal_times[5000],
        open_times[5000],
        datagrams / elapsed.as_secs_f64(),
        datagrams * 1280.0 * 8.0 / elapsed.as_secs_f64() / 1e6
    );
}

// --- candidates -----------------------------------------------------------------------

fn candidates(generation: u16, addresses: &[&str]) -> Vec<u8> {
    let list: Vec<crate::paths::Candidate> = addresses
        .iter()
        .map(|a| crate::paths::Candidate {
            kind: crate::paths::CandidateKind::Public,
            address: a.parse().unwrap(),
        })
        .collect();
    let mut out = [0u8; crate::paths::MAX_CANDIDATES_LEN];
    let len = crate::paths::encode_candidates(generation, &list, &mut out).unwrap();
    out[..len].to_vec()
}

fn listed(endpoint: &Endpoint<Mcu>, peer: &PeerId) -> Vec<core::net::SocketAddr> {
    endpoint
        .peer_candidates(peer, b"session")
        .iter()
        .map(|c| c.address)
        .collect()
}

fn addr(text: &str) -> core::net::SocketAddr {
    text.parse().unwrap()
}

/// Scenario: path messages never reach the application as data.
#[test]
fn path_messages_never_reach_the_application_as_data() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let events = net.b.events.len();
    for (inner_type, data) in [
        (inner::CANDIDATES, candidates(1, &["192.0.2.1:9"])),
        (inner::ANSWER, vec![7; 15]),
    ] {
        let packet = crafted(&mut net, inner_type, &data);
        assert_eq!(net.deliver(true, &packet), None);
    }
    // A probe is answered, with a packet, never an event.
    let packet = crafted(&mut net, inner::PROBE, &[7; 8]);
    assert!(net.deliver(true, &packet).is_some());
    assert_eq!(net.b.events.len(), events);
}

/// Scenario: stream frames never reach the application as datagrams; they
/// are handed up as frames, unread, once each.
#[test]
fn stream_frames_are_handed_up_never_as_datagrams() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let datagrams = net.b_datagrams().len();
    let mut packets = Vec::new();
    for (inner_type, data) in [
        (inner::STREAM_DATA, &b"any bytes, unread"[..]),
        (inner::STREAM_ACK, &[0xff; 3][..]),
        (inner::STREAM_DATA, &[][..]),
    ] {
        let packet = crafted(&mut net, inner_type, data);
        assert_eq!(
            net.deliver(true, &packet),
            None,
            "nothing is sent for a frame"
        );
        packets.push(packet);
    }
    for packet in &packets {
        net.deliver(true, packet);
    }
    let frames: Vec<_> = net
        .b
        .events
        .iter()
        .filter_map(|e| match e {
            Ev::Frame(context, kind, data, relayed) => {
                Some((context.clone(), *kind, data.clone(), *relayed))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        frames,
        [
            (
                ctx().as_bytes().to_vec(),
                FrameKind::Data,
                b"any bytes, unread".to_vec(),
                false
            ),
            (
                ctx().as_bytes().to_vec(),
                FrameKind::Ack,
                vec![0xff; 3],
                false
            ),
            (ctx().as_bytes().to_vec(), FrameKind::Data, vec![], false),
        ],
        "each frame once, replays refused"
    );
    assert_eq!(net.b_datagrams().len(), datagrams);
}

/// A frame goes as a datagram would: one packet, 31 bytes longer than the
/// frame, handed up whole; and datagrams keep flowing beside frames.
#[test]
fn a_frame_is_sent_as_a_datagram_would_be() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let sent = net.a.sent.len();
    let frame = vec![0x5a; 1349];
    net.a_sends_frame(FrameKind::Data, &frame).unwrap();
    assert_eq!(net.a.sent.len(), sent + 1);
    assert_eq!(net.a.sent[sent].len(), 1380);
    net.a_sends_frame(FrameKind::Ack, b"ack").unwrap();
    assert_eq!(
        net.b_frames(),
        vec![(FrameKind::Data, frame), (FrameKind::Ack, b"ack".to_vec())]
    );
    net.a_sends(b"after").unwrap();
    assert_eq!(
        net.b_datagrams(),
        vec![b"hello".to_vec(), b"after".to_vec()]
    );
}

/// Scenario: a frame on a dormant session is refused, not queued, and starts
/// no handshake.
#[test]
fn a_frame_on_a_dormant_session_is_refused_not_queued() {
    let mut net = Net::new();
    let contacts = net.a.first_contacts_sent();
    assert_eq!(
        net.a_sends_frame(FrameKind::Data, b"frame"),
        Err(SendError::NoKeys),
        "no session yet"
    );
    net.a_sends(b"hello").unwrap();
    net.at(200);
    let contacts_after = net.a.first_contacts_sent();
    let sent = net.a.sent.len();
    assert_eq!(
        net.a_sends_frame(FrameKind::Data, b"frame"),
        Err(SendError::NoKeys),
        "keys expired"
    );
    assert_eq!(net.a.first_contacts_sent(), contacts_after);
    assert_eq!(net.a.sent.len(), sent, "nothing sent");
    let key = (net.b.peer_id(), ctx());
    assert!(
        net.a
            .endpoint
            .sessions
            .get(&key)
            .is_none_or(|session| session.queue.is_empty()),
        "nothing queued"
    );
    assert!(contacts_after > contacts);
    assert!(net.b_frames().is_empty());
}

/// Scenario: an oversized frame is refused, naming both sizes.
#[test]
fn an_oversized_frame_is_refused() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let sent = net.a.sent.len();
    assert_eq!(
        net.a_sends_frame(FrameKind::Data, &[0; 1350]),
        Err(SendError::TooLarge {
            packet: 1381,
            path: 1380
        })
    );
    assert_eq!(net.a.sent.len(), sent);
}

/// A frame sent past 120 s starts a rekey, as a datagram does.
#[test]
fn a_frame_past_120_seconds_starts_a_rekey() {
    let mut net = Net::new();
    net.a_sends(b"one").unwrap();
    net.at(121);
    let before = net.a.first_contacts_sent();
    net.a_sends_frame(FrameKind::Data, b"frame").unwrap();
    assert_eq!(net.a.first_contacts_sent(), before + 1);
    assert_eq!(net.b_frames(), vec![(FrameKind::Data, b"frame".to_vec())]);
}

/// Scenario: an old or malformed list changes nothing, and is not answered.
#[test]
fn an_old_or_malformed_list_changes_nothing() {
    let mut net = Net::new();
    net.b.endpoint.set_local_addresses(&[addr("10.0.0.2:2")]);
    net.a_sends(b"hello").unwrap();
    let a = net.a.peer_id();
    let before = net.b.sent.len();

    // A list, received whole: B keeps it, and tells A its own, once.
    let packet = crafted(
        &mut net,
        inner::CANDIDATES,
        &candidates(5, &["192.0.2.1:9"]),
    );
    net.settle_with(VecDeque::from([(true, packet)]));
    assert_eq!(listed(&net.b.endpoint, &a), [addr("192.0.2.1:9")]);
    let b = net.b.peer_id();
    assert_eq!(
        net.a.endpoint.peer_candidates(&b, b"session"),
        net.b.endpoint.candidates(),
        "B told A its own"
    );
    let sent = net.b.sent.len();
    assert!(sent > before);

    let mut count_nine = candidates(1, &["192.0.2.2:9"; 8]);
    count_nine[2] = 9;
    let mut family_five = candidates(9, &["192.0.2.3:9"]);
    family_five[4] = 0x05;
    for data in [
        candidates(5, &["192.0.2.4:9"]),
        candidates(4, &["192.0.2.5:9"]),
        count_nine,
        family_five,
    ] {
        let packet = crafted(&mut net, inner::CANDIDATES, &data);
        net.settle_with(VecDeque::from([(true, packet)]));
    }
    assert_eq!(listed(&net.b.endpoint, &a), [addr("192.0.2.1:9")]);
    assert_eq!(net.b.sent.len(), sent, "nothing in response");

    // A higher generation replaces it, and needs no answer either.
    let packet = crafted(
        &mut net,
        inner::CANDIDATES,
        &candidates(6, &["192.0.2.6:9"]),
    );
    net.settle_with(VecDeque::from([(true, packet)]));
    assert_eq!(listed(&net.b.endpoint, &a), [addr("192.0.2.6:9")]);
    assert_eq!(net.b.sent.len(), sent);
}

/// Scenario: an excluded prefix is never offered nor used. B excludes the
/// prefix A is in: what A proposes there is dropped, and packets from A's
/// address do not become the session's path.
#[test]
fn an_excluded_prefix_never_becomes_a_path() {
    let mut net = Net::new();
    net.b
        .endpoint
        .exclude_prefix("10.0.0.0".parse().unwrap(), 30)
        .unwrap();
    net.a_sends(b"hello").unwrap();
    assert_eq!(net.b_datagrams(), [b"hello".to_vec()]);
    let a = net.a.peer_id();
    let key = (a, ctx());
    assert_eq!(net.b.endpoint.sessions.get(&key).unwrap().last_source, None);

    let packet = crafted(
        &mut net,
        inner::CANDIDATES,
        &candidates(1, &["10.0.0.1:1", "192.0.2.1:9"]),
    );
    net.settle_with(VecDeque::from([(true, packet)]));
    assert_eq!(listed(&net.b.endpoint, &a), [addr("192.0.2.1:9")]);

    // B has no path to A: neither the source nor its hint, which is excluded.
    let sent = net.b.sent.len();
    net.b_replies(b"back").unwrap();
    assert_eq!(net.b.sent.len(), sent);
}

/// A prefix excluded while it is a session's path stops being one.
#[test]
fn excluding_the_current_path_ends_it() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let key = (net.a.peer_id(), ctx());
    assert!(
        net.b
            .endpoint
            .sessions
            .get(&key)
            .unwrap()
            .last_source
            .is_some()
    );
    net.b
        .endpoint
        .exclude_prefix("10.0.0.1".parse().unwrap(), 32)
        .unwrap();
    assert_eq!(net.b.endpoint.sessions.get(&key).unwrap().last_source, None);
}

/// New keys: the peer may have restarted, so each side's list is sent again,
/// and the next list received is taken whatever its generation.
#[test]
fn new_keys_send_the_list_again() {
    let mut net = Net::new();
    net.b.endpoint.set_local_addresses(&[addr("10.0.0.2:2")]);
    net.a_sends(b"hello").unwrap();
    let packet = crafted(
        &mut net,
        inner::CANDIDATES,
        &candidates(5, &["192.0.2.1:9"]),
    );
    net.settle_with(VecDeque::from([(true, packet)]));
    let sent = net.b.sent.len();

    // Past REKEY_AFTER, A's send starts a handshake; B answers it and sends
    // its list again under the new keys.
    net.at(130);
    net.a_sends(b"later").unwrap();
    assert!(net.b.sent.len() >= sent + 2, "a response, then B's list");
    // A's own list (the address B's answer told it it is seen at), of a
    // generation below the 5 accepted before, is taken under the new keys.
    let a = net.a.peer_id();
    let own = net.a.endpoint.candidates().to_vec();
    assert!(!own.is_empty());
    assert!(net.a.endpoint.own.list.generation < 5);
    assert_eq!(net.b.endpoint.peer_candidates(&a, b"session"), own);
}

/// A session that goes dormant forgets the peer's candidates with its keys.
#[test]
fn a_dormant_session_forgets_the_peer_candidates() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let packet = crafted(
        &mut net,
        inner::CANDIDATES,
        &candidates(1, &["192.0.2.1:9"]),
    );
    net.settle_with(VecDeque::from([(true, packet)]));
    let a = net.a.peer_id();
    assert_eq!(listed(&net.b.endpoint, &a).len(), 1);
    net.at(200);
    assert!(listed(&net.b.endpoint, &a).is_empty());
}

fn answer(nonce: [u8; 8], seen: &str) -> Vec<u8> {
    let mut out = [0u8; 27];
    let len = crate::paths::encode_answer(&nonce, addr(seen), &mut out).unwrap();
    out[..len].to_vec()
}

/// Scenario: a forged probe or answer moves nothing. B probes A's candidate
/// 192.0.2.1:9, and its probes are lost. Answers from A's address (10.0.0.1:1)
/// with another nonce, or with the right nonce but from an address B did not
/// probe, or that do not open under the keys, validate no path, and B sends
/// nothing in response.
#[test]
fn a_forged_answer_moves_nothing() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    net.drop_to_a = true;
    let packet = crafted(
        &mut net,
        inner::CANDIDATES,
        &candidates(1, &["192.0.2.1:9"]),
    );
    net.settle_with(VecDeque::from([(true, packet)]));
    let key = (net.a.peer_id(), ctx());
    let attempt = net.b.endpoint.sessions.get(&key).unwrap().paths.attempt;
    let nonce = attempt.expect("an attempt").nonces[0];
    let sent = net.b.sent.len();

    let mut forged = vec![
        crafted(&mut net, inner::ANSWER, &answer([0xEE; 8], "10.0.0.2:2")),
        crafted(&mut net, inner::ANSWER, &answer(nonce, "10.0.0.2:2")),
    ];
    let mut unopenable = forged[1].clone();
    let last = unopenable.len() - 1;
    unopenable[last] ^= 1;
    forged.push(unopenable);
    for packet in forged {
        net.settle_with(VecDeque::from([(true, packet)]));
    }
    let session = net.b.endpoint.sessions.get(&key).unwrap();
    assert_eq!(session.paths.direct, None);
    assert!(!session.paths.attempt.unwrap().stopped);
    assert_eq!(net.b.sent.len(), sent, "nothing in response");
    let info = net.b.endpoint.path_info(&key.0, b"session").unwrap();
    assert_eq!(info.validated_after, None);
}

/// A list lost on the way: B's list never reaches A, so A never probes. When
/// B's attempt is over without a path and without a probe from A, B sends its
/// list once more, and A has it.
#[test]
fn a_list_lost_on_the_way_is_sent_again_after_a_silent_attempt() {
    let mut net = Net::new();
    net.b.endpoint.set_local_addresses(&[addr("10.0.0.2:2")]);
    net.a_sends(b"hello").unwrap();
    let b = net.b.peer_id();
    net.drop_to_a = true;
    let packet = crafted(
        &mut net,
        inner::CANDIDATES,
        &candidates(1, &["192.0.2.1:9"]),
    );
    net.settle_with(VecDeque::from([(true, packet)]));
    assert!(
        net.a.endpoint.peer_candidates(&b, b"session").is_empty(),
        "lost"
    );

    // B's attempt: rounds until 2 s, answers until 3 s; nothing from A.
    net.drop_to_a = false;
    for ms in [250, 500, 1000, 2000, 3000] {
        net.now = ms;
        net.settle();
    }
    assert_eq!(
        net.a.endpoint.peer_candidates(&b, b"session"),
        net.b.endpoint.candidates(),
        "sent again, and received"
    );
}

/// What the core costs per datagram, sealing at one end and opening at the
/// other, with no socket: a measurement, run on demand in release with
/// `cargo test -p convesso-core --release --lib -- --ignored per_datagram --nocapture`.
#[test]
#[ignore = "a measurement, run on demand in release"]
fn per_datagram_cost_of_the_core() {
    let mut net = Net::new();
    net.a_sends(b"open").unwrap();
    let address = net.b.address();
    let data = [7u8; 1300];
    let mut out = [0u8; 2048];
    let n = 200_000u32;
    let mut packets = Vec::with_capacity(1);
    let started = std::time::Instant::now();
    let mut sealing = std::time::Duration::ZERO;
    for _ in 0..n {
        let t = std::time::Instant::now();
        let output = net
            .a
            .endpoint
            .send(
                Target::Address(&address),
                b"session",
                &data,
                PATH,
                net.t(),
                &mut net.a.policy,
                &mut net.a.entropy,
                &mut out,
            )
            .unwrap();
        sealing += t.elapsed();
        let Output::Transmit { len, .. } = output else {
            panic!("a packet")
        };
        packets.clear();
        packets.push(out[..len].to_vec());
        let source = net.a.source;
        let mut reply = [0u8; 2048];
        let handled = net.b.endpoint.handle_packet(
            &mut packets[0],
            Source::Direct(&source),
            net.t(),
            &mut net.b.policy,
            &mut net.b.entropy,
            &mut reply,
        );
        assert!(matches!(handled, Output::Event(Event::Datagram { .. })));
    }
    let total = started.elapsed();
    std::println!(
        "per datagram: {:.2} us in all, {:.2} us sealing ({:.0} Mbit/s for the core alone)",
        total.as_secs_f64() * 1e6 / f64::from(n),
        sealing.as_secs_f64() * 1e6 / f64::from(n),
        f64::from(n) * 1300.0 * 8.0 / total.as_secs_f64() / 1e6
    );
}

/// The AEAD alone, as the transport packet uses it: a measurement.
#[test]
#[ignore = "a measurement, run on demand in release"]
fn per_datagram_cost_of_the_aead() {
    let key = [9u8; 32];
    let data = [7u8; 1300];
    let mut out = [0u8; 2048];
    let n = 200_000u64;
    let started = std::time::Instant::now();
    for counter in 0..n {
        let len = transport::seal(&key, 1, counter, inner::DATAGRAM, &data, &mut out).unwrap();
        core::hint::black_box(len);
    }
    let elapsed = started.elapsed();
    std::println!(
        "seal alone: {:.2} us per 1,300-byte datagram",
        elapsed.as_secs_f64() * 1e6 / n as f64
    );
}
