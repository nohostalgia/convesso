//! The unknown-index signal (`PROTOCOL.md §5`): a side that lost a session
//! tells the peer that still sends under it, which renews at once.

use super::*;
use std::boxed::Box;

use crate::storage::Server;

/// B restarts with the same identity: a new endpoint, nothing kept.
fn restart_b(net: &mut Net) {
    net.b = Node::new(0, [10, 0, 0, 2, 0, 2], 999);
    let a = net.a.peer_id();
    let a_source = net.a.source;
    net.b.endpoint.set_hints(a, &[&a_source], net.t()).unwrap();
}

/// The unknown-index signals `node` sent.
fn signals(node: &Node) -> Vec<Vec<u8>> {
    node.sent
        .iter()
        .filter(|p| p.len() == transport::UNKNOWN_INDEX_LEN && p[..2] == [0x01, 0x07])
        .cloned()
        .collect()
}

/// The receiver index of the last transport packet `node` sent.
fn last_receiver_index(node: &Node) -> u64 {
    let packet = node.sent.iter().rev().find(|p| p[1] == 0x04).unwrap();
    transport::parse_header(packet).unwrap().receiver_index
}

/// Scenario: a session lost by restart is signalled, and the peer that dialled
/// renews at once: its next datagram is delivered.
#[test]
fn a_session_lost_by_restart_is_signalled() {
    let mut net = Net::new();
    net.a_sends(b"before").unwrap();
    let old = last_receiver_index(&net.a);
    restart_b(&mut net);
    net.a_sends(b"lost").unwrap();
    let sent = signals(&net.b);
    assert_eq!(sent.len(), 1, "one signal");
    assert_eq!(sent[0], transport::write_unknown_index(old));
    assert!(
        net.b_datagrams().is_empty(),
        "nothing delivered under old keys"
    );
    net.a_sends(b"after").unwrap();
    assert_eq!(net.b_datagrams(), vec![b"after".to_vec()]);
    assert!(net.b.events.contains(&Ev::Connected(b"session".to_vec())));
}

/// Scenario: a stranger hears nothing: an index this endpoint never issued is
/// not answered.
#[test]
fn a_stranger_hears_nothing() {
    let mut net = Net::new();
    let mut packet = vec![0u8; transport::OVERHEAD];
    packet[..2].copy_from_slice(&[0x01, 0x04]);
    packet[2..10].copy_from_slice(&0x0123_4567_89ab_cdef_u64.to_le_bytes());
    assert_eq!(net.deliver(true, &packet), None);
    assert!(signals(&net.b).is_empty());
}

/// Scenario: a forged packet under live keys is not signalled.
#[test]
fn a_forged_packet_under_live_keys_is_not_signalled() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let mut forged = net
        .a
        .sent
        .iter()
        .rev()
        .find(|p| p[1] == 0x04)
        .unwrap()
        .clone();
    let last = forged.len() - 1;
    forged[10] = forged[10].wrapping_add(1);
    forged[last] ^= 1;
    assert_eq!(net.deliver(true, &forged), None);
    assert!(signals(&net.b).is_empty());
}

/// Scenario: the rate of signals is bounded: 100 packets in a second for
/// indices it no longer holds give a microcontroller at most 25 signals.
#[test]
fn the_rate_of_signals_is_bounded() {
    let mut net = Net::new();
    net.a_sends(b"before").unwrap();
    let old = net
        .a
        .sent
        .iter()
        .rev()
        .find(|p| p[1] == 0x04)
        .unwrap()
        .clone();
    restart_b(&mut net);
    net.now += 10_000;
    let mut answered = 0;
    for i in 0..100 {
        net.now += 10;
        let _ = i;
        if net.deliver(true, &old).is_some() {
            answered += 1;
        }
    }
    assert!(answered <= 25, "{answered} signals in a second");
    assert!(answered >= 5, "a burst is answered");
}

/// Scenario: a forged signal costs one renewal and nothing else.
#[test]
fn a_forged_signal_costs_one_renewal() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let index = last_receiver_index(&net.a);
    let (a_events, b_events) = (net.a.events.len(), net.b.events.len());
    let contacts = net.a.first_contacts_sent();
    let signal = transport::write_unknown_index(index);
    let mut queue = VecDeque::new();
    queue.push_back((false, signal.to_vec()));
    net.settle_with(queue);
    assert_eq!(net.a.first_contacts_sent(), contacts + 1, "one renewal");
    assert_eq!(net.a.events.len(), a_events, "no event at A");
    assert_eq!(net.b.events.len(), b_events, "no event at B");
    net.a_sends(b"still").unwrap();
    assert_eq!(
        net.b_datagrams(),
        vec![b"hello".to_vec(), b"still".to_vec()]
    );
}

/// Scenario: a signal for no session, or of another length, is ignored.
#[test]
fn a_signal_for_no_session_is_ignored() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    let contacts = net.a.first_contacts_sent();
    let index = last_receiver_index(&net.a);
    let mut long = transport::write_unknown_index(index).to_vec();
    long.push(0);
    for packet in [
        transport::write_unknown_index(index ^ 1).to_vec(),
        long,
        transport::write_unknown_index(index)[..9].to_vec(),
    ] {
        assert_eq!(net.deliver(false, &packet), None);
        net.settle();
    }
    assert_eq!(net.a.first_contacts_sent(), contacts);
}

/// Scenario: a refused renewal ends the keys once: the peer that lost the
/// session refuses with `0x0001`, the sender drops its keys, is told of the
/// failure with that code and of no idle event, and ignores later signals.
#[test]
fn a_refused_renewal_ends_the_keys_once() {
    let mut net = Net::new();
    net.a_sends(b"before").unwrap();
    let old = last_receiver_index(&net.a);
    restart_b(&mut net);
    net.b.policy.decision = Decision::Refuse {
        code: RefusalCode::CAPACITY_EXHAUSTED,
        psk: None,
    };
    net.a_sends(b"lost").unwrap();
    assert!(
        net.a.events.contains(&Ev::ReopenFailed(
            b"session".to_vec(),
            DialError::Refused(RefusalCode::CAPACITY_EXHAUSTED)
        )),
        "{:?}",
        net.a.events
    );
    assert!(!net.a.events.contains(&Ev::Idle(b"session".to_vec())));
    let b = net.b.peer_id();
    assert!(!net.a.endpoint.is_live(&b, b"session", net.t()));
    let contacts = net.a.first_contacts_sent();
    assert_eq!(
        net.deliver(false, &transport::write_unknown_index(old)),
        None
    );
    net.settle();
    assert_eq!(net.a.first_contacts_sent(), contacts, "nothing more");
}

/// Scenario: a side without the address waits for the peer: a responder that
/// knows its initiator only by `PeerId`, its address packet lost, starts no
/// handshake on a signal and keeps its keys.
#[test]
fn a_side_without_the_address_waits_for_the_peer() {
    let mut net = Net::new();
    net.a_sends(b"hello").unwrap();
    net.b_replies(b"back").unwrap();
    // The address packet lost: B knows A by `PeerId` only.
    let key = (net.a.peer_id(), ctx());
    net.b.endpoint.sessions.get_mut(&key).unwrap().address = None;
    let index = last_receiver_index(&net.b);
    let contacts = net.b.first_contacts_sent();
    let mut queue = VecDeque::new();
    queue.push_back((true, transport::write_unknown_index(index).to_vec()));
    net.settle_with(queue);
    assert_eq!(net.b.first_contacts_sent(), contacts, "no handshake");
    let a = net.a.peer_id();
    assert!(net.b.endpoint.is_live(&a, b"session", net.t()));
}

// --- a server --------------------------------------------------------------------------

/// Two server endpoints that reach each other directly, moved by hand.
struct Servers {
    nodes: [Box<Endpoint<Server>>; 2],
    entropy: [TestEntropy; 2],
    policy: Policy,
    received: Vec<Vec<u8>>,
}

const SOURCES: [[u8; 6]; 2] = [[10, 0, 0, 1, 0, 1], [10, 0, 0, 2, 0, 2]];

impl Servers {
    fn new() -> Self {
        let mut servers = Self {
            nodes: [
                Box::new(Endpoint::new(identity(1), &[b"session"]).unwrap()),
                Box::new(Endpoint::new(identity(0), &[b"session"]).unwrap()),
            ],
            entropy: [TestEntropy(1), TestEntropy(2)],
            policy: Policy {
                decision: Decision::Accept { psk: None },
                asked: 0,
                refuse: Vec::new(),
            },
            received: Vec::new(),
        };
        servers.hints();
        servers
    }

    fn hints(&mut self) {
        for i in 0..2 {
            let peer = self.nodes[1 - i].identity().unwrap().peer_id();
            self.nodes[i]
                .set_hints(peer, &[&SOURCES[1 - i]], Instant::from_millis(0))
                .unwrap();
        }
    }

    fn carry(&mut self, mut queue: VecDeque<(usize, Vec<u8>)>, now: Instant) {
        for _ in 0..100 {
            for i in 0..2 {
                loop {
                    let mut out = [0u8; 2048];
                    match self.nodes[i].poll(now, &mut self.policy, &mut self.entropy[i], &mut out)
                    {
                        Poll::Transmit { len, .. } => queue.push_back((i, out[..len].to_vec())),
                        Poll::Event(Event::Datagram { data, .. }) => {
                            self.received.push(data.to_vec());
                        }
                        Poll::Event(_) => {}
                        _ => break,
                    }
                }
            }
            if queue.is_empty() {
                return;
            }
            while let Some((from, mut packet)) = queue.pop_front() {
                let to = 1 - from;
                let mut out = [0u8; 2048];
                match self.nodes[to].handle_packet(
                    &mut packet,
                    Source::Direct(&SOURCES[from]),
                    now,
                    &mut self.policy,
                    &mut self.entropy[to],
                    &mut out,
                ) {
                    Output::Transmit { len, .. } => queue.push_back((to, out[..len].to_vec())),
                    Output::Event(Event::Datagram { data, .. }) => {
                        self.received.push(data.to_vec());
                    }
                    _ => {}
                }
            }
        }
    }

    fn send(&mut self, data: &[u8], now: Instant) {
        let address = *self.nodes[1].identity().unwrap().address();
        let mut out = [0u8; 2048];
        let output = self.nodes[0]
            .send(
                Target::Address(&address),
                b"session",
                data,
                PATH,
                now,
                &mut self.policy,
                &mut self.entropy[0],
                &mut out,
            )
            .unwrap();
        let mut queue = VecDeque::new();
        if let Output::Transmit { len, .. } = output {
            queue.push_back((0, out[..len].to_vec()));
        }
        self.carry(queue, now);
    }
}

/// On the server profile a dial's attempts are found through the map of
/// indices: it holds the four kept, and releases each one an attempt replaces.
#[test]
fn a_server_keeps_the_indices_of_four_attempts_per_dial() {
    let mut servers = Servers::new();
    let address = *servers.nodes[1].identity().unwrap().address();
    let mut out = [0u8; 2048];
    let _ = servers.nodes[0]
        .send(
            Target::Address(&address),
            b"session",
            b"unanswered",
            PATH,
            Instant::from_millis(0),
            &mut servers.policy,
            &mut servers.entropy[0],
            &mut out,
        )
        .unwrap();
    let mut most = servers.nodes[0].indices.len();
    for ms in (0..=15_000).step_by(100) {
        let now = Instant::from_millis(ms);
        loop {
            match servers.nodes[0].poll(now, &mut servers.policy, &mut servers.entropy[0], &mut out)
            {
                Poll::Wait(_) | Poll::Idle => break,
                _ => {}
            }
        }
        most = most.max(servers.nodes[0].indices.len());
    }
    assert_eq!(most, crate::handshake::ATTEMPTS_KEPT);
    assert_eq!(
        servers.nodes[0].indices.len(),
        0,
        "all released when the dial gave up"
    );
}

/// On the server profile the signal finds its session through the map of
/// remote indices, which holds one entry per current pair.
#[test]
fn a_server_finds_the_signalled_session_by_its_index() {
    let mut servers = Servers::new();
    let now = Instant::from_millis(0);
    servers.send(b"before", now);
    assert_eq!(servers.nodes[0].remotes.len(), 1);
    *servers.nodes[1] = Endpoint::new(identity(0), &[b"session"]).unwrap();
    servers.hints();
    let later = Instant::from_millis(5000);
    servers.send(b"lost", later);
    servers.send(b"after", later);
    assert_eq!(
        servers.received,
        vec![b"before".to_vec(), b"after".to_vec()]
    );
    assert_eq!(
        servers.nodes[0].remotes.len(),
        1,
        "the old pair's entry is gone"
    );
}
