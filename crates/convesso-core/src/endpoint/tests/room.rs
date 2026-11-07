//! Room on bounded tables (`PROTOCOL.md §5`, `§6`): indices that never outlive
//! their owner, queues lent while reopening, idle sessions closed to make
//! room, newcomers refused by name, and the pinned relay's reserved room.

use super::*;
use crate::storage::Server;

crate::profile! {
    /// Two sessions and two dials: a board full after two peers.
    Tiny: Mcu { sessions: 2, dials: 2 }
}

crate::profile! {
    /// Four sessions and four dials, but two queues: the queues run out first.
    Lending: Mcu { sessions: 4, dials: 4, queues: 2 }
}

/// Endpoints of profile `C` that reach each other directly, each at its own
/// source: client `i` at `10.0.0.(i+1)`.
struct Mesh<C: Config> {
    nodes: Vec<MeshNode<C>>,
    now: u64,
    /// Packets towards these nodes are dropped.
    dropped: Vec<usize>,
    /// Packets towards these nodes are held, for [`Self::release`].
    holding: Vec<usize>,
    held: VecDeque<(usize, To, Vec<u8>)>,
}

struct MeshNode<C: Config> {
    endpoint: Endpoint<C>,
    policy: Policy,
    entropy: TestEntropy,
    source: [u8; 6],
    events: Vec<Ev>,
    /// The node whose packet it handled last: where `To::Source` goes.
    last_from: usize,
}

impl<C: Config> Mesh<C> {
    /// `n` endpoints, of the test identities 0 to `n - 1`, each knowing where
    /// every other is.
    fn new(n: usize) -> Self {
        let mut nodes: Vec<MeshNode<C>> = (0..n)
            .map(|i| {
                let host = u8::try_from(i + 1).unwrap();
                MeshNode {
                    endpoint: Endpoint::new(identity(i), &[b"session", b"other", b"third"])
                        .unwrap(),
                    policy: Policy {
                        decision: Decision::Accept { psk: None },
                        asked: 0,
                        refuse: Vec::new(),
                    },
                    entropy: TestEntropy(1000 + i as u64),
                    source: [10, 0, 0, host, 0, host],
                    events: Vec::new(),
                    last_from: i,
                }
            })
            .collect();
        let sources: Vec<_> = nodes.iter().map(|node| node.source).collect();
        let peers: Vec<_> = nodes
            .iter()
            .map(|node| node.endpoint.identity().unwrap().peer_id())
            .collect();
        for (i, node) in nodes.iter_mut().enumerate() {
            for (j, peer) in peers.iter().enumerate() {
                if i != j {
                    node.endpoint
                        .set_hints(*peer, &[&sources[j]], Instant::from_millis(0))
                        .unwrap();
                }
            }
        }
        Self {
            nodes,
            now: 0,
            dropped: Vec::new(),
            holding: Vec::new(),
            held: VecDeque::new(),
        }
    }

    fn t(&self) -> Instant {
        Instant::from_millis(self.now)
    }

    /// Where a packet from `from` towards `to` goes.
    fn dest(&self, from: usize, to: To) -> Option<usize> {
        match to {
            To::Source => Some(self.nodes[from].last_from),
            To::Direct(key) => {
                let bytes = key.as_direct()?;
                self.nodes.iter().position(|node| node.source == bytes)
            }
            To::Relay(_) | To::RelayKeepAlive => None,
        }
    }

    /// Delivers and polls until nothing moves at the current instant.
    fn settle(&mut self, mut queue: VecDeque<(usize, To, Vec<u8>)>) {
        for _ in 0..1000 {
            let mut moved = false;
            let now = self.t();
            for i in 0..self.nodes.len() {
                let node = &mut self.nodes[i];
                loop {
                    let mut out = [0u8; 2048];
                    match node
                        .endpoint
                        .poll(now, &mut node.policy, &mut node.entropy, &mut out)
                    {
                        Poll::Transmit { to, len } => {
                            queue.push_back((i, to, out[..len].to_vec()));
                            moved = true;
                        }
                        Poll::Event(event) => {
                            node.events.push(own(event));
                            moved = true;
                        }
                        Poll::OpenRelayLink | Poll::CloseRelayLink => {}
                        Poll::Wait(_) | Poll::Idle => break,
                    }
                }
            }
            while let Some((from, to, packet)) = queue.pop_front() {
                moved = true;
                let Some(dest) = self.dest(from, to) else {
                    continue;
                };
                if self.dropped.contains(&dest) {
                    continue;
                }
                if self.holding.contains(&dest) {
                    self.held.push_back((from, to, packet));
                    continue;
                }
                let source = self.nodes[from].source;
                let node = &mut self.nodes[dest];
                node.last_from = from;
                let mut buffer = packet;
                let mut out = [0u8; 2048];
                match node.endpoint.handle_packet(
                    &mut buffer,
                    Source::Direct(&source),
                    now,
                    &mut node.policy,
                    &mut node.entropy,
                    &mut out,
                ) {
                    // An answer goes back to this packet's sender, whatever
                    // the node handles next.
                    Output::Transmit { to, len } => {
                        let to = match to {
                            To::Source => To::Direct(Source::Direct(&source).key().unwrap()),
                            to => to,
                        };
                        queue.push_back((dest, to, out[..len].to_vec()));
                    }
                    Output::Event(event) => node.events.push(own(event)),
                    Output::Nothing => {}
                }
            }
            if !moved {
                return;
            }
        }
        panic!("the mesh never settled");
    }

    /// Node `i` sends `data` to node `j` in `context`, by address.
    fn send_in(
        &mut self,
        i: usize,
        j: usize,
        context: &[u8],
        data: &[u8],
    ) -> Result<(), SendError> {
        let now = self.t();
        let address = *self.nodes[j].endpoint.identity().unwrap().address();
        let node = &mut self.nodes[i];
        let mut out = [0u8; 2048];
        let output = node.endpoint.send(
            Target::Address(&address),
            context,
            data,
            PATH,
            now,
            &mut node.policy,
            &mut node.entropy,
            &mut out,
        )?;
        let mut queue = VecDeque::new();
        if let Output::Transmit { to, len } = output {
            queue.push_back((i, to, out[..len].to_vec()));
        }
        self.settle(queue);
        Ok(())
    }

    fn send(&mut self, i: usize, j: usize, data: &[u8]) -> Result<(), SendError> {
        self.send_in(i, j, b"session", data)
    }

    /// Delivers what was held, in order, and holds nothing more.
    fn release(&mut self) {
        self.holding.clear();
        let held = core::mem::take(&mut self.held);
        self.settle(held);
    }

    fn at(&mut self, millis: u64) {
        self.now = millis;
        self.settle(VecDeque::new());
    }

    /// Whether node `i` received `data`.
    fn got(&self, i: usize, data: &[u8]) -> bool {
        self.nodes[i]
            .events
            .iter()
            .any(|ev| matches!(ev, Ev::Datagram(_, d, _) if d == data))
    }

    fn closes(&self, i: usize, code: u16, by_peer: bool) -> usize {
        self.nodes[i]
            .events
            .iter()
            .filter(|ev| matches!(ev, Ev::Closed(_, c, b) if *c == code && *b == by_peer))
            .count()
    }
}

// --- indices ------------------------------------------------------------------------------

/// The first contacts' initiator indices among `packets`.
fn first_contact_indices(packets: &[Vec<u8>]) -> Vec<u32> {
    packets
        .iter()
        .filter(|p| p[0] == 0x01 && crate::handshake::messages::is_first_contact_type(p[1]))
        .map(|p| u32::from_le_bytes([p[2], p[3], p[4], p[5]]))
        .collect()
}

/// Scenario: completed, refused and unanswered dials leave no index. On the
/// growable profile, which keeps a table of indices, only the open session's
/// remain.
#[test]
fn completed_refused_and_unanswered_dials_leave_no_index() {
    let mut mesh: Mesh<Server> = Mesh::new(3);
    // Completed: one session, with its one index.
    mesh.send(0, 1, b"completed").unwrap();
    assert!(mesh.got(1, b"completed"));
    // Refused.
    mesh.nodes[2].policy.decision = Decision::Refuse {
        code: RefusalCode::application(0x0101).unwrap(),
        psk: None,
    };
    mesh.send(0, 2, b"refused").unwrap();
    // Unanswered: every attempt dropped, then given up.
    mesh.nodes[2].policy.decision = Decision::Accept { psk: None };
    mesh.dropped.push(2);
    mesh.send_in(0, 2, b"other", b"unanswered").unwrap();
    for second in 1..=16 {
        mesh.at(second * 1000);
    }
    let held = mesh.nodes[0].endpoint.indices.len();
    assert_eq!(held, 1, "only the open session's index");
}

/// Scenario: a late response to an ended dial is ignored.
#[test]
fn a_late_response_to_an_ended_dial_is_ignored() {
    let mut net = Net::new();
    net.drop_to_a = true;
    net.a_sends(b"lost").unwrap();
    let response = net.b.sent[0].clone();
    for second in 1..=16 {
        net.at(second);
    }
    assert!(matches!(
        net.a.events.last(),
        Some(Ev::ReopenFailed(_, DialError::NoResponse))
    ));
    net.drop_to_a = false;
    assert_eq!(net.deliver(false, &response), None);
    assert_eq!(net.a.endpoint.session_count(), 0, "no session opens");
    assert!(!net.a.events.iter().any(|ev| matches!(ev, Ev::Connected(_))));
}

/// Scenario: an index never outlives its owner. On the microcontroller
/// profile, which keeps no table of indices, a hundred dials of every ending
/// leave nothing that a packet can find, and the two sessions open at the end
/// deliver.
#[test]
fn an_index_never_outlives_its_owner() {
    let mut net = Net::new();
    let code = RefusalCode::application(0x0101).unwrap();
    for round in 0..34u64 {
        let base = round * 200;
        net.at(base);
        // Refused.
        net.b.policy.decision = Decision::Refuse { code, psk: None };
        net.a_sends(b"refused").unwrap();
        // Unanswered.
        net.b.policy.decision = Decision::Accept { psk: None };
        net.drop_to_b = true;
        net.a_sends(b"unanswered").unwrap();
        for second in 1..=16 {
            net.at(base + second);
        }
        net.drop_to_b = false;
        // Completed, then let go idle and forgotten.
        net.a_sends(b"completed").unwrap();
        net.at(base + 199);
    }
    let ended = first_contact_indices(&net.a.sent);
    assert!(ended.len() >= 100);
    // Two sessions now, in two contexts.
    net.a_sends(b"first").unwrap();
    net.connect_in(true, b"other");
    for index in ended {
        let owner = net.a.endpoint.owner(index);
        let live = [b"session".as_slice(), b"other"]
            .into_iter()
            .any(|context| {
                let key = (net.b.peer_id(), Context::new(context).unwrap());
                net.a.endpoint.sessions.get(&key).is_some_and(|session| {
                    session
                        .current
                        .as_ref()
                        .is_some_and(|pair| pair.local_index == index)
                })
            });
        assert!(
            owner.is_none() || live,
            "index {index} found no owner, or a live one"
        );
    }
    assert!(net.b_datagrams().contains(&b"first".to_vec()));
}

// --- queues --------------------------------------------------------------------------------

/// Scenario: queues are lent while reopening. With two queues, a third
/// session reopening with a datagram is refused as full, until a queue is
/// given back.
#[test]
fn queues_are_lent_while_reopening() {
    let mut mesh: Mesh<Lending> = Mesh::new(4);
    mesh.dropped.extend([1, 2, 3]);
    mesh.send(0, 1, b"one").unwrap();
    mesh.send(0, 2, b"two").unwrap();
    assert_eq!(mesh.nodes[0].endpoint.queues.lent(), 2);
    assert!(matches!(
        mesh.send(0, 3, b"three"),
        Err(SendError::QueueFull(_))
    ));
    // The first two give up, and give their queues back.
    for second in 1..=16 {
        mesh.at(second * 1000);
    }
    assert_eq!(mesh.nodes[0].endpoint.queues.lent(), 0);
    mesh.dropped.clear();
    mesh.send(0, 3, b"three").unwrap();
    assert!(mesh.got(3, b"three"));
}

// --- eviction and refusal ------------------------------------------------------------------

/// Scenarios: a board serves more peers than its slots; an evicted peer comes
/// back on its next send. Two peers fill a two-session board; a third, 40
/// seconds later, takes the place of the least recently active, which is
/// sent a close with code `0x0002` (`02 00`) and comes back on its next send.
#[test]
fn an_idle_session_makes_room_and_its_peer_is_told() {
    assert_eq!(CLOSE_TO_MAKE_ROOM.to_le_bytes(), [0x02, 0x00]);
    let mut mesh: Mesh<Tiny> = Mesh::new(4);
    mesh.send(1, 0, b"from 1").unwrap();
    mesh.at(1000);
    mesh.send(2, 0, b"from 2").unwrap();
    mesh.at(41_000);
    mesh.send(3, 0, b"from 3").unwrap();
    assert!(mesh.got(0, b"from 3"), "the newcomer is served");
    assert_eq!(
        mesh.closes(0, CLOSE_TO_MAKE_ROOM, false),
        1,
        "the board is told"
    );
    assert_eq!(
        mesh.closes(1, CLOSE_TO_MAKE_ROOM, true),
        1,
        "the least recently active peer is told why"
    );
    assert_eq!(mesh.closes(2, CLOSE_TO_MAKE_ROOM, true), 0);
    // The evicted peer comes back, in the place of the next idle one.
    mesh.at(82_000);
    mesh.send(1, 0, b"from 1 again").unwrap();
    assert!(mesh.got(0, b"from 1 again"));
    assert_eq!(mesh.closes(0, CLOSE_TO_MAKE_ROOM, false), 2);
}

/// Scenarios: busy sessions are never evicted; a full board refuses a new
/// peer by name; a send with no room is refused by name.
#[test]
fn a_busy_board_refuses_a_newcomer_by_name() {
    let mut mesh: Mesh<Tiny> = Mesh::new(4);
    mesh.send(1, 0, b"from 1").unwrap();
    mesh.send(2, 0, b"from 2").unwrap();
    mesh.at(10_000);
    mesh.send(3, 0, b"from 3").unwrap();
    assert!(!mesh.got(0, b"from 3"));
    assert_eq!(mesh.closes(0, CLOSE_TO_MAKE_ROOM, false), 0);
    assert!(mesh.nodes[3].events.contains(&Ev::ReopenFailed(
        b"session".to_vec(),
        DialError::Refused(RefusalCode::CAPACITY_EXHAUSTED)
    )));
    // The board itself cannot open a third.
    assert!(matches!(mesh.send(0, 3, b"to 3"), Err(SendError::Capacity)));
}

/// Scenario: a known peer is never refused for room. Two peers keep a full
/// board busy past their keys' renewal, and both keep being delivered.
#[test]
fn a_known_peer_renews_on_a_full_board() {
    let mut mesh: Mesh<Tiny> = Mesh::new(3);
    for second in (0..200).step_by(10) {
        mesh.at(second * 1000);
        let (one, two) = (second.to_le_bytes(), (second + 1).to_le_bytes());
        mesh.send(1, 0, &one).unwrap();
        mesh.send(2, 0, &two).unwrap();
        assert!(mesh.got(0, &one) && mesh.got(0, &two), "at {second} s");
    }
    assert_eq!(mesh.closes(0, CLOSE_TO_MAKE_ROOM, false), 0);
}

// --- the relay's reserved room -------------------------------------------------------------

/// Pins, on node `i`, a relay that is never reached.
fn pin_unreachable_relay<C: Config>(mesh: &mut Mesh<C>, i: usize) {
    let relay = *identity(4).address();
    let now = mesh.t();
    mesh.nodes[i].endpoint.pin_relay(relay, now).unwrap();
}

/// Scenario: peers cannot crowd out the relay. On a two-session board whose
/// relay session is not held, one peer takes the free slot, and the next is
/// refused: the last slot is the relay's.
#[test]
fn the_last_session_slot_is_the_relays() {
    let mut mesh: Mesh<Tiny> = Mesh::new(3);
    pin_unreachable_relay(&mut mesh, 0);
    mesh.send(1, 0, b"from 1").unwrap();
    assert!(mesh.got(0, b"from 1"));
    mesh.send(2, 0, b"from 2").unwrap();
    assert!(!mesh.got(0, b"from 2"), "the relay's slot is not given");
    assert!(mesh.nodes[2].events.contains(&Ev::ReopenFailed(
        b"session".to_vec(),
        DialError::Refused(RefusalCode::CAPACITY_EXHAUSTED)
    )));
}

/// Scenario: a peer's dial cannot take the relay's. With two dials and its
/// relay session not being dialled, a board dials one new peer, and a second
/// send to another new peer is refused by name.
#[test]
fn the_last_dial_is_the_relays() {
    let mut mesh: Mesh<Mcu> = Mesh::new(3);
    pin_unreachable_relay(&mut mesh, 0);
    mesh.dropped.extend([1, 2]);
    mesh.send(0, 1, b"to 1").unwrap();
    assert!(matches!(mesh.send(0, 2, b"to 2"), Err(SendError::Capacity)));
}

/// Scenario: a confirmation that arrives when the session can no longer be
/// kept is answered with a close `0x0002`, and leaves the initiator holding
/// no keys. Two first contacts reach a board with one free slot, both
/// accepted; the first confirmation takes the slot, the second is closed.
#[test]
fn a_confirmation_without_room_is_closed() {
    let mut mesh: Mesh<Tiny> = Mesh::new(4);
    mesh.send(1, 0, b"from 1").unwrap();
    mesh.holding.push(0);
    mesh.send(2, 0, b"from 2").unwrap();
    mesh.send(3, 0, b"from 3").unwrap();
    mesh.release();
    assert!(mesh.got(0, b"from 2"));
    assert!(!mesh.got(0, b"from 3"));
    assert_eq!(
        mesh.closes(3, CLOSE_TO_MAKE_ROOM, true),
        1,
        "the initiator is told"
    );
    let board = (
        mesh.nodes[0].endpoint.identity().unwrap().peer_id(),
        Context::new(b"session").unwrap(),
    );
    assert!(
        mesh.nodes[3]
            .endpoint
            .sessions
            .get(&board)
            .is_none_or(|session| session.current.is_none()),
        "no keys left on the initiator"
    );
}
