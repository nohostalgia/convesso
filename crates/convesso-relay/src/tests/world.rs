//! The simulated world: one relay, clients behind NATs, the links between them.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use convesso_core::dos::{Source, decode_ip, encode_ip};
use convesso_core::endpoint::{
    Endpoint, Event, FrameKind, Output, Poll, RelayError, RelayPath, SendError, Target, To,
};
use convesso_core::handshake::{Admission, Context, Decision, DialError, Entropy};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::paths::PathKind;
use convesso_core::relay::Link;
use convesso_core::relay::framing::{Deframed, Deframer, KEEPALIVE, PREAMBLE, frame};
use convesso_core::storage::Mcu;
use convesso_core::time::Instant;
use convesso_stream::config::Server as StreamServer;
use convesso_stream::frame::MAX_DATA_LEN;
use convesso_stream::{Channels, Event as StreamEvent, Poll as StreamPoll, Reason};
use serde_json::Value;

use crate::{Action, Config, LinkId, Policy, Relay};

pub(crate) const SESSION: &[u8] = b"session";
/// The path a client gives for sends through the relay.
pub(crate) const RELAY_PATH_MAX: usize = convesso_core::relay::MAX_CARRIED;

pub(crate) fn identity(i: usize) -> Identity {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../convesso-core/vectors/identity.json")).unwrap();
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

/// Deterministic entropy: BLAKE2s-like mixing of a counter, good enough for
/// distinct keys and indices in a test.
pub(crate) struct TestEntropy(pub(crate) u64);

impl Entropy for TestEntropy {
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

/// What a client's application saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ev {
    Connected(PeerId),
    Datagram {
        peer: PeerId,
        data: Vec<u8>,
        relayed: bool,
    },
    Closed(PeerId, u16),
    ReopenFailed(PeerId),
    NotAtRelay(PeerId),
    Observed(Link, SocketAddr),
    RelayUnavailable(RelayError),
    RelayAvailable,
    Payload,
    PathChanged(PeerId, PathKind),
    Frame {
        peer: PeerId,
        kind: FrameKind,
        data: Vec<u8>,
        relayed: bool,
    },
}

fn own(event: Event<'_>) -> Ev {
    match event {
        Event::Connected { peer, .. } => Ev::Connected(peer),
        Event::Datagram {
            peer,
            data,
            relayed,
            ..
        } => Ev::Datagram {
            peer,
            data: data.to_vec(),
            relayed,
        },
        Event::Frame {
            peer,
            kind,
            data,
            relayed,
            ..
        } => Ev::Frame {
            peer,
            kind,
            data: data.to_vec(),
            relayed,
        },
        Event::Closed { peer, code, .. } => Ev::Closed(peer, code),
        Event::ReopenFailed { peer, .. } => Ev::ReopenFailed(peer),
        Event::PeerNotAtRelay { peer } => Ev::NotAtRelay(peer),
        Event::ObservedAddress { link, address } => Ev::Observed(link, address),
        Event::RelayUnavailable { error } => Ev::RelayUnavailable(error),
        Event::RelayAvailable => Ev::RelayAvailable,
        Event::Payload { .. } => Ev::Payload,
        Event::PathChanged { peer, path, .. } => Ev::PathChanged(peer, path),
    }
}

/// What a client sent, by kind: what the idle tests count.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sent {
    pub(crate) udp: usize,
    pub(crate) udp_bytes: usize,
    pub(crate) tcp: usize,
    pub(crate) tcp_bytes: usize,
    pub(crate) keepalives: usize,
}

/// How a NAT picks the public port of an outbound flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mapping {
    /// One port for every destination, the inside port kept: most home routers.
    Independent,
    /// A new port for each destination: a symmetric NAT.
    Dependent,
}

/// What a NAT lets in to a mapped port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Filtering {
    /// Anyone: a full cone.
    None,
    /// Only addresses the inside host sent to.
    Address,
    /// Only addresses and ports the inside host sent to.
    AddressAndPort,
}

/// A NAT in front of one client's LAN, or a stateful firewall when it keeps
/// every port (`Mapping::Independent`) in front of public addresses.
#[derive(Debug, Clone)]
pub(crate) struct Nat {
    pub(crate) mapping: Mapping,
    pub(crate) filtering: Filtering,
    /// Each flow, by inside port and destination: its public port, and when a
    /// packet last passed on it, either way.
    flows: BTreeMap<(u16, SocketAddr), Flow>,
    next_port: u16,
}

#[derive(Debug, Clone, Copy)]
struct Flow {
    port: u16,
    last: u64,
}

/// The inside port of every client, kept by an endpoint-independent NAT.
pub(crate) const INSIDE_PORT: u16 = 40000;

/// Where the relay's UDP is, as the NATs see it.
pub(crate) const RELAY_UDP: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 7400);

/// How long a NAT keeps a flow no packet passes on: Linux's timeout for a UDP
/// flow, and the shortest common one. The relay's flow is kept: the world
/// carries the relay's packets without its NATs.
pub(crate) const NAT_LIFETIME: u64 = 30_000;

impl Nat {
    pub(crate) fn new(mapping: Mapping, filtering: Filtering) -> Self {
        Self {
            mapping,
            filtering,
            flows: BTreeMap::new(),
            next_port: 50001,
        }
    }

    /// Forgets the flows idle for [`NAT_LIFETIME`] at `now`.
    fn expire(&mut self, now: u64) {
        self.flows
            .retain(|(_, to), flow| *to == RELAY_UDP || now < flow.last + NAT_LIFETIME);
    }

    /// The public port a flow from inside port `inside` to `to` leaves from
    /// at `now`, mapped if new: a port-keeping NAT keeps the inside port; a
    /// symmetric one gives each destination, and each forgotten flow, a new
    /// port.
    fn outbound(&mut self, to: SocketAddr, inside: u16, now: u64) -> u16 {
        self.expire(now);
        let port = match (self.mapping, self.flows.get(&(inside, to))) {
            (Mapping::Independent, _) => inside,
            (Mapping::Dependent, Some(flow)) => flow.port,
            (Mapping::Dependent, None) => {
                self.next_port += 1;
                self.next_port - 1
            }
        };
        self.flows.insert((inside, to), Flow { port, last: now });
        port
    }

    /// The inside port a packet from `from` to public port `port` goes to at
    /// `now`, if it gets in: it must hit a live flow on that port that the
    /// filter lets it through (one flow per port when the mapping depends on
    /// the destination, as in Linux's conntrack). The flow is kept alive.
    fn admits(&mut self, from: SocketAddr, port: u16, now: u64) -> Option<u16> {
        self.expire(now);
        let filtering = self.filtering;
        let passes = |to: &SocketAddr| match filtering {
            Filtering::None => true,
            Filtering::Address => to.ip() == from.ip(),
            Filtering::AddressAndPort => *to == from,
        };
        let key = self
            .flows
            .iter()
            .find(|((_, to), flow)| flow.port == port && passes(to))
            .map(|(key, _)| *key)?;
        let flow = self.flows.get_mut(&key)?;
        flow.last = now;
        Some(key.0)
    }
}

/// The NATs between a client and the internet, its own router first: a
/// packet out crosses them in order, a packet in in reverse.
fn out_through(nats: &mut [Nat], to: SocketAddr, now: u64) -> Option<u16> {
    if nats.is_empty() {
        return None;
    }
    let mut port = INSIDE_PORT;
    for nat in nats {
        port = nat.outbound(to, port, now);
    }
    Some(port)
}

fn in_through(nats: &mut [Nat], from: SocketAddr, port: u16, now: u64) -> bool {
    if nats.is_empty() {
        return false;
    }
    let mut port = port;
    for nat in nats.iter_mut().rev() {
        match nat.admits(from, port, now) {
            Some(inside) => port = inside,
            None => return false,
        }
    }
    true
}

pub(crate) struct Client {
    pub(crate) endpoint: Endpoint<Mcu>,
    pub(crate) policy: AcceptAll,
    pub(crate) entropy: TestEntropy,
    /// The address the relay sees this client's UDP at.
    pub(crate) nat: SocketAddr,
    /// The address the relay sees this client's UDP at over IPv6, for a
    /// dual-stack client; where `RelayPath::UdpOther` goes.
    pub(crate) nat6: Option<SocketAddr>,
    /// Its UDP to the relay alternates between the families, as a dual-stack
    /// client's might.
    pub(crate) alternate: bool,
    /// This client's address on its LAN.
    pub(crate) lan: SocketAddr,
    /// Clients with the same LAN number reach each other's LAN address.
    pub(crate) lan_id: usize,
    /// The NATs in front of its LAN, its router's first; without any, direct
    /// IPv4 packets to and from it go nowhere.
    pub(crate) nats: Vec<Nat>,
    /// The stateful firewall in front of its IPv6 address (`nat6`), which no
    /// NAT changes; without one, direct IPv6 packets to and from it go nowhere.
    pub(crate) firewall6: Option<Nat>,
    /// The address the relay sees this client's TCP link from.
    pub(crate) tcp_from: SocketAddr,
    pub(crate) link: Option<LinkId>,
    pub(crate) deframer: Deframer,
    pub(crate) udp_blocked: bool,
    /// The relay refuses this client's TCP connections, as if it were down.
    pub(crate) tcp_refused: bool,
    /// The relay's TCP port swallows connection attempts: neither opened nor
    /// refused.
    pub(crate) tcp_hangs: bool,
    /// This client's link silently drops everything, both ways, without a
    /// close reaching either end.
    pub(crate) link_blackhole: bool,
    /// The relay answers this client's keep-alives but never its handshakes:
    /// its first contacts to the relay are lost.
    pub(crate) handshakes_ignored: bool,
    /// When the core asked for a link, in ms.
    pub(crate) opens: Vec<u64>,
    /// When the core asked to close the link, in ms.
    pub(crate) closes: Vec<u64>,
    /// Keep-alive answers received from the relay.
    pub(crate) keepalive_answers: usize,
    pub(crate) events: Vec<Ev>,
    /// When each event happened, in ms.
    pub(crate) event_at: Vec<u64>,
    pub(crate) sent: Sent,
    /// Every UDP datagram this client sent to the relay, for replays.
    pub(crate) udp_log: Vec<Vec<u8>>,
    /// Every packet this client sent on its TCP link.
    pub(crate) tcp_log: Vec<Vec<u8>>,
    pub(crate) deadline: Option<Instant>,
    /// Reliable messages, when the test turns them on.
    pub(crate) stream: Option<Box<Channels<StreamServer>>>,
    /// Whether the application takes messages.
    pub(crate) deliver: bool,
    pub(crate) messages: Vec<Vec<u8>>,
    pub(crate) message_at: Vec<u64>,
    pub(crate) stream_resets: Vec<Reason>,
    pub(crate) writable: usize,
    /// Every packet the core gave this client to send, whatever its path.
    pub(crate) transmitted: usize,
}

impl Client {
    pub(crate) fn peer_id(&self) -> PeerId {
        self.endpoint.identity().peer_id()
    }

    pub(crate) fn address(&self) -> Address {
        *self.endpoint.identity().address()
    }

    pub(crate) fn datagrams(&self) -> Vec<(Vec<u8>, bool)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                Ev::Datagram { data, relayed, .. } => Some((data.clone(), *relayed)),
                _ => None,
            })
            .collect()
    }
}

/// Something on the wire, due at a time.
#[derive(Debug, Clone)]
enum Msg {
    RelayUdp {
        from: SocketAddr,
        client: usize,
        packet: Vec<u8>,
    },
    RelayLink {
        link: LinkId,
        bytes: Vec<u8>,
    },
    ClientUdp {
        client: usize,
        packet: Vec<u8>,
    },
    /// Bytes the relay wrote on a link, for the client at its end: lost when
    /// that link is no longer the client's, as a closed socket's would be.
    ClientLink {
        client: usize,
        link: LinkId,
        bytes: Vec<u8>,
    },
    /// A packet on a direct path between two clients.
    Direct {
        to: usize,
        from: usize,
        packet: Vec<u8>,
    },
    /// A packet on a direct IP path, as it arrives at client `to`.
    DirectIp {
        to: usize,
        source: SocketAddr,
        packet: Vec<u8>,
    },
}

pub(crate) struct World<P: Policy> {
    pub(crate) relay: Relay<P, TestEntropy>,
    pub(crate) clients: Vec<Client>,
    pub(crate) now: u64,
    /// One-way delay of every hop, in milliseconds.
    pub(crate) delay: u64,
    wire: BTreeMap<(u64, u64), Msg>,
    seq: u64,
    next_link: LinkId,
    relay_deadline: Option<Instant>,
    /// UDP datagrams the relay sent, to whom, and how many bytes.
    pub(crate) relay_udp_sent: Vec<(SocketAddr, usize)>,
    /// Bytes the relay wrote on each link, keep-alives excluded (it sends none).
    pub(crate) relay_link_sent: BTreeMap<LinkId, usize>,
    /// Packets the relay wrote on each link, by their byte 1, in order.
    pub(crate) relay_link_types: BTreeMap<LinkId, Vec<u8>>,
    /// Whether direct paths between clients carry packets. A direct address
    /// in this world is one byte: the client's index.
    pub(crate) direct: bool,
    /// When set, UDP loses 10%, duplicates 5% and delays 10 to 60 ms (so
    /// reorders), drawn from this seed. TCP links stay reliable and in order.
    pub(crate) chaos: Option<u64>,
    /// When set, every UDP datagram, to the relay or direct, is lost with
    /// this probability in percent, drawn from the seed: a lossy access link.
    pub(crate) loss: Option<(u64, u64)>,
    /// Whether `chaos` and `loss` also strike direct packets between clients
    /// (a hinted path, addressed by index), not only UDP to and from the relay.
    pub(crate) lossy_direct: bool,
    /// Every direct IP packet a client sent: by whom, to where.
    direct_log: Vec<(usize, SocketAddr)>,
    /// Whether a NAT forwards a packet from its own LAN to its own public
    /// address back in, as some routers do.
    pub(crate) hairpin: bool,
}

pub(crate) fn t(ms: u64) -> Instant {
    Instant::from_millis(ms)
}

impl<P: Policy> World<P> {
    pub(crate) fn new(policy: P, config: Config, clients: usize) -> Self {
        let relay = Relay::new(identity(0), policy, TestEntropy(1), config, t(0)).unwrap();
        let address = relay.address();
        let mut world = Self {
            relay,
            clients: Vec::new(),
            now: 0,
            delay: 20,
            wire: BTreeMap::new(),
            seq: 0,
            next_link: 1,
            relay_deadline: None,
            relay_udp_sent: Vec::new(),
            relay_link_sent: BTreeMap::new(),
            relay_link_types: BTreeMap::new(),
            direct: true,
            chaos: None,
            direct_log: Vec::new(),
            loss: None,
            lossy_direct: false,
            hairpin: false,
        };
        for i in 0..clients {
            let mut endpoint = Endpoint::new(identity(i + 1), &[SESSION]).unwrap();
            endpoint.pin_relay(address, t(0)).unwrap();
            let host = u8::try_from(i + 1).unwrap();
            world.clients.push(Client {
                endpoint,
                policy: AcceptAll,
                entropy: TestEntropy(100 + i as u64),
                nat: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, host)), 40000),
                nat6: None,
                alternate: false,
                lan: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, host, 0, 2)), INSIDE_PORT),
                lan_id: i,
                nats: Vec::new(),
                firewall6: None,
                tcp_from: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, host)), 50000),
                link: None,
                deframer: Deframer::default(),
                udp_blocked: false,
                tcp_refused: false,
                tcp_hangs: false,
                link_blackhole: false,
                handshakes_ignored: false,
                opens: Vec::new(),
                closes: Vec::new(),
                keepalive_answers: 0,
                events: Vec::new(),
                event_at: Vec::new(),
                sent: Sent::default(),
                udp_log: Vec::new(),
                tcp_log: Vec::new(),
                deadline: None,
                stream: None,
                deliver: true,
                messages: Vec::new(),
                message_at: Vec::new(),
                stream_resets: Vec::new(),
                writable: 0,
                transmitted: 0,
            });
        }
        world
    }

    pub(crate) fn instant(&self) -> Instant {
        t(self.now)
    }

    fn put(&mut self, delay: u64, msg: Msg) {
        let blackholed = match &msg {
            Msg::RelayLink { link, .. } => self
                .clients
                .iter()
                .any(|c| c.link == Some(*link) && c.link_blackhole),
            Msg::ClientLink { client, .. } => self.clients[*client].link_blackhole,
            _ => false,
        };
        if blackholed {
            return;
        }
        let direct = self.lossy_direct && matches!(msg, Msg::Direct { .. });
        if let (true, Some((state, percent))) = (
            direct
                || matches!(
                    msg,
                    Msg::RelayUdp { .. } | Msg::ClientUdp { .. } | Msg::DirectIp { .. }
                ),
            self.loss.as_mut(),
        ) {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            if *state % 100 < *percent {
                return;
            }
        }
        let udp = direct || matches!(msg, Msg::RelayUdp { .. } | Msg::ClientUdp { .. });
        if let (true, Some(state)) = (udp, self.chaos.as_mut()) {
            let mut next = || {
                *state ^= *state << 13;
                *state ^= *state >> 7;
                *state ^= *state << 17;
                *state
            };
            if next() % 100 < 10 {
                return;
            }
            let copies = if next() % 100 < 5 { 2 } else { 1 };
            for _ in 0..copies {
                let delay = 10 + next() % 51;
                self.seq += 1;
                self.wire.insert((self.now + delay, self.seq), msg.clone());
            }
            return;
        }
        self.seq += 1;
        self.wire.insert((self.now + delay, self.seq), msg);
    }

    fn record(&mut self, i: usize, event: Ev) {
        let now = self.now;
        let instant = self.instant();
        let client = &mut self.clients[i];
        if let Some(stream) = client.stream.as_mut() {
            let context = Context::new(SESSION).unwrap();
            match &event {
                Ev::Frame {
                    peer, kind, data, ..
                } => stream.handle_frame(*peer, context, *kind, data, instant),
                Ev::Closed(peer, code) => stream.session_closed(*peer, context, *code),
                Ev::ReopenFailed(peer) => {
                    stream.reopen_failed(*peer, context, DialError::NoResponse);
                }
                _ => {}
            }
        }
        client.events.push(event);
        client.event_at.push(now);
    }

    /// When client `i` first saw `event`, if it did.
    pub(crate) fn when(&self, i: usize, event: &Ev) -> Option<u64> {
        let client = &self.clients[i];
        client
            .events
            .iter()
            .position(|e| e == event)
            .map(|at| client.event_at[at])
    }

    /// Client `i`'s process restarts, on another UDP port: a new endpoint
    /// with the same identity and nothing else, its old link silently dead.
    pub(crate) fn restart(&mut self, i: usize) {
        let relay = self.relay.address();
        let now = self.instant();
        let mut endpoint = Endpoint::new(identity(i + 1), &[SESSION]).unwrap();
        endpoint.pin_relay(relay, now).unwrap();
        let client = &mut self.clients[i];
        client.endpoint = endpoint;
        if client.stream.is_some() {
            client.stream = Some(Box::default());
        }
        client.link_blackhole = true;
        client.link = None;
        client.deframer = Deframer::default();
        client.nat = SocketAddr::new(client.nat.ip(), client.nat.port() + 1);
    }

    /// Another relay, with key `key` of the vectors, takes the place of the
    /// world's relay, at the same address: what the old one knew is gone, and
    /// every link to it closes, as at a restart of its host.
    pub(crate) fn replace_relay(&mut self, relay: Relay<P, TestEntropy>) {
        self.relay = relay;
        self.relay_deadline = None;
        let now = self.instant();
        for client in &mut self.clients {
            if client.link.take().is_some() {
                client.deframer = Deframer::default();
                client.endpoint.relay_link_closed(now);
            }
        }
        self.settle();
    }

    /// Client `i` moves to the world's relay as it is now.
    pub(crate) fn move_to_relay(&mut self, i: usize) {
        let relay = self.relay.address();
        let now = self.instant();
        self.clients[i]
            .endpoint
            .set_relay(Some(relay), now)
            .unwrap();
        self.settle();
    }

    /// Client `i` asks to be reachable; returns the link its core opened.
    pub(crate) fn open_link(&mut self, i: usize) -> LinkId {
        let now = self.instant();
        self.clients[i].endpoint.set_reachable(true, now);
        self.settle();
        self.clients[i].link.expect("the core opens a link at once")
    }

    /// The driver's part: open the link the core asked for.
    fn do_open(&mut self, i: usize) {
        let now = self.instant();
        self.clients[i].opens.push(self.now);
        if self.clients[i].tcp_hangs {
            return;
        }
        if self.clients[i].tcp_refused {
            self.clients[i].endpoint.relay_link_closed(now);
            return;
        }
        let id = self.next_link;
        self.next_link += 1;
        let from = self.clients[i].tcp_from;
        if !self.relay.link_opened(id, from, now) {
            self.clients[i].endpoint.relay_link_closed(now);
            self.relay_actions();
            return;
        }
        let client = &mut self.clients[i];
        client.link = Some(id);
        client.link_blackhole = false;
        client.deframer = Deframer::default();
        client.endpoint.relay_link_opened(now);
        self.put(
            self.delay,
            Msg::RelayLink {
                link: id,
                bytes: PREAMBLE.to_vec(),
            },
        );
        self.relay_actions();
    }

    /// The driver's part: close the link the core asked to close. A
    /// blackholed link's close never reaches the relay.
    fn do_close(&mut self, i: usize) {
        self.clients[i].closes.push(self.now);
        let blackhole = self.clients[i].link_blackhole;
        if let Some(id) = self.clients[i].link.take()
            && !blackhole
        {
            self.relay.link_closed(id);
        }
    }

    /// Client `i` learns client `j`'s direct address.
    pub(crate) fn hint(&mut self, i: usize, j: usize) {
        let now = self.instant();
        let peer = self.clients[j].peer_id();
        self.clients[i]
            .endpoint
            .set_hints(peer, &[&[u8::try_from(j).unwrap()]], now)
            .unwrap();
    }

    /// Client `i` seals `data` for client `to` as the core would send it, and
    /// sends that packet through the relay instead: a packet that took the
    /// relay, as one delayed there would arrive.
    pub(crate) fn send_through_relay(&mut self, i: usize, to: usize, data: &[u8]) {
        let address = self.clients[to].address();
        let peer = address.peer_id();
        let now = self.instant();
        let client = &mut self.clients[i];
        let mut out = [0u8; 2048];
        let output = client
            .endpoint
            .send(
                Target::Address(&address),
                SESSION,
                data,
                RELAY_PATH_MAX,
                now,
                &mut client.policy,
                &mut client.entropy,
                &mut out,
            )
            .unwrap();
        let Output::Transmit { len, .. } = output else {
            panic!("a session with keys sends at once");
        };
        let output = client
            .endpoint
            .through_relay(
                peer,
                len,
                now,
                &mut client.policy,
                &mut client.entropy,
                &mut out,
            )
            .unwrap();
        self.client_output(i, output.into(), &mut out);
    }

    /// Client `i` sends `data` to client `to`, by the path the core chooses.
    pub(crate) fn send(&mut self, i: usize, to: usize, data: &[u8]) -> Result<(), SendError> {
        self.send_in(i, to, SESSION, data)
    }

    /// [`Self::send`] in `context`.
    pub(crate) fn send_in(
        &mut self,
        i: usize,
        to: usize,
        context: &[u8],
        data: &[u8],
    ) -> Result<(), SendError> {
        let address = self.clients[to].address();
        let now = self.instant();
        let client = &mut self.clients[i];
        let mut out = [0u8; 2048];
        let output = client.endpoint.send(
            Target::Address(&address),
            context,
            data,
            RELAY_PATH_MAX,
            now,
            &mut client.policy,
            &mut client.entropy,
            &mut out,
        )?;
        self.client_output(i, output.into(), &mut out);
        Ok(())
    }

    /// Client `i` sends client `to` a stream frame, on the session's path.
    pub(crate) fn send_frame(
        &mut self,
        i: usize,
        to: usize,
        kind: FrameKind,
        frame: &[u8],
    ) -> Result<(), SendError> {
        let peer = self.clients[to].peer_id();
        let now = self.instant();
        let client = &mut self.clients[i];
        let mut out = [0u8; 2048];
        let output = client.endpoint.send_frame(
            peer,
            SESSION,
            kind,
            frame,
            now,
            &mut client.policy,
            &mut client.entropy,
            &mut out,
        )?;
        self.client_output(i, output.into(), &mut out);
        Ok(())
    }

    /// Handles one output of client `i`, with its packet in `out`.
    fn client_output(&mut self, i: usize, output: Step, out: &mut [u8; 2048]) {
        if matches!(output, Step::Transmit { .. }) {
            self.clients[i].transmitted += 1;
        }
        match output {
            Step::Transmit { to, len } => match to {
                To::Relay(path) => self.client_to_relay(i, path, out[..len].to_vec()),
                To::RelayKeepAlive => {
                    let client = &mut self.clients[i];
                    client.sent.keepalives += 1;
                    if let Some(link) = client.link {
                        self.put(
                            self.delay,
                            Msg::RelayLink {
                                link,
                                bytes: KEEPALIVE.to_vec(),
                            },
                        );
                    }
                }
                To::Direct(address) => {
                    let bytes = address.as_direct().expect("a direct address");
                    if let Some(to) = decode_ip(bytes) {
                        self.send_ip(i, to, out[..len].to_vec());
                        return;
                    }
                    let to = usize::from(bytes[0]);
                    if self.direct {
                        self.put(
                            self.delay,
                            Msg::Direct {
                                to,
                                from: i,
                                packet: out[..len].to_vec(),
                            },
                        );
                    }
                }
                To::Source => {}
            },
            Step::Event(event) => self.record(i, event),
            Step::Nothing => {}
        }
    }

    /// Puts client `i` behind a NAT, on its own LAN: its endpoint learns its
    /// LAN address, and the relay sees it at the NAT's mapping for the relay.
    pub(crate) fn behind(&mut self, i: usize, mapping: Mapping, filtering: Filtering) {
        self.behind_chain(i, &[(mapping, filtering)]);
    }

    /// Puts client `i` behind NATs chained, its router's first: a carrier's
    /// NAT behind which its router's is.
    pub(crate) fn behind_chain(&mut self, i: usize, layers: &[(Mapping, Filtering)]) {
        let now = self.now;
        let client = &mut self.clients[i];
        client.nats = layers
            .iter()
            .map(|(mapping, filtering)| Nat::new(*mapping, *filtering))
            .collect();
        let port = out_through(&mut client.nats, RELAY_UDP, now).unwrap_or(INSIDE_PORT);
        client.nat = SocketAddr::new(client.nat.ip(), port);
        self.report_interfaces(i);
    }

    /// Gives client `i` a global IPv6 address behind a stateful firewall, the
    /// relay reaching it there too.
    pub(crate) fn firewalled_v6(&mut self, i: usize) {
        self.dual_stack(i);
        self.clients[i].firewall6 = Some(Nat::new(Mapping::Independent, Filtering::AddressAndPort));
        self.report_interfaces(i);
    }

    /// Client `i`'s endpoint learns its interfaces: its LAN address, and its
    /// global IPv6 address if it has one.
    fn report_interfaces(&mut self, i: usize) {
        let client = &mut self.clients[i];
        let mut addresses = vec![client.lan];
        if client.firewall6.is_some()
            && let Some(v6) = client.nat6
        {
            addresses.push(v6);
        }
        client.endpoint.set_local_addresses(&addresses);
    }

    /// Client `i` moves to another network: a new public address, NATs that
    /// know none of its flows, and its driver telling the core.
    pub(crate) fn move_network(&mut self, i: usize, public: Ipv4Addr) {
        let now = self.now;
        let client = &mut self.clients[i];
        for nat in &mut client.nats {
            *nat = Nat::new(nat.mapping, nat.filtering);
        }
        let port = out_through(&mut client.nats, RELAY_UDP, now).unwrap_or(INSIDE_PORT);
        client.nat = SocketAddr::new(IpAddr::V4(public), port);
        let now = self.instant();
        self.clients[i].endpoint.network_changed(now);
        self.report_interfaces(i);
    }

    /// Puts client `j` on client `i`'s LAN: each reaches the other's LAN address.
    pub(crate) fn same_lan(&mut self, i: usize, j: usize) {
        self.clients[j].lan_id = self.clients[i].lan_id;
    }

    /// Direct IP packets client `i` sent, to whom.
    pub(crate) fn sent_direct(&self, i: usize) -> Vec<SocketAddr> {
        self.direct_log
            .iter()
            .filter(|(from, _)| *from == i)
            .map(|(_, to)| *to)
            .collect()
    }

    /// Client `i` sends `packet` to IP address `to`: on its LAN, straight
    /// there; to an IPv6 address, through both firewalls; otherwise out
    /// through its NATs, and in through those of the client whose public
    /// address `to` is, if they let it in.
    fn send_ip(&mut self, i: usize, to: SocketAddr, packet: Vec<u8>) {
        self.direct_log.push((i, to));
        let now = self.now;
        // A network that drops UDP drops it to peers too.
        if self.clients[i].udp_blocked {
            return;
        }
        let lan_id = self.clients[i].lan_id;
        if let Some(j) = self
            .clients
            .iter()
            .position(|c| c.lan == to && c.lan_id == lan_id)
        {
            let source = self.clients[i].lan;
            if j != i {
                self.put(
                    self.delay,
                    Msg::DirectIp {
                        to: j,
                        source,
                        packet,
                    },
                );
            }
            return;
        }
        if to.is_ipv6() {
            let client = &mut self.clients[i];
            let (Some(source), Some(firewall)) = (client.nat6, client.firewall6.as_mut()) else {
                return;
            };
            firewall.outbound(to, source.port(), now);
            let target = self.clients.iter_mut().position(|c| {
                c.nat6 == Some(to)
                    && c.firewall6
                        .as_mut()
                        .is_some_and(|firewall| firewall.admits(source, to.port(), now).is_some())
            });
            if let Some(j) = target {
                self.put(
                    self.delay,
                    Msg::DirectIp {
                        to: j,
                        source,
                        packet,
                    },
                );
            }
            return;
        }
        let public = self.clients[i].nat.ip();
        let Some(port) = out_through(&mut self.clients[i].nats, to, now) else {
            return;
        };
        let source = SocketAddr::new(public, port);
        let hairpin = self.hairpin;
        let target = self.clients.iter_mut().position(|c| {
            (c.lan_id != lan_id || hairpin)
                && c.nat.ip() == to.ip()
                && in_through(&mut c.nats, source, to.port(), now)
        });
        if let Some(j) = target {
            self.put(
                self.delay,
                Msg::DirectIp {
                    to: j,
                    source,
                    packet,
                },
            );
        }
    }

    /// Makes client `i` dual-stack: the relay sees its UDP over IPv6 too.
    pub(crate) fn dual_stack(&mut self, i: usize) {
        let host = u16::try_from(i + 1).unwrap();
        self.clients[i].nat6 = Some(SocketAddr::new(
            IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, host]),
            40000,
        ));
        // Its driver reaches the relay over IPv4, and over IPv6 too.
        self.clients[i].endpoint.set_relay_families(false, true);
    }

    fn client_to_relay(&mut self, i: usize, path: RelayPath, packet: Vec<u8>) {
        let client = &mut self.clients[i];
        if client.handshakes_ignored && crate::is_first_contact(&packet) {
            return;
        }
        if matches!(path, RelayPath::UdpOther) {
            if let (Some(from), false) = (client.nat6, client.udp_blocked) {
                client.sent.udp += 1;
                client.sent.udp_bytes += packet.len();
                self.put(
                    self.delay,
                    Msg::RelayUdp {
                        from,
                        client: i,
                        packet,
                    },
                );
            }
            return;
        }
        if matches!(path, RelayPath::Udp | RelayPath::Both) {
            client.sent.udp += 1;
            client.sent.udp_bytes += packet.len();
            client.udp_log.push(packet.clone());
            if !client.udp_blocked {
                let other = (client.alternate && client.sent.udp.is_multiple_of(2))
                    .then_some(client.nat6)
                    .flatten();
                let from = other.unwrap_or(client.nat);
                self.put(
                    self.delay,
                    Msg::RelayUdp {
                        from,
                        client: i,
                        packet: packet.clone(),
                    },
                );
            }
        }
        let client = &mut self.clients[i];
        if matches!(path, RelayPath::Tcp | RelayPath::Both) {
            client.sent.tcp += 1;
            client.sent.tcp_bytes += packet.len();
            client.tcp_log.push(packet.clone());
            if let Some(link) = client.link {
                let mut bytes = vec![0u8; packet.len() + 2];
                let n = frame(&packet, &mut bytes).unwrap();
                bytes.truncate(n);
                self.put(self.delay, Msg::RelayLink { link, bytes });
            }
        }
    }

    /// Hands a packet from the relay to client `i`.
    fn client_receives(&mut self, i: usize, link: Link, packet: &[u8]) {
        let now = self.instant();
        let client = &mut self.clients[i];
        let mut buffer = packet.to_vec();
        let mut out = [0u8; 2048];
        let output: Step = client
            .endpoint
            .handle_relay_packet(
                &mut buffer,
                link,
                now,
                &mut client.policy,
                &mut client.entropy,
                &mut out,
            )
            .into();
        self.client_output(i, output, &mut out);
    }

    fn poll_client(&mut self, i: usize) {
        loop {
            let now = self.instant();
            let client = &mut self.clients[i];
            let mut out = [0u8; 2048];
            let poll = client
                .endpoint
                .poll(now, &mut client.policy, &mut client.entropy, &mut out);
            match poll {
                Poll::Transmit { to, len } => {
                    self.client_output(i, Step::Transmit { to, len }, &mut out);
                }
                Poll::Event(event) => self.record(i, own(event)),
                Poll::OpenRelayLink => self.do_open(i),
                Poll::CloseRelayLink => self.do_close(i),
                Poll::Wait(at) => {
                    let stream = self.poll_stream(i);
                    self.clients[i].deadline = Some(stream.map_or(at, |s| s.min(at)));
                    return;
                }
                Poll::Idle => {
                    self.clients[i].deadline = self.poll_stream(i);
                    return;
                }
            }
        }
    }

    /// Drains client `i`'s channels, as a driver would; returns their deadline.
    fn poll_stream(&mut self, i: usize) -> Option<Instant> {
        let now = self.instant();
        let at = self.now;
        let mut frame = [0u8; MAX_DATA_LEN];
        loop {
            let mut out = [0u8; 2048];
            let client = &mut self.clients[i];
            let deliver = client.deliver;
            let stream = client.stream.as_mut()?;
            let step = match stream.poll(now, deliver, &mut frame) {
                StreamPoll::SendFrame {
                    peer,
                    context,
                    kind,
                    len,
                } => match client.endpoint.send_frame(
                    peer,
                    context.as_bytes(),
                    kind,
                    &frame[..len],
                    now,
                    &mut client.policy,
                    &mut client.entropy,
                    &mut out,
                ) {
                    Ok(output) => Some(Step::from(output)),
                    Err(_) => {
                        stream.frame_refused(now);
                        None
                    }
                },
                StreamPoll::Dial { address, context } => client
                    .endpoint
                    .connect(
                        &address,
                        context.as_bytes(),
                        now,
                        &mut client.policy,
                        &mut client.entropy,
                        &mut out,
                    )
                    .ok()
                    .map(Step::from),
                StreamPoll::Event(StreamEvent::Message { data, .. }) => {
                    let data = data.to_vec();
                    client.messages.push(data);
                    client.message_at.push(at);
                    None
                }
                StreamPoll::Event(StreamEvent::Reset { reason, .. }) => {
                    client.stream_resets.push(reason);
                    None
                }
                StreamPoll::Event(StreamEvent::Writable { .. }) => {
                    client.writable += 1;
                    None
                }
                StreamPoll::Wait(at) => return Some(at),
                StreamPoll::Idle => return None,
            };
            if let Some(step) = step {
                self.client_output(i, step, &mut out);
            }
        }
    }

    /// Whether client `i`'s channels hold no deadline: at rest.
    pub(crate) fn stream_idle(&mut self, i: usize) -> bool {
        self.poll_stream(i).is_none()
    }

    /// Gives every client reliable messages.
    pub(crate) fn with_streams(&mut self) {
        for client in &mut self.clients {
            client.stream = Some(Box::default());
        }
    }

    /// Client `i` sends client `to` a reliable message.
    pub(crate) fn send_message(
        &mut self,
        i: usize,
        to: usize,
        message: &[u8],
    ) -> Result<(), convesso_stream::SendError> {
        let address = self.clients[to].address();
        let now = self.instant();
        let client = &mut self.clients[i];
        let stream = client.stream.as_mut().expect("streams on");
        let result = stream.send_message(
            address.peer_id(),
            Some(&address),
            SESSION,
            message,
            now,
            &mut client.entropy,
        );
        self.settle();
        result
    }

    /// Moves the relay's actions onto the wire.
    pub(crate) fn relay_actions(&mut self) {
        while let Some(action) = self.relay.next_action() {
            match action {
                Action::Udp { to, packet } => {
                    self.relay_udp_sent.push((to, packet.len()));
                    if let Some(i) = self
                        .clients
                        .iter()
                        .position(|c| c.nat == to || c.nat6 == Some(to))
                        && !self.clients[i].udp_blocked
                    {
                        self.put(self.delay, Msg::ClientUdp { client: i, packet });
                    }
                }
                Action::Link { id, bytes } => {
                    *self.relay_link_sent.entry(id).or_default() += bytes.len();
                    if bytes.len() > 3 && !bytes.starts_with(&PREAMBLE) {
                        self.relay_link_types.entry(id).or_default().push(bytes[3]);
                    }
                    if let Some(i) = self.clients.iter().position(|c| c.link == Some(id)) {
                        self.put(
                            self.delay,
                            Msg::ClientLink {
                                client: i,
                                link: id,
                                bytes,
                            },
                        );
                    }
                }
                Action::Close { id } => {
                    let now = self.instant();
                    if let Some(i) = self.clients.iter().position(|c| c.link == Some(id)) {
                        self.clients[i].link = None;
                        self.clients[i].endpoint.relay_link_closed(now);
                    }
                }
            }
        }
    }

    fn deliver(&mut self, msg: Msg) {
        let now = self.instant();
        match msg {
            Msg::RelayUdp {
                from,
                client,
                packet,
            } => {
                if !self.clients[client].udp_blocked {
                    self.relay.udp(&packet, from, now);
                }
            }
            Msg::RelayLink { link, bytes } => self.relay.link_bytes(link, &bytes, now),
            Msg::ClientUdp { client, packet } => self.client_receives(client, Link::Udp, &packet),
            Msg::Direct { to, from, packet } => {
                let now = self.instant();
                let source = [u8::try_from(from).unwrap()];
                let client = &mut self.clients[to];
                let mut buffer = packet;
                let mut out = [0u8; 2048];
                let output: Step = client
                    .endpoint
                    .handle_packet(
                        &mut buffer,
                        Source::Direct(&source),
                        now,
                        &mut client.policy,
                        &mut client.entropy,
                        &mut out,
                    )
                    .into();
                if let Step::Transmit {
                    to: To::Source,
                    len,
                } = output
                {
                    self.put(
                        self.delay,
                        Msg::Direct {
                            to: from,
                            from: to,
                            packet: out[..len].to_vec(),
                        },
                    );
                } else {
                    self.client_output(to, output, &mut out);
                }
            }
            Msg::DirectIp { to, source, packet } => {
                let now = self.instant();
                let (encoded, n) = encode_ip(source);
                let client = &mut self.clients[to];
                let mut buffer = packet;
                let mut out = [0u8; 2048];
                let output: Step = client
                    .endpoint
                    .handle_packet(
                        &mut buffer,
                        Source::Direct(&encoded[..n]),
                        now,
                        &mut client.policy,
                        &mut client.entropy,
                        &mut out,
                    )
                    .into();
                if let Step::Transmit {
                    to: To::Source,
                    len,
                } = output
                {
                    self.send_ip(to, source, out[..len].to_vec());
                } else {
                    self.client_output(to, output, &mut out);
                }
            }
            Msg::ClientLink {
                client,
                link,
                bytes,
            } => {
                // Bytes of a link this client no longer has: its socket is
                // closed, and they reach nothing.
                if self.clients[client].link != Some(link) {
                    self.relay_actions();
                    return;
                }
                let mut packets = Vec::new();
                let mut answers = 0;
                {
                    let deframer = &mut self.clients[client].deframer;
                    let mut at = 0;
                    loop {
                        let (used, result) = deframer.feed(&bytes[at..]);
                        at += used;
                        match result {
                            Deframed::Packet(p) => packets.push(p.to_vec()),
                            Deframed::KeepAlive => answers += 1,
                            Deframed::NeedMore | Deframed::Closed(_) => break,
                        }
                    }
                }
                let now = self.instant();
                for _ in 0..answers {
                    self.clients[client].keepalive_answers += 1;
                    self.clients[client].endpoint.relay_keepalive_received(now);
                }
                for packet in packets {
                    self.client_receives(client, Link::Tcp, &packet);
                }
            }
        }
        self.relay_actions();
    }

    /// Everything due now: wire, clients, relay; until nothing moves.
    fn settle(&mut self) {
        for _ in 0..10_000 {
            let mut moved = false;
            while let Some((&key, _)) = self.wire.iter().next() {
                if key.0 > self.now {
                    break;
                }
                let msg = self.wire.remove(&key).unwrap();
                self.deliver(msg);
                moved = true;
            }
            for i in 0..self.clients.len() {
                self.poll_client(i);
            }
            let now = self.instant();
            self.relay_deadline = self.relay.poll(now);
            let before = self.wire.len();
            self.relay_actions();
            moved |= self.wire.len() != before;
            let due_now = self.wire.keys().next().is_some_and(|k| k.0 <= self.now);
            if !moved && !due_now {
                return;
            }
        }
        panic!("the world never settled at {} ms", self.now);
    }

    /// Runs until `until` ms, jumping from one event to the next.
    pub(crate) fn run_until(&mut self, until: u64) {
        loop {
            self.settle();
            let mut next = self.wire.keys().next().map(|k| k.0);
            let mut consider = |at: Option<u64>| {
                if let Some(at) = at {
                    next = Some(next.map_or(at, |n| n.min(at)));
                }
            };
            for client in &self.clients {
                consider(client.deadline.map(Instant::as_millis));
            }
            consider(self.relay_deadline.map(Instant::as_millis));
            let next = next.map(|at| if at > self.now { at } else { self.now + 1 });
            match next {
                Some(at) if at <= until => self.now = at,
                _ => {
                    self.now = until;
                    self.settle();
                    return;
                }
            }
        }
    }

    pub(crate) fn run_for(&mut self, ms: u64) {
        let until = self.now + ms;
        self.run_until(until);
    }

    /// Puts a packet client `i` produced on its path to the relay: UDP.
    pub(crate) fn inject_from(&mut self, i: usize, packet: &[u8]) {
        let from = self.clients[i].nat;
        self.put(
            self.delay,
            Msg::RelayUdp {
                from,
                client: i,
                packet: packet.to_vec(),
            },
        );
    }

    /// Injects a UDP datagram to the relay, as if from `from`.
    pub(crate) fn inject_udp(&mut self, from: SocketAddr, packet: &[u8]) {
        let now = self.instant();
        self.relay.udp(packet, from, now);
        self.relay_actions();
    }

    /// Hands a packet to a client's endpoint as a deliver from the relay would.
    pub(crate) fn handle_direct(&mut self, i: usize, packet: &mut [u8], source: Source<'_>) {
        let now = self.instant();
        let client = &mut self.clients[i];
        let mut out = [0u8; 2048];
        let output: Step = client
            .endpoint
            .handle_packet(
                packet,
                source,
                now,
                &mut client.policy,
                &mut client.entropy,
                &mut out,
            )
            .into();
        self.client_output(i, output, &mut out);
    }
}

/// An output, owning its event.
pub(crate) enum Step {
    Transmit { to: To, len: usize },
    Event(Ev),
    Nothing,
}

impl From<Output<'_>> for Step {
    fn from(output: Output<'_>) -> Self {
        match output {
            Output::Transmit { to, len } => Self::Transmit { to, len },
            Output::Event(event) => Self::Event(own(event)),
            Output::Nothing => Self::Nothing,
        }
    }
}
