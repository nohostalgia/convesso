//! The convesso relay server (`PROTOCOL.md §6`), sans-IO.
//!
//! A relay is a convesso endpoint serving one context, `convesso-relay`. Each
//! client opens a session with it; the client's frames travel as that
//! session's datagrams, and the relay forwards the packets they carry between
//! the keys it authenticated. It reads none of them.
//!
//! ```text
//! inputs                                 outputs (Relay::next_action)
//!   udp(packet, from)                      Action::Udp { to, packet }
//!   link_opened(id, from) / link_bytes      Action::Link { id, bytes }  (framed)
//!   link_closed(id) / set_link_backlog      Action::Close { id }
//!   poll(now)                              deadlines
//! ```
//!
//! What it trusts, and when:
//! - a client's UDP address, and a TCP link's binding to a key, only from a
//!   transport packet that opened under that client's keys with a counter
//!   above every one accepted before;
//! - nothing to an address that is not confirmed beyond the handshake's own
//!   answer, which is never larger than what it answers;
//! - the sender of every deliver is the key of the session the forward
//!   arrived on.
//!
//! Every limit drops; the relay never waits for anyone. It answers each
//! keep-alive on a link with one keep-alive, and starts none. Sockets, timers
//! and the TLS wrapper are the driver's.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use convesso_core::dos::Source;
use convesso_core::endpoint::{Endpoint, Event, Output, Poll, Target, To};
use convesso_core::handshake::{
    Admission, Decision, Entropy, RefusalCode, ResponderError, messages::is_first_contact_type,
};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::relay::framing::{self, Deframed, Deframer, PREAMBLE};
use convesso_core::relay::{self, Frame, Link};
use convesso_core::storage::Server;
use convesso_core::time::Instant;

/// The driver's name for a TCP link.
pub type LinkId = u64;

/// A client's limits, counting TCP and UDP together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Bytes of forwards a second.
    pub bytes_per_second: u64,
    /// Bytes of forwards at once.
    pub bytes_burst: u64,
    /// Forwards a second.
    pub packets_per_second: u64,
    /// Forwards at once.
    pub packets_burst: u64,
}

impl Default for Limits {
    /// 2.5 MB/s with a 10 MB burst, 5,000 packets a second: a tunnel's ssh,
    /// desktop sessions and ordinary sync fit; a bulk backup reaches it.
    fn default() -> Self {
        Self {
            bytes_per_second: 2_500_000,
            bytes_burst: 10_000_000,
            packets_per_second: 5_000,
            packets_burst: 5_000,
        }
    }
}

/// The relay's own limits and timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// The limits of a client the policy accepts without a class of its own.
    pub limits: Limits,
    /// First contacts carried to one recipient a second.
    pub first_contacts_per_recipient: u64,
    /// First contacts carried to one recipient at once.
    pub first_contacts_burst: u64,
    /// First contacts to the relay a second from one IP address.
    pub handshakes_per_ip: u64,
    /// First contacts to the relay at once from one IP address.
    pub handshakes_burst: u64,
    /// TCP links open at once from one IP address: several devices behind one
    /// NAT must fit.
    pub links_per_ip: usize,
    /// New TCP links a second, over all addresses.
    pub new_links_per_second: u64,
    /// New TCP links at once.
    pub new_links_burst: u64,
    /// Bytes a recipient's TCP link may have waiting to be written before
    /// packets for it are dropped.
    pub queue_per_recipient: usize,
    /// A link on which nothing arrives for this long is closed. Sends nothing.
    pub link_silence: Duration,
    /// At most one not-connected notice this often per sender and recipient.
    pub not_connected_every: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            first_contacts_per_recipient: 20,
            first_contacts_burst: 5,
            handshakes_per_ip: 20,
            handshakes_burst: 20,
            links_per_ip: 64,
            new_links_per_second: 5,
            new_links_burst: 50,
            queue_per_recipient: 256 * 1024,
            link_silence: Duration::from_secs(180),
            not_connected_every: Duration::from_secs(1),
        }
    }
}

/// UDP to a client is proven while an authenticated UDP packet from it arrived
/// this recently (`PROTOCOL.md §6`).
pub const UDP_PROVEN_FOR: Duration = convesso_core::endpoint::UDP_PROVEN_FOR;

/// How long after a client's first contact with a payload the relay keeps
/// deliveries for it waiting for its confirmation: the pending handshake's
/// lifetime.
const PENDING_FOR: Duration = Duration::from_secs(5);

/// The largest packet the relay sends a client: a deliver of the largest
/// carried packet, sealed.
const MAX_OUT: usize = 2048;

/// A client with no link, no proven UDP and no session for this long is
/// forgotten: nothing could reach it anyway, and a relay open to everyone must
/// not keep every key that ever handshook.
const FORGET_AFTER: Duration = Duration::from_secs(600);

/// The operator's decision about a client key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Refuse it, with this code, in the authenticated refusal.
    Refuse(RefusalCode),
    /// Accept it, with these limits, or the configuration's.
    Accept(Option<Limits>),
}

/// The operator's admission policy.
pub trait Policy {
    /// Whether `peer` may use the relay.
    fn admit(&mut self, peer: &PeerId) -> Admit;
}

/// Anyone may use the relay, within the default limits.
#[derive(Debug, Clone, Copy, Default)]
pub struct Open;

impl Policy for Open {
    fn admit(&mut self, _peer: &PeerId) -> Admit {
        Admit::Accept(None)
    }
}

/// What the driver does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a UDP datagram.
    Udp {
        /// To whom.
        to: SocketAddr,
        /// The datagram.
        packet: Vec<u8>,
    },
    /// Write bytes on a TCP link: the preamble, or framed packets.
    Link {
        /// The link.
        id: LinkId,
        /// The bytes, framed.
        bytes: Vec<u8>,
    },
    /// Close a TCP link; it is forgotten.
    Close {
        /// The link.
        id: LinkId,
    },
}

/// A token bucket in thousandths of a token, refilled from the time given.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    level: u64,
    at: Instant,
}

impl Bucket {
    fn full(burst: u64, now: Instant) -> Self {
        Self {
            level: burst.saturating_mul(1000),
            at: now,
        }
    }

    fn take(&mut self, amount: u64, rate: u64, burst: u64, now: Instant) -> bool {
        let elapsed = now.as_millis().saturating_sub(self.at.as_millis());
        self.level = self
            .level
            .saturating_add(elapsed.saturating_mul(rate))
            .min(burst.saturating_mul(1000));
        self.at = now;
        let need = amount.saturating_mul(1000);
        if self.level >= need {
            self.level -= need;
            true
        } else {
            false
        }
    }
}

/// Where a packet came from, or goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Dest {
    Udp(SocketAddr),
    Link(LinkId),
}

impl Dest {
    /// The driver-side source for the core's DoS checks: up to 18 bytes.
    fn label(self) -> ([u8; 19], usize) {
        let mut label = [0u8; 19];
        match self {
            Self::Udp(addr) => {
                let (ip, len) = match addr.ip() {
                    IpAddr::V4(ip) => {
                        label[1..5].copy_from_slice(&ip.octets());
                        (5, 7)
                    }
                    IpAddr::V6(ip) => {
                        label[1..17].copy_from_slice(&ip.octets());
                        (17, 19)
                    }
                };
                label[0] = b'U';
                if let Some(field) = label.get_mut(ip..len) {
                    field.copy_from_slice(&addr.port().to_le_bytes());
                }
                (label, len)
            }
            Self::Link(id) => {
                label[0] = b'L';
                label[1..9].copy_from_slice(&id.to_le_bytes());
                (label, 9)
            }
        }
    }

    /// The destination a label names: the inverse of [`Self::label`].
    fn from_label(label: &[u8]) -> Option<Self> {
        match label {
            [b'U', a, b, c, d, lo, hi] => Some(Self::Udp(SocketAddr::new(
                IpAddr::from([*a, *b, *c, *d]),
                u16::from_le_bytes([*lo, *hi]),
            ))),
            [b'U', rest @ ..] if rest.len() == 18 => {
                let ip: [u8; 16] = rest.get(..16)?.try_into().ok()?;
                let port: [u8; 2] = rest.get(16..)?.try_into().ok()?;
                Some(Self::Udp(SocketAddr::new(
                    IpAddr::from(ip),
                    u16::from_le_bytes(port),
                )))
            }
            [b'L', id @ ..] => Some(Self::Link(u64::from_le_bytes(id.try_into().ok()?))),
            _ => None,
        }
    }
}

/// A client's UDP address in one family, and when it last proved itself.
#[derive(Debug, Clone, Copy)]
struct Udp {
    address: SocketAddr,
    at: Instant,
}

struct Client {
    peer: PeerId,
    limits: Limits,
    address: Option<Address>,
    link: Option<LinkId>,
    /// Its UDP address over IPv4 and over IPv6: a dual-stack client has both.
    udp4: Option<Udp>,
    udp6: Option<Udp>,
    pending_until: Option<Instant>,
    /// When the client last handshook or authenticated a packet.
    seen: Instant,
    bytes: Bucket,
    packets: Bucket,
    first_contacts: Bucket,
}

impl Client {
    fn new(peer: PeerId, limits: Limits, config: &Config, now: Instant) -> Self {
        Self {
            peer,
            limits,
            address: None,
            link: None,
            udp4: None,
            udp6: None,
            pending_until: None,
            seen: now,
            bytes: Bucket::full(limits.bytes_burst, now),
            packets: Bucket::full(limits.packets_burst, now),
            first_contacts: Bucket::full(config.first_contacts_burst, now),
        }
    }

    /// Its UDP address in `address`'s family.
    const fn udp_like(&mut self, address: SocketAddr) -> &mut Option<Udp> {
        if address.is_ipv4() {
            &mut self.udp4
        } else {
            &mut self.udp6
        }
    }

    /// The proven UDP address that last carried an authenticated packet.
    fn udp(&self, now: Instant) -> Option<SocketAddr> {
        [self.udp4, self.udp6]
            .into_iter()
            .flatten()
            .filter(|udp| now < udp.at.saturating_add(UDP_PROVEN_FOR))
            .max_by_key(|udp| udp.at)
            .map(|udp| udp.address)
    }

    fn udp_proven(&self, now: Instant) -> bool {
        self.udp(now).is_some()
    }

    /// Where packets for this client go now, if anywhere.
    fn path(&self, now: Instant) -> Option<Dest> {
        self.udp(now)
            .map(Dest::Udp)
            .or_else(|| self.link.map(Dest::Link))
    }

    /// Whether a packet for this client can reach it, now or once its
    /// pending handshake is confirmed.
    fn reachable(&self, now: Instant) -> bool {
        self.path(now).is_some() || self.pending_until.is_some_and(|until| now < until)
    }
}

struct LinkState {
    from: SocketAddr,
    deframer: Box<Deframer>,
    last_received: Instant,
    bound: Option<[u8; 32]>,
    backlog: usize,
}

struct IpState {
    links: usize,
    handshakes: Bucket,
}

/// The policy as the core's admission: records the limits of each client the
/// operator accepts.
struct Admitting<'a, P> {
    policy: &'a mut P,
    clients: &'a mut HashMap<[u8; 32], Client>,
    config: &'a Config,
    now: Instant,
}

impl<P: Policy> Admission for Admitting<'_, P> {
    fn admit(&mut self, peer: &PeerId, context: &[u8]) -> Decision {
        if context != relay::CONTEXT {
            return Decision::Refuse {
                code: RefusalCode::BUSY,
                psk: None,
            };
        }
        match self.policy.admit(peer) {
            Admit::Refuse(code) => Decision::Refuse { code, psk: None },
            Admit::Accept(limits) => {
                let limits = limits.unwrap_or(self.config.limits);
                self.clients
                    .entry(*peer.as_bytes())
                    .and_modify(|client| {
                        client.limits = limits;
                        client.seen = self.now;
                    })
                    .or_insert_with(|| Client::new(*peer, limits, self.config, self.now));
                Decision::Accept { psk: None }
            }
        }
    }
}

/// A relay.
pub struct Relay<P, E> {
    endpoint: Endpoint<Server>,
    policy: P,
    entropy: E,
    config: Config,
    clients: HashMap<[u8; 32], Client>,
    /// The client each confirmed UDP address or bound link belongs to: where
    /// the endpoint's packets for a session go back to its client.
    owners: HashMap<Dest, [u8; 32]>,
    links: HashMap<LinkId, LinkState>,
    ips: HashMap<IpAddr, IpState>,
    new_links: Bucket,
    notices: HashMap<([u8; 32], [u8; 32]), Instant>,
    actions: VecDeque<Action>,
    out: Vec<u8>,
    /// The packet being handled already reported its sender's address: a
    /// question it carries needs no second answer.
    reported: bool,
    /// Bytes sent to each address that is not a confirmed client's, and bytes
    /// received from it: what the anti-amplification tests read.
    #[cfg(test)]
    unconfirmed: HashMap<Dest, (usize, usize)>,
    /// Each first contact forwarded, as its recipient and its ephemeral key:
    /// what the tests of a dial's attempts read.
    #[cfg(test)]
    first_contacts_forwarded: Vec<([u8; 32], [u8; 32])>,
}

fn is_first_contact(packet: &[u8]) -> bool {
    matches!(
        packet,
        [0x01, kind, ..] if is_first_contact_type(*kind)
    )
}

impl<P: Policy, E: Entropy> Relay<P, E> {
    /// A relay with `identity`, admitting by `policy`, under `config`.
    ///
    /// # Errors
    ///
    /// A [`ResponderError`] if the relay context cannot be served, which does
    /// not happen with a fresh endpoint.
    pub fn new(
        identity: Identity,
        policy: P,
        entropy: E,
        config: Config,
        now: Instant,
    ) -> Result<Self, ResponderError> {
        let mut endpoint = Endpoint::new(identity, &[])?;
        endpoint.serve_relay_context()?;
        Ok(Self {
            endpoint,
            policy,
            entropy,
            config,
            clients: HashMap::new(),
            owners: HashMap::new(),
            links: HashMap::new(),
            ips: HashMap::new(),
            new_links: Bucket::full(config.new_links_burst, now),
            notices: HashMap::new(),
            actions: VecDeque::new(),
            out: vec![0; MAX_OUT],
            #[cfg(test)]
            unconfirmed: HashMap::new(),
            #[cfg(test)]
            first_contacts_forwarded: Vec::new(),
            reported: false,
        })
    }

    /// The relay's address, which clients pin.
    #[must_use]
    pub fn address(&self) -> Address {
        *self.endpoint.identity().address()
    }

    /// The next thing to do, if any.
    pub fn next_action(&mut self) -> Option<Action> {
        self.actions.pop_front()
    }

    /// A TCP link was accepted from `from`. Returns whether the relay keeps
    /// it; when it does not, an [`Action::Close`] follows.
    pub fn link_opened(&mut self, id: LinkId, from: SocketAddr, now: Instant) -> bool {
        let config = self.config;
        let ip = self.ips.entry(from.ip()).or_insert_with(|| IpState {
            links: 0,
            handshakes: Bucket::full(config.handshakes_burst, now),
        });
        if ip.links >= config.links_per_ip
            || !self
                .new_links
                .take(1, config.new_links_per_second, config.new_links_burst, now)
        {
            self.actions.push_back(Action::Close { id });
            return false;
        }
        ip.links += 1;
        self.links.insert(
            id,
            LinkState {
                from,
                deframer: Box::default(),
                last_received: now,
                bound: None,
                backlog: 0,
            },
        );
        self.actions.push_back(Action::Link {
            id,
            bytes: PREAMBLE.to_vec(),
        });
        true
    }

    /// The driver has `bytes` written on link `id` but not yet sent.
    pub fn set_link_backlog(&mut self, id: LinkId, bytes: usize) {
        if let Some(link) = self.links.get_mut(&id) {
            link.backlog = bytes;
        }
    }

    /// The link closed.
    pub fn link_closed(&mut self, id: LinkId) {
        self.forget_link(id);
    }

    /// Bytes read from link `id`.
    pub fn link_bytes(&mut self, id: LinkId, bytes: &[u8], now: Instant) {
        let mut at = 0;
        loop {
            let Some(link) = self.links.get_mut(&id) else {
                return;
            };
            link.last_received = now;
            let from = link.from;
            let (used, result) = link.deframer.feed(bytes.get(at..).unwrap_or_default());
            at += used;
            match result {
                Deframed::NeedMore => return,
                // Answered, so that the client can tell a live link from a dead
                // one; the relay starts none.
                Deframed::KeepAlive => self.actions.push_back(Action::Link {
                    id,
                    bytes: framing::KEEPALIVE.to_vec(),
                }),
                Deframed::Packet(packet) => {
                    let mut packet = packet.to_vec();
                    self.packet(&mut packet, Dest::Link(id), from.ip(), now);
                }
                Deframed::Closed(_) => {
                    self.actions.push_back(Action::Close { id });
                    self.forget_link(id);
                    return;
                }
            }
        }
    }

    /// A UDP datagram from `from`.
    pub fn udp(&mut self, packet: &[u8], from: SocketAddr, now: Instant) {
        // A dual-stack socket names an IPv4 sender in IPv6: it is the IPv4 one.
        let from = match from.ip() {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map_or(from, |v4| SocketAddr::new(IpAddr::V4(v4), from.port())),
            IpAddr::V4(_) => from,
        };
        let mut packet = packet.to_vec();
        self.packet(&mut packet, Dest::Udp(from), from.ip(), now);
    }

    /// Does what is due at `now`, and returns when it next has something to do.
    pub fn poll(&mut self, now: Instant) -> Option<Instant> {
        let silence = self.config.link_silence;
        let silent: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, link)| now >= link.last_received.saturating_add(silence))
            .map(|(id, _)| *id)
            .collect();
        for id in silent {
            self.actions.push_back(Action::Close { id });
            self.forget_link(id);
        }
        self.prune(now);
        let mut next = self.drain(now);
        for link in self.links.values() {
            let due = link.last_received.saturating_add(silence);
            next = Some(next.map_or(due, |n: Instant| n.min(due)));
        }
        next
    }

    /// Forgets what no longer matters: clients nothing could reach, idle IP
    /// addresses, old not-connected notices.
    fn prune(&mut self, now: Instant) {
        let endpoint = &self.endpoint;
        self.clients.retain(|_, client| {
            client.link.is_some()
                || client.udp_proven(now)
                || client.reachable(now)
                || now < client.seen.saturating_add(FORGET_AFTER)
                || endpoint.is_live(&client.peer, relay::CONTEXT, now)
        });
        let clients = &self.clients;
        self.owners.retain(|_, key| clients.contains_key(key));
        let every = self.config.not_connected_every;
        self.notices.retain(|_, at| now < at.saturating_add(every));
        let config = self.config;
        // An address with no link and a full bucket holds nothing worth keeping.
        self.ips.retain(|_, ip| {
            let mut bucket = ip.handshakes;
            ip.links > 0
                || !bucket.take(
                    config.handshakes_burst,
                    config.handshakes_per_ip,
                    config.handshakes_burst,
                    now,
                )
        });
    }

    /// How many clients, links, addresses and notices the relay holds.
    #[must_use]
    pub fn table_sizes(&self) -> (usize, usize, usize, usize) {
        (
            self.clients.len(),
            self.links.len(),
            self.ips.len(),
            self.notices.len(),
        )
    }

    fn forget_link(&mut self, id: LinkId) {
        self.owners.remove(&Dest::Link(id));
        if let Some(link) = self.links.remove(&id) {
            if let Some(ip) = self.ips.get_mut(&link.from.ip()) {
                ip.links = ip.links.saturating_sub(1);
            }
            if let Some(client) = link.bound.and_then(|key| self.clients.get_mut(&key))
                && client.link == Some(id)
            {
                client.link = None;
            }
        }
    }

    /// A packet from `from`, whose IP address is `ip`.
    fn packet(&mut self, packet: &mut [u8], from: Dest, ip: IpAddr, now: Instant) {
        let config = self.config;
        self.reported = false;
        if is_first_contact(packet) {
            let state = self.ips.entry(ip).or_insert_with(|| IpState {
                links: 0,
                handshakes: Bucket::full(config.handshakes_burst, now),
            });
            if !state
                .handshakes
                .take(1, config.handshakes_per_ip, config.handshakes_burst, now)
            {
                return;
            }
        }
        // A link bound to one key carries no other key's session.
        if let Dest::Link(id) = from
            && let Some(bound) = self.links.get(&id).and_then(|link| link.bound)
            && let Some(owner) = self.endpoint.owner_of(packet)
            && *owner.as_bytes() != bound
        {
            return;
        }
        #[cfg(test)]
        {
            self.unconfirmed.entry(from).or_default().1 += packet.len();
        }
        let (label, label_len) = from.label();
        let mut admission = Admitting {
            policy: &mut self.policy,
            clients: &mut self.clients,
            config: &self.config,
            now,
        };
        let output = self.endpoint.handle_packet(
            packet,
            Source::Direct(label.get(..label_len).unwrap_or_default()),
            now,
            &mut admission,
            &mut self.entropy,
            &mut self.out,
        );
        // What the output carries, owned, so that the endpoint is free again.
        let (transmit, frame) = match output {
            Output::Transmit { to, len } => (Some((to, len)), None),
            Output::Event(Event::Payload { peer, data, .. }) => {
                if let Some(client) = self.clients.get_mut(peer.as_bytes()) {
                    client.pending_until = Some(now.saturating_add(PENDING_FOR));
                }
                (None, Some((peer, data.to_vec(), true)))
            }
            Output::Event(Event::Datagram { peer, data, .. }) => {
                (None, Some((peer, data.to_vec(), false)))
            }
            Output::Event(_) | Output::Nothing => (None, None),
        };
        if let Some(authenticated) = self.endpoint.last_authenticated()
            && authenticated.newest
        {
            self.authenticated(authenticated.peer, from, now);
        }
        if let Some((to, len)) = transmit {
            self.emit(to, len, Some(from), now);
        }
        if let Some((sender, data, wake)) = frame {
            self.frame(sender, &data, wake, from, now);
        }
        self.drain_from(Some(from), now);
    }

    /// `peer` authenticated a packet no one can have recorded, from `from`.
    fn authenticated(&mut self, peer: PeerId, from: Dest, now: Instant) {
        let Some(client) = self.clients.get_mut(peer.as_bytes()) else {
            return;
        };
        client.pending_until = None;
        client.seen = now;
        self.owners.insert(from, *peer.as_bytes());
        let observed = match from {
            Dest::Udp(addr) => {
                // One address per family, each news when it becomes proven
                // or changes; packets go on the one that carried this one.
                let slot = client.udp_like(addr);
                let news = slot.is_none_or(|udp| {
                    udp.address != addr || now >= udp.at.saturating_add(UDP_PROVEN_FOR)
                });
                if let Some(old) = slot.filter(|udp| udp.address != addr) {
                    self.owners.remove(&Dest::Udp(old.address));
                }
                *slot = Some(Udp {
                    address: addr,
                    at: now,
                });
                news.then_some((Link::Udp, addr))
            }
            Dest::Link(id) => {
                if client.link == Some(id) {
                    None
                } else {
                    let old = client.link.replace(id);
                    // A new link: the client (re)connected, from a restart or
                    // another network. The UDP addresses its earlier packets
                    // proved may be gone; its next UDP packet proves one again,
                    // and until then the link carries what is for it.
                    for udp in [client.udp4.take(), client.udp6.take()]
                        .into_iter()
                        .flatten()
                    {
                        self.owners.remove(&Dest::Udp(udp.address));
                    }
                    let Some(link) = self.links.get_mut(&id) else {
                        return;
                    };
                    link.bound = Some(*peer.as_bytes());
                    let addr = link.from;
                    if let Some(old) = old {
                        self.actions.push_back(Action::Close { id: old });
                        if let Some(link) = self.links.get_mut(&old) {
                            link.bound = None;
                        }
                        self.forget_link(old);
                    }
                    Some((Link::Tcp, addr))
                }
            }
        };
        if let Some((link, address)) = observed {
            let mut frame = [0u8; 21];
            if let Ok(len) = relay::encode(&Frame::Observed { link, address }, &mut frame) {
                self.send_to(peer, frame.get(..len).unwrap_or_default(), now);
                self.reported = true;
            }
        }
    }

    /// A relay frame from `sender`'s session; `wake` when it came in the
    /// payload of a first contact, before the session is confirmed.
    fn frame(&mut self, sender: PeerId, data: &[u8], wake: bool, from: Dest, now: Instant) {
        match relay::decode(data) {
            Ok(Frame::Forward { recipient, packet }) => {
                if recipient == *sender.as_bytes() {
                    return;
                }
                if !wake {
                    // A wake is charged to its source's handshake rate, on
                    // arrival: a replay cannot spend the key's budget.
                    let Some(client) = self.clients.get_mut(sender.as_bytes()) else {
                        return;
                    };
                    let limits = client.limits;
                    let bytes = u64::try_from(data.len()).unwrap_or(u64::MAX);
                    if !client
                        .packets
                        .take(1, limits.packets_per_second, limits.packets_burst, now)
                        || !client.bytes.take(
                            bytes,
                            limits.bytes_per_second,
                            limits.bytes_burst,
                            now,
                        )
                    {
                        return;
                    }
                }
                self.forward(sender, recipient, packet, now);
            }
            Ok(Frame::Register { address }) => {
                if let Ok(address) = Address::parse(address)
                    && address.peer_id() == sender
                    && let Some(client) = self.clients.get_mut(sender.as_bytes())
                {
                    client.address = Some(address);
                }
            }
            // A client asking where the relay sees it, on the path the
            // question came on: the answer is about that path, and goes
            // back on it (the path that last carried the client's packet).
            // Charged as any packet; as large as the question at most.
            Ok(Frame::Observed { .. }) if !self.reported => {
                let Some(client) = self.clients.get_mut(sender.as_bytes()) else {
                    return;
                };
                let limits = client.limits;
                if !client
                    .packets
                    .take(1, limits.packets_per_second, limits.packets_burst, now)
                {
                    return;
                }
                let observed = match from {
                    Dest::Udp(address) => Some((Link::Udp, address)),
                    Dest::Link(id) => self.links.get(&id).map(|link| (Link::Tcp, link.from)),
                };
                if let Some((link, address)) = observed {
                    let mut frame = [0u8; 21];
                    if let Ok(len) = relay::encode(&Frame::Observed { link, address }, &mut frame) {
                        self.send_to(sender, frame.get(..len).unwrap_or_default(), now);
                    }
                }
            }
            // The relay's own frames, from a client, and anything malformed.
            Ok(Frame::Deliver { .. } | Frame::NotConnected { .. } | Frame::Observed { .. })
            | Err(_) => {}
        }
    }

    /// Carries `packet` from `sender` to `recipient`, or says it cannot.
    fn forward(&mut self, sender: PeerId, recipient: [u8; 32], packet: &[u8], now: Instant) {
        let config = self.config;
        let Some(client) = self
            .clients
            .get_mut(&recipient)
            .filter(|client| client.reachable(now))
        else {
            self.not_connected(sender, recipient, now);
            return;
        };
        if is_first_contact(packet)
            && !client.first_contacts.take(
                1,
                config.first_contacts_per_recipient,
                config.first_contacts_burst,
                now,
            )
        {
            return;
        }
        #[cfg(test)]
        if is_first_contact(packet)
            && let Some(ephemeral) = packet.get(6..38).and_then(|e| e.try_into().ok())
        {
            self.first_contacts_forwarded.push((recipient, ephemeral));
        }
        let peer = client.peer;
        let mut frame = vec![0u8; relay::ROUTED_HEADER_LEN + packet.len()];
        let Ok(len) = relay::encode(
            &Frame::Deliver {
                sender: *sender.as_bytes(),
                packet,
            },
            &mut frame,
        ) else {
            return;
        };
        self.send_to(peer, frame.get(..len).unwrap_or_default(), now);
    }

    /// Tells `sender`, at most once per interval, that `recipient` is not here.
    fn not_connected(&mut self, sender: PeerId, recipient: [u8; 32], now: Instant) {
        let pair = (*sender.as_bytes(), recipient);
        if self
            .notices
            .get(&pair)
            .is_some_and(|at| now < at.saturating_add(self.config.not_connected_every))
        {
            return;
        }
        self.notices.insert(pair, now);
        let mut frame = [0u8; relay::ROUTED_HEADER_LEN];
        if let Ok(len) = relay::encode(&Frame::NotConnected { recipient }, &mut frame) {
            self.send_to(sender, frame.get(..len).unwrap_or_default(), now);
        }
    }

    /// Sends a relay frame in `peer`'s session: sealed now if it has keys,
    /// otherwise queued; a session without keys is reopened from the client's
    /// registered address, on the client's current path, the frame in the
    /// first contact's payload. The endpoint keeps no session without keys:
    /// where the client is, the relay knows.
    fn send_to(&mut self, peer: PeerId, frame: &[u8], now: Instant) {
        let live = self.endpoint.is_live(&peer, relay::CONTEXT, now);
        let (address, at) = self
            .clients
            .get(peer.as_bytes())
            .map_or((None, None), |client| (client.address, client.path(now)));
        let at = at.map(Dest::label);
        let target = match (&address, &at) {
            (Some(address), Some((label, len))) if !live => {
                Target::AddressAt(address, label.get(..*len).unwrap_or_default())
            }
            (Some(address), None) if !live => Target::Address(address),
            _ => Target::Peer(peer),
        };
        let mut admission = Admitting {
            policy: &mut self.policy,
            clients: &mut self.clients,
            config: &self.config,
            now,
        };
        let result = self.endpoint.send(
            target,
            relay::CONTEXT,
            frame,
            framing::MAX_FRAME,
            now,
            &mut admission,
            &mut self.entropy,
            &mut self.out,
        );
        // Queued, or dropped: a full queue or an unknown address is a loss.
        if let Ok(Output::Transmit { to, len }) = result {
            self.emit(to, len, None, now);
        }
    }

    /// Sends `out[..len]`: to `answer` for an answer to the packet being
    /// handled, or on a client's path.
    fn emit(&mut self, to: To, len: usize, answer: Option<Dest>, now: Instant) {
        let dest = match to {
            To::Source => answer,
            // The endpoint names where the session was last heard from; the
            // relay sends on its client's current path.
            To::Direct(address) => address
                .as_direct()
                .and_then(Dest::from_label)
                .and_then(|dest| self.owners.get(&dest))
                .and_then(|key| self.clients.get(key))
                .and_then(|client| client.path(now)),
            To::Relay(_) | To::RelayKeepAlive => None,
        };
        let (Some(dest), Some(packet)) = (dest, self.out.get(..len)) else {
            return;
        };
        let packet = packet.to_vec();
        #[cfg(test)]
        {
            self.unconfirmed.entry(dest).or_default().0 += packet.len();
        }
        match dest {
            Dest::Udp(to) => self.actions.push_back(Action::Udp { to, packet }),
            Dest::Link(id) => {
                let Some(link) = self.links.get_mut(&id) else {
                    return;
                };
                let mut bytes = vec![0u8; packet.len() + 2];
                let Some(framed) = framing::frame(&packet, &mut bytes) else {
                    return;
                };
                if link.backlog + framed > self.config.queue_per_recipient {
                    return;
                }
                link.backlog += framed;
                bytes.truncate(framed);
                self.actions.push_back(Action::Link { id, bytes });
            }
        }
    }

    /// Drains the endpoint's polls; returns its next deadline.
    fn drain(&mut self, now: Instant) -> Option<Instant> {
        self.drain_from(None, now)
    }

    fn drain_from(&mut self, answer: Option<Dest>, now: Instant) -> Option<Instant> {
        loop {
            let mut admission = Admitting {
                policy: &mut self.policy,
                clients: &mut self.clients,
                config: &self.config,
                now,
            };
            match self
                .endpoint
                .poll(now, &mut admission, &mut self.entropy, &mut self.out)
            {
                Poll::Transmit { to, len } => self.emit(to, len, answer, now),
                // A relay pins no relay: no link commands come from its endpoint.
                Poll::Event(_) | Poll::OpenRelayLink | Poll::CloseRelayLink => {}
                Poll::Wait(at) => return Some(at),
                Poll::Idle => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests;
