//! The path messages (`PROTOCOL.md §7`): the data of three inner
//! types of a session's transport packets.
//!
//! The inner types are in [`crate::transport::inner`].
//!
//! ```text
//! 0x03 candidates   generation (2, LE) | count (1, <= 8) | count x entry
//!                   entry: kind (1) | family (1) | address (4|16) | port (2, LE)
//!                   kind: 0x00 local, 0x01 public, 0x02 seen by peer
//! 0x04 probe        nonce (8)
//! 0x05 answer       nonce (8) | family (1) | address (4|16) | port (2, LE)
//! ```
//!
//! They travel inside the session, so they are authenticated and encrypted;
//! these codecs only check their shape. Decoders never panic, allocate, or
//! loop beyond their input.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use crate::time::Instant;

/// The most candidates a list carries.
pub const MAX_CANDIDATES: usize = 8;

/// The longest candidate list.
pub const MAX_CANDIDATES_LEN: usize = 3 + MAX_CANDIDATES * ENTRY_V6;

/// A probe's nonce.
pub type Nonce = [u8; 8];

const ENTRY_V6: usize = 1 + 1 + 16 + 2;

/// Where a candidate comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateKind {
    /// An interface address.
    Local,
    /// A public address, as the relay observed it.
    Public,
    /// An address a peer saw this endpoint at.
    SeenByPeer,
}

/// An address a peer might reach this endpoint at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Candidate {
    /// Where it comes from.
    pub kind: CandidateKind,
    /// The address and port.
    pub address: SocketAddr,
}

impl Candidate {
    const NONE: Self = Self {
        kind: CandidateKind::Local,
        address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
}

/// A decoded candidate list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateList {
    /// Its generation: a list replaces only a lower one.
    pub generation: u16,
    len: u8,
    items: [Candidate; MAX_CANDIDATES],
}

impl CandidateList {
    /// An empty list of `generation`.
    #[must_use]
    pub const fn new(generation: u16) -> Self {
        Self {
            generation,
            len: 0,
            items: [Candidate::NONE; MAX_CANDIDATES],
        }
    }

    /// Appends a candidate; `false` when the list is full.
    pub fn push(&mut self, candidate: Candidate) -> bool {
        let Some(slot) = self.items.get_mut(usize::from(self.len)) else {
            return false;
        };
        *slot = candidate;
        self.len += 1;
        true
    }

    /// The candidates.
    #[must_use]
    pub fn as_slice(&self) -> &[Candidate] {
        self.items.get(..usize::from(self.len)).unwrap_or_default()
    }
}

/// Why bytes are not a path message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// The length does not match what the message says it holds.
    Length,
    /// More than [`MAX_CANDIDATES`] candidates.
    Count,
    /// A kind other than local, public or seen by peer.
    Kind,
    /// A family other than `0x04` or `0x06`.
    Family,
    /// The output buffer is too small.
    BufferTooSmall,
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Length => "a path message of the wrong length",
            Self::Count => "more than 8 candidates",
            Self::Kind => "an unknown candidate kind",
            Self::Family => "an unknown address family",
            Self::BufferTooSmall => "the output buffer is too small",
        })
    }
}

impl core::error::Error for PathError {}

/// Folds an IPv4-mapped IPv6 address to IPv4.
pub(crate) fn canonical(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(address, |v4| {
            SocketAddr::new(IpAddr::V4(v4), address.port())
        }),
        IpAddr::V4(_) => address,
    }
}

/// Reads `family | address | port` from the front of `bytes`; returns it,
/// IPv4-mapped addresses folded to IPv4, and the rest.
fn read_endpoint(bytes: &[u8]) -> Result<(SocketAddr, &[u8]), PathError> {
    let (&family, rest) = bytes.split_first().ok_or(PathError::Length)?;
    let (ip, rest) = match family {
        0x04 => {
            let (ip, rest) = rest.split_at_checked(4).ok_or(PathError::Length)?;
            let ip: [u8; 4] = ip.try_into().map_err(|_| PathError::Length)?;
            (IpAddr::V4(Ipv4Addr::from(ip)), rest)
        }
        0x06 => {
            let (ip, rest) = rest.split_at_checked(16).ok_or(PathError::Length)?;
            let ip: [u8; 16] = ip.try_into().map_err(|_| PathError::Length)?;
            (IpAddr::V6(Ipv6Addr::from(ip)), rest)
        }
        _ => return Err(PathError::Family),
    };
    let (port, rest) = rest.split_at_checked(2).ok_or(PathError::Length)?;
    let port: [u8; 2] = port.try_into().map_err(|_| PathError::Length)?;
    Ok((
        canonical(SocketAddr::new(ip, u16::from_le_bytes(port))),
        rest,
    ))
}

/// Writes `family | address | port` at the front of `out`; returns its length.
fn write_endpoint(address: SocketAddr, out: &mut [u8]) -> Result<usize, PathError> {
    let address = canonical(address);
    let port = address.port().to_le_bytes();
    let v4;
    let mut v6 = [0u8; 19];
    let bytes: &[u8] = match address.ip() {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            v4 = [0x04, a, b, c, d, port[0], port[1]];
            &v4
        }
        IpAddr::V6(ip) => {
            let (family, rest) = v6.split_at_mut(1);
            family.copy_from_slice(&[0x06]);
            let (ip_bytes, port_bytes) = rest.split_at_mut(16);
            ip_bytes.copy_from_slice(&ip.octets());
            port_bytes.copy_from_slice(&port);
            &v6
        }
    };
    out.get_mut(..bytes.len())
        .ok_or(PathError::BufferTooSmall)?
        .copy_from_slice(bytes);
    Ok(bytes.len())
}

/// Reads a candidate list.
///
/// # Errors
///
/// A [`PathError`] naming the first defect.
pub fn decode_candidates(bytes: &[u8]) -> Result<CandidateList, PathError> {
    let &[low, high, count] = bytes.first_chunk::<3>().ok_or(PathError::Length)?;
    let generation = u16::from_le_bytes([low, high]);
    if usize::from(count) > MAX_CANDIDATES {
        return Err(PathError::Count);
    }
    let mut list = CandidateList::new(generation);
    let mut rest = bytes.get(3..).unwrap_or_default();
    for _ in 0..count {
        let (&kind, after) = rest.split_first().ok_or(PathError::Length)?;
        let kind = match kind {
            0x00 => CandidateKind::Local,
            0x01 => CandidateKind::Public,
            0x02 => CandidateKind::SeenByPeer,
            _ => return Err(PathError::Kind),
        };
        let (address, after) = read_endpoint(after)?;
        list.push(Candidate { kind, address });
        rest = after;
    }
    if !rest.is_empty() {
        return Err(PathError::Length);
    }
    Ok(list)
}

/// Writes a candidate list into `out`, returning its length.
///
/// # Errors
///
/// [`PathError::Count`] for more than [`MAX_CANDIDATES`],
/// [`PathError::BufferTooSmall`] when it does not fit.
pub fn encode_candidates(
    generation: u16,
    candidates: &[Candidate],
    out: &mut [u8],
) -> Result<usize, PathError> {
    let count = u8::try_from(candidates.len())
        .ok()
        .filter(|&count| usize::from(count) <= MAX_CANDIDATES)
        .ok_or(PathError::Count)?;
    let header = out.get_mut(..3).ok_or(PathError::BufferTooSmall)?;
    let [low, high] = generation.to_le_bytes();
    header.copy_from_slice(&[low, high, count]);
    let mut at = 3;
    for candidate in candidates {
        let kind = match candidate.kind {
            CandidateKind::Local => 0x00,
            CandidateKind::Public => 0x01,
            CandidateKind::SeenByPeer => 0x02,
        };
        *out.get_mut(at).ok_or(PathError::BufferTooSmall)? = kind;
        at += 1;
        at += write_endpoint(candidate.address, out.get_mut(at..).unwrap_or_default())?;
    }
    Ok(at)
}

/// Reads a probe's nonce.
///
/// # Errors
///
/// [`PathError::Length`] for anything but 8 bytes.
pub fn decode_probe(bytes: &[u8]) -> Result<Nonce, PathError> {
    bytes.try_into().map_err(|_| PathError::Length)
}

/// Reads a probe's answer: its nonce, and the address the probe was seen from.
///
/// # Errors
///
/// A [`PathError`] naming the first defect.
pub fn decode_answer(bytes: &[u8]) -> Result<(Nonce, SocketAddr), PathError> {
    let (nonce, rest) = bytes.split_at_checked(8).ok_or(PathError::Length)?;
    let nonce: Nonce = nonce.try_into().map_err(|_| PathError::Length)?;
    let (address, rest) = read_endpoint(rest)?;
    if !rest.is_empty() {
        return Err(PathError::Length);
    }
    Ok((nonce, address))
}

/// Writes a probe's answer into `out`, returning its length.
///
/// # Errors
///
/// [`PathError::BufferTooSmall`] when it does not fit.
pub fn encode_answer(nonce: &Nonce, seen: SocketAddr, out: &mut [u8]) -> Result<usize, PathError> {
    out.get_mut(..8)
        .ok_or(PathError::BufferTooSmall)?
        .copy_from_slice(nonce);
    Ok(8 + write_endpoint(seen, out.get_mut(8..).unwrap_or_default())?)
}

/// When the rounds of an attempt fall, after it starts: a probe to every
/// candidate in each. NATs and lossy links need a few tries; five rounds open
/// most holes within 2 s. Only while a session opens or is used.
pub const PROBE_ROUNDS: [Duration; 5] = [
    Duration::from_millis(0),
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_millis(1000),
    Duration::from_millis(2000),
];

/// How long after its last round an attempt's answers still validate: the
/// longest round trip a direct path is worth having. Sends nothing.
pub const ANSWERS_WITHIN: Duration = Duration::from_millis(1000);

/// How long a direct path stays fresh after an authenticated packet arrived on
/// it: under the 30 to 60 s many NATs keep a UDP mapping. Sends nothing.
pub const DIRECT_FRESH_FOR: Duration = Duration::from_secs(15);

/// The fewest seconds between two attempts of a session: what a dead path
/// costs a busy session. Only on use.
pub const ATTEMPT_EVERY: Duration = Duration::from_secs(30);

/// How long the probe that checks a stale direct path waits for its answer
/// before the path is taken for lost. Only on use.
pub const CHECK_WITHIN: Duration = Duration::from_millis(2000);

/// The path a session's packets take, as an application is told it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// Through the pinned relay.
    Relayed,
    /// Directly, to this address: its family is the path's.
    Direct(SocketAddr),
}

/// A session's path and how it got there (`PROTOCOL.md §7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathInfo {
    /// The path.
    pub path: PathKind,
    /// When it last changed, if it ever did.
    pub changed_at: Option<Instant>,
    /// How long the last attempt took to validate a path, if it did.
    pub validated_after: Option<Duration>,
    /// The probes this session sent.
    pub probes_sent: u32,
    /// Whether this endpoint's NAT was found symmetric: a peer saw it at
    /// another port than the relay did.
    pub own_symmetric: bool,
    /// Whether the peer's NAT was found symmetric: its probe came from another
    /// port than the relay saw.
    pub peer_symmetric: bool,
}

/// An attempt: probes to each of the peer's candidates, in rounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub(crate) started: Instant,
    /// The round whose probes go next; [`PROBE_ROUNDS`]' length once all went.
    pub(crate) round: u8,
    /// The candidate the next probe of that round goes to.
    pub(crate) next: u8,
    /// A path validated: no more probes, though answers still count.
    pub(crate) stopped: bool,
    /// One nonce per candidate, by its place in the peer's list.
    pub(crate) nonces: [Nonce; MAX_CANDIDATES],
}

impl Attempt {
    /// When its next probe is due, while probes remain.
    pub(crate) fn next_due(&self) -> Option<Instant> {
        if self.stopped {
            return None;
        }
        PROBE_ROUNDS
            .get(usize::from(self.round))
            .map(|offset| self.started.saturating_add(*offset))
    }

    /// Whether its answers still validate at `now`.
    pub(crate) fn answers_open(&self, now: Instant) -> bool {
        now < self.ends()
    }

    /// When its last answers stop counting: the attempt is over.
    pub(crate) fn ends(&self) -> Instant {
        let last = PROBE_ROUNDS.last().copied().unwrap_or_default();
        self.started
            .saturating_add(last)
            .saturating_add(ANSWERS_WITHIN)
    }
}

/// A direct path a session uses while it is fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Direct {
    pub(crate) address: SocketAddr,
    /// Whether this side's probe and its answer proved it both ways; otherwise
    /// the peer's packets arrive from it, after the peer validated it.
    pub(crate) validated: bool,
    /// Its preference: 0 for a local candidate, 1 IPv6, 2 IPv4.
    pub(crate) rank: u8,
    pub(crate) fresh_until: Instant,
}

/// What a session knows of its peer's candidates and of its direct path, and
/// what it told the peer of this endpoint's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerPaths {
    /// The peer's candidates, those excluded left out.
    pub(crate) candidates: CandidateList,
    /// The generation of the last list accepted under the session's current
    /// keys: a list must be above it.
    pub(crate) accepted: Option<u16>,
    /// The generation of this endpoint's list last sent under them.
    pub(crate) sent: Option<u16>,
    /// Whether this session ever carried lists: its path is then the direct
    /// one while fresh, or the relay; and the peer is told of changes.
    pub(crate) exchanged: bool,
    /// An attempt is to start at the next poll, which draws its nonces.
    pub(crate) start_attempt: bool,
    pub(crate) attempt: Option<Attempt>,
    pub(crate) last_attempt: Option<Instant>,
    pub(crate) direct: Option<Direct>,
    /// A probe to check a stale direct path is owed (`None` sent), or was
    /// sent with this nonce at this instant.
    pub(crate) check: Option<Option<(Nonce, Instant)>>,
    /// The path the application was last told of.
    pub(crate) announced: PathKind,
    pub(crate) changed_at: Option<Instant>,
    pub(crate) validated_after: Option<Duration>,
    pub(crate) probes_sent: u32,
    pub(crate) own_symmetric: bool,
    pub(crate) peer_symmetric: bool,
    /// A probe from the peer arrived since the last attempt ended: the peer
    /// has this endpoint's list.
    pub(crate) heard_probe: bool,
}

impl PeerPaths {
    pub(crate) const fn new() -> Self {
        Self {
            candidates: CandidateList::new(0),
            accepted: None,
            sent: None,
            exchanged: false,
            start_attempt: false,
            attempt: None,
            last_attempt: None,
            direct: None,
            check: None,
            announced: PathKind::Relayed,
            changed_at: None,
            validated_after: None,
            probes_sent: 0,
            own_symmetric: false,
            peer_symmetric: false,
            heard_probe: false,
        }
    }

    /// The direct path to use at `now`: one that is fresh.
    pub(crate) fn fresh(&self, now: Instant) -> Option<SocketAddr> {
        self.direct
            .filter(|direct| now < direct.fresh_until)
            .map(|direct| direct.address)
    }

    /// The path as the application is told it: direct while one is known,
    /// fresh or being checked; else the relay.
    pub(crate) fn reported(&self) -> PathKind {
        self.direct
            .map_or(PathKind::Relayed, |direct| PathKind::Direct(direct.address))
    }

    /// An authenticated packet arrived directly from `address`. A packet on
    /// the direct path keeps it fresh; one from elsewhere becomes the path
    /// only when the path is stale or there is none: the peer validated it.
    pub(crate) fn heard_directly(&mut self, address: SocketAddr, now: Instant) {
        let fresh_until = now.saturating_add(DIRECT_FRESH_FOR);
        match self.direct.as_mut() {
            Some(direct) if direct.address == address => {
                direct.fresh_until = fresh_until;
                self.check = None;
            }
            Some(direct) if now < direct.fresh_until => {}
            _ => {
                self.direct = Some(Direct {
                    address,
                    validated: false,
                    rank: self.rank_of(address),
                    fresh_until,
                });
                self.check = None;
            }
        }
    }

    /// The preference of a path to `address`: a local candidate of the peer
    /// first, then IPv6, then IPv4.
    pub(crate) fn rank_of(&self, address: SocketAddr) -> u8 {
        let local = self
            .candidates
            .as_slice()
            .iter()
            .any(|c| c.kind == CandidateKind::Local && c.address == address);
        match (local, address.is_ipv6()) {
            (true, _) => 0,
            (false, true) => 1,
            (false, false) => 2,
        }
    }

    /// New keys: the peer may be a restarted endpoint whose generations start
    /// again, and which knows none of ours. Each side's next list is accepted,
    /// and ours is sent again: one packet per handshake, only while the session
    /// is used, since only use renews keys.
    pub(crate) fn new_keys(&mut self) {
        self.accepted = None;
        self.sent = None;
    }

    /// Whether this endpoint's list of `generation` is owed to the peer: not
    /// yet sent, and the session carried by the relay or already exchanging.
    pub(crate) fn owes(&self, generation: Option<u16>, relayed: bool) -> bool {
        generation.is_some_and(|g| self.sent != Some(g) && (relayed || self.exchanged))
    }
}

#[cfg(test)]
mod tests;
