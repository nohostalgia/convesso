//! Direct paths (`PROTOCOL.md §7`): this endpoint's candidates,
//! the prefixes an application excluded, the exchange of candidate lists
//! inside sessions, and the attempts that find a direct path.
//!
//! ```text
//! own candidates   local (driver)  +  public per family (relay, over UDP)
//!                  +  seen by a peer (a probe's answer)
//!                  -> at most 8, local first, then public IPv6, then IPv4
//!                  -> a new generation on every change
//! a session        carried by the relay, keys, and our list not yet sent
//!                  -> one packet of inner type 0x03 from poll
//! a peer's list    above the last generation, decoded whole, exclusions out
//!                  -> an attempt, while the session has no fresh direct path
//! an attempt       5 rounds (0, 250, 500, 1000, 2000 ms), a probe (0x04) to
//!                  each candidate in each, until an answer (0x05) from the
//!                  address probed carries a probe's nonce: validated
//! a session        uses its direct path while fresh (15 s since a packet came
//!                  on it); stale and used: the relay, and one probe to check
//!                  it; unanswered within 2 s: lost, and an attempt, at most
//!                  one per 30 s
//! ```

use core::net::{IpAddr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use super::{Context, Endpoint, Event, Hop, Key, PeerId, Poll};
use crate::dos::{Source, SourceKey};
use crate::handshake::Entropy;
use crate::paths::{
    self, ATTEMPT_EVERY, Attempt, CHECK_WITHIN, Candidate, CandidateKind, CandidateList,
    DIRECT_FRESH_FOR, Direct, MAX_CANDIDATES, Nonce, PathInfo, PathKind, PeerPaths,
};
use crate::session::{KeyPair, Session};
use crate::storage::{Config, Table};
use crate::time::Instant;
use crate::transport::{self, ReplayWindow, inner};

/// Why a prefix could not be excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExcludeError {
    /// Longer than its family's address: 32 bits for IPv4, 128 for IPv6.
    TooLong {
        /// The length asked for.
        len: u8,
    },
    /// The configuration's bound of excluded prefixes is reached.
    Full {
        /// How many prefixes the configuration keeps.
        bound: usize,
    },
}

impl core::fmt::Display for ExcludeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong { len } => write!(f, "a /{len} prefix is longer than its address"),
            Self::Full { bound } => write!(f, "more than {bound} excluded prefixes"),
        }
    }
}

impl core::error::Error for ExcludeError {}

/// This endpoint's own candidates and what they come from.
pub(crate) struct Own {
    local: [SocketAddr; MAX_CANDIDATES],
    local_len: u8,
    public_v4: Option<SocketAddr>,
    public_v6: Option<SocketAddr>,
    /// Addresses a peer saw this endpoint at that nothing else names.
    seen_v4: Option<SocketAddr>,
    seen_v6: Option<SocketAddr>,
    /// The list peers are sent, with its generation.
    pub(crate) list: CandidateList,
}

impl Own {
    pub(crate) const fn new() -> Self {
        Self {
            local: [SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0); MAX_CANDIDATES],
            local_len: 0,
            public_v4: None,
            public_v6: None,
            seen_v4: None,
            seen_v6: None,
            list: CandidateList::new(0),
        }
    }

    fn locals(&self) -> &[SocketAddr] {
        self.local
            .get(..usize::from(self.local_len))
            .unwrap_or_default()
    }

    /// The generation peers are owed, or `None` while there is nothing to
    /// tell them.
    pub(crate) fn owed_generation(&self) -> Option<u16> {
        (!self.list.as_slice().is_empty()).then_some(self.list.generation)
    }

    /// The public address the relay observed in `address`'s family.
    const fn public_like(&self, address: SocketAddr) -> Option<SocketAddr> {
        if address.is_ipv4() {
            self.public_v4
        } else {
            self.public_v6
        }
    }
}

/// Whether an address can be a path at all, whatever an application excludes:
/// not unspecified, loopback, multicast or broadcast, not IPv6 link-local
/// (unusable without its interface, which the encoding does not carry), and
/// not port 0.
fn usable(address: SocketAddr) -> bool {
    let ip = address.ip();
    let link_local_v6 = matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80);
    let broadcast = matches!(ip, IpAddr::V4(v4) if v4.is_broadcast());
    address.port() != 0
        && !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !broadcast
        && !link_local_v6
}

/// `ip` with every bit past the first `len` cleared.
fn masked(ip: IpAddr, len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            IpAddr::V4((u32::from(v4) & mask).into())
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            IpAddr::V6((u128::from(v6) & mask).into())
        }
    }
}

/// The IP address a source names, if it is a direct IP source.
fn ip_of(source: Source<'_>) -> Option<SocketAddr> {
    source.key().and_then(|key| key.as_ip())
}

/// Seals a path message under the session's current keys, if they live.
fn seal<W: ReplayWindow>(
    pair: &mut Option<KeyPair<W>>,
    now: Instant,
    inner_type: u8,
    data: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let pair = pair.as_mut().filter(|pair| pair.live(now))?;
    let len = transport::seal(
        &pair.send,
        pair.remote_index,
        pair.next_counter,
        inner_type,
        data,
        out,
    )
    .ok()?;
    pair.next_counter += 1;
    Some(len)
}

/// Whether a new attempt may start at `now`: at most one per
/// [`ATTEMPT_EVERY`], and only with candidates to probe.
fn may_attempt(paths: &PeerPaths, now: Instant) -> bool {
    !paths.candidates.as_slice().is_empty()
        && paths
            .last_attempt
            .is_none_or(|at| now >= at.saturating_add(ATTEMPT_EVERY))
}

/// When a check probe sent at `sent` is unanswered for good.
fn check_lost_at(paths: &PeerPaths) -> Option<Instant> {
    match paths.check {
        Some(Some((_, sent))) => Some(sent.saturating_add(CHECK_WITHIN)),
        _ => None,
    }
}

/// Whether a session has path work due at `now`.
pub(super) fn path_wants<W: ReplayWindow, Q>(session: &Session<W, Q>, now: Instant) -> bool {
    let live = session.current.as_ref().is_some_and(|pair| pair.live(now));
    let paths = &session.paths;
    let probe_due = paths
        .attempt
        .and_then(|attempt| attempt.next_due())
        .is_some_and(|due| due <= now);
    let ended = paths.attempt.is_some_and(|attempt| now >= attempt.ends());
    (live && (paths.start_attempt || probe_due || paths.check == Some(None)))
        || ended
        || check_lost_at(paths).is_some_and(|at| now >= at)
        || (paths.exchanged && paths.reported() != paths.announced)
}

/// The next instant a session has path work, if any.
pub(super) fn path_deadline<W: ReplayWindow, Q>(session: &Session<W, Q>) -> Option<Instant> {
    let probe = session
        .current
        .as_ref()
        .and(session.paths.attempt)
        .and_then(|attempt| attempt.next_due());
    let end = session.paths.attempt.map(|attempt| attempt.ends());
    [probe, end, check_lost_at(&session.paths)]
        .into_iter()
        .flatten()
        .min()
}

/// This side sends data in the session at `now`: a stale direct path is
/// checked with one probe, and a session with none tries again, at most once
/// every 30 s.
pub(super) fn note_use(paths: &mut PeerPaths, now: Instant) {
    if !paths.exchanged {
        return;
    }
    match paths.direct {
        Some(direct) if now >= direct.fresh_until => {
            if paths.check.is_none() {
                paths.check = Some(None);
            }
        }
        Some(_) => {}
        None => {
            let running = paths
                .attempt
                .is_some_and(|attempt| attempt.answers_open(now));
            if !running && may_attempt(paths, now) {
                paths.start_attempt = true;
            }
        }
    }
}

/// Closes an attempt that is over. One that found no path, and heard not one
/// probe from the peer, says the peer most likely never received this
/// endpoint's list, lost on the way: the list is owed once more, and a peer
/// that had it ignores it.
/// Returns whether it was such an attempt.
pub(super) fn finish_attempt(paths: &mut PeerPaths, now: Instant) -> bool {
    let mut silent = false;
    if let Some(attempt) = paths.attempt.filter(|attempt| now >= attempt.ends()) {
        silent = paths.direct.is_none() && !paths.heard_probe && !attempt.stopped;
        if silent {
            paths.sent = None;
        }
        paths.attempt = None;
        paths.heard_probe = false;
    }
    silent
}

/// Where a packet of a session goes, before the relay rule: its fresh direct
/// path, when it exchanged candidates; else, for such a session, the relay
/// when one is pinned; else where it was last authenticated from.
pub(super) fn route_source<W, Q>(
    peer: PeerId,
    session: &Session<W, Q>,
    now: Instant,
    relay: bool,
) -> Option<SourceKey> {
    match session.paths.fresh(now) {
        Some(direct) if session.paths.exchanged => Some(SourceKey::from_ip(direct)),
        _ if session.paths.exchanged && relay => Source::Relayed(peer).key(),
        _ => session.last_source,
    }
}

/// The prefix `ip/len` as the table keeps it: masked, and an IPv4-mapped
/// prefix as the IPv4 prefix it maps.
fn prefix(ip: IpAddr, len: u8) -> Result<(IpAddr, u8), ExcludeError> {
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if len > max {
        return Err(ExcludeError::TooLong { len });
    }
    let (ip, len) = match paths::canonical(SocketAddr::new(ip, 0)).ip() {
        v4 @ IpAddr::V4(_) if ip.is_ipv6() && len >= 96 => (v4, len - 96),
        _ => (ip, len),
    };
    Ok((masked(ip, len), len))
}

impl<C: Config> Endpoint<C> {
    /// Excludes the IP prefix `ip/len` from direct paths: no address in it is
    /// proposed as a candidate, probed, or becomes a session's path, whichever
    /// side named it (`PROTOCOL.md §7`). An overlay excludes its own
    /// prefix, so that no path goes through its own tunnel.
    ///
    /// # Errors
    ///
    /// [`ExcludeError`] for a length longer than the address, or no room left.
    pub fn exclude_prefix(&mut self, ip: IpAddr, len: u8) -> Result<(), ExcludeError> {
        let prefix = prefix(ip, len)?;
        if self.excluded.get(&prefix).is_none()
            && let Some(bound) = self
                .excluded
                .capacity()
                .filter(|bound| self.excluded.len() >= *bound)
        {
            return Err(ExcludeError::Full { bound });
        }
        let _ = self.excluded.insert(prefix, ());
        self.apply_exclusion();
        Ok(())
    }

    /// Replaces every excluded prefix with `prefixes`, with the rules of
    /// [`Endpoint::exclude_prefix`]. A prefix no longer excluded is allowed
    /// again from then on: an interface address in it is a candidate again once
    /// the driver reports it (`PROTOCOL.md §7`).
    ///
    /// # Errors
    ///
    /// [`ExcludeError`] for a length longer than its address, or more distinct
    /// prefixes than the configuration keeps; the prefixes excluded before
    /// stay as they were.
    pub fn set_excluded(&mut self, prefixes: &[(IpAddr, u8)]) -> Result<(), ExcludeError> {
        let mut distinct = 0;
        for (i, (ip, len)) in prefixes.iter().enumerate() {
            let this = prefix(*ip, *len)?;
            let earlier = prefixes.get(..i).unwrap_or_default();
            if !earlier
                .iter()
                .any(|(ip, len)| prefix(*ip, *len).is_ok_and(|p| p == this))
            {
                distinct += 1;
            }
        }
        if let Some(bound) = self.excluded.capacity().filter(|bound| distinct > *bound) {
            return Err(ExcludeError::Full { bound });
        }
        self.excluded.retain(|_, ()| false);
        for (ip, len) in prefixes {
            if let Ok(prefix) = prefix(*ip, *len) {
                let _ = self.excluded.insert(prefix, ());
            }
        }
        self.apply_exclusion();
        Ok(())
    }

    /// What the excluded prefixes cover stops being a candidate or a path.
    fn apply_exclusion(&mut self) {
        let excluded = &self.excluded;
        let mut kept = [SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0); MAX_CANDIDATES];
        let mut count = 0;
        for address in self.own.locals() {
            if !covered(excluded, address.ip())
                && let Some(slot) = kept.get_mut(count)
            {
                *slot = *address;
                count += 1;
            }
        }
        self.own.local = kept;
        self.own.local_len = u8::try_from(count).unwrap_or(0);
        self.sessions.retain(|_, session| {
            let paths = &mut session.paths;
            let mut list = CandidateList::new(paths.candidates.generation);
            for candidate in paths.candidates.as_slice() {
                if !covered(excluded, candidate.address.ip()) {
                    list.push(*candidate);
                }
            }
            if list != paths.candidates {
                // The nonces follow the list's order: the attempt is over.
                paths.attempt = None;
                paths.candidates = list;
            }
            if paths
                .direct
                .is_some_and(|direct| covered(excluded, direct.address.ip()))
            {
                paths.direct = None;
                paths.check = None;
            }
            if session
                .last_source
                .and_then(|source| source.as_ip())
                .is_some_and(|address| covered(excluded, address.ip()))
            {
                session.last_source = None;
            }
            true
        });
        self.refresh_candidates();
    }

    /// Reports this endpoint's interface addresses, each with its socket's
    /// port: the driver calls it at start and on every network change, with
    /// every address but loopback. The core keeps those an application did
    /// not exclude and that can be a path, at most 8.
    pub fn set_local_addresses(&mut self, addresses: &[SocketAddr]) {
        let mut local = [SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0); MAX_CANDIDATES];
        let mut count = 0;
        for address in addresses.iter().map(|a| paths::canonical(*a)) {
            let seen = local.get(..count).unwrap_or_default().contains(&address);
            if usable(address)
                && !seen
                && !self.is_excluded(address.ip())
                && let Some(slot) = local.get_mut(count)
            {
                *slot = address;
                count += 1;
            }
        }
        self.own.local = local;
        self.own.local_len = u8::try_from(count).unwrap_or(0);
        self.refresh_candidates();
    }

    /// This endpoint's candidates as peers are told them, in order.
    #[must_use]
    pub fn candidates(&self) -> &[Candidate] {
        self.own.list.as_slice()
    }

    /// The candidates `peer` sent in the session in `context`, those excluded
    /// left out; empty when it sent none, or the session has no keys.
    #[must_use]
    pub fn peer_candidates(&self, peer: &PeerId, context: &[u8]) -> &[Candidate] {
        Context::new(context)
            .ok()
            .and_then(|context| self.sessions.get(&(*peer, context)))
            .map(|session| session.paths.candidates.as_slice())
            .unwrap_or_default()
    }

    /// The path of the session with `peer` in `context`, and how it got there;
    /// `None` without such a session. A session that never exchanged
    /// candidates reports where it was last authenticated from: directly from
    /// an IP address, or else through the relay.
    #[must_use]
    pub fn path_info(&self, peer: &PeerId, context: &[u8]) -> Option<PathInfo> {
        let context = Context::new(context).ok()?;
        let session = self.sessions.get(&(*peer, context))?;
        let paths = &session.paths;
        let path = if paths.exchanged {
            paths.reported()
        } else {
            session
                .last_source
                .and_then(|source| source.as_ip())
                .map_or(PathKind::Relayed, PathKind::Direct)
        };
        Some(PathInfo {
            path,
            changed_at: paths.changed_at,
            validated_after: paths.validated_after,
            probes_sent: paths.probes_sent,
            own_symmetric: paths.own_symmetric,
            peer_symmetric: paths.peer_symmetric,
        })
    }

    /// The pinned relay observed this endpoint's UDP at `address`: its public
    /// candidate in that family.
    pub(super) fn observed_public(&mut self, address: SocketAddr) {
        let address = paths::canonical(address);
        let slot = if address.is_ipv4() {
            &mut self.own.public_v4
        } else {
            &mut self.own.public_v6
        };
        *slot = Some(address);
        self.refresh_candidates();
    }

    /// The relay that reported this endpoint's public addresses is gone: they
    /// are candidates no more, until the next relay reports them.
    pub(super) fn forget_public(&mut self) {
        self.own.public_v4 = None;
        self.own.public_v6 = None;
        self.refresh_candidates();
    }

    /// A peer saw this endpoint at `seen`: a candidate when its IP address is
    /// one no other candidate has. Another port at the public address only
    /// says the NAT is symmetric, and is no candidate for anyone else.
    fn observed_by_peer(&mut self, seen: SocketAddr) {
        let seen = paths::canonical(seen);
        let known = self
            .own
            .list
            .as_slice()
            .iter()
            .any(|candidate| candidate.address.ip() == seen.ip());
        if known || !usable(seen) || self.is_excluded(seen.ip()) {
            return;
        }
        if seen.is_ipv4() {
            self.own.seen_v4 = Some(seen);
        } else {
            self.own.seen_v6 = Some(seen);
        }
        self.refresh_candidates();
    }

    /// Whether `ip` is in a prefix the application excluded.
    pub(super) fn is_excluded(&self, ip: IpAddr) -> bool {
        covered(&self.excluded, ip)
    }

    /// Whether a source may become a session's path: not an IP source in an
    /// excluded prefix.
    pub(super) fn may_be_path(&self, source: Option<SourceKey>) -> bool {
        !source
            .and_then(|source| source.as_ip())
            .is_some_and(|address| self.is_excluded(address.ip()))
    }

    /// Rebuilds the list peers are sent; a new generation if it changed.
    /// Locals give way to the others, so that at most 8 keep the public ones.
    fn refresh_candidates(&mut self) {
        let mut list = CandidateList::new(self.own.list.generation);
        let locals = self.own.locals();
        let others = [
            (CandidateKind::Public, self.own.public_v6),
            (CandidateKind::Public, self.own.public_v4),
            (CandidateKind::SeenByPeer, self.own.seen_v6),
            (CandidateKind::SeenByPeer, self.own.seen_v4),
        ];
        let mut kept = [None; 4];
        for (slot, (kind, address)) in kept.iter_mut().zip(others) {
            *slot = address
                .filter(|a| usable(*a) && !self.is_excluded(a.ip()) && !locals.contains(a))
                .map(|address| Candidate { kind, address });
        }
        let room = MAX_CANDIDATES.saturating_sub(kept.iter().flatten().count());
        for address in locals.iter().take(room) {
            list.push(Candidate {
                kind: CandidateKind::Local,
                address: *address,
            });
        }
        for candidate in kept.into_iter().flatten() {
            list.push(candidate);
        }
        if list.as_slice() != self.own.list.as_slice() {
            list.generation = self.own.list.generation.wrapping_add(1);
            self.own.list = list;
        }
    }

    /// A peer's list, the data of a packet of inner type `0x03` in `key`'s
    /// session: kept if whole and above the last generation, without what is
    /// excluded or unusable. A session with no fresh direct path then tries
    /// to find one.
    pub(super) fn accept_candidates(&mut self, key: Key, data: &[u8], now: Instant) {
        if key.1.as_bytes() == crate::relay::CONTEXT {
            return;
        }
        let Ok(received) = paths::decode_candidates(data) else {
            return;
        };
        let mut list = CandidateList::new(received.generation);
        for candidate in received.as_slice() {
            if usable(candidate.address) && !self.is_excluded(candidate.address.ip()) {
                list.push(*candidate);
            }
        }
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        let paths = &mut session.paths;
        if paths
            .accepted
            .is_some_and(|last| received.generation <= last)
        {
            return;
        }
        paths.accepted = Some(received.generation);
        paths.exchanged = true;
        // The peer no longer offers the address its validated path goes to:
        // it moved, and the path is stale until checked.
        if let Some(direct) = paths.direct.as_mut().filter(|direct| {
            direct.validated
                && !list
                    .as_slice()
                    .iter()
                    .any(|candidate| candidate.address == direct.address)
        }) {
            direct.fresh_until = direct.fresh_until.min(now);
        }
        if list != paths.candidates {
            paths.attempt = None;
            paths.candidates = list;
        }
        if paths.fresh(now).is_none() && !paths.candidates.as_slice().is_empty() {
            paths.start_attempt = true;
        }
    }

    /// A probe, the data of a packet of inner type `0x04` that opened in
    /// `key`'s session: answered to where it came from, with that address.
    /// Probes come directly; one through the relay, or from an excluded
    /// address, is not answered.
    pub(super) fn answer_probe(
        &mut self,
        key: Key,
        data: &[u8],
        source: Source<'_>,
        now: Instant,
        out: &mut [u8],
    ) -> Option<usize> {
        let seen = ip_of(source)?;
        if key.1.as_bytes() == crate::relay::CONTEXT || self.is_excluded(seen.ip()) {
            return None;
        }
        let nonce = paths::decode_probe(data).ok()?;
        let session = self.sessions.get_mut(&key)?;
        // From the IP of the peer's public candidate, but another port: its
        // NAT maps each destination apart.
        if session.paths.candidates.as_slice().iter().any(|c| {
            c.kind == CandidateKind::Public
                && c.address.ip() == seen.ip()
                && c.address.port() != seen.port()
        }) {
            session.paths.peer_symmetric = true;
        }
        session.paths.heard_probe = true;
        let mut answer = [0u8; 27];
        let len = paths::encode_answer(&nonce, seen, &mut answer).ok()?;
        seal(
            &mut session.current,
            now,
            inner::ANSWER,
            answer.get(..len)?,
            out,
        )
    }

    /// An answer, the data of a packet of inner type `0x05` that opened in
    /// `key`'s session. It validates the path it came on when its nonce is
    /// that of a probe sent to that address; anything else moves nothing.
    pub(super) fn take_answer(&mut self, key: Key, data: &[u8], source: Source<'_>, now: Instant) {
        let Some(from) = ip_of(source) else {
            return;
        };
        let Ok((nonce, seen)) = paths::decode_answer(data) else {
            return;
        };
        if self.is_excluded(from.ip()) {
            return;
        }
        let public = self.own.public_like(seen);
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        let paths = &mut session.paths;
        let checked = matches!(paths.check, Some(Some((n, _))) if n == nonce)
            && paths.direct.is_some_and(|direct| direct.address == from);
        let attempt = paths.attempt.filter(|attempt| attempt.answers_open(now));
        let probed = attempt.is_some_and(|attempt| {
            paths.candidates.as_slice().iter().zip(attempt.nonces).any(
                |(candidate, sent): (&Candidate, Nonce)| candidate.address == from && sent == nonce,
            )
        });
        if !checked && !probed {
            return;
        }
        let fresh_until = now.saturating_add(DIRECT_FRESH_FOR);
        if checked && let Some(direct) = paths.direct.as_mut() {
            direct.fresh_until = fresh_until;
            paths.check = None;
        }
        if probed && let Some(attempt) = attempt {
            let rank = paths.rank_of(from);
            let better = paths.direct.is_none_or(|direct| {
                direct.address == from
                    || !direct.validated
                    || rank < direct.rank
                    || now >= direct.fresh_until
            });
            if better {
                paths.direct = Some(Direct {
                    address: from,
                    validated: true,
                    rank,
                    fresh_until,
                });
                paths.check = None;
            }
            if paths.validated_after.is_none() {
                paths.validated_after = Some(Duration::from_millis(
                    now.as_millis().saturating_sub(attempt.started.as_millis()),
                ));
            }
            if let Some(running) = paths.attempt.as_mut() {
                running.stopped = true;
            }
        }
        // The peer saw this endpoint at another port than the relay did, at
        // the same address: this endpoint's NAT maps each destination apart.
        if public.is_some_and(|public| public.ip() == seen.ip() && public.port() != seen.port()) {
            paths.own_symmetric = true;
        } else {
            self.observed_by_peer(seen);
        }
    }

    /// The path work of `key`'s session due at `now`, if any: a lost check, an
    /// attempt to start, a probe, a check, the application told of a change.
    pub(super) fn path_step(
        &mut self,
        key: Key,
        now: Instant,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Option<Poll<Hop>> {
        let session = self.sessions.get_mut(&key)?;
        let paths = &mut session.paths;
        if check_lost_at(paths).is_some_and(|at| now >= at) {
            paths.check = None;
            paths.direct = None;
            if may_attempt(paths, now) {
                paths.start_attempt = true;
            }
        }
        let live = session.current.as_ref().is_some_and(|pair| pair.live(now));
        if live && paths.start_attempt {
            paths.start_attempt = false;
            if !paths.candidates.as_slice().is_empty() {
                let mut nonces = [[0u8; 8]; MAX_CANDIDATES];
                for nonce in &mut nonces {
                    entropy.fill(nonce);
                }
                paths.attempt = Some(Attempt {
                    started: now,
                    round: 0,
                    next: 0,
                    stopped: false,
                    nonces,
                });
                paths.last_attempt = Some(now);
                paths.validated_after = None;
            }
        }
        if live
            && let Some(attempt) = paths.attempt.as_mut()
            && attempt.next_due().is_some_and(|due| due <= now)
        {
            let candidates = paths.candidates.as_slice();
            let index = usize::from(attempt.next);
            let (Some(candidate), Some(nonce)) =
                (candidates.get(index), attempt.nonces.get(index).copied())
            else {
                attempt.stopped = true;
                return None;
            };
            let to = Hop::Direct(SourceKey::from_ip(candidate.address));
            attempt.next += 1;
            if usize::from(attempt.next) >= candidates.len() {
                attempt.next = 0;
                attempt.round += 1;
            }
            paths.probes_sent += 1;
            let len = seal(&mut session.current, now, inner::PROBE, &nonce, out)?;
            return Some(Poll::Transmit { to, len });
        }
        if live
            && paths.check == Some(None)
            && let Some(direct) = paths.direct
        {
            let mut nonce = [0u8; 8];
            entropy.fill(&mut nonce);
            paths.check = Some(Some((nonce, now)));
            paths.probes_sent += 1;
            let len = seal(&mut session.current, now, inner::PROBE, &nonce, out)?;
            return Some(Poll::Transmit {
                to: Hop::Direct(SourceKey::from_ip(direct.address)),
                len,
            });
        }
        if paths.exchanged && paths.reported() != paths.announced {
            paths.announced = paths.reported();
            paths.changed_at = Some(now);
            return Some(Poll::Event(Event::PathChanged {
                peer: key.0,
                context: key.1,
                path: paths.announced,
            }));
        }
        None
    }
}

/// Whether `ip` is in one of `excluded`'s prefixes.
fn covered(excluded: &impl Table<(IpAddr, u8), ()>, ip: IpAddr) -> bool {
    let ip = paths::canonical(SocketAddr::new(ip, 0)).ip();
    let mut found = false;
    excluded.for_each(|(prefix, len), ()| {
        found |= prefix.is_ipv4() == ip.is_ipv4() && masked(ip, *len) == *prefix;
    });
    found
}

#[cfg(test)]
mod tests;
