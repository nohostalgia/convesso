//! The endpoint's relay client (`PROTOCOL.md §6`).
//!
//! The link to the pinned relay is an ordinary session in the context
//! `convesso-relay`; what this module adds is around it:
//!
//! ```text
//! a packet for a peer heard through the relay   -> forward, sealed in place,
//!                                                  in the relay session
//! the relay session has no keys                 -> one first contact to the
//!                                                  relay, the forward as payload
//! a deliver from the relay                      -> handled as from
//!                                                  Source::Relayed(sender)
//! which path to the relay                       -> UDP while proven (15 s),
//!                                                  else TCP (a UDP copy every
//!                                                  10 s), else UDP
//! the TCP link                                  -> opened and closed when the
//!                                                  core says so; a register after
//!                                                  each relay handshake; a
//!                                                  keep-alive after 60 s with
//!                                                  nothing sent on it, which the
//!                                                  relay answers within 20 s or
//!                                                  the link is dead
//! ```
//!
//! The link's lifecycle is the core's, so that every driver behaves alike:
//!
//! ```text
//!   None --set_reachable(true)--> Waiting(at) --at--> Opening --opened--> Open
//!    ^                               ^   ^                |                |
//!    |                               |   +---- failed: backoff (1..60 s) --+ not established
//!    +--set_reachable(false)---------+------ closed / changed / dead: at once (established)
//! ```
//!
//! Every output of the endpoint passes through [`Endpoint::finish`], which
//! routes packets for the relay and turns the relay session's own events into
//! relay events: the application never sees the relay session as a peer.

use core::time::Duration;

use super::{
    Address, Admission, Context, DialError, Endpoint, Entropy, Event, FrameKind, Hop, Instant, Key,
    Output, PeerId, Poll, SendError, Source, To,
};
use crate::dos::SourceKey;
use crate::handshake::{Access, Decision, FIRST_CONTACT_LEN, Psk, ResponderError};
use crate::relay::{self, Frame, Link, MAX_CARRIED, ROUTED_HEADER_LEN, frame_type};
use crate::session::DatagramQueue;
use crate::storage::{Config, Table};
use crate::transport::{self, DATA_AT, OVERHEAD, TAG_LEN, inner};

/// How long an authenticated packet of the relay session received over UDP
/// proves that UDP reaches the relay. Below the 30-60 s many NATs keep a UDP
/// mapping, so a proven path is still open. Sends nothing.
pub const UDP_PROVEN_FOR: Duration = Duration::from_secs(15);

/// While UDP is not proven and a TCP link is up, one packet this often also
/// goes over UDP, as the same bytes. Only while sending: nothing at rest.
/// Without it, a link that started on TCP would never move to UDP.
pub const UDP_PROBE_EVERY: Duration = Duration::from_secs(10);

/// The shortest TCP keep-alive interval: the project allows at most one
/// keep-alive a minute at rest. About 4.6 MB a month over IPv4; without it,
/// NATs forget the link and the endpoint stops being reachable.
pub const MIN_KEEPALIVE: Duration = Duration::from_secs(60);

/// How long after a keep-alive, or after the link opened, a frame from the
/// relay must arrive before the link is taken for dead. Sends nothing. Without
/// it, a link that died silently would leave the device unreachable until TCP
/// gave up, up to about 15 minutes.
pub const LINK_ANSWER_WITHIN: Duration = Duration::from_secs(20);

/// When, after a peer session opens or an attempt finds nothing, this
/// endpoint asks the relay for the public UDP address it lacks: a frame
/// either way may be lost, and without that address no direct path through a
/// NAT can be found. Stops as soon as the relay has answered. Only on use.
pub const ASK_ADDRESS_AT: [Duration; 4] = [
    Duration::from_millis(0),
    Duration::from_millis(1000),
    Duration::from_millis(2000),
    Duration::from_millis(4000),
];

/// The first wait after a failed link attempt; it doubles with each
/// consecutive failure.
pub const BACKOFF_FIRST: Duration = Duration::from_secs(1);

/// The longest wait between link attempts, before jitter: with the jitter of
/// up to half again, attempts on an unreachable relay come every 60 to 90
/// seconds, never more than one a minute.
pub const BACKOFF_CAP: Duration = Duration::from_secs(60);

/// Which way a packet for the relay goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPath {
    /// A UDP datagram to the relay.
    Udp,
    /// A frame on the TCP link.
    Tcp,
    /// Both, as the same bytes: the relay keeps the first that arrives.
    Both,
    /// A UDP datagram to the relay's address in the family the endpoint does
    /// not otherwise use, so that the relay observes its public address in
    /// both (`PROTOCOL.md §6`). A driver with the relay's address in one family
    /// only drops it: it is a keep-alive of the relay session, carrying
    /// nothing.
    UdpOther,
}

/// Why the relay cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    /// Its session's dial failed: refused by the relay (with the relay's
    /// code), not answered, or answered with an unknown version.
    Dial(DialError),
    /// Its session was closed, by the relay or by this endpoint, with this
    /// code.
    Closed {
        /// The code.
        code: u16,
        /// Whether the relay closed it.
        by_relay: bool,
    },
    /// The TCP link to it failed.
    Link(LinkFailure),
}

/// How a TCP link to the relay failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkFailure {
    /// The driver reported it closed while it was opening: refused, or not
    /// reached.
    NotOpened,
    /// Its opening was not reported within [`LINK_ANSWER_WITHIN`].
    Hung,
    /// No frame came from the relay within [`LINK_ANSWER_WITHIN`] of a
    /// keep-alive.
    Dead,
    /// The driver reported it closed after it opened.
    Lost,
}

/// A keep-alive interval below [`MIN_KEEPALIVE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepAliveTooShort {
    /// The interval asked for.
    pub asked: Duration,
}

impl core::fmt::Display for KeepAliveTooShort {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "a keep-alive every {} ms is more than one a minute",
            self.asked.as_millis()
        )
    }
}

impl core::error::Error for KeepAliveTooShort {}

const LABEL_UDP: &[u8] = b"convesso relay udp";
const LABEL_TCP: &[u8] = b"convesso relay tcp";

/// Where the TCP link to the relay stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkState {
    /// No link, and none wanted.
    None,
    /// A link is wanted: ask for it at this instant, or, when unset, as soon
    /// as the backoff's jitter is drawn.
    Waiting(Option<Instant>),
    /// The driver was asked to open it, at this instant: an attempt that has
    /// not opened within [`LINK_ANSWER_WITHIN`] failed, however long the
    /// operating system would wait.
    Opening(Instant),
    /// Open. `established` once a frame from the relay arrived on it;
    /// `awaiting`: since when a frame from the relay is expected.
    Open {
        established: bool,
        awaiting: Option<Instant>,
    },
}

/// The pinned relay and the state of the paths to it.
pub(crate) struct RelayClient {
    address: Address,
    context: Context,
    reachable: bool,
    link: LinkState,
    /// Consecutive link attempts that ended before this endpoint was
    /// registered on the link.
    failures: u32,
    /// Registered on the current link: its relay session live on it, and its
    /// register sent. Only this resets the backoff (`DESIGN.md §6`).
    registered: bool,
    /// What to tell the application next about the relay: available, or
    /// unavailable and why. Small, rather than a whole event, for the
    /// microcontroller's RAM.
    pending: Option<Result<(), RelayError>>,
    /// The driver is to be asked to close the link.
    close_due: bool,
    udp_proven: Option<Instant>,
    last_probe: Option<Instant>,
    last_tcp_sent: Instant,
    keepalive: Duration,
    /// A keep-alive is due now, whatever was sent: the one that opens a link.
    keepalive_now: bool,
    pub(super) register_due: bool,
    /// The relay's families as the driver resolved it: whether the address it
    /// uses is IPv6, and whether it has one in the other family. Unknown,
    /// only the address in use is asked about.
    families: Option<(bool, bool)>,
    /// The families the relay reported this endpoint's UDP address in, since
    /// the network last changed.
    reported_v4: bool,
    reported_v6: bool,
    /// Asking the relay to report: when the asking started, and which of
    /// [`ASK_ADDRESS_AT`] is next.
    ask: Option<(Instant, usize)>,
    /// The question over the other family is owed now, after the first.
    ask_other_now: bool,
    /// The network changed: once the relay registers this endpoint again,
    /// each live session sends its peer one packet, on the new link.
    tell_peers: bool,
}

impl RelayClient {
    /// A client of `address`, not yet reachable.
    fn new(address: Address, context: Context, now: Instant) -> Self {
        Self {
            address,
            context,
            reachable: false,
            link: LinkState::None,
            failures: 0,
            registered: false,
            pending: None,
            close_due: false,
            udp_proven: None,
            last_probe: None,
            last_tcp_sent: now,
            keepalive: MIN_KEEPALIVE,
            keepalive_now: false,
            register_due: false,
            families: None,
            reported_v4: false,
            reported_v6: false,
            ask: None,
            ask_other_now: false,
            tell_peers: false,
        }
    }

    /// Becomes a client of `address`, keeping what the application asked
    /// (reachable, the keep-alive interval) and nothing it learned: the old
    /// relay's link, if any, is asked closed without an event, and a reachable
    /// client asks for the new one at once.
    fn replace(&mut self, address: Address, now: Instant) {
        let link_up = matches!(self.link, LinkState::Opening(_) | LinkState::Open { .. });
        *self = Self {
            reachable: self.reachable,
            keepalive: self.keepalive,
            tell_peers: self.tell_peers,
            close_due: link_up,
            link: if self.reachable {
                LinkState::Waiting(Some(now))
            } else {
                LinkState::None
            },
            ..Self::new(address, self.context, now)
        };
    }

    /// Whether `key` is the relay session's.
    pub(super) fn is(&self, key: &Key) -> bool {
        key.0 == self.address.peer_id() && key.1 == self.context
    }

    fn key(&self) -> Key {
        (self.address.peer_id(), self.context)
    }

    /// Whether the TCP link is open.
    pub(super) const fn link_open(&self) -> bool {
        matches!(self.link, LinkState::Open { .. })
    }

    /// When the TCP keep-alive is due, while the link is open.
    fn keepalive_due(&self) -> Option<Instant> {
        self.link_open().then(|| {
            if self.keepalive_now {
                Instant::from_millis(0)
            } else {
                self.last_tcp_sent.saturating_add(self.keepalive)
            }
        })
    }

    /// When the link is taken for dead, if a frame from the relay is awaited.
    fn answer_due(&self) -> Option<Instant> {
        match self.link {
            LinkState::Open {
                awaiting: Some(since),
                ..
            }
            | LinkState::Opening(since) => Some(since.saturating_add(LINK_ANSWER_WITHIN)),
            _ => None,
        }
    }

    /// The next instant the relay client has something to do, if any.
    pub(super) fn next_due(&self) -> Option<Instant> {
        let waiting = match self.link {
            LinkState::Waiting(at) => Some(at.unwrap_or(Instant::from_millis(0))),
            _ => None,
        };
        let close = (self.close_due || self.pending.is_some()).then_some(Instant::from_millis(0));
        [
            self.keepalive_due(),
            self.answer_due(),
            waiting,
            close,
            self.ask_due(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// A frame from the relay arrived on the link: it is established, and
    /// nothing more is awaited. The backoff waits for registration.
    pub(super) fn heard_on_link(&mut self) {
        if let LinkState::Open { .. } = self.link {
            self.link = LinkState::Open {
                established: true,
                awaiting: None,
            };
        }
    }

    /// The link is gone: `reported` by the driver as closed, or given up for
    /// want of an answer. A link this endpoint was registered on is replaced
    /// at once; any other ends a failed attempt, and the next waits for the
    /// backoff. The application is told why.
    fn link_gone(&mut self, now: Instant, reported: bool) {
        let failure = match (self.link, reported) {
            (LinkState::Opening(_), true) => LinkFailure::NotOpened,
            (LinkState::Opening(_), false) => LinkFailure::Hung,
            (_, true) => LinkFailure::Lost,
            (_, false) => LinkFailure::Dead,
        };
        let registered = core::mem::take(&mut self.registered);
        self.register_due = false;
        self.link = if !self.reachable {
            LinkState::None
        } else if registered {
            self.failures = 0;
            LinkState::Waiting(Some(now))
        } else {
            self.failures = self.failures.saturating_add(1);
            LinkState::Waiting(None)
        };
        if self.reachable {
            self.pending = Some(Err(RelayError::Link(failure)));
        }
    }

    /// The relay session's dial failed, refused or unanswered. On an open
    /// link this endpoint is not yet registered on, that attempt is over: the
    /// link is closed, and the next one waits for the backoff, rather than
    /// the session being dialled again at once. The dial's own event tells
    /// the application.
    pub(super) fn session_failed(&mut self) {
        if self.reachable && !self.registered && self.link_open() {
            self.close_due = true;
            self.register_due = false;
            self.failures = self.failures.saturating_add(1);
            self.link = LinkState::Waiting(None);
        }
    }

    fn udp_proven(&self, now: Instant) -> bool {
        self.udp_proven
            .is_some_and(|at| now < at.saturating_add(UDP_PROVEN_FOR))
    }

    const fn reported(&self, ipv6: bool) -> bool {
        if ipv6 {
            self.reported_v6
        } else {
            self.reported_v4
        }
    }

    /// Which reports are missing: over the relay's address in use, and over
    /// its address in the other family.
    fn missing(&self) -> (bool, bool) {
        match self.families {
            Some((ipv6, other)) => (!self.reported(ipv6), other && !self.reported(!ipv6)),
            None => (!self.reported_v4 && !self.reported_v6, false),
        }
    }

    /// When the next question to the relay is due, while asking.
    fn ask_due(&self) -> Option<Instant> {
        if self.ask_other_now {
            return Some(Instant::from_millis(0));
        }
        let (started, next) = self.ask?;
        ASK_ADDRESS_AT
            .get(next)
            .map(|offset| started.saturating_add(*offset))
    }
}

/// A direct address an application gave for a peer, and when it was last
/// used, so that a full table forgets the one used least recently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hint {
    address: SourceKey,
    used: Instant,
}

/// A peer's hints, in order: at most [`MAX_HINTS`].
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Hints([Option<SourceKey>; MAX_HINTS], usize);

impl Hints {
    /// The hints, in order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = SourceKey> + '_ {
        self.0.iter().take(self.1).flatten().copied()
    }
}

/// The most direct address hints one peer has.
pub const MAX_HINTS: usize = 8;

/// A hint longer than a direct source may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HintTooLong {
    /// Its length.
    pub len: usize,
}

/// Why a peer's hints were refused; its hints are then as they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintError {
    /// A hint longer than a direct source may be.
    TooLong(HintTooLong),
    /// More hints than one peer may have ([`MAX_HINTS`]), or than the storage
    /// profile's hint table holds.
    TooMany {
        /// How many were given.
        hints: usize,
        /// The most that fit.
        max: usize,
    },
}

impl core::fmt::Display for HintError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong(error) => error.fmt(f),
            Self::TooMany { hints, max } => {
                write!(f, "{hints} hints, where at most {max} fit")
            }
        }
    }
}

impl core::error::Error for HintError {}

impl core::fmt::Display for HintTooLong {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "a {}-byte hint is longer than a direct source may be",
            self.len
        )
    }
}

impl core::error::Error for HintTooLong {}

/// A first contact still owed to the hints after the first: sent to the next
/// one at each poll, before anything else (`PROTOCOL.md §6`).
pub(crate) struct Fan {
    peer: PeerId,
    bytes: [u8; FIRST_CONTACT_LEN],
    len: usize,
    /// The hint it goes to next.
    next: usize,
}

/// The path the rule chose. It lives on the stack for one routing step, and
/// there is no allocator to box the hints in.
#[allow(clippy::large_enum_variant)]
enum Path {
    Direct(SourceKey),
    /// Every hint of the peer at once: the first now, the others fanned out.
    Hints(Hints),
    RelaySession,
    Forward,
    None,
}

/// How to answer the packet being handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Answer {
    /// To its source, directly.
    Direct,
    /// On the relay link it came on.
    Link(Link),
    /// Through the relay, to the sender the relay named.
    Relayed(PeerId),
}

/// On a client with a pinned relay: the application's policy, except in the
/// relay context, which only the pinned relay can reach (it is bound) and which
/// uses no PSK. Elsewhere, on a relay itself, the application's policy alone.
pub(super) struct RelayAware<'p, P> {
    pub(super) inner: &'p mut P,
    pub(super) pinned: bool,
}

impl<P: Admission> Admission for RelayAware<'_, P> {
    fn admit(&mut self, peer: &PeerId, context: &[u8]) -> Decision {
        if self.pinned && context == relay::CONTEXT {
            Decision::Accept { psk: None }
        } else {
            self.inner.admit(peer, context)
        }
    }

    fn psk(&mut self, peer: &PeerId, context: &[u8]) -> Option<Psk> {
        if self.pinned && context == relay::CONTEXT {
            None
        } else {
            self.inner.psk(peer, context)
        }
    }
}

/// What the first pass over a packet from the relay produced, without
/// borrowing it: offsets into the packet's buffer instead of slices.
enum Step {
    /// A relay frame from the relay session.
    Frame { at: usize, len: usize },
    /// A datagram of another session.
    Datagram {
        peer: PeerId,
        context: Context,
        at: usize,
        len: usize,
        connected: bool,
        relayed: bool,
    },
    /// A stream frame of another session.
    StreamFrame {
        peer: PeerId,
        context: Context,
        kind: FrameKind,
        at: usize,
        len: usize,
        connected: bool,
        relayed: bool,
    },
    /// Anything else, owning nothing.
    Done(Output<'static, Hop>),
}

fn offset(base: usize, data: &[u8]) -> usize {
    (data.as_ptr() as usize).saturating_sub(base)
}

impl<C: Config> Endpoint<C> {
    /// `policy`, aware of the relay context when a relay is pinned.
    pub(super) fn aware<'p, P: Admission>(&self, policy: &'p mut P) -> RelayAware<'p, P> {
        RelayAware {
            inner: policy,
            pinned: self.relay.is_some(),
        }
    }

    /// Serves the relay context to whoever admission accepts, with a payload
    /// in first contacts: what a relay does (`PROTOCOL.md §6`).
    ///
    /// # Errors
    ///
    /// A [`ResponderError`] when the relay context is served already, or the
    /// storage profile's contexts table is full.
    pub fn serve_relay_context(&mut self) -> Result<(), ResponderError> {
        self.responder.serve(relay::CONTEXT, Access::Policy)?;
        self.responder.accept_payload(relay::CONTEXT)
    }

    /// Pins `relay`: this endpoint reaches peers it cannot reach directly
    /// through it, and serves the relay context to it alone. As
    /// [`Self::set_relay`] with a relay.
    ///
    /// # Errors
    ///
    /// A [`ResponderError`] when the storage profile's contexts table is full.
    pub fn pin_relay(&mut self, relay: Address, now: Instant) -> Result<(), ResponderError> {
        self.set_relay(Some(relay), now)
    }

    /// Replaces the pinned relay with `relay`, or, with `None`, removes it,
    /// while the endpoint runs (`PROTOCOL.md §6`).
    ///
    /// Everything of the old relay goes: its relay session, dial and pending
    /// handshakes, its link (asked closed, with no relay-unavailable event),
    /// and the public candidates it reported. The relay context is served to
    /// the new relay alone, or no longer served. A reachable endpoint asks for a
    /// link to the new relay at once. Sessions with peers are untouched: one
    /// last heard through the relay goes on through the new one. The relay
    /// already pinned changes nothing.
    ///
    /// # Errors
    ///
    /// A [`ResponderError`] when the storage profile's contexts table is full;
    /// nothing is changed then.
    pub fn set_relay(
        &mut self,
        relay: Option<Address>,
        now: Instant,
    ) -> Result<(), ResponderError> {
        let context = Context::new(relay::CONTEXT).map_err(ResponderError::ContextTooLong)?;
        let current = self.relay.as_ref().map(|client| client.address);
        if current == relay {
            return Ok(());
        }
        // The relay context first: the one step that can be refused.
        match relay {
            Some(address) => {
                let access = Access::Bound(address.peer_id());
                if self.responder.serves(&context) {
                    self.responder.set_access(&context, access)?;
                } else {
                    self.responder.serve(relay::CONTEXT, access)?;
                }
                self.responder.accept_payload(relay::CONTEXT)?;
            }
            None => {
                self.responder.stop_serving(&context);
            }
        }
        if let Some(old) = current {
            let old_peer = old.peer_id();
            self.remove_session((old_peer, context));
            self.responder
                .retain_pending(|pending| *pending.peer() != old_peer);
            self.forget_public();
        }
        match (relay, self.relay.as_mut()) {
            (Some(address), Some(client)) => client.replace(address, now),
            (Some(address), None) => self.relay = Some(RelayClient::new(address, context, now)),
            (None, Some(client)) => {
                if matches!(client.link, LinkState::Opening(_) | LinkState::Open { .. }) {
                    self.link_close_owed = true;
                }
                self.relay = None;
            }
            (None, None) => {}
        }
        Ok(())
    }

    /// The pinned relay's identity, if any.
    #[must_use]
    pub fn relay(&self) -> Option<PeerId> {
        self.relay.as_ref().map(|relay| relay.address.peer_id())
    }

    /// Gives the core the direct addresses of `peer`, in the driver's encoding
    /// of a direct source, replacing those it had; none forgets them. A dial's
    /// first attempt goes to every one of them at once (`PROTOCOL.md §6`).
    /// Hints that do not fit make room by forgetting every hint of the peer
    /// whose hints were used least recently.
    ///
    /// # Errors
    ///
    /// [`HintError`] for an address longer than a direct source may be, or
    /// for more than [`MAX_HINTS`] or than the hint table holds; the peer's
    /// hints are then as they were.
    pub fn set_hints<A: AsRef<[u8]>>(
        &mut self,
        peer: PeerId,
        addresses: &[A],
        now: Instant,
    ) -> Result<(), HintError> {
        let max = self
            .hints
            .capacity()
            .map_or(MAX_HINTS, |capacity| capacity.min(MAX_HINTS));
        if addresses.len() > max {
            return Err(HintError::TooMany {
                hints: addresses.len(),
                max,
            });
        }
        let mut sources = [None; MAX_HINTS];
        for (slot, address) in sources.iter_mut().zip(addresses) {
            let address = address.as_ref();
            let too_long = HintError::TooLong(HintTooLong { len: address.len() });
            *slot = Some(Source::Direct(address).key().ok_or(too_long)?);
        }
        self.hints.retain(|(p, _), _| *p != peer);
        while let Some(capacity) = self.hints.capacity()
            && self.hints.len() + addresses.len() > capacity
        {
            let mut oldest: Option<(Instant, PeerId)> = None;
            self.hints.for_each(|(p, _), hint| {
                if oldest.is_none_or(|(used, _)| hint.used < used) {
                    oldest = Some((hint.used, *p));
                }
            });
            let Some((_, evicted)) = oldest else {
                break;
            };
            self.hints.retain(|(p, _), _| *p != evicted);
        }
        for (index, address) in (0u8..).zip(sources.into_iter().flatten()) {
            let _ = self
                .hints
                .insert((peer, index), Hint { address, used: now });
        }
        Ok(())
    }

    /// The hints of `peer`, in the order given, marked used at `now`.
    pub(super) fn use_hints(&mut self, peer: &PeerId, now: Instant) -> Hints {
        let mut hints = Hints::default();
        for index in 0..MAX_HINTS {
            let key = (*peer, u8::try_from(index).unwrap_or(u8::MAX));
            let Some(hint) = self.hints.get_mut(&key) else {
                break;
            };
            hint.used = now;
            if let Some(slot) = hints.0.get_mut(hints.1) {
                *slot = Some(hint.address);
                hints.1 += 1;
            }
        }
        hints
    }

    /// A session with a peer is opening: this endpoint's public addresses are
    /// about to be its candidates, so the relay is asked for those it has not
    /// reported, the one over the other family included.
    pub(super) fn peer_session_opening(&mut self, key: &Key, now: Instant) {
        if self.relay.as_ref().is_some_and(|relay| !relay.is(key)) {
            self.ask_relay(now);
        }
    }

    /// Asks the relay, on [`ASK_ADDRESS_AT`]'s schedule, for the public UDP
    /// addresses it has not reported, unless already asking.
    pub(super) fn ask_relay(&mut self, now: Instant) {
        if let Some(relay) = self.relay.as_mut()
            && relay.ask.is_none()
            && relay.missing() != (false, false)
        {
            relay.ask = Some((now, 0));
        }
    }

    /// Tells the core in which families the driver reaches the relay: whether
    /// the address it uses is IPv6, and whether it also has one in the other
    /// family, where [`RelayPath::UdpOther`] goes. Without it, the core asks
    /// the relay only about the address in use.
    pub fn set_relay_families(&mut self, ipv6: bool, other: bool) {
        if let Some(relay) = self.relay.as_mut() {
            relay.families = Some((ipv6, other));
        }
    }

    /// Whether the core knows a way to `peer`: a session heard from it, a
    /// hint, or a pinned relay.
    pub(super) fn has_path(&self, peer: &PeerId, _now: Instant) -> bool {
        let mut heard = false;
        self.sessions.for_each(|(p, _), session| {
            heard |= *p == *peer && session.last_source.is_some();
        });
        heard || self.relay.is_some() || self.hints.get(&(*peer, 0)).is_some()
    }

    /// Asks the endpoint to stay reachable through its pinned relay, keeping
    /// a TCP link to it, or to stop. The core decides when the link is opened
    /// and closed ([`Poll::OpenRelayLink`], [`Poll::CloseRelayLink`]).
    pub fn set_reachable(&mut self, reachable: bool, now: Instant) {
        let Some(relay) = self.relay.as_mut() else {
            return;
        };
        relay.reachable = reachable;
        if !reachable {
            relay.registered = false;
        }
        match (reachable, relay.link) {
            (true, LinkState::None) => {
                relay.failures = 0;
                relay.link = LinkState::Waiting(Some(now));
            }
            (false, LinkState::Opening(_) | LinkState::Open { .. }) => {
                relay.close_due = true;
                relay.link = LinkState::None;
            }
            (false, LinkState::Waiting(_)) => relay.link = LinkState::None,
            _ => {}
        }
    }

    /// The driver opened the TCP link the core asked for, and wrote the
    /// preamble.
    pub fn relay_link_opened(&mut self, now: Instant) {
        let Some(relay) = self.relay.as_mut() else {
            return;
        };
        if matches!(relay.link, LinkState::Opening(_)) {
            relay.link = LinkState::Open {
                established: false,
                awaiting: Some(now),
            };
            relay.last_tcp_sent = now;
            // A keep-alive at once: the relay's answer establishes the link,
            // even when everything else reaches this endpoint over UDP.
            relay.keepalive_now = true;
            relay.register_due = true;
            relay.registered = false;
        } else {
            // A link nobody asks for any more.
            relay.close_due = true;
        }
    }

    /// The TCP link closed, or could not be opened.
    pub fn relay_link_closed(&mut self, now: Instant) {
        if let Some(relay) = self.relay.as_mut()
            && matches!(relay.link, LinkState::Opening(_) | LinkState::Open { .. })
        {
            relay.link_gone(now, true);
        }
    }

    /// A keep-alive from the relay arrived on the TCP link.
    pub fn relay_keepalive_received(&mut self, _now: Instant) {
        if let Some(relay) = self.relay.as_mut() {
            relay.heard_on_link();
        }
    }

    /// The network changed: addresses or interfaces. A reachable endpoint
    /// replaces its link at once, and every direct path is stale: the NAT
    /// holes it went through may be gone, so the next packet takes the relay,
    /// and one probe checks the path (`PROTOCOL.md §7`).
    pub fn network_changed(&mut self, now: Instant) {
        if let Some(relay) = self.relay.as_mut() {
            relay.reported_v4 = false;
            relay.reported_v6 = false;
        }
        // A peer last heard from a direct source may be out of reach from the
        // new network: with a relay pinned, the next packets take the relay
        // (`PROTOCOL.md §6`, rule 4), where the session exchanges candidates
        // and an attempt finds a direct path again. Without one, that source
        // is still the best guess. The relay's own session is left alone.
        //
        // And each session with live keys sends one packet, its new list if
        // one is owed, else a keep-alive: through the relay, the newest the
        // peer has, it tells the peer to stop sending where this endpoint was
        // (`PROTOCOL.md §7`), even when the application here has nothing to
        // send. An endpoint that keeps a link sends it once the relay has it
        // again, on the new link (`tell_peers`); one without a link, at once,
        // over UDP, the only path it has. One packet a session for each change
        // of network; nothing at rest, and a dormant session is not woken.
        let relay_key = self.relay.as_ref().map(RelayClient::key);
        let wait_for_link = self.relay.as_ref().is_some_and(|relay| relay.reachable);
        self.sessions.retain(|key, session| {
            if let Some(direct) = session.paths.direct.as_mut() {
                direct.fresh_until = direct.fresh_until.min(now);
            }
            if relay_key.is_some_and(|relay| relay != *key) {
                if session
                    .last_source
                    .is_some_and(|source| source.as_direct().is_some())
                {
                    session.last_source = None;
                }
                if !wait_for_link && session.current.as_ref().is_some_and(|pair| pair.live(now)) {
                    session.confirm = true;
                }
            }
            true
        });
        if let Some(relay) = self.relay.as_mut() {
            // UDP to the relay was proven from the old network: from the new
            // one it may not work yet. Until it is proven again, the link
            // carries what is for the relay (`PROTOCOL.md §6`), and the first
            // packet after the change also goes over UDP, without waiting for
            // the 10 s of the copies: where UDP works, the relay learns the new
            // address at once, and does not depend on the link alone.
            relay.udp_proven = None;
            relay.last_probe = None;
            relay.tell_peers |= wait_for_link;
        }
        let Some(relay) = self.relay.as_mut().filter(|relay| relay.reachable) else {
            return;
        };
        if matches!(relay.link, LinkState::Opening(_) | LinkState::Open { .. }) {
            relay.close_due = true;
        }
        relay.failures = 0;
        relay.registered = false;
        relay.link = LinkState::Waiting(Some(now));
    }

    /// Sets the TCP keep-alive interval: [`MIN_KEEPALIVE`] by default, never
    /// less.
    ///
    /// # Errors
    ///
    /// [`KeepAliveTooShort`] below a minute; the interval is unchanged.
    pub fn set_relay_keepalive(&mut self, interval: Duration) -> Result<(), KeepAliveTooShort> {
        if interval < MIN_KEEPALIVE {
            return Err(KeepAliveTooShort { asked: interval });
        }
        if let Some(relay) = self.relay.as_mut() {
            relay.keepalive = interval;
        }
        Ok(())
    }

    /// Whether UDP to the relay is proven at `now`.
    #[must_use]
    pub fn relay_udp_proven(&self, now: Instant) -> bool {
        self.relay
            .as_ref()
            .is_some_and(|relay| relay.udp_proven(now))
    }

    /// Sends the packet in `out[..len]`, which an output named for `peer`,
    /// through the relay: the driver calls it when it has no direct path to
    /// the peer. The forward is built around the packet in place, so `out`
    /// must hold `len + 65` bytes, and, for a wake, a first contact carrying
    /// it.
    ///
    /// # Errors
    ///
    /// [`SendError::NoRelay`], [`SendError::TooLarge`] for a packet over
    /// [`MAX_CARRIED`] bytes, or the relay session's queue or tables being
    /// full.
    #[cfg(feature = "testing")]
    pub fn through_relay(
        &mut self,
        peer: PeerId,
        len: usize,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<Output<'static>, SendError> {
        let mut policy = self.aware(policy);
        Ok(
            match self.forward_in_place(peer, len, now, &mut policy, entropy, out)? {
                Some((to, len)) => {
                    self.note_sent(to, now);
                    Output::Transmit { to, len }
                }
                None => Output::Nothing,
            },
        )
    }

    /// Handles a packet received from the pinned relay on `link`: a UDP
    /// datagram from its address, or a packet the TCP link's
    /// [`Deframer`](crate::relay::framing::Deframer) produced.
    pub fn handle_relay_packet<'a>(
        &mut self,
        packet: &'a mut [u8],
        link: Link,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Output<'a> {
        let Some(relay_key) = self.relay.as_ref().map(RelayClient::key) else {
            return Output::Nothing;
        };
        let mut policy = self.aware(policy);
        if link == Link::Tcp
            && let Some(relay) = self.relay.as_mut()
        {
            relay.heard_on_link();
        }
        let label = match link {
            Link::Udp => LABEL_UDP,
            Link::Tcp => LABEL_TCP,
        };
        let base = packet.as_ptr() as usize;
        let step = match self.handle_inner(
            &mut *packet,
            Source::Direct(label),
            now,
            &mut policy,
            entropy,
            out,
        ) {
            Output::Event(
                Event::Datagram {
                    peer,
                    context,
                    data,
                    ..
                }
                | Event::Payload {
                    peer,
                    context,
                    data,
                },
            ) if (peer, context) == relay_key => Step::Frame {
                at: offset(base, data),
                len: data.len(),
            },
            Output::Event(Event::Datagram {
                peer,
                context,
                data,
                connected,
                relayed,
            }) => Step::Datagram {
                peer,
                context,
                at: offset(base, data),
                len: data.len(),
                connected,
                relayed,
            },
            // The relay sends no stream frames; one on its session is ignored.
            Output::Event(Event::Frame { peer, context, .. }) if (peer, context) == relay_key => {
                Step::Done(Output::Nothing)
            }
            Output::Event(Event::Frame {
                peer,
                context,
                kind,
                data,
                connected,
                relayed,
            }) => Step::StreamFrame {
                peer,
                context,
                kind,
                at: offset(base, data),
                len: data.len(),
                connected,
                relayed,
            },
            Output::Event(Event::Payload { .. }) => Step::Done(Output::Nothing),
            Output::Event(event) => Step::Done(Output::Event(event.owned())),
            Output::Transmit { to, len } => Step::Done(Output::Transmit { to, len }),
            Output::Nothing => Step::Done(Output::Nothing),
        };
        if link == Link::Udp
            && self.last_opened.is_some_and(|(key, _)| key == relay_key)
            && let Some(relay) = self.relay.as_mut()
        {
            relay.udp_proven = Some(now);
        }
        // A response owed to a first contact from the relay goes back on its link.
        if let Some((_, to)) = self.owed.as_mut().filter(|(_, to)| *to == Hop::Source) {
            *to = Hop::Relay(match link {
                Link::Udp => RelayPath::Udp,
                Link::Tcp => RelayPath::Tcp,
            });
        }
        match step {
            Step::Done(output) => {
                self.finish(output, Answer::Link(link), now, &mut policy, entropy, out)
            }
            Step::Datagram {
                peer,
                context,
                at,
                len,
                connected,
                relayed,
            } => Output::Event(Event::Datagram {
                peer,
                context,
                data: packet.get(at..at + len).unwrap_or_default(),
                connected,
                relayed,
            }),
            Step::StreamFrame {
                peer,
                context,
                kind,
                at,
                len,
                connected,
                relayed,
            } => Output::Event(Event::Frame {
                peer,
                context,
                kind,
                data: packet.get(at..at + len).unwrap_or_default(),
                connected,
                relayed,
            }),
            Step::Frame { at, len } => {
                let Some(frame) = packet.get(at..at + len) else {
                    return Output::Nothing;
                };
                match relay::decode(frame) {
                    Ok(Frame::Deliver {
                        sender,
                        packet: inner,
                    }) => {
                        let start = at + offset(packet.as_ptr() as usize + at, inner);
                        let end = start + inner.len();
                        let sender = PeerId::vouched(sender);
                        let Some(inner) = packet.get_mut(start..end) else {
                            return Output::Nothing;
                        };
                        let output = self.handle_inner(
                            inner,
                            Source::Relayed(sender),
                            now,
                            &mut policy,
                            entropy,
                            out,
                        );
                        self.finish(
                            output,
                            Answer::Relayed(sender),
                            now,
                            &mut policy,
                            entropy,
                            out,
                        )
                    }
                    Ok(Frame::NotConnected { recipient }) => Output::Event(Event::PeerNotAtRelay {
                        peer: PeerId::vouched(recipient),
                    }),
                    Ok(Frame::Observed { link, address }) => {
                        if link == Link::Udp {
                            self.observed_public(address);
                            if let Some(relay) = self.relay.as_mut() {
                                if crate::paths::canonical(address).is_ipv4() {
                                    relay.reported_v4 = true;
                                } else {
                                    relay.reported_v6 = true;
                                }
                                if relay.missing() == (false, false) {
                                    relay.ask = None;
                                    relay.ask_other_now = false;
                                }
                            }
                        }
                        Output::Event(Event::ObservedAddress { link, address })
                    }
                    // A forward or register is the relay's to receive; and
                    // anything malformed is ignored.
                    Ok(Frame::Forward { .. } | Frame::Register { .. }) | Err(_) => Output::Nothing,
                }
            }
        }
    }

    /// Routes an output and turns the relay session's events into relay events.
    pub(super) fn finish<'a>(
        &mut self,
        output: Output<'a, Hop>,
        answer: Answer,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Output<'a> {
        match output {
            Output::Transmit { to, len } => {
                match self.route(to, len, answer, now, policy, entropy, out) {
                    Some((to, len)) => {
                        self.note_sent(to, now);
                        Output::Transmit { to, len }
                    }
                    None => Output::Nothing,
                }
            }
            Output::Event(event) => self.relay_event(event),
            Output::Nothing => Output::Nothing,
        }
    }

    /// The relay session's events, as the application sees them.
    fn relay_event<'a, D>(&self, event: Event<'a>) -> Output<'a, D> {
        let Some(relay) = self.relay.as_ref() else {
            return Output::Event(event);
        };
        let ours = |peer: &PeerId, context: &Context| relay.is(&(*peer, *context));
        match event {
            Event::Connected { peer, context }
            | Event::Datagram { peer, context, .. }
            | Event::Frame { peer, context, .. }
            | Event::Payload { peer, context, .. }
                if ours(&peer, &context) =>
            {
                Output::Nothing
            }
            Event::Closed {
                peer,
                context,
                code,
                by_peer,
            } if ours(&peer, &context) => Output::Event(Event::RelayUnavailable {
                error: RelayError::Closed {
                    code,
                    by_relay: by_peer,
                },
            }),
            Event::ReopenFailed {
                peer,
                context,
                error,
            } if ours(&peer, &context) => Output::Event(Event::RelayUnavailable {
                error: RelayError::Dial(error),
            }),
            event => Output::Event(event),
        }
    }

    /// The path of a packet in `out[..len]`, by the rule of `PROTOCOL.md §6`:
    /// where the peer was last authenticated from; else, for a dial's first
    /// attempt, its hint; else the pinned relay; else the hint. `None` when it
    /// was queued for the relay session, or has no path and is dropped.
    #[allow(
        clippy::too_many_arguments,
        reason = "a route can open the relay session: the sans-IO inputs of a dial"
    )]
    fn route(
        &mut self,
        to: Hop,
        len: usize,
        answer: Answer,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Option<(To, usize)> {
        match to {
            Hop::Source => match answer {
                Answer::Direct => Some((To::Source, len)),
                Answer::Link(link) => Some((
                    To::Relay(match link {
                        Link::Udp => RelayPath::Udp,
                        Link::Tcp => RelayPath::Tcp,
                    }),
                    len,
                )),
                Answer::Relayed(peer) if self.relay.is_some() => self
                    .forward_in_place(peer, len, now, policy, entropy, out)
                    .ok()
                    .flatten(),
                Answer::Relayed(_) => Some((To::Source, len)),
            },
            Hop::Relay(path) => Some((To::Relay(path), len)),
            Hop::Direct(address) => Some((To::Direct(address), len)),
            Hop::Peer {
                peer,
                last_source,
                attempt,
            } => match self.path_of(peer, last_source, attempt, now) {
                Path::Direct(address) => Some((To::Direct(address), len)),
                Path::Hints(hints) => self.fan_out(peer, &hints, len, out),
                Path::RelaySession => Some((To::Relay(self.relay_path(now)), len)),
                Path::Forward => self
                    .forward_in_place(peer, len, now, policy, entropy, out)
                    .ok()
                    .flatten(),
                Path::None => None,
            },
        }
    }

    /// The rule of `PROTOCOL.md §6` for a packet to `peer`.
    fn path_of(
        &mut self,
        peer: PeerId,
        last_source: Option<SourceKey>,
        attempt: Option<usize>,
        now: Instant,
    ) -> Path {
        if self.relay() == Some(peer) {
            return Path::RelaySession;
        }
        if let Some(source) = last_source {
            if source.relayed_from() == Some(peer) {
                return if self.relay.is_some() {
                    Path::Forward
                } else {
                    Path::None
                };
            }
            if source.as_direct().is_some() {
                return Path::Direct(source);
            }
        }
        let hints = self.usable_hints(&peer, now);
        let hinted = hints.iter().next().is_some();
        match (attempt, hinted, self.relay.is_some()) {
            (Some(0), true, _) | (_, true, false) => Path::Hints(hints),
            (_, _, true) => Path::Forward,
            (_, false, false) => Path::None,
        }
    }

    /// The hints of `peer` a path may use, in order, marked used at `now`.
    fn usable_hints(&mut self, peer: &PeerId, now: Instant) -> Hints {
        let all = self.use_hints(peer, now);
        let mut usable = Hints::default();
        for hint in all.iter() {
            if self.may_be_path(Some(hint))
                && let Some(slot) = usable.0.get_mut(usable.1)
            {
                *slot = Some(hint);
                usable.1 += 1;
            }
        }
        usable
    }

    /// Sends the packet in `out[..len]` to the first of `hints` now, and keeps
    /// it for the others, which [`Self::next_fan`] sends one a poll. A packet
    /// longer than a first contact, or one that finds the table of fan-outs
    /// full, goes to the first hint only.
    fn fan_out(
        &mut self,
        peer: PeerId,
        hints: &Hints,
        len: usize,
        out: &[u8],
    ) -> Option<(To, usize)> {
        let first = hints.iter().next()?;
        if hints.1 > 1
            && let Some(packet) = out.get(..len)
            && len <= FIRST_CONTACT_LEN
        {
            let mut bytes = [0u8; FIRST_CONTACT_LEN];
            if let Some(slot) = bytes.get_mut(..len) {
                slot.copy_from_slice(packet);
            }
            self.fan_seq = self.fan_seq.wrapping_add(1);
            let fan = Fan {
                peer,
                bytes,
                len,
                next: 1,
            };
            let _ = self.fans.insert(self.fan_seq, fan);
        }
        Some((To::Direct(first), len))
    }

    /// The next first contact owed to a hint, written in `out`: the oldest
    /// fan-out's, to its next hint. The hints are read again, so that one
    /// given meanwhile is used, and one forgotten is not.
    pub(super) fn next_fan(&mut self, now: Instant, out: &mut [u8]) -> Option<(To, usize)> {
        loop {
            let mut oldest: Option<u32> = None;
            self.fans.for_each(|seq, _| {
                if oldest.is_none_or(|o| seq.wrapping_sub(o) > u32::MAX / 2) {
                    oldest = Some(*seq);
                }
            });
            let seq = oldest?;
            let (peer, next) = self.fans.get(&seq).map(|fan| (fan.peer, fan.next))?;
            let hints = self.usable_hints(&peer, now);
            let Some(hint) = hints.iter().nth(next) else {
                self.fans.remove(&seq);
                continue;
            };
            let fan = self.fans.get_mut(&seq)?;
            fan.next += 1;
            let len = fan.len;
            let sent = match (out.get_mut(..len), fan.bytes.get(..len)) {
                (Some(slot), Some(bytes)) => {
                    slot.copy_from_slice(bytes);
                    true
                }
                _ => false,
            };
            if fan.next >= hints.1 || !sent {
                self.fans.remove(&seq);
            }
            if sent {
                return Some((To::Direct(hint), len));
            }
        }
    }

    /// Which way the next packet for the relay goes, at `now`.
    fn relay_path(&mut self, now: Instant) -> RelayPath {
        let Some(relay) = self.relay.as_mut() else {
            return RelayPath::Udp;
        };
        if relay.udp_proven(now) {
            RelayPath::Udp
        } else if relay.link_open() {
            if relay
                .last_probe
                .is_none_or(|at| now >= at.saturating_add(UDP_PROBE_EVERY))
            {
                relay.last_probe = Some(now);
                RelayPath::Both
            } else {
                RelayPath::Tcp
            }
        } else {
            RelayPath::Udp
        }
    }

    /// Records a send on the TCP link, for its keep-alive.
    pub(super) fn note_sent(&mut self, to: To, now: Instant) {
        if let Some(relay) = self.relay.as_mut()
            && matches!(
                to,
                To::Relay(RelayPath::Tcp | RelayPath::Both) | To::RelayKeepAlive
            )
        {
            relay.last_tcp_sent = now;
        }
    }

    /// Wraps the packet in `out[..len]` in a forward to `peer` and sends it in
    /// the relay session.
    fn forward_in_place(
        &mut self,
        peer: PeerId,
        len: usize,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<Option<(To, usize)>, SendError> {
        let frame_len = self.wrap_forward(peer, len, out)?;
        self.send_relay_frame(frame_len, None, now, policy, entropy, out)
    }

    /// Builds, around the packet in `out[..len]`, a forward to `peer` at
    /// `out[DATA_AT..]`, returning the frame's length.
    fn wrap_forward(&self, peer: PeerId, len: usize, out: &mut [u8]) -> Result<usize, SendError> {
        if self.relay.is_none() {
            return Err(SendError::NoRelay);
        }
        if len > MAX_CARRIED {
            return Err(SendError::TooLarge {
                packet: len,
                path: MAX_CARRIED,
            });
        }
        let frame_len = ROUTED_HEADER_LEN + len;
        let at = DATA_AT + ROUTED_HEADER_LEN;
        if out.len() < at + len + TAG_LEN || len == 0 {
            return Err(SendError::TooLarge {
                packet: OVERHEAD + frame_len,
                path: out.len(),
            });
        }
        out.copy_within(..len, at);
        let header = out.get_mut(DATA_AT..).ok_or(SendError::Capacity)?;
        relay::write_routed_header(frame_type::FORWARD, peer.as_bytes(), header)
            .map_err(|_| SendError::Capacity)?;
        Ok(frame_len)
    }

    /// Seals the relay frame in `out[DATA_AT..][..frame_len]` under the relay
    /// session's keys, if it has live keys and nothing queued before it.
    /// Never dials, so it needs no policy or entropy.
    fn seal_relay_frame(
        &mut self,
        frame_len: usize,
        path: Option<RelayPath>,
        now: Instant,
        out: &mut [u8],
    ) -> Result<Option<(To, usize)>, SendError> {
        let Some(key) = self.relay.as_ref().map(RelayClient::key) else {
            return Err(SendError::NoRelay);
        };
        let dialling = self.dials.get(&key).is_some();
        let ready = self.sessions.get(&key).is_some_and(|session| {
            session.queue.is_empty() && session.current.as_ref().is_some_and(|pair| pair.live(now))
        });
        if !ready {
            return Ok(None);
        }
        let path = path.unwrap_or_else(|| self.relay_path(now));
        let session = self.sessions.get_mut(&key).ok_or(SendError::Capacity)?;
        let pair = session.current.as_mut().ok_or(SendError::Capacity)?;
        let len = transport::seal_in_place(
            &pair.send,
            pair.remote_index,
            pair.next_counter,
            inner::DATAGRAM,
            frame_len,
            out,
        )
        .map_err(|_| SendError::TooLarge {
            packet: OVERHEAD + frame_len,
            path: out.len(),
        })?;
        pair.next_counter += 1;
        if pair.wants_rekey(now) && !dialling {
            session.rekey = true;
        }
        session.confirm = false;
        session.last_sent = Some(now);
        session.last_used = now;
        Ok(Some((To::Relay(path), len)))
    }

    /// Where a packet goes when it may only use a live relay session: what
    /// [`Endpoint::close`] needs, without a policy or entropy to dial with. A
    /// packet for a peer heard through the relay is dropped when the relay
    /// session has no keys.
    pub(super) fn route_live(
        &mut self,
        to: Hop,
        len: usize,
        now: Instant,
        out: &mut [u8],
    ) -> Option<(To, usize)> {
        match to {
            Hop::Source => Some((To::Source, len)),
            Hop::Relay(path) => Some((To::Relay(path), len)),
            Hop::Direct(address) => Some((To::Direct(address), len)),
            Hop::Peer {
                peer,
                last_source,
                attempt,
            } => match self.path_of(peer, last_source, attempt, now) {
                Path::Direct(address) => Some((To::Direct(address), len)),
                Path::Hints(hints) => self.fan_out(peer, &hints, len, out),
                Path::RelaySession => Some((To::Relay(self.relay_path(now)), len)),
                Path::Forward => {
                    let frame_len = self.wrap_forward(peer, len, out).ok()?;
                    self.seal_relay_frame(frame_len, None, now, out)
                        .ok()
                        .flatten()
                }
                Path::None => None,
            },
        }
    }

    /// Sends the relay frame in `out[DATA_AT..][..frame_len]` in the relay
    /// session: sealed in place while it has keys; otherwise queued, and, if
    /// nothing is opening the session yet, a wake: a first contact to the relay
    /// carrying the head of the queue.
    #[allow(
        clippy::too_many_arguments,
        reason = "a frame can open the relay session: the sans-IO inputs of a dial"
    )]
    fn send_relay_frame(
        &mut self,
        frame_len: usize,
        path: Option<RelayPath>,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<Option<(To, usize)>, SendError> {
        let Some((key, address)) = self.relay.as_ref().map(|r| (r.key(), r.address)) else {
            return Err(SendError::NoRelay);
        };
        self.expire(now);
        if let Some(sealed) = self.seal_relay_frame(frame_len, path, now, out)? {
            return Ok(Some(sealed));
        }
        let dialling = self.dials.get(&key).is_some();
        let live = self
            .sessions
            .get(&key)
            .and_then(|session| session.current.as_ref())
            .is_some_and(|pair| pair.live(now));

        let frame = out
            .get(DATA_AT..DATA_AT + frame_len)
            .ok_or(SendError::Capacity)?;
        let session = self.session_for(key, now).ok_or(SendError::Capacity)?;
        session.address = Some(address);
        session.last_used = now;
        session.queue.push(frame).map_err(SendError::QueueFull)?;
        let pending = self.responder.pending_for(&key.0) > 0;
        if dialling || live || pending {
            return Ok(None);
        }
        self.wake(path, now, policy, entropy, out).map(Some)
    }

    /// Opens the relay session: its first contact carries the head of the
    /// queue, when it fits (`Endpoint::start_dial`).
    fn wake(
        &mut self,
        path: Option<RelayPath>,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<(To, usize), SendError> {
        let Some((key, address)) = self.relay.as_ref().map(|r| (r.key(), r.address)) else {
            return Err(SendError::NoRelay);
        };
        let len = self.start_dial(key, &address, now, policy, entropy, out)?;
        let path = path.unwrap_or_else(|| self.relay_path(now));
        Ok((To::Relay(path), len))
    }

    /// Polls, routing each output, and adds the relay's own work: the TCP
    /// keep-alive, the register, and a queue left without a dial.
    pub(super) fn poll_routed(
        &mut self,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Poll {
        // A first contact owed to the next of a peer's hints goes before
        // anything else, so that every hint has it at once.
        if let Some((to, len)) = self.next_fan(now, out) {
            self.note_sent(to, now);
            return Poll::Transmit { to, len };
        }
        // Each turn either returns or consumes something queued, so this ends;
        // the bound is a backstop.
        for _ in 0..64 {
            if let Some(poll) = self.relay_step(now, policy, entropy, out) {
                return poll;
            }
            match self.poll_inner(now, policy, entropy, out) {
                Poll::Transmit { to, len } => {
                    if let Some((to, len)) =
                        self.route(to, len, Answer::Direct, now, policy, entropy, out)
                    {
                        self.note_sent(to, now);
                        return Poll::Transmit { to, len };
                    }
                }
                Poll::Event(event) => {
                    if let Output::<To>::Event(event) = self.relay_event(event) {
                        return Poll::Event(event);
                    }
                }
                Poll::OpenRelayLink => return Poll::OpenRelayLink,
                Poll::CloseRelayLink => return Poll::CloseRelayLink,
                Poll::Wait(at) => return Poll::Wait(at),
                Poll::Idle => return Poll::Idle,
            }
        }
        Poll::Wait(now)
    }

    /// The questions to the relay due at `now`: the address in use first,
    /// then the other family's at once. A question is an observed-address
    /// frame, which the relay answers with the address it sees it from. Only
    /// while the relay session has keys; a question that cannot go counts.
    fn ask_step(
        &mut self,
        live: bool,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Option<Poll> {
        let relay = self.relay.as_mut()?;
        let due = relay.ask_due().is_some_and(|due| now >= due);
        if !due {
            return None;
        }
        let (primary, other) = relay.missing();
        let path = if relay.ask_other_now {
            relay.ask_other_now = false;
            RelayPath::UdpOther
        } else {
            if let Some((_, next)) = relay.ask.as_mut() {
                *next += 1;
                if *next >= ASK_ADDRESS_AT.len() {
                    relay.ask = None;
                }
            }
            match (primary, other) {
                (true, true) => {
                    relay.ask_other_now = true;
                    RelayPath::Udp
                }
                (true, false) => RelayPath::Udp,
                (false, true) => RelayPath::UdpOther,
                (false, false) => {
                    relay.ask = None;
                    return None;
                }
            }
        };
        if !live {
            relay.ask_other_now = false;
            return None;
        }
        let question = Frame::Observed {
            link: Link::Udp,
            address: core::net::SocketAddr::new(
                core::net::IpAddr::V6(core::net::Ipv6Addr::UNSPECIFIED),
                0,
            ),
        };
        let len = relay::encode(&question, out.get_mut(DATA_AT..)?).ok()?;
        let (to, len) = self
            .send_relay_frame(len, Some(path), now, policy, entropy, out)
            .ok()
            .flatten()?;
        Some(Poll::Transmit { to, len })
    }

    /// The relay's own work at `now`, if any is due.
    fn relay_step(
        &mut self,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Option<Poll> {
        if self.link_close_owed {
            self.link_close_owed = false;
            return Some(Poll::CloseRelayLink);
        }
        let relay = self.relay.as_mut()?;
        let key = relay.key();
        if relay.close_due {
            relay.close_due = false;
            return Some(Poll::CloseRelayLink);
        }
        if let Some(state) = relay.pending.take() {
            return Some(Poll::Event(match state {
                Ok(()) => Event::RelayAvailable,
                Err(error) => Event::RelayUnavailable { error },
            }));
        }
        if relay.answer_due().is_some_and(|due| now >= due) {
            // Nothing from the relay in time: the link is dead.
            relay.link_gone(now, false);
            return Some(Poll::CloseRelayLink);
        }
        if relay.link == LinkState::Waiting(None) {
            let exponent = relay.failures.saturating_sub(1).min(16);
            let wait = BACKOFF_FIRST.saturating_mul(1 << exponent).min(BACKOFF_CAP);
            let mut draw = [0u8; 2];
            entropy.fill(&mut draw);
            let base = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
            let jitter = base.saturating_mul(u64::from(u16::from_le_bytes(draw))) / 131_070;
            relay.link = LinkState::Waiting(Some(
                now.saturating_add(Duration::from_millis(base.saturating_add(jitter))),
            ));
        }
        if let LinkState::Waiting(Some(at)) = relay.link
            && now >= at
        {
            relay.link = LinkState::Opening(now);
            return Some(Poll::OpenRelayLink);
        }
        if relay.keepalive_due().is_some_and(|due| now >= due) {
            relay.last_tcp_sent = now;
            relay.keepalive_now = false;
            if let LinkState::Open {
                established,
                awaiting: None,
            } = relay.link
            {
                relay.link = LinkState::Open {
                    established,
                    awaiting: Some(now),
                };
            }
            return Some(Poll::Transmit {
                to: To::RelayKeepAlive,
                len: 0,
            });
        }
        let register = relay.link_open() && relay.register_due;
        let address = relay.address;
        let live = self.is_live(&key.0, relay::CONTEXT, now);
        if let Some(poll) = self.ask_step(live, now, policy, entropy, out) {
            return Some(poll);
        }
        let opening = self.dials.get(&key).is_some() || self.responder.pending_for(&key.0) > 0;
        if register {
            if live {
                if let Some(relay) = self.relay.as_mut() {
                    relay.register_due = false;
                }
                let frame = Frame::Register {
                    address: *self.responder.identity().address().as_bytes(),
                };
                let len = relay::encode(&frame, out.get_mut(DATA_AT..)?).ok()?;
                let (to, len) = self
                    .send_relay_frame(len, Some(RelayPath::Tcp), now, policy, entropy, out)
                    .ok()
                    .flatten()?;
                self.note_sent(to, now);
                // Registered: peers reach this endpoint through the relay.
                let mut tell = false;
                if let Some(relay) = self.relay.as_mut() {
                    relay.registered = true;
                    relay.failures = 0;
                    relay.pending = Some(Ok(()));
                    tell = core::mem::take(&mut relay.tell_peers);
                }
                // After a change of network, each live session tells its peer
                // now, on the new link, behind the register.
                if tell {
                    self.sessions.retain(|session_key, session| {
                        if *session_key != key
                            && session.current.as_ref().is_some_and(|pair| pair.live(now))
                        {
                            session.confirm = true;
                        }
                        true
                    });
                }
                return Some(Poll::Transmit { to, len });
            }
            if !opening {
                // A new link with a dormant session: open it on the link, so
                // that the relay binds the link; the register follows.
                let output = self
                    .connect_inner(&address, relay::CONTEXT, now, policy, entropy, out)
                    .ok()?;
                if let Output::Transmit { len, .. } = output {
                    let to = To::Relay(RelayPath::Tcp);
                    self.note_sent(to, now);
                    return Some(Poll::Transmit { to, len });
                }
            }
        }
        // Frames queued while a pending handshake from the relay was not
        // confirmed, and nothing else opening the session: open it.
        let stuck = !live
            && !opening
            && self
                .sessions
                .get(&key)
                .is_some_and(|session| !session.queue.is_empty());
        if stuck {
            let (to, len) = self.wake(None, now, policy, entropy, out).ok()?;
            self.note_sent(to, now);
            return Some(Poll::Transmit { to, len });
        }
        None
    }
}

impl Event<'_> {
    /// The event, owning nothing: for events that borrow no packet.
    fn owned(self) -> Event<'static> {
        match self {
            Event::Connected { peer, context } => Event::Connected { peer, context },
            Event::Closed {
                peer,
                context,
                code,
                by_peer,
            } => Event::Closed {
                peer,
                context,
                code,
                by_peer,
            },
            Event::ReopenFailed {
                peer,
                context,
                error,
            } => Event::ReopenFailed {
                peer,
                context,
                error,
            },
            Event::PeerNotAtRelay { peer } => Event::PeerNotAtRelay { peer },
            Event::ObservedAddress { link, address } => Event::ObservedAddress { link, address },
            Event::RelayUnavailable { error } => Event::RelayUnavailable { error },
            Event::RelayAvailable => Event::RelayAvailable,
            Event::PathChanged {
                peer,
                context,
                path,
            } => Event::PathChanged {
                peer,
                context,
                path,
            },
            // These borrow a packet; the caller handles them before.
            Event::Datagram { .. } | Event::Frame { .. } | Event::Payload { .. } => {
                Event::RelayUnavailable {
                    error: RelayError::Closed {
                        code: 0,
                        by_relay: false,
                    },
                }
            }
        }
    }
}
