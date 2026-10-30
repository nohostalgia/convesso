//! An endpoint: one sans-IO object that answers first contacts, dials peers,
//! and carries datagrams over sessions (`PROTOCOL.md §5`).
//!
//! ```text
//! packets, time, entropy, policy  -->  Endpoint  -->  packets to send, events, deadlines
//! ```
//!
//! One call returns one [`Output`] (or [`Poll`]). The caller drains with
//! [`Endpoint::poll`] until it says [`Poll::Wait`] or [`Poll::Idle`]; that is
//! how several packets leave (a queue flushing after a handshake) without a
//! buffer per packet. [`Poll::Idle`] means no deadline at all: what an endpoint
//! whose sessions are all dormant returns, and why an idle device sends
//! nothing.
//!
//! A first contact with a payload is answered with two things: the response,
//! and the payload for the application. The call returns the payload, as
//! [`Event::Payload`], and the response leaves through the next
//! [`Endpoint::poll`], as a transmission to the source of that packet.

use core::net::{IpAddr, SocketAddr};

use crate::dos::{Source, SourceKey};
use crate::handshake::messages::{TYPE_RESPONSE, is_first_contact_type};
use crate::handshake::{
    Access, Admission, ChannelBinding, Context, ContextTooLong, Decision, Dial, DialError,
    DialEvent, DialPoll, Entropy, Established, RESPONSE_LEN, Responder, ResponderError,
    ResponderOutput, Standing,
};
use crate::identity::{Address, Identity, PeerId};
use crate::paths::PathKind;
use crate::relay::{self, Link};
use crate::session::{DatagramQueue, KeyPair, QueueFull, Session};
use crate::storage::{Config, Table};
use crate::time::Instant;
use crate::transport::{self, OVERHEAD, ReplayWindow, TYPE_TRANSPORT, inner};
use crate::wire::{self, Classified, Version, VersionNotSupported};

mod direct;
mod index;
mod relayed;

pub use direct::ExcludeError;
use index::{Look, Sessions};
pub use relayed::{
    ASK_ADDRESS_AT, BACKOFF_CAP, BACKOFF_FIRST, HintError, HintTooLong, KeepAliveTooShort,
    LINK_ANSWER_WITHIN, LinkFailure, MAX_HINTS, MIN_KEEPALIVE, RELAY_AFTER_HINTS, RelayError,
    RelayPath, UDP_PROBE_EVERY, UDP_PROVEN_FOR,
};
use relayed::{Answer, RelayClient};

type Key = (PeerId, Context);
type SessionOf<C> = Session<<C as Config>::ReplayWindow, <C as Config>::Queue>;

/// What an index names: a dial's attempt, or a session's key pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// An attempt of the dial to this peer, in this context.
    Dial(PeerId, Context),
    /// A key pair of the session with this peer, in this context.
    Session(PeerId, Context),
}

/// Which stream frame a packet carries (`PROTOCOL.md §8`). The core
/// carries both kinds without reading them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Stream data, inner type `0x06`.
    Data,
    /// A stream acknowledgement, inner type `0x07`.
    Ack,
}

impl FrameKind {
    /// The inner type that carries this kind.
    #[must_use]
    pub const fn inner_type(self) -> u8 {
        match self {
            Self::Data => inner::STREAM_DATA,
            Self::Ack => inner::STREAM_ACK,
        }
    }
}

/// Whom a datagram is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<'a> {
    /// A peer by its address: a dormant session can be reopened.
    Address(&'a Address),
    /// A peer by its identity: only while the session has keys, because a
    /// `PeerId` does not determine the address bytes `mac1` is keyed by.
    Peer(PeerId),
    /// A peer by its address, at a direct source the caller knows it at, in
    /// the encoding the driver gives sources in: a session without keys is
    /// reopened there. A live session keeps its own path. What a relay uses
    /// to reach a client it knows the path of (`PROTOCOL.md §6`).
    AddressAt(&'a Address, &'a [u8]),
}

/// Where a packet goes. The core always names the path; a driver never
/// chooses one (`PROTOCOL.md §6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum To {
    /// Back to where the packet being handled came from. From
    /// [`Endpoint::poll`], the packet handled last: a response owed to a first
    /// contact with a payload, which the caller drains before handling another.
    Source,
    /// To this direct address, in the driver's encoding
    /// ([`SourceKey::as_direct`]).
    Direct(SourceKey),
    /// To the pinned relay, on this path: a packet of the relay session, which
    /// may carry a packet for a peer.
    Relay(RelayPath),
    /// The TCP link's keep-alive: the driver writes the empty frame. `len` is 0.
    RelayKeepAlive,
}

/// Something the application should know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// A session with this peer in this context has keys, where it had none
    /// (`PROTOCOL.md §5`): its first handshake, or one after [`Event::Idle`].
    Connected {
        /// The peer.
        peer: PeerId,
        /// The context.
        context: Context,
    },
    /// The session with this peer in this context has no keys left: they
    /// expired. It sends nothing more; the next datagram to the peer opens a
    /// session again, with [`Event::Connected`]. Never raised for a session
    /// that was closed, nor for one whose opening failed.
    Idle {
        /// The peer.
        peer: PeerId,
        /// The context.
        context: Context,
    },
    /// A datagram, decrypted in place in the packet's buffer.
    Datagram {
        /// The peer.
        peer: PeerId,
        /// The context.
        context: Context,
        /// The data.
        data: &'a [u8],
        /// Whether this datagram also confirmed a first session with the peer:
        /// the application learns of the connection with its first data.
        connected: bool,
        /// Whether it arrived through the relay rather than directly.
        relayed: bool,
    },
    /// A stream frame, for the stream layer (`PROTOCOL.md §8`),
    /// decrypted in place and not read by the core. Never a datagram.
    Frame {
        /// The peer.
        peer: PeerId,
        /// The context.
        context: Context,
        /// Which frame.
        kind: FrameKind,
        /// The frame's bytes.
        data: &'a [u8],
        /// Whether this frame also confirmed a first session with the peer.
        connected: bool,
        /// Whether it arrived through the relay rather than directly.
        relayed: bool,
    },
    /// The session ended.
    Closed {
        /// The peer.
        peer: PeerId,
        /// The context.
        context: Context,
        /// The code, in the refusal code space.
        code: u16,
        /// Whether the peer closed it (otherwise, this side did).
        by_peer: bool,
    },
    /// The payload of an admitted first contact with a payload, decrypted in
    /// the packet's buffer. It is authenticated as the peer's but
    /// **unconfirmed**: the same first contact, replayed, delivers it again.
    /// Only contexts that accept a payload produce it.
    Payload {
        /// The initiator.
        peer: PeerId,
        /// The context.
        context: Context,
        /// The payload.
        data: &'a [u8],
    },
    /// The relay could not reach `peer`. Information only: no session or dial
    /// with the peer ends because of it.
    PeerNotAtRelay {
        /// The peer.
        peer: PeerId,
    },
    /// The address the pinned relay sees this endpoint at, on one link.
    ObservedAddress {
        /// The link.
        link: Link,
        /// The address and port.
        address: SocketAddr,
    },
    /// A session's path changed (`PROTOCOL.md §7`): a direct path was
    /// found, or lost and the relay carries the session again. Raised only for
    /// sessions that exchanged candidates.
    PathChanged {
        /// The peer.
        peer: PeerId,
        /// The context.
        context: Context,
        /// The new path, and with a direct one its family.
        path: PathKind,
    },
    /// The session with the pinned relay could not be opened, or ended, or
    /// the link to it failed; what the relay session had queued is
    /// discarded.
    RelayUnavailable {
        /// Why.
        error: RelayError,
    },
    /// The endpoint is registered with its pinned relay on a link: peers can
    /// reach it through the relay. Raised again after each new registration.
    RelayAvailable,
    /// A dial to reopen a session failed; the datagrams queued are discarded.
    ReopenFailed {
        /// The peer.
        peer: PeerId,
        /// The context.
        context: Context,
        /// Why.
        error: DialError,
    },
}

/// The session a transport packet just authenticated, as
/// [`Endpoint::last_authenticated`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authenticated {
    /// The peer.
    pub peer: PeerId,
    /// The context.
    pub context: Context,
    /// Whether its counter was above every one accepted before under its keys:
    /// a packet no one can have recorded, so its source can be trusted to be
    /// the peer's current one.
    pub newest: bool,
}

/// Where a packet goes, inside the endpoint, before the core chooses its
/// path: to a peer, with what the choice depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hop {
    /// Back to the source of the packet being handled.
    Source,
    /// To a peer. `attempt`: the number of the dial's first contact this is.
    Peer {
        peer: PeerId,
        last_source: Option<SourceKey>,
        attempt: Option<usize>,
    },
    /// Already routed to the relay.
    Relay(RelayPath),
    /// To this direct address, whatever the session's path: a probe.
    Direct(SourceKey),
}

/// What a call produced. `D` is where a packet goes: [`To`] for every
/// output an application or driver sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output<'a, D = To> {
    /// Send the first `len` bytes of the output buffer.
    Transmit {
        /// Where.
        to: D,
        /// How many bytes.
        len: usize,
    },
    /// Tell the application.
    Event(Event<'a>),
    /// Nothing now.
    Nothing,
}

/// What [`Endpoint::poll`] produced. `D` is as for [`Output`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll<D = To> {
    /// Send the first `len` bytes of the output buffer.
    Transmit {
        /// Where.
        to: D,
        /// How many bytes.
        len: usize,
    },
    /// Tell the application.
    Event(Event<'static>),
    /// Open the TCP link to the pinned relay, write the preamble, and report
    /// [`Endpoint::relay_link_opened`] or [`Endpoint::relay_link_closed`].
    OpenRelayLink,
    /// Close the TCP link to the pinned relay. Nothing is reported back.
    CloseRelayLink,
    /// Nothing until this instant, or a packet.
    Wait(Instant),
    /// Nothing until a packet or a send: no deadline at all.
    Idle,
}

/// Why a datagram was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// Its packet would exceed the path's size.
    TooLarge {
        /// The packet's size.
        packet: usize,
        /// The path's size.
        path: usize,
    },
    /// The session's queue cannot take it.
    QueueFull(QueueFull),
    /// The session has no keys and the peer's address is unknown.
    AddressUnknown,
    /// The source given with [`Target::AddressAt`] is longer than any source
    /// the core keeps.
    SourceTooLong {
        /// Its length.
        len: usize,
    },
    /// The context is too long.
    ContextTooLong(ContextTooLong),
    /// The endpoint's tables are full.
    Capacity,
    /// No relay is pinned.
    NoRelay,
    /// The relay context is the endpoint's own.
    ReservedContext,
    /// No path to the peer is known: no session heard from it, no hint for
    /// it, and no relay pinned.
    NoPath,
    /// A stream frame's session has no current key pair. Frames are never
    /// queued: the stream layer reopens the session with a dial.
    NoKeys,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge { packet, path } => {
                write!(f, "a {packet}-byte packet does not fit a {path}-byte path")
            }
            Self::QueueFull(full) => write!(f, "the session's {}-byte queue is full", full.limit),
            Self::AddressUnknown => {
                f.write_str("the session has no keys and the peer's address is unknown")
            }
            Self::SourceTooLong { len } => write!(f, "a {len}-byte source is too long"),
            Self::ContextTooLong(error) => error.fmt(f),
            Self::Capacity => f.write_str("the endpoint's tables are full"),
            Self::NoRelay => f.write_str("no relay is pinned"),
            Self::ReservedContext => f.write_str("the relay context is reserved"),
            Self::NoPath => f.write_str("no path to the peer is known"),
            Self::NoKeys => f.write_str("the session has no keys for a stream frame"),
        }
    }
}

impl core::error::Error for SendError {}

/// What an application chooses for a context, on both sides of its sessions
/// (`PROTOCOL.md §3`, §5). The default is every choice off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Settings {
    /// Whether each session opening in the context sends the passive
    /// keepalive, until a session overrides it
    /// ([`Endpoint::set_passive_keepalive`]).
    pub passive_keepalive: bool,
    /// Whether the context carries early data: a dial carries the first
    /// queued datagram in its first contacts when it fits, and a first
    /// contact with a payload is accepted, its payload handed over as
    /// [`Event::Payload`], unconfirmed. Both sides of a context choose it
    /// alike.
    pub early_data: bool,
}

/// The endpoint holds no session with that peer in that context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoSession;

impl core::fmt::Display for NoSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no session with that peer in that context")
    }
}

impl core::error::Error for NoSession {}

/// An endpoint for one identity.
pub struct Endpoint<C: Config> {
    responder: Responder<C>,
    dials: C::Dials<Key, Dial>,
    /// The sessions, with the index of what is due among them.
    sessions: Sessions<C>,
    indices: C::Indices<u32, Owner>,
    /// A response owed to the source of the last packet, sent by the next poll.
    owed: Option<([u8; RESPONSE_LEN], Hop)>,
    /// First contacts owed to the hints after the first, one per dial attempt,
    /// by the order they were made in.
    fans: C::Dials<u32, relayed::Fan>,
    fan_seq: u32,
    /// Direct address hints for peers, given by the application: a peer's
    /// hints in the order given.
    hints: C::Hints<(PeerId, u8), relayed::Hint>,
    /// The pinned relay, if any.
    relay: Option<RelayClient>,
    /// The driver is to be asked to close the link of a relay removed.
    link_close_owed: bool,
    /// The session whose transport packet opened last, if the last packet was
    /// one, and whether its counter was the newest.
    last_opened: Option<(Key, bool)>,
    /// This endpoint's candidates (`PROTOCOL.md §7`).
    own: direct::Own,
    /// The prefixes no direct path may use, by masked address and length.
    excluded: C::Excluded<(IpAddr, u8), ()>,
    /// The settings of the contexts that have any, served or dialled in.
    settings: C::Contexts<Context, Settings>,
    /// Whether each poll checks the index against a walk of every session.
    #[cfg(any(test, feature = "testing"))]
    check_index: bool,
}

impl<C: Config> Endpoint<C> {
    /// An endpoint for `identity`, serving `contexts` under
    /// [`Access::Policy`]. With none, it answers no first contact until it
    /// serves one, and it can dial in any context.
    ///
    /// # Errors
    ///
    /// As [`Self::serve`].
    pub fn new(identity: Identity, contexts: &[&[u8]]) -> Result<Self, ResponderError> {
        if contexts.contains(&relay::CONTEXT) {
            return Err(ResponderError::RelayContext);
        }
        Ok(Self {
            responder: Responder::new(identity, contexts)?,
            dials: Default::default(),
            sessions: Default::default(),
            indices: Default::default(),
            owed: None,
            fans: Default::default(),
            fan_seq: 0,
            hints: Default::default(),
            relay: None,
            link_close_owed: false,
            last_opened: None,
            own: direct::Own::new(),
            excluded: Default::default(),
            settings: Default::default(),
            #[cfg(any(test, feature = "testing"))]
            check_index: true,
        })
    }

    /// Turns off the check that each poll's index finds what a walk of every
    /// session finds, on by default with `testing`: for measurements, which
    /// it would make cost as much as the walk.
    #[cfg(any(test, feature = "testing"))]
    pub fn set_index_check(&mut self, on: bool) {
        self.check_index = on;
    }

    /// Serves `context`, reached under `access`, while the endpoint runs. A
    /// first contact in a context not served meets silence, as one in a
    /// context unknown.
    ///
    /// # Errors
    ///
    /// A [`ResponderError`] for the relay context, which only
    /// [`Self::pin_relay`] or [`Self::serve_relay_context`] serve; for a
    /// context served already; or for one more than the storage profile's
    /// contexts table holds, the relay's included.
    pub fn serve(&mut self, context: &[u8], access: Access) -> Result<(), ResponderError> {
        if context == relay::CONTEXT {
            return Err(ResponderError::RelayContext);
        }
        self.responder.serve(context, access)?;
        self.apply_early_data(context)
    }

    /// Sets what the application chooses for `context`, served or only
    /// dialled in, in place of what it chose before. A session takes the
    /// passive keepalive when it opens, so the sessions open keep theirs.
    ///
    /// # Errors
    ///
    /// [`ResponderError::RelayContext`] for the relay context, whose settings
    /// are the relay's; [`ResponderError::ContextTooLong`]; and
    /// [`ResponderError::TooManyContexts`] for one context more than the
    /// storage profile holds.
    pub fn set_context_settings(
        &mut self,
        context: &[u8],
        settings: Settings,
    ) -> Result<(), ResponderError> {
        if context == relay::CONTEXT {
            return Err(ResponderError::RelayContext);
        }
        let name = Context::new(context).map_err(ResponderError::ContextTooLong)?;
        if settings == Settings::default() {
            self.settings.remove(&name);
        } else {
            self.settings.insert(name, settings).map_err(|full| {
                ResponderError::TooManyContexts {
                    capacity: full.capacity,
                }
            })?;
        }
        self.apply_early_data(context)
    }

    /// The settings of `context`: the default when it has none.
    fn settings_of(&self, context: &Context) -> Settings {
        self.settings.get(context).copied().unwrap_or_default()
    }

    /// Has the responder accept a payload in `context` as its settings say,
    /// if it serves it.
    fn apply_early_data(&mut self, context: &[u8]) -> Result<(), ResponderError> {
        let name = Context::new(context).map_err(ResponderError::ContextTooLong)?;
        if self.responder.serves(&name) {
            let early = self.settings_of(&name).early_data;
            self.responder.set_accepts_payload(&name, early)?;
        }
        Ok(())
    }

    /// Changes who may reach this endpoint in `context`: `Some(access)` serves
    /// it under that access, `None` serves it no longer, so that it is only
    /// dialled in.
    ///
    /// Every session this side accepted in it (whose latest handshake this
    /// side answered) and every pending handshake in it that the new access
    /// would not admit is closed, with an authenticated close that leaves
    /// through [`Self::poll`], or discarded. Under [`Access::Policy`],
    /// `policy` is asked again, and a refusal closes with its code; otherwise
    /// the close carries `code`. Sessions whose latest handshake this side
    /// started are not affected: access governs who may reach this endpoint.
    ///
    /// # Errors
    ///
    /// [`ResponderError::RelayContext`] for the relay context, and as
    /// [`Self::serve`] when a context not served is served.
    pub fn set_access(
        &mut self,
        context: &[u8],
        access: Option<Access>,
        code: u16,
        policy: &mut impl Admission,
    ) -> Result<(), ResponderError> {
        if context == relay::CONTEXT {
            return Err(ResponderError::RelayContext);
        }
        let served = Context::new(context).map_err(ResponderError::ContextTooLong)?;
        match access {
            Some(access) if self.responder.serves(&served) => {
                self.responder.set_access(&served, access)?;
            }
            Some(access) => {
                self.responder.serve(context, access)?;
                self.apply_early_data(context)?;
            }
            None => {
                self.responder.stop_serving(&served);
            }
        }
        self.sessions.retain(|(peer, in_context), session| {
            if *in_context == served
                && session.accepted
                && session.closing.is_none()
                && let Some(code) = refused(access, code, peer, context, policy)
            {
                session.closing = Some(code.max(1));
                session.queue.clear();
            }
            true
        });
        self.responder.retain_pending(|pending| {
            *pending.context() != served
                || refused(access, code, pending.peer(), context, policy).is_none()
        });
        Ok(())
    }

    /// Closes `context`: every session in it, accepted or dialled, is closed
    /// with `code` (the closes leave through [`Self::poll`]); its dials and
    /// pending handshakes are discarded; and it is served no longer, freeing
    /// its entry. Sessions in other contexts are unaffected.
    ///
    /// # Errors
    ///
    /// [`ResponderError::RelayContext`] for the relay context.
    pub fn close_context(&mut self, context: &[u8], code: u16) -> Result<(), ResponderError> {
        if context == relay::CONTEXT {
            return Err(ResponderError::RelayContext);
        }
        let closed = Context::new(context).map_err(ResponderError::ContextTooLong)?;
        self.sessions.retain(|(_, in_context), session| {
            if *in_context == closed {
                session.closing.get_or_insert(code.max(1));
                session.queue.clear();
            }
            true
        });
        let indices = &mut self.indices;
        self.dials.retain(|(_, in_context), dial| {
            if *in_context == closed {
                for index in dial.attempt_indices() {
                    indices.remove(&index);
                }
                false
            } else {
                true
            }
        });
        self.responder
            .retain_pending(|pending| *pending.context() != closed);
        self.responder.stop_serving(&closed);
        self.settings.remove(&closed);
        Ok(())
    }

    /// Whether `context` is served: a first contact in it can be answered.
    #[must_use]
    pub fn serves(&self, context: &[u8]) -> bool {
        Context::new(context).is_ok_and(|context| self.responder.serves(&context))
    }

    /// How many contexts are served, the relay's included.
    #[must_use]
    pub fn contexts_served(&self) -> usize {
        self.responder.contexts_served()
    }

    /// This endpoint's identity.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        self.responder.identity()
    }

    /// Handles a packet received at `now` from `source`. The packet is
    /// decrypted in place, and a delivered datagram or payload borrows it. An
    /// answer is written in `out`, which must hold at least
    /// [`FIRST_CONTACT_LEN`](crate::handshake::FIRST_CONTACT_LEN) bytes, and,
    /// for a first contact with a payload to be handled, its response and
    /// payload.
    pub fn handle_packet<'a>(
        &mut self,
        packet: &'a mut [u8],
        source: Source<'_>,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Output<'a> {
        let mut policy = self.aware(policy);
        let output = self.handle_inner(packet, source, now, &mut policy, entropy, out);
        let answer = match source {
            Source::Relayed(peer) => Answer::Relayed(peer),
            Source::Direct(_) => Answer::Direct,
        };
        self.finish(output, answer, now, &mut policy, entropy, out)
    }

    fn handle_inner<'a>(
        &mut self,
        packet: &'a mut [u8],
        source: Source<'_>,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Output<'a, Hop> {
        self.last_opened = None;
        self.expire(now);
        match wire::classify(packet) {
            Classified::Version(Version::V1) => match packet.get(1).copied() {
                Some(kind) if is_first_contact_type(kind) => {
                    self.first_contact(packet, source, now, policy, entropy, out)
                }
                Some(TYPE_RESPONSE) => self.route_to_dial(packet, 6, source, now),
                Some(crate::dos::TYPE_COOKIE_REPLY) => self.route_to_dial(packet, 2, source, now),
                Some(TYPE_TRANSPORT) => self.transport(packet, source, now, out),
                _ => Output::Nothing,
            },
            Classified::Version(_) => self.first_contact(packet, source, now, policy, entropy, out),
            Classified::VersionNotSupported => self.version_not_supported(packet, source, now),
            Classified::Drop => Output::Nothing,
        }
    }

    fn first_contact<'a>(
        &mut self,
        packet: &'a mut [u8],
        source: Source<'_>,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Output<'a, Hop> {
        // Two openings that cross: the one the greater `PeerId` started wins,
        // at both ends, so that one handshake completes (`PROTOCOL.md §3`).
        let me = self.responder.identity().peer_id();
        let (sessions, dials) = (&self.sessions, &self.dials);
        let mut yields = None;
        let standing = |peer: &PeerId, context: &Context, renewal: bool| {
            let key = (*peer, *context);
            if !renewal && dials.get(&key).is_some_and(|dial| !dial.is_renewal()) {
                if me > *peer {
                    return Standing::Ignore;
                }
                yields = Some(key);
            }
            let live = sessions
                .get(&key)
                .and_then(|session| session.current.as_ref())
                .is_some_and(|pair| pair.live(now));
            if live {
                Standing::LiveKeys
            } else {
                Standing::NoKeys
            }
        };
        let answered = self
            .responder
            .handle_with(packet, source, now, policy, standing, entropy, out);
        // This side's opening lost the crossing: its dial ends, and what it
        // carried goes once the peer's handshake gives keys.
        if let Some(key) = yields
            && self.responder.pending_in(&key.0, &key.1)
        {
            self.remove_dial(key);
            if let Some(session) = self.sessions.get_mut(&key) {
                session.carried = false;
            }
        }
        match answered {
            ResponderOutput::Send(len) => Output::Transmit {
                to: Hop::Source,
                len,
            },
            ResponderOutput::Payload {
                len,
                payload,
                peer,
                context,
            } => {
                // The payload moves into the packet's buffer, longer than it,
                // so that the event borrows it as a datagram would; the
                // response waits for the next poll.
                let (Some(response), Some(plaintext), Some(field)) = (
                    out.get(..len)
                        .and_then(|r| <[u8; RESPONSE_LEN]>::try_from(r).ok()),
                    out.get(len..len + payload),
                    packet.get_mut(..payload),
                ) else {
                    return Output::Nothing;
                };
                field.copy_from_slice(plaintext);
                // The poll that sends the response no longer knows where the
                // packet came from: it is named now.
                self.owed = Some((response, relayed::answer_hop(source)));
                Output::Event(Event::Payload {
                    peer,
                    context,
                    data: packet.get(..payload).unwrap_or_default(),
                })
            }
            ResponderOutput::Silent => Output::Nothing,
        }
    }

    /// A response or a cookie reply: its initiator index, at `at`, names a dial.
    fn route_to_dial<'a>(
        &mut self,
        packet: &[u8],
        at: usize,
        source: Source<'_>,
        now: Instant,
    ) -> Output<'a, Hop> {
        let Some(index) = packet
            .get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
        else {
            return Output::Nothing;
        };
        let Some(Owner::Dial(peer, context)) = self.indices.get(&index).copied() else {
            return Output::Nothing;
        };
        self.dial_event((peer, context), packet, source, now)
    }

    fn version_not_supported<'a>(
        &mut self,
        packet: &[u8],
        source: Source<'_>,
        now: Instant,
    ) -> Output<'a, Hop> {
        let Ok(answer) = VersionNotSupported::decode(packet) else {
            return Output::Nothing;
        };
        let mut found = None;
        self.dials.for_each(|key, dial| {
            if found.is_none() && dial.sent_mac1(answer.echo()) {
                found = Some(*key);
            }
        });
        match found {
            Some(key) => self.dial_event(key, packet, source, now),
            None => Output::Nothing,
        }
    }

    fn dial_event<'a>(
        &mut self,
        key: Key,
        packet: &[u8],
        source: Source<'_>,
        now: Instant,
    ) -> Output<'a, Hop> {
        let identity = self.responder.identity();
        let Some(dial) = self.dials.get_mut(&key) else {
            return Output::Nothing;
        };
        match dial.handle(identity, packet, now) {
            DialEvent::Ignored => Output::Nothing,
            DialEvent::Established(established) => {
                self.establish(key, &established, source.key(), now)
            }
            DialEvent::Failed(error) => Output::Event(self.dial_failed(key, error)),
        }
    }

    /// An initiator's handshake completed: its keys become the session's current
    /// pair, and the responder is owed a confirming packet.
    fn establish<'a>(
        &mut self,
        key: Key,
        established: &Established,
        source: Option<SourceKey>,
        now: Instant,
    ) -> Output<'a, Hop> {
        let address = self.dials.get(&key).map(|dial| *dial.remote());
        let source = source.filter(|source| self.may_be_path(Some(*source)));
        self.remove_dial(key);
        let Some(keys) = established.keys() else {
            return Output::Nothing;
        };
        let pair = KeyPair::new(
            keys,
            established.local_index(),
            established.remote_index(),
            now,
        );
        let local_index = pair.local_index;
        if let Some(relay) = self.relay.as_mut().filter(|relay| relay.is(&key)) {
            relay.register_due |= relay.link_open();
        }
        let Some(session) = self.session_for(key) else {
            return Output::Nothing;
        };
        if address.is_some() {
            session.address = address;
        }
        // The response authenticated the peer: where it came from is where
        // the session is heard from.
        if source.is_some() {
            session.last_source = source;
        }
        session.accepted = false;
        // A handshake both ends agreed opens the session starts its life: a
        // connection, whether it had no keys or keys the new ones replace.
        let first = established.opens();
        let freed = session.promote(pair, established.channel_binding(), first);
        session.connected |= first;
        // The dial carried the head of the queue in its first contact.
        if session.carried {
            session.queue.pop();
            session.carried = false;
        }
        // The first datagram in the queue confirms as well as a keepalive would.
        session.confirm = session.queue.is_empty();
        if let Some(index) = freed {
            self.indices.remove(&index);
        }
        let _ = self
            .indices
            .insert(local_index, Owner::Session(key.0, key.1));
        if first {
            Output::Event(Event::Connected {
                peer: key.0,
                context: key.1,
            })
        } else {
            Output::Nothing
        }
    }

    fn dial_failed(&mut self, key: Key, error: DialError) -> Event<'static> {
        self.remove_dial(key);
        // The relay session refused or unanswered on the link: that attempt is
        // over, and the next one waits for the backoff.
        if let Some(relay) = self.relay.as_mut()
            && relay.is(&key)
        {
            relay.session_failed();
        }
        if let Some(session) = self.sessions.get_mut(&key) {
            session.queue.clear();
        }
        Event::ReopenFailed {
            peer: key.0,
            context: key.1,
            error,
        }
    }

    fn transport<'a>(
        &mut self,
        packet: &'a mut [u8],
        source: Source<'_>,
        now: Instant,
        out: &mut [u8],
    ) -> Output<'a, Hop> {
        let Ok(header) = transport::parse_header(packet) else {
            return Output::Nothing;
        };
        match self.indices.get(&header.receiver_index).copied() {
            Some(Owner::Session(peer, context)) => {
                self.session_packet((peer, context), packet, header, source, now, out)
            }
            Some(Owner::Dial(..)) => Output::Nothing,
            None => self.confirming_packet(packet, header, source, now, out),
        }
    }

    /// A packet under one of a session's key pairs.
    fn session_packet<'a>(
        &mut self,
        key: Key,
        packet: &'a mut [u8],
        header: transport::Header,
        source: Source<'_>,
        now: Instant,
        out: &mut [u8],
    ) -> Output<'a, Hop> {
        let path = self.may_be_path(source.key());
        let Some(session) = self.sessions.get_mut(&key) else {
            return Output::Nothing;
        };
        let current = session
            .current
            .as_ref()
            .is_some_and(|pair| pair.local_index == header.receiver_index);
        let pair = [session.current.as_mut(), session.previous.as_mut()]
            .into_iter()
            .flatten()
            .find(|pair| pair.local_index == header.receiver_index);
        let Some(pair) = pair.filter(|pair| pair.live(now)) else {
            return Output::Nothing;
        };
        if !pair.window.may_accept(header.counter) {
            return Output::Nothing;
        }
        let newest = pair
            .window
            .highest()
            .is_none_or(|highest| header.counter > highest);
        let Ok(opened) = transport::open(&pair.recv, packet) else {
            return Output::Nothing;
        };
        pair.window.accept(header.counter);
        pair.received += 1;
        heard(
            session,
            opened.inner_type,
            source,
            path,
            newest && current,
            newest,
            now,
        );
        self.last_opened = Some((key, newest));
        let relayed = matches!(source, Source::Relayed(_));
        let arrival = Arrival {
            connected: false,
            relayed,
            source,
            now,
        };
        self.deliver(key, opened.inner_type, opened.data, arrival, out)
    }

    /// A packet under a pending handshake's keys: the initiator confirms it.
    fn confirming_packet<'a>(
        &mut self,
        packet: &'a mut [u8],
        header: transport::Header,
        source: Source<'_>,
        now: Instant,
        out: &mut [u8],
    ) -> Output<'a, Hop> {
        let Some(pending) = self.responder.pending(header.receiver_index) else {
            return Output::Nothing;
        };
        let Some(keys) = pending.keys() else {
            return Output::Nothing;
        };
        let (peer, context) = (*pending.peer(), *pending.context());
        let binding = *pending.channel_binding();
        let opens = pending.opens();
        let mut pair: KeyPair<C::ReplayWindow> = KeyPair::new(
            keys,
            pending.responder_index(),
            pending.initiator_index(),
            pending.completed_at(),
        );
        if !pair.live(now) {
            return Output::Nothing;
        }
        let Ok(opened) = transport::open(&pair.recv, packet) else {
            return Output::Nothing;
        };
        pair.window.accept(header.counter);
        pair.received = 1;
        let _ = self.responder.take_pending(header.receiver_index);

        let key = (peer, context);
        let path = self.may_be_path(source.key());
        let Some(session) = self.session_for(key) else {
            return Output::Nothing;
        };
        session.accepted = true;
        // The first packet of a pending pair: the newest it has, and the
        // pair is the session's current one from here.
        heard(session, opened.inner_type, source, path, true, true, now);
        let local_index = pair.local_index;
        let first = opens;
        let freed = session.promote(pair, &binding, opens);
        session.connected |= first;
        if let Some(index) = freed {
            self.indices.remove(&index);
        }
        let _ = self
            .indices
            .insert(local_index, Owner::Session(peer, context));
        self.last_opened = Some((key, true));
        if let Some(relay) = self.relay.as_mut().filter(|relay| relay.is(&key)) {
            relay.register_due |= relay.link_open();
        }
        if matches!(source, Source::Relayed(_)) {
            self.peer_session_opening(&key, now);
        }
        let relayed = matches!(source, Source::Relayed(_));
        let arrival = Arrival {
            connected: first,
            relayed,
            source,
            now,
        };
        self.deliver(key, opened.inner_type, opened.data, arrival, out)
    }

    /// What an opened packet means to its session.
    fn deliver<'a>(
        &mut self,
        key: Key,
        inner_type: u8,
        data: &'a [u8],
        arrival: Arrival<'_>,
        out: &mut [u8],
    ) -> Output<'a, Hop> {
        let Arrival {
            connected,
            relayed,
            source,
            now,
        } = arrival;
        let connected_event = || {
            if connected {
                Output::Event(Event::Connected {
                    peer: key.0,
                    context: key.1,
                })
            } else {
                Output::Nothing
            }
        };
        match (inner_type, data) {
            (inner::DATAGRAM, data) => {
                if let Some(session) = self.sessions.get_mut(&key) {
                    session.last_received_data = Some(now);
                }
                Output::Event(Event::Datagram {
                    peer: key.0,
                    context: key.1,
                    data,
                    connected,
                    relayed,
                })
            }
            (inner::STREAM_DATA | inner::STREAM_ACK, data) => {
                let kind = if inner_type == inner::STREAM_DATA {
                    if let Some(session) = self.sessions.get_mut(&key) {
                        session.last_received_data = Some(now);
                    }
                    FrameKind::Data
                } else {
                    FrameKind::Ack
                };
                Output::Event(Event::Frame {
                    peer: key.0,
                    context: key.1,
                    kind,
                    data,
                    connected,
                    relayed,
                })
            }
            (inner::CANDIDATES, data) => {
                self.accept_candidates(key, data, now);
                connected_event()
            }
            (inner::PROBE, data) => match self.answer_probe(key, data, source, now, out) {
                Some(len) => Output::Transmit {
                    to: Hop::Source,
                    len,
                },
                None => connected_event(),
            },
            (inner::ANSWER, data) => {
                self.take_answer(key, data, source, now);
                connected_event()
            }
            (inner::CLOSE, &[lo, hi]) if u16::from_le_bytes([lo, hi]) != 0 => {
                self.remove_session(key);
                Output::Event(Event::Closed {
                    peer: key.0,
                    context: key.1,
                    code: u16::from_le_bytes([lo, hi]),
                    by_peer: true,
                })
            }
            // A keepalive, a malformed close or keepalive, or a reserved type:
            // accepted for anti-replay, content ignored.
            _ => connected_event(),
        }
    }

    /// Sends a datagram to `target` in `context`, at `now`, over a path that
    /// takes packets of at most `path_max` bytes. `out` must hold at least
    /// [`FIRST_CONTACT_LEN`](crate::handshake::FIRST_CONTACT_LEN) bytes, and
    /// the datagram's packet.
    ///
    /// # Errors
    ///
    /// A [`SendError`] naming why nothing was sent or queued.
    #[allow(
        clippy::too_many_arguments,
        reason = "the sans-IO inputs: target, data, path, time, policy, entropy, buffer"
    )]
    pub fn send(
        &mut self,
        target: Target<'_>,
        context: &[u8],
        data: &[u8],
        path_max: usize,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<Output<'static>, SendError> {
        if self.relay.is_some() && context == crate::relay::CONTEXT {
            return Err(SendError::ReservedContext);
        }
        if let Target::Address(address) = target
            && !self.has_path(&address.peer_id(), now)
        {
            return Err(SendError::NoPath);
        }
        let mut policy = self.aware(policy);
        let output = self.send_inner(
            target,
            context,
            data,
            path_max,
            now,
            &mut policy,
            entropy,
            out,
        )?;
        Ok(self.finish(output, Answer::Direct, now, &mut policy, entropy, out))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the sans-IO inputs: target, data, path, time, policy, entropy, buffer"
    )]
    fn send_inner(
        &mut self,
        target: Target<'_>,
        context: &[u8],
        data: &[u8],
        path_max: usize,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<Output<'static, Hop>, SendError> {
        let packet = OVERHEAD + data.len();
        if packet > path_max {
            return Err(SendError::TooLarge {
                packet,
                path: path_max,
            });
        }
        let context = Context::new(context).map_err(SendError::ContextTooLong)?;
        self.expire(now);
        let (peer, address, at) = match target {
            Target::Address(address) => (address.peer_id(), Some(*address), None),
            Target::Peer(peer) => (peer, None, None),
            Target::AddressAt(address, source) => {
                let at = Source::Direct(source)
                    .key()
                    .ok_or(SendError::SourceTooLong { len: source.len() })?;
                (address.peer_id(), Some(*address), Some(at))
            }
        };
        let key = (peer, context);
        let dialling = self.dials.get(&key).is_some();

        if let Some(session) = self.sessions.get_mut(&key) {
            if address.is_some() {
                session.address = address;
            }
            let live = session.current.as_ref().is_some_and(|pair| pair.live(now));
            if live && session.queue.is_empty() {
                return self.seal_live(key, inner::DATAGRAM, data, now, out);
            }
        }

        // No live keys, or a queue to keep in order: queue it, and dial; or,
        // when the peer's own handshake is pending here, wait for it to be
        // confirmed rather than cross it with a dial.
        let known = self.sessions.get(&key).and_then(|session| session.address);
        let live = self
            .sessions
            .get(&key)
            .and_then(|session| session.current.as_ref())
            .is_some_and(|pair| pair.live(now));
        let pending = self.responder.pending_in(&peer, &context);
        let Some(address) = address.or(known) else {
            // Keys, or a handshake about to give them: the queue drains
            // without a dial.
            if !pending && !live {
                return Err(SendError::AddressUnknown);
            }
            let session = self.session_for(key).ok_or(SendError::Capacity)?;
            session.queue.push(data).map_err(SendError::QueueFull)?;
            return Ok(Output::Nothing);
        };
        let session = self.session_for(key).ok_or(SendError::Capacity)?;
        session.address = Some(address);
        if at.is_some() && !live {
            // Reopened where the caller knows the peer is.
            session.last_source = at;
        }
        session.queue.push(data).map_err(SendError::QueueFull)?;
        if dialling || pending || session.current.as_ref().is_some_and(|pair| pair.live(now)) {
            return Ok(Output::Nothing);
        }
        self.start_dial(
            key,
            &address,
            Some(path_max),
            false,
            now,
            policy,
            entropy,
            out,
        )
        .map(|len| Output::Transmit {
            to: Hop::Peer {
                peer,
                last_source: self
                    .sessions
                    .get(&key)
                    .and_then(|s| direct::route_source(peer, s, now, self.relay.is_some())),
                attempt: Some(0),
            },
            len,
        })
    }

    /// Seals `data` as `inner_type` under the live keys of `key`'s session,
    /// for the session's current path: what a datagram and a stream frame
    /// share. [`SendError::NoKeys`] when the session has no live keys.
    fn seal_live(
        &mut self,
        key: Key,
        inner_type: u8,
        data: &[u8],
        now: Instant,
        out: &mut [u8],
    ) -> Result<Output<'static, Hop>, SendError> {
        let (peer, _) = key;
        let dialling = self.dials.get(&key).is_some();
        let relayed = self.relay.is_some();
        let Some(session) = self.sessions.get_mut(&key) else {
            return Err(SendError::NoKeys);
        };
        if !session.current.as_ref().is_some_and(|pair| pair.live(now)) {
            return Err(SendError::NoKeys);
        }
        direct::note_use(&mut session.paths, now);
        let to = Hop::Peer {
            peer,
            last_source: direct::route_source(peer, session, now, relayed),
            attempt: None,
        };
        let Some(pair) = session.current.as_mut() else {
            return Err(SendError::NoKeys);
        };
        let len = transport::seal(
            &pair.send,
            pair.remote_index,
            pair.next_counter,
            inner_type,
            data,
            out,
        )
        .map_err(|_| SendError::TooLarge {
            packet: OVERHEAD + data.len(),
            path: out.len(),
        })?;
        pair.next_counter += 1;
        if pair.wants_rekey(now) && session.address.is_some() && !dialling {
            session.rekey = true;
        }
        session.confirm = false;
        session.last_sent = Some(now);
        Ok(Output::Transmit { to, len })
    }

    /// Sends a stream frame (`PROTOCOL.md §8`) to `peer` in
    /// `context`, at `now`: one transport packet of inner type
    /// `kind.inner_type()`, under the session's current keys and on its
    /// current path, as a datagram would go. The core does not read `frame`.
    ///
    /// A frame is never queued and never starts a handshake: on a session
    /// without live keys it is refused with [`SendError::NoKeys`], and the
    /// stream layer reopens the session through [`Endpoint::connect`].
    ///
    /// # Errors
    ///
    /// [`SendError::TooLarge`] when the packet would exceed
    /// [`MAX_CARRIED`](crate::relay::MAX_CARRIED), the longest packet every
    /// path takes; [`SendError::NoKeys`]; [`SendError::ContextTooLong`];
    /// [`SendError::ReservedContext`] for the relay's context.
    #[allow(
        clippy::too_many_arguments,
        reason = "the sans-IO inputs: peer, frame, time, policy, entropy, buffer"
    )]
    pub fn send_frame(
        &mut self,
        peer: PeerId,
        context: &[u8],
        kind: FrameKind,
        frame: &[u8],
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<Output<'static>, SendError> {
        if self.relay.is_some() && context == crate::relay::CONTEXT {
            return Err(SendError::ReservedContext);
        }
        let packet = OVERHEAD + frame.len();
        if packet > crate::relay::MAX_CARRIED {
            return Err(SendError::TooLarge {
                packet,
                path: crate::relay::MAX_CARRIED,
            });
        }
        let context = Context::new(context).map_err(SendError::ContextTooLong)?;
        self.expire(now);
        let mut policy = self.aware(policy);
        let output = self.seal_live((peer, context), kind.inner_type(), frame, now, out)?;
        Ok(self.finish(output, Answer::Direct, now, &mut policy, entropy, out))
    }

    /// Opens a session with `address` in `context` without sending data: the
    /// handshake's confirmation is a keepalive. Does nothing if the session
    /// already has keys or is being dialled.
    ///
    /// # Errors
    ///
    /// [`SendError::ContextTooLong`] or [`SendError::Capacity`].
    pub fn connect(
        &mut self,
        address: &Address,
        context: &[u8],
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<Output<'static>, SendError> {
        if self.relay.is_some() && context == crate::relay::CONTEXT {
            return Err(SendError::ReservedContext);
        }
        if !self.has_path(&address.peer_id(), now) {
            return Err(SendError::NoPath);
        }
        let mut policy = self.aware(policy);
        let output = self.connect_inner(address, context, now, &mut policy, entropy, out)?;
        Ok(self.finish(output, Answer::Direct, now, &mut policy, entropy, out))
    }

    fn connect_inner(
        &mut self,
        address: &Address,
        context: &[u8],
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<Output<'static, Hop>, SendError> {
        let context = Context::new(context).map_err(SendError::ContextTooLong)?;
        self.expire(now);
        let key = (address.peer_id(), context);
        if self.dials.get(&key).is_some() || self.is_live(&key.0, context.as_bytes(), now) {
            return Ok(Output::Nothing);
        }
        let session = self.session_for(key).ok_or(SendError::Capacity)?;
        session.address = Some(*address);
        let len = self.start_dial(key, address, None, false, now, policy, entropy, out)?;
        Ok(Output::Transmit {
            to: Hop::Peer {
                peer: key.0,
                last_source: self
                    .sessions
                    .get(&key)
                    .and_then(|s| direct::route_source(key.0, s, now, self.relay.is_some())),
                attempt: Some(0),
            },
            len,
        })
    }

    /// Starts a dial for `key`. Its first contacts carry the head of the
    /// session's queue when it fits ([`Self::wake_payload`]): the one-datagram
    /// wake of the relay context (`PROTOCOL.md §6`), and early data in a
    /// context that carries it (`PROTOCOL.md §3`), within `path_max`.
    #[allow(
        clippy::too_many_arguments,
        reason = "the sans-IO inputs of a dial, and the path it takes"
    )]
    fn start_dial(
        &mut self,
        key: Key,
        address: &Address,
        path_max: Option<usize>,
        renewal: bool,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<usize, SendError> {
        if self.dials.capacity().is_some_and(|c| self.dials.len() >= c) {
            return Err(SendError::Capacity);
        }
        let psk = policy.psk(&key.0, key.1.as_bytes());
        // A renewal carries no payload (`PROTOCOL.md §3`).
        let payload = if renewal {
            &[][..]
        } else {
            self.wake_payload(&key, out.len(), path_max)
        };
        let started = if renewal {
            Dial::renew(
                self.responder.identity(),
                address,
                key.1.as_bytes(),
                psk,
                now,
                entropy,
                out,
            )
        } else {
            Dial::start_with_payload(
                self.responder.identity(),
                address,
                key.1.as_bytes(),
                psk,
                payload,
                now,
                entropy,
                out,
            )
        };
        let (dial, len) = started.map_err(|_| SendError::Capacity)?;
        let carried = !payload.is_empty();
        if let Some(session) = self.sessions.get_mut(&key) {
            session.carried = carried;
        }
        self.peer_session_opening(&key, now);
        self.register_attempts(key, &dial);
        self.dials
            .insert(key, dial)
            .map_err(|_| SendError::Capacity)?;
        self.sessions.touch(&key);
        Ok(len)
    }

    fn register_attempts(&mut self, key: Key, dial: &Dial) {
        for index in dial.attempt_indices() {
            let _ = self.indices.insert(index, Owner::Dial(key.0, key.1));
        }
    }

    /// Closes the session with `peer` in `context`, sending one authenticated
    /// close with `code` if it has keys. The code must not be 0.
    pub fn close(
        &mut self,
        peer: PeerId,
        context: &[u8],
        code: u16,
        now: Instant,
        out: &mut [u8],
    ) -> Output<'static> {
        if self.relay.is_some() && context == crate::relay::CONTEXT {
            return Output::Nothing;
        }
        // A close is a packet or nothing; it raises no event.
        let Output::Transmit { to, len } = self.close_inner(peer, context, code, now, out) else {
            return Output::Nothing;
        };
        // A close to a peer heard through the relay goes through the relay,
        // while the relay session has keys: a close never opens one.
        match self.route_live(to, len, now, out) {
            Some((to, len)) => {
                self.note_sent(to, now);
                Output::Transmit { to, len }
            }
            None => Output::Nothing,
        }
    }

    fn close_inner(
        &mut self,
        peer: PeerId,
        context: &[u8],
        code: u16,
        now: Instant,
        out: &mut [u8],
    ) -> Output<'static, Hop> {
        let Ok(context) = Context::new(context) else {
            return Output::Nothing;
        };
        let key = (peer, context);
        self.remove_dial(key);
        let Some(session) = self.sessions.get_mut(&key) else {
            return Output::Nothing;
        };
        let to = Hop::Peer {
            peer,
            last_source: direct::route_source(peer, session, now, self.relay.is_some()),
            attempt: None,
        };
        let sealed = session
            .current
            .as_mut()
            .filter(|pair| pair.live(now))
            .and_then(|pair| {
                let len = transport::seal(
                    &pair.send,
                    pair.remote_index,
                    pair.next_counter,
                    inner::CLOSE,
                    &code.max(1).to_le_bytes(),
                    out,
                )
                .ok()?;
                pair.next_counter += 1;
                Some(len)
            });
        self.remove_session(key);
        match sealed {
            Some(len) => Output::Transmit { to, len },
            None => Output::Nothing,
        }
    }

    /// Revokes `peer`: closes every session with it, in every context (the
    /// closes leave through [`Self::poll`]), and discards its dials, pending
    /// handshakes and queued datagrams.
    pub fn close_peer(&mut self, peer: PeerId, code: u16) {
        self.sessions.retain(|(p, _), session| {
            if *p == peer {
                session.closing = Some(code.max(1));
                session.queue.clear();
            }
            true
        });
        let indices = &mut self.indices;
        self.dials.retain(|(p, _), dial| {
            if *p == peer {
                for index in dial.attempt_indices() {
                    indices.remove(&index);
                }
                false
            } else {
                true
            }
        });
        self.responder.discard_peer(&peer);
    }

    /// Turns the passive keepalive on or off for the session with `peer` in
    /// `context`, in place of its context's default, for the session's life:
    /// the next session takes the default again ([`Settings`]).
    ///
    /// # Errors
    ///
    /// [`NoSession`] when the endpoint holds no session with `peer` in
    /// `context`; nothing changes.
    pub fn set_passive_keepalive(
        &mut self,
        peer: PeerId,
        context: &[u8],
        on: bool,
    ) -> Result<(), NoSession> {
        let session = Context::new(context)
            .ok()
            .and_then(|context| self.sessions.get_mut(&(peer, context)))
            .ok_or(NoSession)?;
        session.passive_keepalive = on;
        Ok(())
    }

    /// Does what is due at `now`: dial retries and failures, confirmations,
    /// rekeys, queued datagrams, closes, passive keepalives. Call until it says
    /// [`Poll::Wait`] or [`Poll::Idle`].
    pub fn poll(
        &mut self,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Poll {
        let mut policy = self.aware(policy);
        self.poll_routed(now, &mut policy, entropy, out)
    }

    fn poll_inner(
        &mut self,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Poll<Hop> {
        self.expire(now);

        // A session whose keys expired: the application is told, once, and
        // the session is forgotten if nothing is in progress.
        // A renewal in flight holds it back: completed, the session goes on.
        let mut idle = None;
        let (dials, responder) = (&self.dials, &self.responder);
        let idles = |key: &Key, session: &SessionOf<C>| {
            session.connected
                && session.dormant()
                && !dials.get(key).is_some_and(Dial::is_renewal)
                && !responder.renewal_pending(&key.0, &key.1)
        };
        self.sessions.for_each_ready(|key, session| {
            if idle.is_none() && idles(key, session) {
                idle = Some(*key);
            }
        });
        #[cfg(any(test, feature = "testing"))]
        if self.check_index {
            let mut walk = false;
            self.sessions
                .for_each(|key, session| walk |= idles(key, session));
            assert_eq!(
                idle.is_some(),
                walk,
                "the index and a walk find idle sessions"
            );
        }
        if let Some(key) = idle {
            if let Some(session) = self.sessions.get_mut(&key) {
                session.end_life();
            }
            self.expire(now);
            return Poll::Event(Event::Idle {
                peer: key.0,
                context: key.1,
            });
        }

        if let Some((response, to)) = self.owed.take()
            && let Some(field) = out.get_mut(..RESPONSE_LEN)
        {
            field.copy_from_slice(&response);
            return Poll::Transmit {
                to,
                len: RESPONSE_LEN,
            };
        }

        // Dials whose next step is due.
        let mut due_dial = None;
        self.dials.for_each(|key, dial| {
            if due_dial.is_none() && dial.next_due().is_some_and(|due| due <= now) {
                due_dial = Some(*key);
            }
        });
        if let Some(key) = due_dial {
            let identity = self.responder.identity();
            let payload: &[u8] = self
                .sessions
                .get(&key)
                .filter(|session| session.carried)
                .and_then(|session| session.queue.front())
                .unwrap_or_default();
            if let Some(dial) = self.dials.get_mut(&key) {
                match dial.poll_with_payload(identity, payload, now, entropy, out) {
                    DialPoll::Send(len) => {
                        let mut indices = [0u32; 4];
                        let mut count = 0;
                        for (slot, index) in indices.iter_mut().zip(dial.attempt_indices()) {
                            *slot = index;
                            count += 1;
                        }
                        for index in indices.iter().take(count) {
                            let _ = self.indices.insert(*index, Owner::Dial(key.0, key.1));
                        }
                        let last_source = self.sessions.get(&key).and_then(|s| {
                            direct::route_source(key.0, s, now, self.relay.is_some())
                        });
                        return Poll::Transmit {
                            to: Hop::Peer {
                                peer: key.0,
                                last_source,
                                attempt: Some(count.saturating_sub(1)),
                            },
                            len,
                        };
                    }
                    DialPoll::Failed(error) => return Poll::Event(self.dial_failed(key, error)),
                    DialPoll::Wait(_) => {}
                }
            }
        }

        // Sessions with something to send now.
        let mut due_session = None;
        let dials = &self.dials;
        let generation = self.own.owed_generation();
        // The ready sessions with nothing to do leave the set; one whose
        // renewal holds back its idle stays until the renewal ends.
        self.sessions.retain_ready(|key, session| {
            let wants = wants(key, session, now, generation, dials);
            if wants && due_session.is_none() {
                due_session = Some(*key);
            }
            wants || (session.connected && session.dormant())
        });
        #[cfg(any(test, feature = "testing"))]
        if self.check_index {
            let mut walk = false;
            self.sessions
                .for_each(|key, session| walk |= wants(key, session, now, generation, dials));
            assert_eq!(
                due_session.is_some(),
                walk,
                "the index and a walk find sessions with something to do"
            );
        }
        if let Some(key) = due_session
            && let Some(result) = self.session_step(key, now, policy, entropy, out)
        {
            return result;
        }

        self.expire(now);
        self.responder.expire(now);
        match self.next_deadline() {
            Some(deadline) => Poll::Wait(deadline),
            None => Poll::Idle,
        }
    }

    fn session_step(
        &mut self,
        key: Key,
        now: Instant,
        policy: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Option<Poll<Hop>> {
        let session = self.sessions.get_mut(&key)?;
        let to = Hop::Peer {
            peer: key.0,
            last_source: direct::route_source(key.0, session, now, self.relay.is_some()),
            attempt: None,
        };
        let live = session.current.as_ref().is_some_and(|pair| pair.live(now));

        if let Some(code) = session.closing {
            let sealed = session.current.as_mut().filter(|_| live).and_then(|pair| {
                let len = transport::seal(
                    &pair.send,
                    pair.remote_index,
                    pair.next_counter,
                    inner::CLOSE,
                    &code.to_le_bytes(),
                    out,
                )
                .ok()?;
                pair.next_counter += 1;
                Some(len)
            });
            self.remove_session(key);
            return Some(match sealed {
                Some(len) => Poll::Transmit { to, len },
                None => Poll::Event(Event::Closed {
                    peer: key.0,
                    context: key.1,
                    code,
                    by_peer: false,
                }),
            });
        }

        if session.rekey {
            session.rekey = false;
            if let (true, Some(address)) = (self.dials.get(&key).is_none(), session.address) {
                let to = Hop::Peer {
                    peer: key.0,
                    last_source: direct::route_source(key.0, session, now, self.relay.is_some()),
                    attempt: Some(0),
                };
                return self
                    .start_dial(key, &address, None, true, now, policy, entropy, out)
                    .ok()
                    .map(|len| Poll::Transmit { to, len });
            }
        }

        let generation = self.own.owed_generation();
        let mut list = [0u8; crate::paths::MAX_CANDIDATES_LEN];
        let list_len = crate::paths::encode_candidates(
            self.own.list.generation,
            self.own.list.as_slice(),
            &mut list,
        )
        .unwrap_or(0);
        let session = self.sessions.get_mut(&key)?;
        // Perhaps it was this endpoint's public address that was missing: the
        // relay's report of it lost, while UDP to the relay works.
        if direct::finish_attempt(&mut session.paths, now) && self.relay_udp_proven(now) {
            self.ask_relay(now);
        }
        let session = self.sessions.get_mut(&key)?;
        if live && candidates_owed(&key, session, generation) {
            let pair = session.current.as_mut()?;
            let len = transport::seal(
                &pair.send,
                pair.remote_index,
                pair.next_counter,
                inner::CANDIDATES,
                list.get(..list_len).unwrap_or_default(),
                out,
            )
            .ok()?;
            pair.next_counter += 1;
            session.paths.sent = generation;
            session.paths.exchanged = true;
            session.confirm = false;
            session.last_sent = Some(now);
            return Some(Poll::Transmit { to, len });
        }

        if let Some(poll) = self.path_step(key, now, entropy, out) {
            return Some(poll);
        }

        let session = self.sessions.get_mut(&key)?;
        let owed = session.confirm
            || !session.queue.is_empty()
            || session
                .passive_keepalive_due()
                .is_some_and(|due| due <= now);
        if !owed {
            return None;
        }
        if !session.queue.is_empty() {
            direct::note_use(&mut session.paths, now);
        }
        let to = Hop::Peer {
            peer: key.0,
            last_source: direct::route_source(key.0, session, now, self.relay.is_some()),
            attempt: None,
        };
        let pair = session.current.as_mut().filter(|pair| pair.live(now))?;
        let (inner_type, data): (u8, &[u8]) = match session.queue.front() {
            Some(datagram) => (inner::DATAGRAM, datagram),
            None => (inner::KEEPALIVE, &[]),
        };
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
        if inner_type == inner::DATAGRAM {
            session.queue.pop();
        }
        session.confirm = false;
        session.last_sent = Some(now);
        Some(Poll::Transmit { to, len })
    }

    /// The next instant anything is due, or `None` when nothing ever is.
    fn next_deadline(&self) -> Option<Instant> {
        let mut next: Option<Instant> = self.responder.next_deadline();
        let mut consider = |at: Instant| {
            next = Some(next.map_or(at, |n| n.min(at)));
        };
        self.dials.for_each(|_, dial| {
            if let Some(due) = dial.next_due() {
                consider(due);
            }
        });
        if let Some(due) = self.sessions.next_deadline() {
            consider(due);
        }
        if let Some(due) = self.relay.as_ref().and_then(RelayClient::next_due) {
            consider(due);
        }
        if let Some(due) = self.fan_deadline() {
            consider(due);
        }
        #[cfg(any(test, feature = "testing"))]
        if self.check_index {
            let mut walk: Option<Instant> = None;
            self.sessions.for_each(|_, session| {
                if let Some(due) = session_deadline(session) {
                    walk = Some(walk.map_or(due, |w| w.min(due)));
                }
            });
            assert_eq!(
                walk,
                self.sessions.next_deadline(),
                "the index and a walk find the next deadline"
            );
        }
        next
    }

    /// Brings the index up to `now`, for the sessions touched and those whose
    /// deadline came: deletes expired key pairs. A session left without keys
    /// stays, dormant: costs no traffic and no deadline. Once the application
    /// was told it went idle, it is forgotten, unless something is in
    /// progress: a dial, a queued datagram, a close (`PROTOCOL.md §5`). The
    /// endpoint thus holds the sessions in use, whatever the peers it met.
    fn expire(&mut self, now: Instant) {
        let indices = &mut self.indices;
        let dials = &self.dials;
        let generation = self.own.owed_generation();
        self.sessions.refresh(now, |key, session| {
            for index in session.expire(now).into_iter().flatten() {
                indices.remove(&index);
            }
            look(key, session, now, generation, dials)
        });
        #[cfg(any(test, feature = "testing"))]
        if self.check_index {
            self.sessions.check(now, |key, session| {
                look(key, session, now, generation, dials)
            });
        }
    }

    /// The session for `key`, created if needed; `None` when the table is
    /// full. Nothing is evicted to make room: the sessions held are in use.
    fn session_for(&mut self, key: Key) -> Option<&mut SessionOf<C>> {
        if self.sessions.get(&key).is_none() {
            let mut session = Session::new();
            session.passive_keepalive = self.settings_of(&key.1).passive_keepalive;
            if !self.sessions.insert(key, session) {
                return None;
            }
        }
        self.sessions.get_mut(&key)
    }

    fn remove_session(&mut self, key: Key) {
        if let Some(session) = self.sessions.remove(&key) {
            for pair in [session.current.as_ref(), session.previous.as_ref()]
                .into_iter()
                .flatten()
            {
                self.indices.remove(&pair.local_index);
            }
        }
        self.remove_dial(key);
    }

    fn remove_dial(&mut self, key: Key) {
        if let Some(dial) = self.dials.remove(&key) {
            for index in dial.attempt_indices() {
                self.indices.remove(&index);
            }
            self.sessions.touch(&key);
        }
    }

    /// The head of `key`'s queue, if a dial for it should carry it, when it
    /// fits a first contact and an output of `room` bytes: in the relay
    /// context; and in a context that carries early data, when the dial
    /// starts from a send whose path takes `path_max` bytes, the first contact
    /// fitting that path too.
    fn wake_payload(&self, key: &Key, room: usize, path_max: Option<usize>) -> &[u8] {
        let room = if key.1.as_bytes() == crate::relay::CONTEXT {
            room
        } else {
            match path_max {
                Some(path) if self.settings_of(&key.1).early_data => room.min(path),
                _ => return &[],
            }
        };
        self.sessions
            .get(key)
            .and_then(|session| session.queue.front())
            .filter(|head| {
                head.len() <= crate::handshake::MAX_PAYLOAD
                    && room >= crate::handshake::FIRST_CONTACT_LEN + head.len()
            })
            .unwrap_or_default()
    }

    /// How many sessions the endpoint holds, its relay session included.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// The session the last packet handled authenticated, if it was a
    /// transport packet that opened; `None` after any other packet.
    #[must_use]
    pub const fn last_authenticated(&self) -> Option<Authenticated> {
        match self.last_opened {
            Some(((peer, context), newest)) => Some(Authenticated {
                peer,
                context,
                newest,
            }),
            None => None,
        }
    }

    /// The peer whose session a transport packet names by its receiver index,
    /// without opening it: what a relay checks before handling a packet on a
    /// link bound to another key.
    #[must_use]
    pub fn owner_of(&self, packet: &[u8]) -> Option<PeerId> {
        let header = transport::parse_header(packet).ok()?;
        match self.indices.get(&header.receiver_index).copied()? {
            Owner::Session(peer, _) | Owner::Dial(peer, _) => Some(peer),
        }
    }

    /// Whether the session with `peer` in `context` has keys.
    #[must_use]
    pub fn is_live(&self, peer: &PeerId, context: &[u8], now: Instant) -> bool {
        Context::new(context).ok().is_some_and(|context| {
            self.sessions
                .get(&(*peer, context))
                .and_then(|session| session.current.as_ref())
                .is_some_and(|pair| pair.live(now))
        })
    }

    /// The channel binding of the session with `peer` in `context`: the hash
    /// of the handshake that opened it, kept across key renewals
    /// (`PROTOCOL.md §5`). `None` without such a session, or while it
    /// has no keys.
    #[must_use]
    pub fn channel_binding(&self, peer: &PeerId, context: &[u8]) -> Option<ChannelBinding> {
        let context = Context::new(context).ok()?;
        self.sessions.get(&(*peer, context))?.binding
    }
}

/// How an opened packet arrived.
#[derive(Clone, Copy)]
struct Arrival<'s> {
    /// It confirmed a first session with the peer.
    connected: bool,
    relayed: bool,
    source: Source<'s>,
    now: Instant,
}

/// An authenticated packet of `inner_type` arrived from `source`: where the
/// session is heard from, unless the source is excluded (`path` false). Only
/// the newest packet of its key pair moves it (`newest`), as only it moves a
/// relay's address for a client: a packet that arrives after a newer one, late
/// on an old path or reordered between a relay's UDP and its TCP link, would
/// otherwise take the session back to where nothing may reach the peer any
/// more. A probe or an answer proves one way only, so it moves nothing but the
/// freshness of the direct path it came on.
///
/// The newest packet of the current key pair arriving through the relay
/// (`latest`) ends the freshness of a direct path the peer's packets came on:
/// the peer sent it after everything that came on that path, so it is
/// elsewhere, or no longer reaches this side directly, and the next packet
/// takes the relay with one probe on the path (`PROTOCOL.md §7`). The newest
/// of the previous pair does not: it is older than every packet of the current
/// one. Nor does a path the peer has not sent on yet: it may not have taken it
/// yet, and will once this side's packets arrive there.
fn heard<W, Q>(
    session: &mut Session<W, Q>,
    inner_type: u8,
    source: Source<'_>,
    path: bool,
    latest: bool,
    newest: bool,
    now: Instant,
) {
    if !path {
        return;
    }
    let probing = matches!(inner_type, inner::PROBE | inner::ANSWER);
    if !probing && newest {
        session.last_source = source.key();
    }
    if !probing
        && latest
        && matches!(source, Source::Relayed(_))
        && let Some(direct) = session.paths.direct.as_mut().filter(|d| d.carried)
    {
        direct.fresh_until = direct.fresh_until.min(now);
    }
    let Some(address) = source.key().and_then(|key| key.as_ip()) else {
        return;
    };
    let paths = &mut session.paths;
    if !paths.exchanged {
        return;
    }
    if !probing {
        paths.heard_directly(address, now);
    } else if let Some(direct) = paths.direct.as_mut().filter(|d| d.address == address) {
        direct.fresh_until = now.saturating_add(crate::paths::DIRECT_FRESH_FOR);
    }
}

/// Whether `key`'s session owes the peer this endpoint's list of
/// `generation`: never in the relay context, which is the relay's own session.
/// What the index makes of a session: forgotten when it has no keys and
/// nothing in progress after it was told idle; otherwise its next deadline,
/// and whether it may have something to do now.
fn look<W: ReplayWindow, Q: DatagramQueue>(
    key: &Key,
    session: &Session<W, Q>,
    now: Instant,
    generation: Option<u16>,
    dials: &impl Table<Key, Dial>,
) -> Look {
    if session.dormant()
        && !session.connected
        && session.queue.is_empty()
        && session.closing.is_none()
        && dials.get(key).is_none()
    {
        return Look::Forget;
    }
    Look::Keep {
        deadline: session_deadline(session),
        ready: (session.connected && session.dormant())
            || wants(key, session, now, generation, dials),
    }
}

/// Whether a session has something to send at `now`.
fn wants<W: ReplayWindow, Q: DatagramQueue>(
    key: &Key,
    session: &Session<W, Q>,
    now: Instant,
    generation: Option<u16>,
    dials: &impl Table<Key, Dial>,
) -> bool {
    let live = session.current.as_ref().is_some_and(|pair| pair.live(now));
    session.closing.is_some()
        || (live && session.confirm)
        || (live && !session.queue.is_empty())
        || (live && candidates_owed(key, session, generation))
        || (session.rekey && session.address.is_some() && dials.get(key).is_none())
        || session
            .passive_keepalive_due()
            .is_some_and(|due| due <= now)
        || direct::path_wants(session, now)
}

/// The next instant a session has anything due: its keys' expiry, its
/// passive keepalive, its path work.
fn session_deadline<W: ReplayWindow, Q: DatagramQueue>(session: &Session<W, Q>) -> Option<Instant> {
    [
        session.current.as_ref().map(KeyPair::expires_at),
        session.previous.as_ref().map(KeyPair::expires_at),
        session.passive_keepalive_due(),
        direct::path_deadline(session),
    ]
    .into_iter()
    .flatten()
    .min()
}

fn candidates_owed<W, Q>(key: &Key, session: &Session<W, Q>, generation: Option<u16>) -> bool {
    let relayed = session
        .last_source
        .is_some_and(|source| source.relayed_from().is_some());
    key.1.as_bytes() != crate::relay::CONTEXT && session.paths.owes(generation, relayed)
}

/// The code a session or pending handshake with `peer` is closed with when its
/// context's access becomes `access`, or `None` when the access admits it.
fn refused(
    access: Option<Access>,
    code: u16,
    peer: &PeerId,
    context: &[u8],
    policy: &mut impl Admission,
) -> Option<u16> {
    match access {
        None => Some(code),
        Some(Access::Bound(bound)) => (bound != *peer).then_some(code),
        Some(Access::Policy) => match policy.admit(peer, context) {
            Decision::Accept { .. } => None,
            Decision::Refuse { code, .. } => Some(code.get()),
        },
    }
}

#[cfg(test)]
mod tests;
