//! An endpoint on tokio: the [`Node`] handle, a [`Context`] handle per
//! context, and the task that owns the core.
//!
//! ```text
//!  Node (cloneable) ------ commands ----> task: Endpoint<Server>  <--- one UDP socket, both families
//!  Context per context --- commands ---->   |                     <--- the relay's TCP link
//!  application <-- node events (bounded) ---+
//!  application <-- each context's events ---+-- sleep until the core's next deadline
//! ```
//!
//! The socket is dual-stack (`[::]`, `IPV6_V6ONLY` off) unless the
//! configuration binds an IPv4 address: IPv4 peers are reached through it as
//! IPv4-mapped addresses, and reported to the core as IPv4. The relay's host
//! is resolved in both families; the interfaces' addresses are reported to the
//! core at start and on every network change.
//!
//! The task decides nothing. It hands the core every packet with where it came
//! from, sends what the core outputs on the path it names, opens and closes the
//! relay link when told, reports what happened to it, and calls the core again
//! at each deadline. It never waits on the application, and never stops reading
//! for it (`DESIGN.md §5`): a datagram for a context whose event stream is full
//! is dropped and counted; events without data wait aside, one per context,
//! peer and kind (for the node, one per kind), the latest replacing the
//! earlier, so an application that reads late sees the latest state; a
//! context's messages wait in their channel, whose window closes, so that only
//! their sender waits. In a context with per-peer delivery, datagrams and
//! messages go to a [`Receiver`] per peer instead.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant as Clock};

use convesso_core::dos::Source;
use convesso_core::endpoint::{
    Endpoint, Event, ExcludeError, HintError, KeepAliveTooShort, NoSession, Output, Poll,
    RelayError, RelayPath, SendError, Settings, Target, To,
};
use convesso_core::handshake::{self, ChannelBinding, Context as Name};
use convesso_core::handshake::{Admission, Decision, DialError, ResponderError};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::paths::{Candidate, PathInfo, PathKind};
use convesso_core::relay::Link;
use convesso_core::relay::framing::{self, Deframed, Deframer, KEEPALIVE, PREAMBLE};
use convesso_core::storage::Server;
use convesso_core::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Notify, mpsc, oneshot};

use crate::address;
use crate::entropy::{EntropyError, OsEntropy, SystemEntropy};
use crate::receiver::{ELEMENT_COST, Receiver, SessionClosed, Shared};

#[cfg(feature = "stream")]
use convesso_core::endpoint::FrameKind;
#[cfg(feature = "stream")]
use convesso_stream::config::Server as StreamServer;
#[cfg(feature = "stream")]
use convesso_stream::{Channels, Event as StreamEvent, Poll as StreamPoll};

/// The stream configuration of [`start`] and [`start_with`].
#[cfg(feature = "stream")]
type DefaultStream = StreamServer;
#[cfg(not(feature = "stream"))]
type DefaultStream = ();

/// What a task's stream configuration is: one of the stream layer's, or,
/// without the stream layer, nothing.
#[cfg(feature = "stream")]
trait Profile: convesso_stream::config::StreamConfig + 'static {}
#[cfg(feature = "stream")]
impl<T: convesso_stream::config::StreamConfig + 'static> Profile for T {}
#[cfg(not(feature = "stream"))]
trait Profile: 'static {}
#[cfg(not(feature = "stream"))]
impl<T: 'static> Profile for T {}

/// The largest datagram a direct path is given: a UDP payload that fits a
/// 1,500-byte IPv6 path.
pub const DIRECT_PATH_MAX: usize = 1452;

/// The code a context's sessions are closed with when its handle is dropped
/// without [`Context::close_context`]: the core's default code.
pub const DROPPED: u16 = 1;

/// How many rounds of ready commands and datagrams the task handles before
/// it drains the core.
const BATCH: usize = 64;

/// Where the relay is: its key, which is what is trusted, and its network
/// location, resolved at each link opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLocation {
    /// The relay's address (its key).
    pub address: Address,
    /// `host:port`, for UDP and TCP alike.
    pub host: String,
    /// Whether the TCP link is wrapped in TLS 1.3, which authenticates
    /// nothing: the certificate is not checked, and the relay's key alone is
    /// trusted (`PROTOCOL.md §6`). The host is named in the handshake when it
    /// is a name. Only with the feature `tls`; refused without it.
    pub tls: bool,
}

impl RelayLocation {
    /// Whether this build can open the link this location asks for.
    fn supported(&self) -> bool {
        !self.tls || cfg!(feature = "tls")
    }
}

/// The operating system's handle of a socket: a file descriptor on Unix and
/// Android, a `SOCKET` on Windows.
#[cfg(unix)]
pub type SocketHandle = std::os::fd::RawFd;
/// The operating system's handle of a socket: a file descriptor on Unix and
/// Android, a `SOCKET` on Windows.
#[cfg(windows)]
pub type SocketHandle = std::os::windows::io::RawSocket;

/// Called with every socket the node opens, before it is used: the UDP socket
/// before it is bound, each TCP connection to the relay before it connects.
/// On Android, it calls `VpnService.protect`, so that the node's own traffic
/// stays out of the tunnel it carries. It must not block.
pub type SocketHook = Arc<dyn Fn(SocketHandle) -> std::io::Result<()> + Send + Sync>;

/// Resolves a relay's `host:port` to its addresses, in place of the system's
/// resolver: for tests, which cannot make a name resolve late otherwise.
#[doc(hidden)]
pub type Resolver = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
        + Send
        + Sync,
>;

/// The relay's UDP addresses, as resolved: the one used, and one in the
/// other family.
type RelayAddresses = (SocketAddr, Option<SocketAddr>);

/// The first wait before resolving the relay's host again, after a failure;
/// it doubles up to [`RESOLVE_BACKOFF_CAP`].
const RESOLVE_BACKOFF_FIRST: Duration = Duration::from_secs(1);

/// The longest wait between two resolutions of the relay's host that failed:
/// at most one query a minute while packets go to a relay whose name does not
/// resolve, none at rest.
const RESOLVE_BACKOFF_CAP: Duration = Duration::from_secs(60);

/// How to start a node. It serves no context until the application opens
/// one with [`Node::context`].
pub struct Config {
    /// The local UDP address to bind: `[::]:0` by default, a dual-stack
    /// socket; an IPv4 address binds IPv4 only.
    pub bind: SocketAddr,
    /// The relay to pin, if any.
    pub relay: Option<RelayLocation>,
    /// How many of the node's own events wait for the application.
    pub events: usize,
    /// Given every socket the node opens, before it is used.
    pub socket_hook: Option<SocketHook>,
    /// How the relay's host is resolved: the system's resolver when `None`.
    #[doc(hidden)]
    pub resolver: Option<Resolver>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            relay: None,
            events: 64,
            socket_hook: None,
            resolver: None,
        }
    }
}

/// Who may reach this node in a context.
#[derive(Default)]
pub enum Access {
    /// Every peer.
    #[default]
    Everyone,
    /// The peers this policy admits, asked for each first contact.
    Admit(Box<dyn Admission + Send>),
    /// This peer alone: a first contact from any other meets silence.
    Bound(PeerId),
    /// No one: the context is not served, and only dialled in.
    DialOnly,
}

impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Everyone => f.write_str("Everyone"),
            Self::Admit(_) => f.write_str("Admit(..)"),
            Self::Bound(peer) => f.debug_tuple("Bound").field(peer).finish(),
            Self::DialOnly => f.write_str("DialOnly"),
        }
    }
}

/// How to open a context.
#[derive(Debug)]
pub struct ContextOptions {
    /// Who may reach this node in it.
    pub access: Access,
    /// Where its peers' messages and datagrams go.
    pub delivery: Delivery,
    /// How many events wait in its event stream for the application.
    pub events: usize,
    /// Its largest message, at most the stream configuration's; the
    /// configuration's when unset (feature `stream`).
    #[cfg(feature = "stream")]
    pub max_message: Option<usize>,
    /// Whether its sessions send the passive keepalive: one keepalive 10 s
    /// after data arrives, if they sent nothing since. A session can override
    /// it ([`Context::set_passive_keepalive`]). Off by default.
    pub passive_keepalive: bool,
    /// Whether it carries early data: the first datagram to a peer with no
    /// session travels in the first contact, and arrives as
    /// [`ContextEvent::EarlyDatagram`], unconfirmed. Both sides of the
    /// context must set it. Off by default.
    pub early_data: bool,
}

impl Default for ContextOptions {
    fn default() -> Self {
        Self {
            access: Access::Everyone,
            delivery: Delivery::Events,
            events: 256,
            #[cfg(feature = "stream")]
            max_message: None,
            passive_keepalive: false,
            early_data: false,
        }
    }
}

/// Where a context's peers' messages and datagrams go.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Delivery {
    /// To the context's event stream, with its other events.
    #[default]
    Events,
    /// To a [`Receiver`] per peer, opened with [`Context::receiver`], each
    /// holding at most `messages` bytes of messages and `datagrams` bytes of
    /// datagrams, every element costing its length plus
    /// [`crate::ELEMENT_COST`]. A peer's channel is granted only the free room
    /// of its receiver, so a receiver that is not read holds back its own
    /// sender alone (`DESIGN.md §8`). A datagram that does not fit, or for a
    /// peer with no receiver open, is dropped and counted in
    /// [`Stats::datagrams_dropped`].
    PerPeer {
        /// The message budget, at least the cost of the context's largest
        /// message.
        messages: usize,
        /// The datagram budget.
        datagrams: usize,
    },
}

/// Why a node did not start.
#[derive(Debug)]
pub enum StartError {
    /// The operating system's generator could not be read.
    Entropy(EntropyError),
    /// The UDP socket could not be bound.
    Bind(std::io::Error),
    /// The socket hook refused the UDP socket.
    Hook(std::io::Error),
    /// The relay asks for TLS, and this build has no feature `tls`.
    NoTls,
    /// The core refused the configuration.
    Core(ResponderError),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Entropy(error) => error.fmt(f),
            Self::Bind(error) => write!(f, "binding the UDP socket: {error}"),
            Self::Hook(error) => write!(f, "the socket hook: {error}"),
            Self::NoTls => {
                f.write_str("the relay asks for TLS, and this build has no feature `tls`")
            }
            Self::Core(error) => write!(f, "the core: {error}"),
        }
    }
}

impl std::error::Error for StartError {}

/// Why a command failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    /// The core refused it, with its named error.
    Send(SendError),
    /// The hints were refused, with the core's named error.
    Hint(HintError),
    /// The relay could not be pinned, with the core's named error.
    Relay(ResponderError),
    /// The new relay asks for TLS, and this build has no feature `tls`.
    NoTls,
    /// The prefix could not be excluded, with the core's named error.
    Exclude(ExcludeError),
    /// The context could not be opened, or its access changed, with the
    /// core's named error: open already, the relay context, or one more than
    /// the storage profile serves.
    Context(ResponderError),
    /// The context was closed.
    ContextClosed,
    /// The per-peer message budget is below the cost of the context's
    /// largest message, which could then never be delivered.
    Budget {
        /// The budget given.
        budget: usize,
        /// The cost of the largest message.
        needed: usize,
    },
    /// The node's task has ended.
    Stopped,
    /// A receiver asked for in a context that delivers to its event stream.
    NotPerPeer,
    /// A receiver asked for a peer that already has one open.
    ReceiverOpen,
    /// No session with that peer in that context.
    NoSession,
    /// The relay link's keep-alive interval was refused, with the core's
    /// named error.
    KeepAlive(KeepAliveTooShort),
    /// The stream layer refused a message, or a context's largest message,
    /// with its named error.
    #[cfg(feature = "stream")]
    Message(convesso_stream::SendError),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Send(error) => error.fmt(f),
            Self::Hint(error) => error.fmt(f),
            Self::Relay(error) => write!(f, "the relay: {error}"),
            Self::NoTls => {
                f.write_str("the relay asks for TLS, and this build has no feature `tls`")
            }
            Self::Exclude(error) => error.fmt(f),
            Self::Context(error) => write!(f, "the context: {error}"),
            Self::ContextClosed => f.write_str("the context was closed"),
            Self::Budget { budget, needed } => write!(
                f,
                "a message budget of {budget} bytes is below the {needed} a largest message costs"
            ),
            Self::Stopped => f.write_str("the node has stopped"),
            Self::NotPerPeer => {
                f.write_str("the context delivers to its event stream, not per peer")
            }
            Self::ReceiverOpen => f.write_str("the peer already has a receiver open"),
            Self::NoSession => NoSession.fmt(f),
            Self::KeepAlive(error) => error.fmt(f),
            #[cfg(feature = "stream")]
            Self::Message(error) => write!(f, "the message was refused: {error:?}"),
        }
    }
}

impl std::error::Error for NodeError {}

/// Something about the node the application should know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    /// The relay cannot reach a peer.
    PeerNotAtRelay {
        /// The peer.
        peer: PeerId,
    },
    /// The address the relay sees this node at.
    ObservedAddress {
        /// The link.
        link: Link,
        /// The address.
        address: SocketAddr,
    },
    /// The relay cannot be used: its session could not be opened, or ended,
    /// or the link to it failed. Peers cannot reach this node through it
    /// until the next relay-available event.
    RelayUnavailable {
        /// Why.
        error: RelayError,
    },
    /// The node is registered with its relay: peers reach it through it.
    RelayAvailable,
}

/// Something in a context the application should know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextEvent {
    /// A session with a peer has keys, where it had none: its first, or one
    /// after [`ContextEvent::Idle`].
    Connected {
        /// The peer.
        peer: PeerId,
    },
    /// The session with a peer has no keys left: they expired. The next
    /// datagram opens one again, with [`ContextEvent::Connected`].
    Idle {
        /// The peer.
        peer: PeerId,
    },
    /// A datagram that came in a peer's first contact, in a context that
    /// carries early data, before the session with it is confirmed. It is
    /// authenticated as the peer's, but **unconfirmed**: a replay of that
    /// first contact delivers it again, and each attempt of the peer's dial
    /// may deliver it. To the event stream whatever the context's delivery.
    EarlyDatagram {
        /// The peer.
        peer: PeerId,
        /// The data.
        data: Vec<u8>,
    },
    /// A datagram.
    Datagram {
        /// The peer.
        peer: PeerId,
        /// The data.
        data: Vec<u8>,
        /// Whether it came through the relay.
        relayed: bool,
    },
    /// A session ended.
    Closed {
        /// The peer.
        peer: PeerId,
        /// The code.
        code: u16,
        /// Whether the peer closed it.
        by_peer: bool,
    },
    /// A dial failed; what it had queued is discarded.
    ReopenFailed {
        /// The peer.
        peer: PeerId,
        /// Why.
        error: DialError,
    },
    /// The path to a peer changed: a direct path was found, or lost and the
    /// relay carries the session again.
    PathChanged {
        /// The peer.
        peer: PeerId,
        /// The new path.
        path: PathKind,
    },
    /// A reliable message, whole and in order (feature `stream`).
    #[cfg(feature = "stream")]
    Message {
        /// The peer.
        peer: PeerId,
        /// The message.
        data: Vec<u8>,
    },
    /// The message channel with a peer was reset: what it held is gone, both
    /// ways (feature `stream`).
    #[cfg(feature = "stream")]
    ChannelReset {
        /// The peer.
        peer: PeerId,
        /// Why.
        reason: convesso_stream::Reason,
    },
}

/// What the node's sockets carried, counted where they are written and read.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// UDP datagrams sent.
    pub udp_sent: u64,
    /// Bytes of them.
    pub udp_sent_bytes: u64,
    /// UDP datagrams received.
    pub udp_received: u64,
    /// Bytes of them.
    pub udp_received_bytes: u64,
    /// Packets framed onto the relay link.
    pub frames_sent: u64,
    /// Bytes on the link, framing and keep-alives included, preambles excluded.
    pub link_sent_bytes: u64,
    /// Packets read from the relay link.
    pub frames_received: u64,
    /// Bytes read from the link, framing and keep-alives included.
    pub link_received_bytes: u64,
    /// Keep-alives written on the link.
    pub keepalives_sent: u64,
    /// Keep-alives read from the link.
    pub keepalives_received: u64,
    /// Relay links opened.
    pub links_opened: u64,
    /// Packets the core asked to send, counted once per path it named: what
    /// the sockets' counts are checked against.
    pub core_udp_outputs: u64,
    /// Packets and keep-alives the core asked to put on the link.
    pub core_link_outputs: u64,
    /// Stream frames the message channels sent through the core (feature
    /// `stream`).
    #[cfg(feature = "stream")]
    pub stream_frames_sent: u64,
    /// Datagrams dropped: for a context whose event stream had no room, or,
    /// with per-peer delivery, for a peer with no receiver open or beyond its
    /// receiver's budget.
    pub datagrams_dropped: u64,
}

/// A context, opened: what the task needs to open it.
struct Opening {
    name: Vec<u8>,
    access: Access,
    delivery: Delivery,
    events: mpsc::Sender<ContextEvent>,
    #[cfg(feature = "stream")]
    max_message: Option<usize>,
    settings: Settings,
}

enum Command {
    Open(Opening, oneshot::Sender<Result<(), NodeError>>),
    SetAccess(Name, Access, u16, oneshot::Sender<Result<(), NodeError>>),
    Send(
        Name,
        Address,
        Vec<u8>,
        oneshot::Sender<Result<(), NodeError>>,
    ),
    SendToPeer(
        Name,
        PeerId,
        Vec<u8>,
        oneshot::Sender<Result<(), NodeError>>,
    ),
    Hint(
        PeerId,
        Vec<SocketAddr>,
        oneshot::Sender<Result<(), NodeError>>,
    ),
    Relay(Option<Resolved>, oneshot::Sender<Result<(), NodeError>>),
    Reachable(bool),
    Close(Name, PeerId, u16),
    ClosePeer(PeerId, u16),
    NetworkChanged,
    Stats(oneshot::Sender<Stats>),
    Path(Name, PeerId, oneshot::Sender<Option<PathInfo>>),
    Candidates(oneshot::Sender<Vec<Candidate>>),
    Exclude(
        Vec<(IpAddr, u8)>,
        bool,
        oneshot::Sender<Result<(), NodeError>>,
    ),
    Binding(Name, PeerId, oneshot::Sender<Option<ChannelBinding>>),
    RelayUdpProven(oneshot::Sender<bool>),
    Receiver(Name, PeerId, oneshot::Sender<Result<Receiver, NodeError>>),
    #[cfg(feature = "stream")]
    SendMessage(Parked),
    Connect(Name, Address, oneshot::Sender<Result<(), NodeError>>),
    IsLive(Name, PeerId, oneshot::Sender<bool>),
    PeerCandidates(Name, PeerId, oneshot::Sender<Vec<Candidate>>),
    PassiveKeepalive(Name, PeerId, bool, oneshot::Sender<Result<(), NodeError>>),
    RelayKeepalive(Duration, oneshot::Sender<Result<(), NodeError>>),
    PinnedRelay(oneshot::Sender<Option<RelayLocation>>),
}

/// A relay and the UDP addresses its host resolved to, if it did.
type Resolved = (RelayLocation, Option<RelayAddresses>);

/// Wakes the task when the application reads an event stream while something
/// waits for room in one.
#[derive(Default)]
struct Room {
    notify: Notify,
    waiting: AtomicBool,
}

impl Room {
    fn read(&self) {
        if self.waiting.load(Ordering::Acquire) {
            self.notify.notify_one();
        }
    }
}

/// A handle on a running node. Cloneable; the node stops when every handle,
/// every [`Context`], and the [`Events`] are dropped.
#[derive(Clone)]
pub struct Node {
    commands: mpsc::Sender<Command>,
    closes: mpsc::UnboundedSender<(Name, u16)>,
    room: Arc<Room>,
    local: SocketAddr,
    address: Address,
    dual_stack: bool,
    resolver: Option<Resolver>,
}

/// The node's own events, in order.
pub struct Events {
    events: mpsc::Receiver<NodeEvent>,
    room: Arc<Room>,
}

impl Events {
    /// The next event, or `None` once the node has stopped.
    pub async fn next(&mut self) -> Option<NodeEvent> {
        let event = self.events.recv().await;
        self.room.read();
        event
    }
}

/// A context's events, in order.
pub struct ContextEvents {
    events: mpsc::Receiver<ContextEvent>,
    room: Arc<Room>,
}

impl ContextEvents {
    /// The next event, or `None` once the context is closed or the node has
    /// stopped.
    pub async fn next(&mut self) -> Option<ContextEvent> {
        let event = self.events.recv().await;
        self.room.read();
        event
    }
}

impl Node {
    /// This node's address, which peers send to.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The local address of its UDP socket.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Whether its one socket carries both families. A node bound to an IPv4
    /// address, or on a system without IPv6, carries IPv4 only.
    #[must_use]
    pub const fn dual_stack(&self) -> bool {
        self.dual_stack
    }

    /// Opens the context `name` while the node runs: serves it under the
    /// options' access, and returns its handle and its event stream. The
    /// context lives as long as the handle: dropping every clone of it closes
    /// the context.
    ///
    /// # Errors
    ///
    /// [`NodeError::Context`] with the core's error for a name already open,
    /// the relay context, or one context more than the storage profile
    /// serves; [`NodeError::Budget`] for a per-peer message budget below the
    /// cost of the context's largest message; `NodeError::Message` (feature
    /// `stream`) for a largest message over the stream configuration's; or
    /// [`NodeError::Stopped`]. The context is then not open.
    pub async fn context(
        &self,
        name: &[u8],
        options: ContextOptions,
    ) -> Result<(Context, ContextEvents), NodeError> {
        let context = Name::new(name)
            .map_err(|error| NodeError::Context(ResponderError::ContextTooLong(error)))?;
        let (events_tx, events) = mpsc::channel(options.events.max(1));
        let opening = Opening {
            name: name.to_vec(),
            access: options.access,
            delivery: options.delivery,
            events: events_tx,
            #[cfg(feature = "stream")]
            max_message: options.max_message,
            settings: Settings {
                passive_keepalive: options.passive_keepalive,
                early_data: options.early_data,
            },
        };
        self.answer(|reply| Command::Open(opening, reply)).await?;
        Ok((
            Context {
                handle: Arc::new(Handle {
                    commands: self.commands.clone(),
                    closes: self.closes.clone(),
                    context,
                    closed: AtomicBool::new(false),
                }),
            },
            ContextEvents {
                events,
                room: self.room.clone(),
            },
        ))
    }

    /// Whether UDP to the relay is proven now; otherwise the relay is reached
    /// over its TCP link, if at all.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn relay_udp_proven(&self) -> Result<bool, NodeError> {
        let (reply, answer) = oneshot::channel();
        ask(&self.commands, Command::RelayUdpProven(reply)).await?;
        answer.await.map_err(|_| NodeError::Stopped)
    }

    /// This node's candidates, as peers are told them, in order
    /// (`PROTOCOL.md §7`).
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn candidates(&self) -> Result<Vec<Candidate>, NodeError> {
        let (reply, answer) = oneshot::channel();
        ask(&self.commands, Command::Candidates(reply)).await?;
        answer.await.map_err(|_| NodeError::Stopped)
    }

    /// Excludes the IP prefix `ip/len` from direct paths: no address in it is
    /// a candidate, probed, or a path. An overlay excludes its own tunnels'
    /// prefixes.
    ///
    /// # Errors
    ///
    /// [`NodeError::Exclude`] with the core's error, or [`NodeError::Stopped`].
    pub async fn exclude_prefix(&self, ip: IpAddr, len: u8) -> Result<(), NodeError> {
        self.answer(|reply| Command::Exclude(vec![(ip, len)], false, reply))
            .await
    }

    /// Replaces every excluded prefix with `prefixes`: one no longer excluded
    /// is allowed again, its interfaces candidates again.
    ///
    /// # Errors
    ///
    /// As [`Self::exclude_prefix`]; a set refused leaves the old one.
    pub async fn set_excluded(&self, prefixes: Vec<(IpAddr, u8)>) -> Result<(), NodeError> {
        self.answer(|reply| Command::Exclude(prefixes, true, reply))
            .await
    }

    async fn answer(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<(), NodeError>>) -> Command,
    ) -> Result<(), NodeError> {
        answer(&self.commands, make).await
    }

    /// Gives the core a direct address for `peer`, in every context: as
    /// [`Self::set_hints`] with one address.
    ///
    /// # Errors
    ///
    /// As [`Self::set_hints`].
    pub async fn set_hint(&self, peer: PeerId, at: SocketAddr) -> Result<(), NodeError> {
        self.set_hints(peer, vec![at]).await
    }

    /// Gives the core up to [`MAX_HINTS`] direct addresses for `peer`, in
    /// every context, replacing those it had; none forgets them. A dial's
    /// first attempt goes to every one at once (`PROTOCOL.md §6`).
    ///
    /// # Errors
    ///
    /// [`NodeError::Hint`] with the core's error for more than [`MAX_HINTS`]
    /// or more than the hint table holds, which leaves the old hints; or
    /// [`NodeError::Stopped`].
    ///
    /// [`MAX_HINTS`]: convesso_core::endpoint::MAX_HINTS
    pub async fn set_hints(&self, peer: PeerId, at: Vec<SocketAddr>) -> Result<(), NodeError> {
        self.answer(|reply| Command::Hint(peer, at, reply)).await
    }

    /// Replaces the pinned relay with `relay`, or, with `None`, removes it,
    /// without restarting the node (`PROTOCOL.md §6`). The new host is
    /// resolved here, in the caller's task. Sessions with peers and contexts
    /// stay; the old relay's link is closed, and a reachable node registers on
    /// the new relay at once. The relay already pinned changes nothing.
    ///
    /// # Errors
    ///
    /// [`NodeError::NoTls`] for TLS asked for without the feature,
    /// [`NodeError::Relay`] with the core's error, or [`NodeError::Stopped`];
    /// the old relay then stays. A host that does not resolve yet is no
    /// error: it is resolved again when the relay is needed.
    pub async fn set_relay(&self, relay: Option<RelayLocation>) -> Result<(), NodeError> {
        let resolved = match relay {
            Some(relay) if !relay.supported() => return Err(NodeError::NoTls),
            Some(relay) => {
                let addresses = resolve(self.resolver.as_ref(), &relay.host, self.dual_stack)
                    .await
                    .ok();
                Some((relay, addresses))
            }
            None => None,
        };
        self.answer(|reply| Command::Relay(resolved, reply)).await
    }

    /// Asks to stay reachable through the relay, keeping a link to it, or not.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn set_reachable(&self, reachable: bool) -> Result<(), NodeError> {
        ask(&self.commands, Command::Reachable(reachable)).await
    }

    /// Revokes `peer`: closes every session with it, in every context.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn close_peer(&self, peer: PeerId, code: u16) -> Result<(), NodeError> {
        ask(&self.commands, Command::ClosePeer(peer, code)).await
    }

    /// The pinned relay, as the node was last given it; `None` without one.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn relay(&self) -> Result<Option<RelayLocation>, NodeError> {
        let (reply, answer) = oneshot::channel();
        ask(&self.commands, Command::PinnedRelay(reply)).await?;
        answer.await.map_err(|_| NodeError::Stopped)
    }

    /// Sets how long the relay link may stay silent before a keep-alive: 60
    /// seconds by default, never less.
    ///
    /// # Errors
    ///
    /// [`NodeError::KeepAlive`] below a minute, the interval unchanged; or
    /// [`NodeError::Stopped`].
    pub async fn set_relay_keepalive(&self, interval: Duration) -> Result<(), NodeError> {
        let (reply, answer) = oneshot::channel();
        ask(&self.commands, Command::RelayKeepalive(interval, reply)).await?;
        answer.await.map_err(|_| NodeError::Stopped)?
    }

    /// Tells the core the network changed: a reachable node replaces its
    /// relay link at once.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn network_changed(&self) -> Result<(), NodeError> {
        ask(&self.commands, Command::NetworkChanged).await
    }

    /// What the node's sockets have carried so far.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn stats(&self) -> Result<Stats, NodeError> {
        let (reply, answer) = oneshot::channel();
        ask(&self.commands, Command::Stats(reply)).await?;
        answer.await.map_err(|_| NodeError::Stopped)
    }
}

async fn ask(commands: &mpsc::Sender<Command>, command: Command) -> Result<(), NodeError> {
    commands.send(command).await.map_err(|_| NodeError::Stopped)
}

async fn answer(
    commands: &mpsc::Sender<Command>,
    make: impl FnOnce(oneshot::Sender<Result<(), NodeError>>) -> Command,
) -> Result<(), NodeError> {
    let (reply, answer) = oneshot::channel();
    ask(commands, make(reply)).await?;
    answer.await.map_err(|_| NodeError::Stopped)?
}

/// What every clone of a [`Context`] shares: dropping the last closes the
/// context.
struct Handle {
    commands: mpsc::Sender<Command>,
    closes: mpsc::UnboundedSender<(Name, u16)>,
    context: Name,
    closed: AtomicBool,
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Acquire) {
            let _ = self.closes.send((self.context, DROPPED));
        }
    }
}

/// A handle on one context of a node: every operation acts in it, and its
/// [`ContextEvents`] carry its events alone. Cloneable; the context is closed
/// when every clone is dropped, or by [`Self::close_context`].
#[derive(Clone)]
pub struct Context {
    handle: Arc<Handle>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("name", &self.handle.context)
            .finish()
    }
}

impl Context {
    /// The context's name.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        self.handle.context.as_bytes()
    }

    fn name_of(&self) -> Name {
        self.handle.context
    }

    async fn ask(&self, command: Command) -> Result<(), NodeError> {
        ask(&self.handle.commands, command).await
    }

    async fn answer(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<(), NodeError>>) -> Command,
    ) -> Result<(), NodeError> {
        answer(&self.handle.commands, make).await
    }

    /// Changes who may reach this node in the context. The sessions this side
    /// accepted that the new access would not admit are closed: with a
    /// policy's refusal code when it is a policy that refuses, with `code`
    /// otherwise; and so are the pending handshakes. Sessions this side
    /// dialled go on.
    ///
    /// # Errors
    ///
    /// [`NodeError::Context`] with the core's error when a dial-only context
    /// cannot be served, [`NodeError::ContextClosed`], or
    /// [`NodeError::Stopped`].
    pub async fn set_access(&self, access: Access, code: u16) -> Result<(), NodeError> {
        let context = self.name_of();
        self.answer(|reply| Command::SetAccess(context, access, code, reply))
            .await
    }

    /// Closes the context: its sessions closed with `code`, its dials and
    /// pending handshakes discarded, its slot freed. Every clone of the handle
    /// then refers to a closed context.
    pub fn close_context(self, code: u16) {
        if !self.handle.closed.swap(true, Ordering::AcqRel) {
            let _ = self.handle.closes.send((self.handle.context, code));
        }
    }

    /// Sends a datagram to the peer at `to`: through its session, or a new
    /// one, by the path the core chooses.
    ///
    /// # Errors
    ///
    /// The core's [`SendError`], [`NodeError::ContextClosed`], or
    /// [`NodeError::Stopped`].
    pub async fn send(&self, to: Address, data: Vec<u8>) -> Result<(), NodeError> {
        let context = self.name_of();
        self.answer(|reply| Command::Send(context, to, data, reply))
            .await
    }

    /// Sends a datagram to a peer by its identity: only while a session with
    /// it has keys, or its handshake is pending here.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    pub async fn send_to_peer(&self, to: PeerId, data: Vec<u8>) -> Result<(), NodeError> {
        let context = self.name_of();
        self.answer(|reply| Command::SendToPeer(context, to, data, reply))
            .await
    }

    /// Closes the session with `peer`, with `code`.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn close(&self, peer: PeerId, code: u16) -> Result<(), NodeError> {
        self.ask(Command::Close(self.name_of(), peer, code)).await
    }

    /// Opens a session with the peer at `to` without sending data: the
    /// handshake's confirmation is a keepalive. Nothing is done for a session
    /// with keys or one opening.
    ///
    /// # Errors
    ///
    /// [`NodeError::Send`] with the core's error; [`NodeError::ContextClosed`];
    /// or [`NodeError::Stopped`].
    pub async fn connect(&self, to: Address) -> Result<(), NodeError> {
        let context = self.name_of();
        self.answer(|reply| Command::Connect(context, to, reply))
            .await
    }

    /// Whether the session with `peer` has keys now.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn is_live(&self, peer: PeerId) -> Result<bool, NodeError> {
        let (reply, answer) = oneshot::channel();
        self.ask(Command::IsLive(self.name_of(), peer, reply))
            .await?;
        answer.await.map_err(|_| NodeError::Stopped)
    }

    /// The candidates `peer` announced in its session (`PROTOCOL.md §7`);
    /// none without a session with keys.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn peer_candidates(&self, peer: PeerId) -> Result<Vec<Candidate>, NodeError> {
        let (reply, answer) = oneshot::channel();
        self.ask(Command::PeerCandidates(self.name_of(), peer, reply))
            .await?;
        answer.await.map_err(|_| NodeError::Stopped)
    }

    /// Turns the passive keepalive on or off for the session with `peer`, in
    /// place of the context's default, for that session's life.
    ///
    /// # Errors
    ///
    /// [`NodeError::NoSession`] without a session with `peer`; or
    /// [`NodeError::Stopped`].
    pub async fn set_passive_keepalive(&self, peer: PeerId, on: bool) -> Result<(), NodeError> {
        let context = self.name_of();
        self.answer(|reply| Command::PassiveKeepalive(context, peer, on, reply))
            .await
    }

    /// The path to `peer`, and how it got there; `None` without a session.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn path(&self, peer: PeerId) -> Result<Option<PathInfo>, NodeError> {
        let (reply, answer) = oneshot::channel();
        self.ask(Command::Path(self.name_of(), peer, reply)).await?;
        answer.await.map_err(|_| NodeError::Stopped)
    }

    /// The channel binding of the session with `peer`: the hash of the
    /// handshake that opened it, the same at both ends and kept across key
    /// renewals (`PROTOCOL.md §5`). `None` without a session with
    /// keys.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn channel_binding(&self, peer: PeerId) -> Result<Option<[u8; 32]>, NodeError> {
        let (reply, answer) = oneshot::channel();
        self.ask(Command::Binding(self.name_of(), peer, reply))
            .await?;
        answer.await.map_err(|_| NodeError::Stopped)
    }

    /// Sends a reliable message to the peer at `to` (feature `stream`): it
    /// arrives whole, once and in order, or the channel is reset. Waits while
    /// the channel's send buffer is full.
    ///
    /// # Errors
    ///
    /// [`NodeError::Message`] for a message that can never be sent, larger
    /// than the context's largest message included; [`NodeError::ContextClosed`];
    /// or [`NodeError::Stopped`].
    #[cfg(feature = "stream")]
    pub async fn send_message(&self, to: Address, data: Vec<u8>) -> Result<(), NodeError> {
        let context = self.name_of();
        self.answer(|reply| {
            Command::SendMessage(Parked {
                context,
                peer: to.peer_id(),
                address: Some(to),
                data,
                reply,
            })
        })
        .await
    }

    /// Sends a reliable message to a peer by its identity (feature `stream`):
    /// without its address, a dormant session waits for the peer to reopen it.
    ///
    /// # Errors
    ///
    /// As [`Self::send_message`].
    #[cfg(feature = "stream")]
    pub async fn send_message_to_peer(&self, to: PeerId, data: Vec<u8>) -> Result<(), NodeError> {
        let context = self.name_of();
        self.answer(|reply| {
            Command::SendMessage(Parked {
                context,
                peer: to,
                address: None,
                data,
                reply,
            })
        })
        .await
    }

    /// Opens the receiver of `peer`'s messages and datagrams in this context,
    /// whose delivery is per peer; before its session exists, too. Open it
    /// when the peer connects: until then its messages wait in its channel,
    /// and its datagrams are dropped.
    ///
    /// # Errors
    ///
    /// [`NodeError::NotPerPeer`] in a context that delivers to its event
    /// stream, [`NodeError::ReceiverOpen`] while the peer has one open,
    /// [`NodeError::ContextClosed`], or [`NodeError::Stopped`].
    pub async fn receiver(&self, peer: PeerId) -> Result<Receiver, NodeError> {
        let (reply, answer) = oneshot::channel();
        self.ask(Command::Receiver(self.name_of(), peer, reply))
            .await?;
        answer.await.map_err(|_| NodeError::Stopped)?
    }
}

/// Starts a node for `identity`, with entropy from the operating system. It
/// serves no context until the application opens one with [`Node::context`].
///
/// # Errors
///
/// A [`StartError`].
pub async fn start(identity: Identity, config: Config) -> Result<(Node, Events), StartError> {
    start_with(identity, config, OsEntropy).await
}

/// Starts a node with the given entropy source, which is checked first.
///
/// # Errors
///
/// A [`StartError`]: [`StartError::Entropy`] before anything else is done.
pub async fn start_with<E: SystemEntropy>(
    identity: Identity,
    config: Config,
    entropy: E,
) -> Result<(Node, Events), StartError> {
    let (task, node, events) = build::<E, DefaultStream>(identity, config, entropy).await?;
    tokio::spawn(task.run());
    Ok((node, events))
}

/// Starts a node whose message channels use the stream configuration `C`
/// (feature `stream`): its largest message, every context's at most that, and
/// its buffers. [`start`] and [`start_with`] use
/// [`convesso_stream::config::Server`]. A peer refuses a message larger than
/// the largest it advertised, so peers that exchange such messages use
/// configurations that accept them.
///
/// # Errors
///
/// As [`start_with`].
#[cfg(feature = "stream")]
pub async fn start_with_stream<C, E>(
    identity: Identity,
    config: Config,
    entropy: E,
) -> Result<(Node, Events), StartError>
where
    C: convesso_stream::config::StreamConfig + 'static,
    Channels<C>: Send,
    E: SystemEntropy,
{
    let (task, node, events) = build::<E, C>(identity, config, entropy).await?;
    tokio::spawn(task.run());
    Ok((node, events))
}

/// The task of a node, not yet running, and its handles: spawned by the
/// caller, which knows the task can be sent to another thread.
async fn build<E: SystemEntropy, C: Profile>(
    identity: Identity,
    mut config: Config,
    mut entropy: E,
) -> Result<(Task<E, C>, Node, Events), StartError> {
    entropy.check().map_err(StartError::Entropy)?;
    let address = *identity.address();
    let mut endpoint = Endpoint::<Server>::new(identity, &[]).map_err(StartError::Core)?;
    let clock = Clock::now();
    let hook = config.socket_hook.take();
    let (udp, dual_stack) =
        bind_udp(config.bind, hook.as_ref()).map_err(|failure| match failure {
            Failure::Hook(error) => StartError::Hook(error),
            Failure::Socket(error) => StartError::Bind(error),
        })?;
    let local = udp.local_addr().map_err(StartError::Bind)?;
    let relay_udp = match &config.relay {
        Some(relay) if !relay.supported() => return Err(StartError::NoTls),
        Some(relay) => {
            endpoint
                .pin_relay(relay.address, Instant::from_millis(0))
                .map_err(StartError::Core)?;
            // A host that does not resolve yet is resolved again when the
            // relay is needed: the node runs meanwhile, on its other paths.
            resolve(config.resolver.as_ref(), &relay.host, dual_stack)
                .await
                .ok()
        }
        None => None,
    };
    endpoint.set_local_addresses(&local_addresses(local, dual_stack));
    if let Some((primary, other)) = relay_udp {
        endpoint.set_relay_families(primary.is_ipv6(), other.is_some());
    }
    let (commands_tx, commands) = mpsc::channel(64);
    let (closes_tx, closes) = mpsc::unbounded_channel();
    let (events_tx, events) = mpsc::channel(config.events.max(1));
    let room = Arc::new(Room::default());
    let task = Task {
        endpoint,
        policies: Policies(HashMap::new()),
        contexts: HashMap::new(),
        entropy,
        udp,
        dual_stack,
        relay: config.relay.take(),
        relay_udp: relay_udp.map(|(primary, _)| primary),
        relay_other: relay_udp.and_then(|(_, other)| other),
        last_from: None,
        link: None,
        connecting: None,
        resolver: config.resolver.clone(),
        resolving: None,
        resolve_backoff: RESOLVE_BACKOFF_FIRST,
        resolve_not_before: None,
        events: events_tx,
        held: VecDeque::new(),
        room: room.clone(),
        commands,
        closes,
        stats: Stats::default(),
        clock,
        rx: vec![0; 2048],
        out: vec![0; 2048],
        link_rx: vec![0; 4096],
        hook,
        receivers_wake: Arc::new(Notify::new()),
        #[cfg(feature = "stream")]
        channels: Box::new(Channels::<C>::new()),
        #[cfg(feature = "stream")]
        frame: vec![0; convesso_stream::frame::MAX_DATA_LEN],
        #[cfg(feature = "stream")]
        parked: Vec::new(),
        #[cfg(not(feature = "stream"))]
        stream: std::marker::PhantomData,
    };
    Ok((
        task,
        Node {
            commands: commands_tx,
            closes: closes_tx,
            room: room.clone(),
            local,
            address,
            dual_stack,
            resolver: config.resolver.take(),
        },
        Events { events, room },
    ))
}

/// Why a socket was not opened.
enum Failure {
    /// The application's hook refused it.
    Hook(std::io::Error),
    /// The system did.
    Socket(std::io::Error),
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::Socket(error)
    }
}

/// Hands a socket to the application's hook, if any.
fn hand(hook: Option<&SocketHook>, handle: SocketHandle) -> std::io::Result<()> {
    hook.map_or(Ok(()), |hook| hook(handle))
}

/// The operating system's handle of `socket`.
#[cfg(unix)]
fn handle_of(socket: &impl std::os::fd::AsRawFd) -> SocketHandle {
    socket.as_raw_fd()
}

/// The operating system's handle of `socket`.
#[cfg(windows)]
fn handle_of(socket: &impl std::os::windows::io::AsRawSocket) -> SocketHandle {
    socket.as_raw_socket()
}

/// Binds the node's UDP socket: dual-stack for an unspecified IPv6 address,
/// falling back to IPv4 where the system has no IPv6; as asked otherwise. The
/// hook has it before it is bound. Returns it and whether it carries both
/// families.
fn bind_udp(bind: SocketAddr, hook: Option<&SocketHook>) -> Result<(UdpSocket, bool), Failure> {
    let open = |bind: SocketAddr, dual: bool| -> Result<UdpSocket, Failure> {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(bind),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        if dual {
            socket.set_only_v6(false)?;
        }
        socket.set_nonblocking(true)?;
        hand(hook, handle_of(&socket)).map_err(Failure::Hook)?;
        socket.bind(&bind.into())?;
        widen(&socket2::SockRef::from(&socket));
        Ok(UdpSocket::from_std(socket.into())?)
    };
    match bind.ip() {
        IpAddr::V6(ip) if ip.is_unspecified() => match open(bind, true) {
            Ok(socket) => Ok((socket, true)),
            Err(Failure::Hook(error)) => Err(Failure::Hook(error)),
            Err(Failure::Socket(_)) => Ok((
                open(SocketAddr::from(([0, 0, 0, 0], bind.port())), false)?,
                false,
            )),
        },
        _ => Ok((open(bind, false)?, false)),
    }
}

/// Asks the system for socket buffers that hold a burst of a window of
/// messages: the defaults (64 KiB on Windows) drop a burst the protocol then
/// has to recover by timeout. The system may grant less; that is not an error.
fn widen(socket: &socket2::SockRef<'_>) {
    let _ = socket.set_recv_buffer_size(UDP_RECV_BUFFER);
    let _ = socket.set_send_buffer_size(UDP_SEND_BUFFER);
}

/// The UDP receive buffer the node asks for.
const UDP_RECV_BUFFER: usize = 2 << 20;

/// The UDP send buffer the node asks for.
const UDP_SEND_BUFFER: usize = 1 << 20;

/// The relay's UDP addresses: the first the system resolves, which the node
/// uses, and the first in the other family, if the socket can reach it.
async fn resolve(
    resolver: Option<&Resolver>,
    host: &str,
    dual_stack: bool,
) -> std::io::Result<RelayAddresses> {
    let addresses: Vec<SocketAddr> = match resolver {
        Some(resolver) => resolver(host.to_owned()).await?,
        None => tokio::net::lookup_host(host).await?.collect(),
    };
    pick(&addresses, dual_stack)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address for the host"))
}

/// Of the addresses a host resolved to, in the system's order: the first the
/// socket can reach, and the first in the other family, if it can reach that.
fn pick(addresses: &[SocketAddr], dual_stack: bool) -> Option<(SocketAddr, Option<SocketAddr>)> {
    let mut usable = addresses
        .iter()
        .map(|address| canonical(*address))
        .filter(|address| dual_stack || address.is_ipv4());
    let primary = usable.next()?;
    let other = usable.find(|address| address.is_ipv4() != primary.is_ipv4());
    Some((primary, other))
}

/// An IPv4-mapped IPv6 address as the IPv4 address it is.
fn canonical(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(address, |v4| {
            SocketAddr::new(IpAddr::V4(v4), address.port())
        }),
        IpAddr::V4(_) => address,
    }
}

/// Where the socket bound at `local` can be reached: every interface's
/// address for a socket bound to all of them; the one it is bound to
/// otherwise, since it is reached nowhere else.
fn local_addresses(local: SocketAddr, dual_stack: bool) -> Vec<SocketAddr> {
    if local.ip().is_unspecified() {
        interface_addresses(local.port(), dual_stack)
    } else {
        vec![canonical(local)]
    }
}

/// The addresses of the system's interfaces, but loopback, with the socket's
/// port: IPv6 ones only on a dual-stack socket. Nothing else is filtered; the
/// core decides which become candidates (`DESIGN.md §5`).
pub(crate) fn interface_addresses(port: u16, dual_stack: bool) -> Vec<SocketAddr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|interface| !interface.is_loopback())
        .map(|interface| SocketAddr::new(interface.ip(), port))
        .filter(|address| dual_stack || address.is_ipv4())
        .collect()
}

/// The core's one admission: each context's question goes to that context's
/// policy; a context without one admits everyone (its access may still bind
/// it to one peer, which the core checks first).
struct Policies(HashMap<Name, Box<dyn Admission + Send>>);

impl Policies {
    fn of(&mut self, context: &[u8]) -> Option<&mut Box<dyn Admission + Send>> {
        let context = Name::new(context).ok()?;
        self.0.get_mut(&context)
    }
}

impl Admission for Policies {
    fn admit(&mut self, peer: &PeerId, context: &[u8]) -> Decision {
        match self.of(context) {
            Some(policy) => policy.admit(peer, context),
            None => Decision::Accept { psk: None },
        }
    }

    fn psk(&mut self, peer: &PeerId, context: &[u8]) -> Option<convesso_core::handshake::Psk> {
        self.of(context)
            .and_then(|policy| policy.psk(peer, context))
    }
}

/// An open context, as the task keeps it.
struct Open {
    events: mpsc::Sender<ContextEvent>,
    /// Events without data waiting for room in `events`, in order; those of
    /// a peer and kind coalesced, the latest replacing the earlier.
    held: VecDeque<(Held, ContextEvent)>,
    delivery: Delivery,
    /// The open receivers, with per-peer delivery.
    receivers: HashMap<PeerId, Arc<Shared>>,
    /// Whether its messages wait in the channels for room in `events`.
    blocked: bool,
}

impl Open {
    /// Whether a message may be handed to the application now: with per-peer
    /// delivery, always (the receiver's credit bounds it); otherwise while
    /// the event stream has room and nothing waits aside before it.
    #[cfg(feature = "stream")]
    fn can_deliver(&self) -> bool {
        match self.delivery {
            Delivery::Events => self.held.is_empty() && self.events.capacity() > 0,
            Delivery::PerPeer { .. } => true,
        }
    }

    /// Hands an event to the application without ever waiting for it: into
    /// the event stream, or aside while it is full. A datagram that finds no
    /// room is dropped; returns whether it was.
    fn emit(&mut self, event: ContextEvent) -> bool {
        self.flush();
        let event = if self.held.is_empty() {
            match self.events.try_send(event) {
                Ok(()) | Err(TrySendError::Closed(_)) => return false,
                Err(TrySendError::Full(event)) => event,
            }
        } else {
            event
        };
        let Some(key) = held_key(&event) else {
            return true;
        };
        self.held.retain(|(k, _)| *k != key);
        self.held.push_back((key, event));
        false
    }

    /// Moves what waits aside into the event stream, in order, as far as
    /// there is room.
    fn flush(&mut self) {
        while let Some((key, event)) = self.held.pop_front() {
            match self.events.try_send(event) {
                Ok(()) | Err(TrySendError::Closed(_)) => {}
                Err(TrySendError::Full(event)) => {
                    self.held.push_front((key, event));
                    return;
                }
            }
        }
    }

    /// Whether something waits for room.
    fn waiting(&self) -> bool {
        self.blocked || !self.held.is_empty()
    }

    /// Whether something waits for room that there is room for now.
    fn ready(&self) -> bool {
        self.waiting() && self.events.capacity() > 0
    }
}

struct LinkIo {
    stream: Box<dyn LinkStream>,
    deframer: Box<Deframer>,
}

/// A relay link's stream: TCP, or TLS over TCP.
trait LinkStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> LinkStream for S {}

/// A link connected: its stream, the relay's address it reached, and the
/// relay's address in the other family.
type Linked = (Box<dyn LinkStream>, SocketAddr, Option<SocketAddr>);

type Connecting = Pin<Box<dyn Future<Output = std::io::Result<Linked>> + Send>>;

/// An output of the core, owning nothing, so that the task is free again.
enum Owned {
    Transmit {
        to: To,
        len: usize,
    },
    /// An event of the node's.
    Node(NodeEvent),
    /// An event in a context.
    Context(Name, ContextEvent),
    /// A datagram, with whether it also confirmed a first session: with
    /// per-peer delivery, the connection is told on the event stream apart.
    Datagram {
        context: Name,
        peer: PeerId,
        data: Vec<u8>,
        relayed: bool,
        connected: bool,
    },
    /// A stream frame, for the channels.
    #[cfg(feature = "stream")]
    Frame {
        peer: PeerId,
        context: Name,
        kind: FrameKind,
        data: Vec<u8>,
        connected: bool,
    },
    Nothing,
}

fn own(output: Output<'_>) -> Owned {
    match output {
        Output::Transmit { to, len } => Owned::Transmit { to, len },
        Output::Event(event) => owned_event(event),
        Output::Nothing => Owned::Nothing,
    }
}

/// A core event, as the task keeps it.
fn owned_event(event: Event<'_>) -> Owned {
    match event {
        Event::Connected { peer, context } => {
            Owned::Context(context, ContextEvent::Connected { peer })
        }
        Event::Idle { peer, context } => Owned::Context(context, ContextEvent::Idle { peer }),
        Event::Datagram {
            peer,
            context,
            data,
            relayed,
            connected,
        } => Owned::Datagram {
            context,
            peer,
            data: data.to_vec(),
            relayed,
            connected,
        },
        Event::Closed {
            peer,
            context,
            code,
            by_peer,
        } => Owned::Context(
            context,
            ContextEvent::Closed {
                peer,
                code,
                by_peer,
            },
        ),
        Event::ReopenFailed {
            peer,
            context,
            error,
        } => Owned::Context(context, ContextEvent::ReopenFailed { peer, error }),
        Event::PathChanged {
            peer,
            context,
            path,
        } => Owned::Context(context, ContextEvent::PathChanged { peer, path }),
        Event::PeerNotAtRelay { peer } => Owned::Node(NodeEvent::PeerNotAtRelay { peer }),
        Event::ObservedAddress { link, address } => {
            Owned::Node(NodeEvent::ObservedAddress { link, address })
        }
        Event::RelayUnavailable { error } => Owned::Node(NodeEvent::RelayUnavailable { error }),
        Event::RelayAvailable => Owned::Node(NodeEvent::RelayAvailable),
        #[cfg(feature = "stream")]
        Event::Frame {
            peer,
            context,
            kind,
            data,
            connected,
            ..
        } => Owned::Frame {
            peer,
            context,
            kind,
            data: data.to_vec(),
            connected,
        },
        // Without the stream layer, a frame is not the application's: only
        // the connection it may confirm is.
        #[cfg(not(feature = "stream"))]
        Event::Frame {
            peer,
            context,
            connected,
            ..
        } => {
            if connected {
                Owned::Context(context, ContextEvent::Connected { peer })
            } else {
                Owned::Nothing
            }
        }
        // Early data: the relay context's payloads never reach here.
        Event::Payload {
            peer,
            context,
            data,
        } => Owned::Context(
            context,
            ContextEvent::EarlyDatagram {
                peer,
                data: data.to_vec(),
            },
        ),
    }
}

struct Task<E, C: Profile> {
    endpoint: Endpoint<Server>,
    /// Each context's policy, the core's one admission.
    policies: Policies,
    /// The open contexts.
    contexts: HashMap<Name, Open>,
    entropy: E,
    udp: UdpSocket,
    dual_stack: bool,
    relay: Option<RelayLocation>,
    /// The relay's UDP address the node uses, and the one in the other
    /// family, where `RelayPath::UdpOther` goes.
    relay_udp: Option<SocketAddr>,
    relay_other: Option<SocketAddr>,
    /// The source of the UDP packet handled last: where `To::Source` goes
    /// when the answer leaves through a poll, as an owed response does.
    last_from: Option<SocketAddr>,
    link: Option<LinkIo>,
    connecting: Option<Connecting>,
    resolver: Option<Resolver>,
    /// Resolving the relay's host for its UDP address, which the node lacks.
    resolving: Option<Resolving>,
    /// The wait before the next resolution, after one that failed.
    resolve_backoff: Duration,
    /// No resolution starts before this instant.
    resolve_not_before: Option<Instant>,
    /// The node's events, and those waiting aside for room, one per kind.
    events: mpsc::Sender<NodeEvent>,
    held: VecDeque<(NodeKind, NodeEvent)>,
    /// Woken when the application reads while something waits for room.
    room: Arc<Room>,
    commands: mpsc::Receiver<Command>,
    /// The contexts whose handles were dropped or closed, with the code.
    closes: mpsc::UnboundedReceiver<(Name, u16)>,
    stats: Stats,
    clock: Clock,
    rx: Vec<u8>,
    out: Vec<u8>,
    link_rx: Vec<u8>,
    /// Given every TCP connection to the relay before it connects.
    hook: Option<SocketHook>,
    /// Woken by a receiver that freed room or was dropped.
    receivers_wake: Arc<Notify>,
    /// The message channels, and the frame they write.
    #[cfg(feature = "stream")]
    channels: Box<Channels<C>>,
    #[cfg(feature = "stream")]
    frame: Vec<u8>,
    /// Messages waiting for room in their channel, in order.
    #[cfg(feature = "stream")]
    parked: Vec<Parked>,
    /// The stream configuration, without the stream layer: none.
    #[cfg(not(feature = "stream"))]
    stream: std::marker::PhantomData<C>,
}

/// A message for a peer in a context, with its address when known and the
/// sender's reply.
#[cfg(feature = "stream")]
struct Parked {
    context: Name,
    peer: PeerId,
    address: Option<Address>,
    data: Vec<u8>,
    reply: oneshot::Sender<Result<(), NodeError>>,
}

/// What woke the task.
enum Wake {
    Udp(std::io::Result<(usize, SocketAddr)>),
    Link(std::io::Result<usize>),
    Connected(std::io::Result<Linked>),
    /// The relay's host resolved, or did not: the host asked, and the answer.
    Resolved(String, std::io::Result<RelayAddresses>),
    Command(Option<Command>),
    /// A context's handle was dropped, or closed.
    CloseContext(Option<(Name, u16)>),
    Deadline,
    /// The application read: room for what waited.
    Room,
    /// A receiver freed room, or was dropped.
    Receivers,
}

/// What a context's waiting event is coalesced by: its peer and its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held(PeerId, Kind);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Connected,
    Idle,
    Closed,
    ReopenFailed,
    PathChanged,
    #[cfg(feature = "stream")]
    ChannelReset,
}

/// What a node's waiting event is coalesced by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeKind {
    NotAtRelay(PeerId),
    Observed(Link),
    /// The relay's state: whether it is available, the latest only.
    Relay,
}

/// The key a context's event is coalesced by; `None` for one that carries
/// data.
fn held_key(event: &ContextEvent) -> Option<Held> {
    Some(match *event {
        ContextEvent::Connected { peer } => Held(peer, Kind::Connected),
        ContextEvent::Idle { peer } => Held(peer, Kind::Idle),
        ContextEvent::Closed { peer, .. } => Held(peer, Kind::Closed),
        ContextEvent::ReopenFailed { peer, .. } => Held(peer, Kind::ReopenFailed),
        ContextEvent::PathChanged { peer, .. } => Held(peer, Kind::PathChanged),
        #[cfg(feature = "stream")]
        ContextEvent::ChannelReset { peer, .. } => Held(peer, Kind::ChannelReset),
        ContextEvent::Datagram { .. } | ContextEvent::EarlyDatagram { .. } => return None,
        #[cfg(feature = "stream")]
        ContextEvent::Message { .. } => return None,
    })
}

const fn node_kind(event: &NodeEvent) -> NodeKind {
    match *event {
        NodeEvent::PeerNotAtRelay { peer } => NodeKind::NotAtRelay(peer),
        NodeEvent::ObservedAddress { link, .. } => NodeKind::Observed(link),
        NodeEvent::RelayUnavailable { .. } | NodeEvent::RelayAvailable => NodeKind::Relay,
    }
}

impl<E: SystemEntropy, C: Profile> Task<E, C> {
    fn now(&self) -> Instant {
        Instant::from_millis(u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    async fn run(mut self) {
        let mut deadline: Option<Instant> = None;
        // One timer for the task's life, moved when the deadline moves: a new
        // one per wake registered and cancelled a timer for every packet.
        let sleep = tokio::time::sleep(std::time::Duration::ZERO);
        tokio::pin!(sleep);
        let mut armed: Option<Instant> = None;
        loop {
            if deadline != armed {
                if let Some(at) = deadline {
                    let at = self.clock + std::time::Duration::from_millis(at.as_millis());
                    sleep.as_mut().reset(at.into());
                }
                armed = deadline;
            }
            let waiting = self.waiting();
            self.room.waiting.store(waiting, Ordering::Release);
            // Room may have opened before the flag was up: no wake would come.
            let wake = if waiting && self.room_now() {
                Wake::Room
            } else {
                tokio::select! {
                    r = self.udp.recv_from(&mut self.rx) => Wake::Udp(r),
                    r = read_link(&mut self.link, &mut self.link_rx), if self.link.is_some() => Wake::Link(r),
                    r = poll_connecting(&mut self.connecting), if self.connecting.is_some() => Wake::Connected(r),
                    (host, r) = poll_resolving(&mut self.resolving), if self.resolving.is_some() => Wake::Resolved(host, r),
                    c = self.commands.recv() => Wake::Command(c),
                    c = self.closes.recv() => Wake::CloseContext(c),
                    () = &mut sleep, if armed.is_some() => Wake::Deadline,
                    () = self.room.notify.notified(), if waiting => Wake::Room,
                    () = self.receivers_wake.notified() => Wake::Receivers,
                }
            };
            match wake {
                Wake::Udp(Ok((len, from))) => self.udp_packet(len, from).await,
                Wake::Udp(Err(_)) | Wake::CloseContext(None) => {}
                Wake::Link(Ok(0) | Err(_)) => {
                    self.link = None;
                    let now = self.now();
                    self.endpoint.relay_link_closed(now);
                }
                Wake::Link(Ok(len)) => self.link_bytes(len).await,
                Wake::Connected(result) => self.connected(result).await,
                Wake::Resolved(host, result) => self.resolved(&host, result),
                Wake::Command(None) => {
                    // The last handle is gone: the contexts it closed close
                    // first, their closes sent.
                    while let Ok((context, code)) = self.closes.try_recv() {
                        self.close_context(context, code);
                    }
                    self.drain().await;
                    return;
                }
                Wake::Command(Some(command)) => self.command(command).await,
                Wake::CloseContext(Some((context, code))) => self.close_context(context, code),
                // An elapsed timer is ready at every poll: armed again below.
                Wake::Deadline => armed = None,
                Wake::Room => self.flush(),
                Wake::Receivers => self.settle_receivers(),
            }
            self.take_ready().await;
            deadline = self.drain().await;
            if self.events.is_closed() && self.commands.is_closed() && self.contexts.is_empty() {
                return;
            }
        }
    }

    /// Whether something waits for room in an event stream: events without
    /// data aside, or messages in their channels.
    fn waiting(&self) -> bool {
        !self.held.is_empty() || self.contexts.values().any(Open::waiting)
    }

    /// Whether there is room now for something that waits.
    fn room_now(&self) -> bool {
        (!self.held.is_empty() && self.events.capacity() > 0)
            || self.contexts.values().any(Open::ready)
    }

    /// Handles, without waiting, the commands and datagrams already there,
    /// up to [`BATCH`] rounds: the core is drained once for all of them,
    /// rather than once per packet.
    async fn take_ready(&mut self) {
        for _ in 0..BATCH {
            let mut took = false;
            if let Ok(command) = self.commands.try_recv() {
                self.command(command).await;
                took = true;
            }
            if let Ok((context, code)) = self.closes.try_recv() {
                self.close_context(context, code);
                took = true;
            }
            if let Ok((len, from)) = self.udp.try_recv_from(&mut self.rx) {
                self.udp_packet(len, from).await;
                took = true;
            }
            if !took {
                return;
            }
        }
    }

    async fn udp_packet(&mut self, len: usize, from: SocketAddr) {
        let from = canonical(from);
        self.last_from = Some(from);
        self.stats.udp_received += 1;
        self.stats.udp_received_bytes += len as u64;
        let now = self.now();
        let Some(packet) = self.rx.get_mut(..len) else {
            return;
        };
        let output = if Some(from) == self.relay_udp || Some(from) == self.relay_other {
            own(self.endpoint.handle_relay_packet(
                packet,
                Link::Udp,
                now,
                &mut self.policies,
                &mut self.entropy,
                &mut self.out,
            ))
        } else {
            let (source, source_len) = address::encode(from);
            own(self.endpoint.handle_packet(
                packet,
                Source::Direct(source.get(..source_len).unwrap_or_default()),
                now,
                &mut self.policies,
                &mut self.entropy,
                &mut self.out,
            ))
        };
        self.execute(output, Some(from)).await;
    }

    async fn link_bytes(&mut self, len: usize) {
        self.stats.link_received_bytes += len as u64;
        let mut packets = Vec::new();
        let mut keepalives = 0;
        let mut closed = false;
        if let Some(link) = self.link.as_mut() {
            let mut at = 0;
            loop {
                let (used, result) = link
                    .deframer
                    .feed(self.link_rx.get(at..len).unwrap_or_default());
                at += used;
                match result {
                    Deframed::NeedMore => break,
                    Deframed::KeepAlive => keepalives += 1,
                    Deframed::Packet(packet) => packets.push(packet.to_vec()),
                    Deframed::Closed(_) => {
                        closed = true;
                        break;
                    }
                }
            }
        }
        let now = self.now();
        for _ in 0..keepalives {
            self.stats.keepalives_received += 1;
            self.endpoint.relay_keepalive_received(now);
        }
        for mut packet in packets {
            self.stats.frames_received += 1;
            let output = own(self.endpoint.handle_relay_packet(
                &mut packet,
                Link::Tcp,
                now,
                &mut self.policies,
                &mut self.entropy,
                &mut self.out,
            ));
            self.execute(output, None).await;
        }
        if closed {
            self.link = None;
            self.endpoint.relay_link_closed(now);
        }
    }

    async fn connected(&mut self, result: std::io::Result<Linked>) {
        self.connecting = None;
        let now = self.now();
        let opened = match result {
            Ok((mut stream, at, other)) => {
                if stream.write_all(&PREAMBLE).await.is_ok() {
                    self.relay_udp = Some(canonical(at));
                    self.relay_other = other;
                    self.endpoint
                        .set_relay_families(canonical(at).is_ipv6(), other.is_some());
                    self.link = Some(LinkIo {
                        stream,
                        deframer: Box::default(),
                    });
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        };
        if opened {
            self.stats.links_opened += 1;
            self.endpoint.relay_link_opened(now);
        } else {
            self.endpoint.relay_link_closed(now);
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one arm per command, each a call or two into the core"
    )]
    async fn command(&mut self, command: Command) {
        let now = self.now();
        match command {
            Command::Open(opening, reply) => {
                let _ = reply.send(self.open(opening));
            }
            Command::SetAccess(context, access, code, reply) => {
                let _ = reply.send(self.set_access(context, access, code));
            }
            Command::Send(context, to, data, reply) => {
                if !self.contexts.contains_key(&context) {
                    let _ = reply.send(Err(NodeError::ContextClosed));
                    return;
                }
                let result = self.endpoint.send(
                    Target::Address(&to),
                    context.as_bytes(),
                    &data,
                    DIRECT_PATH_MAX,
                    now,
                    &mut self.policies,
                    &mut self.entropy,
                    &mut self.out,
                );
                self.sent(result, reply).await;
            }
            Command::SendToPeer(context, to, data, reply) => {
                if !self.contexts.contains_key(&context) {
                    let _ = reply.send(Err(NodeError::ContextClosed));
                    return;
                }
                let result = self.endpoint.send(
                    Target::Peer(to),
                    context.as_bytes(),
                    &data,
                    DIRECT_PATH_MAX,
                    now,
                    &mut self.policies,
                    &mut self.entropy,
                    &mut self.out,
                );
                self.sent(result, reply).await;
            }
            Command::Hint(peer, at, reply) => {
                let encoded: Vec<_> = at.into_iter().map(address::encode).collect();
                let hints: Vec<&[u8]> = encoded
                    .iter()
                    .map(|(bytes, len)| bytes.get(..*len).unwrap_or_default())
                    .collect();
                let result = self
                    .endpoint
                    .set_hints(peer, &hints, now)
                    .map_err(NodeError::Hint);
                let _ = reply.send(result);
            }
            Command::Relay(relay, reply) => {
                let _ = reply.send(self.set_relay(relay, now));
            }
            Command::Reachable(on) => self.endpoint.set_reachable(on, now),
            Command::Close(context, peer, code) => {
                if !self.contexts.contains_key(&context) {
                    return;
                }
                let output =
                    own(self
                        .endpoint
                        .close(peer, context.as_bytes(), code, now, &mut self.out));
                self.execute(output, None).await;
                #[cfg(feature = "stream")]
                self.channels.session_closed(peer, context, code);
                self.close_receiver(
                    context,
                    peer,
                    SessionClosed {
                        code,
                        by_peer: false,
                    },
                );
            }
            Command::ClosePeer(peer, code) => {
                self.endpoint.close_peer(peer, code);
                let contexts: Vec<Name> = self.contexts.keys().copied().collect();
                for context in contexts {
                    #[cfg(feature = "stream")]
                    self.channels.session_closed(peer, context, code);
                    self.close_receiver(
                        context,
                        peer,
                        SessionClosed {
                            code,
                            by_peer: false,
                        },
                    );
                }
            }
            Command::NetworkChanged => {
                self.report_interfaces();
                self.endpoint.network_changed(now);
            }
            Command::Candidates(reply) => {
                let _ = reply.send(self.endpoint.candidates().to_vec());
            }
            Command::Exclude(prefixes, replace, reply) => {
                let result = if replace {
                    self.endpoint.set_excluded(&prefixes)
                } else {
                    prefixes
                        .iter()
                        .try_for_each(|(ip, len)| self.endpoint.exclude_prefix(*ip, *len))
                };
                // A prefix let in again: its interfaces are candidates again.
                if replace && result.is_ok() {
                    self.report_interfaces();
                }
                let _ = reply.send(result.map_err(NodeError::Exclude));
            }
            Command::Binding(context, peer, reply) => {
                let _ = reply.send(self.endpoint.channel_binding(&peer, context.as_bytes()));
            }
            Command::Stats(reply) => {
                let _ = reply.send(self.stats);
            }
            Command::Path(context, peer, reply) => {
                let _ = reply.send(self.endpoint.path_info(&peer, context.as_bytes()));
            }
            Command::RelayUdpProven(reply) => {
                let _ = reply.send(self.endpoint.relay_udp_proven(now));
            }
            Command::Connect(context, to, reply) => {
                if !self.contexts.contains_key(&context) {
                    let _ = reply.send(Err(NodeError::ContextClosed));
                    return;
                }
                let result = self.endpoint.connect(
                    &to,
                    context.as_bytes(),
                    now,
                    &mut self.policies,
                    &mut self.entropy,
                    &mut self.out,
                );
                self.sent(result, reply).await;
            }
            Command::IsLive(context, peer, reply) => {
                let _ = reply.send(self.endpoint.is_live(&peer, context.as_bytes(), now));
            }
            Command::PeerCandidates(context, peer, reply) => {
                let candidates = self.endpoint.peer_candidates(&peer, context.as_bytes());
                let _ = reply.send(candidates.to_vec());
            }
            Command::PassiveKeepalive(context, peer, on, reply) => {
                let result = self
                    .endpoint
                    .set_passive_keepalive(peer, context.as_bytes(), on)
                    .map_err(|NoSession| NodeError::NoSession);
                let _ = reply.send(result);
            }
            Command::RelayKeepalive(interval, reply) => {
                let result = self
                    .endpoint
                    .set_relay_keepalive(interval)
                    .map_err(NodeError::KeepAlive);
                let _ = reply.send(result);
            }
            Command::PinnedRelay(reply) => {
                let _ = reply.send(self.relay.clone());
            }
            Command::Receiver(context, peer, reply) => {
                let _ = reply.send(self.open_receiver(context, peer, now));
            }
            #[cfg(feature = "stream")]
            Command::SendMessage(parked) => {
                if !self.contexts.contains_key(&parked.context) {
                    let _ = parked.reply.send(Err(NodeError::ContextClosed));
                    return;
                }
                // A sender that went away no longer waits.
                self.parked.retain(|parked| !parked.reply.is_closed());
                // Behind those already waiting for the same channel: in order.
                if self
                    .parked
                    .iter()
                    .any(|p| p.peer == parked.peer && p.context == parked.context)
                {
                    self.parked.push(parked);
                } else {
                    self.offer(parked, now);
                }
            }
        }
    }

    /// Opens a context: serves it as its access says, and keeps its stream.
    fn open(&mut self, opening: Opening) -> Result<(), NodeError> {
        let Opening {
            name,
            access,
            delivery,
            events,
            #[cfg(feature = "stream")]
            max_message,
            settings,
        } = opening;
        let context = Name::new(&name)
            .map_err(|error| NodeError::Context(ResponderError::ContextTooLong(error)))?;
        if name == convesso_core::relay::CONTEXT {
            return Err(NodeError::Context(ResponderError::RelayContext));
        }
        if self.contexts.contains_key(&context) {
            return Err(NodeError::Context(ResponderError::AlreadyServed));
        }
        #[cfg(feature = "stream")]
        {
            let largest = max_message.unwrap_or(C::MAX_MESSAGE);
            if largest > C::MAX_MESSAGE {
                return Err(NodeError::Message(convesso_stream::SendError::TooLarge {
                    size: largest,
                    max: C::MAX_MESSAGE,
                }));
            }
            if let Delivery::PerPeer { messages, .. } = delivery {
                let needed = largest + ELEMENT_COST;
                if messages < needed {
                    return Err(NodeError::Budget {
                        budget: messages,
                        needed,
                    });
                }
            }
        }
        // The settings first, so that serving takes them; undone if serving
        // fails, the context then not open.
        self.endpoint
            .set_context_settings(&name, settings)
            .map_err(NodeError::Context)?;
        if let Some(access) = core_access(&access)
            && let Err(error) = self.endpoint.serve(&name, access)
        {
            let _ = self
                .endpoint
                .set_context_settings(&name, Settings::default());
            return Err(NodeError::Context(error));
        }
        #[cfg(feature = "stream")]
        if let Err(error) = self.channels.set_context(
            &name,
            max_message,
            matches!(delivery, Delivery::PerPeer { .. }),
        ) {
            // Not opened: nothing of it stays.
            let _ = self.endpoint.close_context(&name, DROPPED);
            return Err(NodeError::Message(error));
        }
        if let Access::Admit(policy) = access {
            self.policies.0.insert(context, policy);
        }
        self.contexts.insert(
            context,
            Open {
                events,
                held: VecDeque::new(),
                delivery,
                receivers: HashMap::new(),
                blocked: false,
            },
        );
        Ok(())
    }

    /// Changes a context's access, judging again the sessions it accepted.
    fn set_access(&mut self, context: Name, access: Access, code: u16) -> Result<(), NodeError> {
        if !self.contexts.contains_key(&context) {
            return Err(NodeError::ContextClosed);
        }
        let core = core_access(&access);
        let previous = self.policies.0.remove(&context);
        if let Access::Admit(policy) = access {
            self.policies.0.insert(context, policy);
        }
        let result = self
            .endpoint
            .set_access(context.as_bytes(), core, code, &mut self.policies)
            .map_err(NodeError::Context);
        if result.is_err() {
            // Refused: the context keeps the access it had.
            self.policies.0.remove(&context);
            if let Some(previous) = previous {
                self.policies.0.insert(context, previous);
            }
        }
        result
    }

    /// Closes a context: its sessions with `code`, its channels, its
    /// receivers; its event stream ends.
    fn close_context(&mut self, context: Name, code: u16) {
        let Some(open) = self.contexts.remove(&context) else {
            return;
        };
        let _ = self.endpoint.close_context(context.as_bytes(), code);
        self.policies.0.remove(&context);
        #[cfg(feature = "stream")]
        {
            self.channels.context_closed(context, code);
            for parked in std::mem::take(&mut self.parked) {
                if parked.context == context {
                    let _ = parked.reply.send(Err(NodeError::ContextClosed));
                } else {
                    self.parked.push(parked);
                }
            }
        }
        for (_, shared) in open.receivers {
            shared.lock().closed.get_or_insert(SessionClosed {
                code,
                by_peer: false,
            });
            shared.closed();
        }
    }

    /// Hands a node event to the application without ever waiting for it:
    /// into the node's stream, or aside, one per kind, while it is full.
    fn emit_node(&mut self, event: NodeEvent) {
        self.flush_node();
        let event = if self.held.is_empty() {
            match self.events.try_send(event) {
                Ok(()) | Err(TrySendError::Closed(_)) => return,
                Err(TrySendError::Full(event)) => event,
            }
        } else {
            event
        };
        let kind = node_kind(&event);
        self.held.retain(|(k, _)| *k != kind);
        self.held.push_back((kind, event));
    }

    fn flush_node(&mut self) {
        while let Some((kind, event)) = self.held.pop_front() {
            match self.events.try_send(event) {
                Ok(()) | Err(TrySendError::Closed(_)) => {}
                Err(TrySendError::Full(event)) => {
                    self.held.push_front((kind, event));
                    return;
                }
            }
        }
    }

    /// Hands an event to its context; a datagram that finds no room is
    /// dropped and counted. An event of a context no longer open is dropped.
    fn emit(&mut self, context: Name, event: ContextEvent) {
        if let Some(open) = self.contexts.get_mut(&context)
            && open.emit(event)
        {
            self.stats.datagrams_dropped += 1;
        }
    }

    /// Moves what waits aside into the event streams, as far as there is
    /// room.
    fn flush(&mut self) {
        self.flush_node();
        for open in self.contexts.values_mut() {
            open.flush();
        }
    }

    /// Opens `peer`'s receiver in `context`, granting its channel the message
    /// budget. A receiver dropped and not yet settled is settled first.
    fn open_receiver(
        &mut self,
        context: Name,
        peer: PeerId,
        now: Instant,
    ) -> Result<Receiver, NodeError> {
        let Some(open) = self.contexts.get(&context) else {
            return Err(NodeError::ContextClosed);
        };
        let Delivery::PerPeer { messages, .. } = open.delivery else {
            return Err(NodeError::NotPerPeer);
        };
        if let Some(shared) = open.receivers.get(&peer) {
            if !shared.lock().dropped {
                return Err(NodeError::ReceiverOpen);
            }
            self.settle_receivers_at(now);
        }
        let shared = Shared::new(self.receivers_wake.clone());
        #[cfg(feature = "stream")]
        self.channels
            .grant(peer, context.as_bytes(), messages)
            .map_err(NodeError::Message)?;
        #[cfg(not(feature = "stream"))]
        let _ = messages;
        if let Some(open) = self.contexts.get_mut(&context) {
            open.receivers.insert(peer, shared.clone());
        }
        Ok(Receiver::new(peer, shared))
    }

    fn settle_receivers(&mut self) {
        let now = self.now();
        self.settle_receivers_at(now);
    }

    /// Grants each channel the room its receiver freed; resets the channel of
    /// a receiver the application dropped, which tells the peer.
    fn settle_receivers_at(&mut self, now: Instant) {
        let mut dropped = Vec::new();
        #[cfg(feature = "stream")]
        let mut grants = Vec::new();
        for (&context, open) in &self.contexts {
            for (&peer, shared) in &open.receivers {
                #[cfg_attr(not(feature = "stream"), allow(unused_mut))]
                let mut state = shared.lock();
                if state.dropped {
                    dropped.push((context, peer));
                    continue;
                }
                #[cfg(feature = "stream")]
                {
                    let freed = std::mem::take(&mut state.freed);
                    if freed > 0 {
                        grants.push((context, peer, freed));
                    }
                }
            }
        }
        #[cfg(feature = "stream")]
        for (context, peer, freed) in grants {
            let _ = self.channels.grant(peer, context.as_bytes(), freed);
        }
        for (context, peer) in dropped {
            if let Some(open) = self.contexts.get_mut(&context) {
                open.receivers.remove(&peer);
            }
            #[cfg(feature = "stream")]
            self.channels.reset_here(peer, context, now);
        }
        #[cfg(not(feature = "stream"))]
        let _ = now;
    }

    /// The session with `peer` in `context` ended: its receiver says so once
    /// it has been read up to here, and stays closed.
    fn close_receiver(&mut self, context: Name, peer: PeerId, closed: SessionClosed) {
        let Some(open) = self.contexts.get_mut(&context) else {
            return;
        };
        if let Some(shared) = open.receivers.remove(&peer) {
            shared.lock().closed.get_or_insert(closed);
            shared.closed();
        }
    }

    /// A datagram, with per-peer delivery: to its receiver, or dropped.
    fn receive_datagram(&mut self, context: Name, peer: PeerId, data: Vec<u8>, relayed: bool) {
        let Some(open) = self.contexts.get(&context) else {
            return;
        };
        let Delivery::PerPeer { datagrams, .. } = open.delivery else {
            return;
        };
        if let Some(shared) = open.receivers.get(&peer) {
            let mut state = shared.lock();
            let cost = data.len() + ELEMENT_COST;
            if !state.dropped && state.datagram_bytes + cost <= datagrams {
                state.datagram_bytes += cost;
                state.datagrams.push_back((data, relayed));
                drop(state);
                shared.datagrams_ready();
                return;
            }
        }
        self.stats.datagrams_dropped += 1;
    }

    /// A message, with per-peer delivery: to its receiver, whose room the
    /// channel's credit reserved.
    #[cfg(feature = "stream")]
    fn receive_message(&mut self, context: Name, peer: PeerId, data: Vec<u8>) {
        // Credit is granted only for an open receiver, and goes with it: a
        // message for none was meant for one just dropped, whose channel is
        // about to be reset.
        let Some(open) = self.contexts.get(&context) else {
            return;
        };
        if let Some(shared) = open.receivers.get(&peer) {
            let mut state = shared.lock();
            if !state.dropped {
                state.held += data.len() + ELEMENT_COST;
                state.items.push_back(crate::receiver::Item::Message(data));
                drop(state);
                shared.messages_ready();
            }
        }
    }

    /// A channel reset, with per-peer delivery: to its receiver after the
    /// messages before it, and the channel granted the receiver's free room
    /// again, since the reset left it no credit.
    #[cfg(feature = "stream")]
    fn receive_reset(&mut self, context: Name, peer: PeerId, reason: convesso_stream::Reason) {
        let Some(open) = self.contexts.get(&context) else {
            return;
        };
        let Delivery::PerPeer { messages, .. } = open.delivery else {
            return;
        };
        let Some(shared) = open.receivers.get(&peer) else {
            return;
        };
        let mut state = shared.lock();
        if state.dropped {
            return;
        }
        state.items.push_back(crate::receiver::Item::Reset(reason));
        state.freed = 0;
        let room = messages.saturating_sub(state.held);
        drop(state);
        shared.messages_ready();
        let _ = self.channels.grant(peer, context.as_bytes(), room);
    }

    /// Whether `context` delivers per peer.
    fn per_peer(&self, context: &Name) -> bool {
        self.contexts
            .get(context)
            .is_some_and(|open| matches!(open.delivery, Delivery::PerPeer { .. }))
    }

    /// Offers a message to its channel: accepted or refused, the sender is
    /// answered; without room, it waits for the channel's `Writable`.
    #[cfg(feature = "stream")]
    fn offer(&mut self, parked: Parked, now: Instant) -> bool {
        // A sender that went away no longer wants its message sent.
        if parked.reply.is_closed() {
            return true;
        }
        let result = self.channels.send_message(
            parked.peer,
            parked.address.as_ref(),
            parked.context.as_bytes(),
            &parked.data,
            now,
            &mut self.entropy,
        );
        match result {
            Err(convesso_stream::SendError::Full) => {
                self.parked.push(parked);
                false
            }
            other => {
                let _ = parked.reply.send(other.map_err(NodeError::Message));
                true
            }
        }
    }

    /// Room opened in a channel: offers its waiting messages, in order.
    #[cfg(feature = "stream")]
    fn retry_parked(&mut self, context: Name, peer: PeerId, now: Instant) {
        let (mine, others): (Vec<_>, Vec<_>) = std::mem::take(&mut self.parked)
            .into_iter()
            .partition(|p| p.peer == peer && p.context == context);
        self.parked = others;
        let mut waiting = mine.into_iter();
        for parked in waiting.by_ref() {
            if !self.offer(parked, now) {
                break;
            }
        }
        self.parked.extend(waiting);
    }

    async fn sent(
        &mut self,
        result: Result<Output<'static>, SendError>,
        reply: oneshot::Sender<Result<(), NodeError>>,
    ) {
        match result {
            Ok(output) => {
                let _ = reply.send(Ok(()));
                self.execute(own(output), None).await;
            }
            Err(error) => {
                let _ = reply.send(Err(NodeError::Send(error)));
            }
        }
    }

    /// Calls the core, and the channels, until neither has anything due;
    /// returns the earlier of their next deadlines.
    async fn drain(&mut self) -> Option<Instant> {
        #[cfg(feature = "stream")]
        loop {
            let core = self.drain_core().await;
            let (stream, worked) = self.drain_stream().await;
            if !worked {
                return [core, stream].into_iter().flatten().min();
            }
        }
        #[cfg(not(feature = "stream"))]
        self.drain_core().await
    }

    /// Calls the channels until they have nothing due: each frame and each
    /// dial to the core, each event to the application. Returns their
    /// deadline, and whether they did anything.
    #[cfg(feature = "stream")]
    async fn drain_stream(&mut self) -> (Option<Instant>, bool) {
        let mut worked = false;
        loop {
            let now = self.now();
            // A context's message is handed out only when the application can
            // take it: otherwise its channel keeps it and its window closes,
            // and the other contexts go on.
            let contexts = &self.contexts;
            let mut blocked: Vec<Name> = Vec::new();
            let deliver = |context: &Name| {
                let can = contexts.get(context).is_some_and(Open::can_deliver);
                if !can && !blocked.contains(context) {
                    blocked.push(*context);
                }
                can
            };
            let poll = self.channels.poll_with(now, deliver, &mut self.frame);
            let output = match poll {
                StreamPoll::SendFrame {
                    peer,
                    context,
                    kind,
                    len,
                } => {
                    let frame = self.frame.get(..len).unwrap_or_default();
                    match self.endpoint.send_frame(
                        peer,
                        context.as_bytes(),
                        kind,
                        frame,
                        now,
                        &mut self.policies,
                        &mut self.entropy,
                        &mut self.out,
                    ) {
                        Ok(output) => {
                            self.stats.stream_frames_sent += 1;
                            own(output)
                        }
                        Err(_) => {
                            self.channels.frame_refused(now);
                            Owned::Nothing
                        }
                    }
                }
                StreamPoll::Dial { address, context } => self
                    .endpoint
                    .connect(
                        &address,
                        context.as_bytes(),
                        now,
                        &mut self.policies,
                        &mut self.entropy,
                        &mut self.out,
                    )
                    .map_or(Owned::Nothing, own),
                StreamPoll::Event(StreamEvent::Message {
                    peer,
                    context,
                    data,
                }) => {
                    let data = data.to_vec();
                    if self.per_peer(&context) {
                        self.receive_message(context, peer, data);
                        Owned::Nothing
                    } else {
                        Owned::Context(context, ContextEvent::Message { peer, data })
                    }
                }
                StreamPoll::Event(StreamEvent::Reset {
                    peer,
                    context,
                    reason,
                }) => {
                    if self.per_peer(&context) {
                        self.receive_reset(context, peer, reason);
                        Owned::Nothing
                    } else {
                        Owned::Context(context, ContextEvent::ChannelReset { peer, reason })
                    }
                }
                StreamPoll::Event(StreamEvent::Writable { peer, context }) => {
                    self.retry_parked(context, peer, now);
                    Owned::Nothing
                }
                StreamPoll::Wait(at) => {
                    self.mark_blocked(&blocked);
                    return (Some(at), worked);
                }
                StreamPoll::Idle => {
                    self.mark_blocked(&blocked);
                    return (None, worked);
                }
            };
            self.mark_blocked(&blocked);
            worked = true;
            self.execute(output, None).await;
        }
    }

    /// Records which contexts' messages wait for room in their streams.
    #[cfg(feature = "stream")]
    fn mark_blocked(&mut self, blocked: &[Name]) {
        for (context, open) in &mut self.contexts {
            open.blocked = blocked.contains(context);
        }
    }

    /// Calls the core until it has nothing due; returns its next deadline.
    async fn drain_core(&mut self) -> Option<Instant> {
        loop {
            let now = self.now();
            let poll =
                self.endpoint
                    .poll(now, &mut self.policies, &mut self.entropy, &mut self.out);
            match poll {
                Poll::Transmit { to, len } => self.execute(Owned::Transmit { to, len }, None).await,
                Poll::Event(event) => {
                    let owned = owned_event(event);
                    if !matches!(owned, Owned::Nothing) {
                        self.execute(owned, None).await;
                    }
                }
                Poll::OpenRelayLink => self.open_link(),
                Poll::CloseRelayLink => {
                    self.connecting = None;
                    self.link = None;
                }
                Poll::Wait(at) => return Some(at),
                Poll::Idle => return None,
            }
        }
    }

    /// Pins `relay`, or none, in the core and here. Moving to another relay
    /// drops the old one's link or connection at once, so that nothing of it
    /// is taken for the new relay's; the core's close that follows finds
    /// nothing.
    fn set_relay(&mut self, relay: Option<Resolved>, now: Instant) -> Result<(), NodeError> {
        let address = relay.as_ref().map(|(location, ..)| location.address);
        let moved = self.relay.as_ref().map(|location| location.address) != address;
        self.endpoint
            .set_relay(address, now)
            .map_err(NodeError::Relay)?;
        if moved {
            self.connecting = None;
            self.link = None;
            self.resolving = None;
            self.resolve_backoff = RESOLVE_BACKOFF_FIRST;
            self.resolve_not_before = None;
        }
        match relay {
            Some((location, addresses)) => {
                if moved {
                    self.relay_udp = addresses.map(|(at, _)| at);
                    self.relay_other = addresses.and_then(|(_, other)| other);
                    if let Some((at, other)) = addresses {
                        self.endpoint
                            .set_relay_families(at.is_ipv6(), other.is_some());
                    }
                }
                self.relay = Some(location);
            }
            None => {
                self.relay = None;
                self.relay_udp = None;
                self.relay_other = None;
            }
        }
        Ok(())
    }

    /// Starts resolving the relay's host, for a packet to it over UDP that has
    /// no address to go to: unless a resolution runs, or the backoff after
    /// one that failed has not elapsed. The packet itself is lost, as on any
    /// network; the core sends again what needs it.
    fn resolve_relay(&mut self) {
        let now = self.now();
        if self.resolving.is_some() || self.resolve_not_before.is_some_and(|at| now < at) {
            return;
        }
        let Some(relay) = self.relay.clone() else {
            return;
        };
        let resolver = self.resolver.clone();
        let dual_stack = self.dual_stack;
        self.resolving = Some(Box::pin(async move {
            let result = resolve(resolver.as_ref(), &relay.host, dual_stack).await;
            (relay.host, result)
        }));
    }

    /// The relay's host resolved, or did not. An answer for a relay no longer
    /// pinned is dropped.
    fn resolved(&mut self, host: &str, result: std::io::Result<RelayAddresses>) {
        self.resolving = None;
        if self.relay.as_ref().is_none_or(|relay| relay.host != host) {
            return;
        }
        match result {
            Ok((at, other)) => {
                self.resolve_backoff = RESOLVE_BACKOFF_FIRST;
                self.resolve_not_before = None;
                if self.relay_udp.is_none() {
                    self.relay_udp = Some(at);
                    self.relay_other = other;
                    self.endpoint
                        .set_relay_families(at.is_ipv6(), other.is_some());
                }
            }
            Err(_) => {
                let now = self.now();
                self.resolve_not_before = Some(now.saturating_add(self.resolve_backoff));
                self.resolve_backoff = self
                    .resolve_backoff
                    .saturating_mul(2)
                    .min(RESOLVE_BACKOFF_CAP);
            }
        }
    }

    /// Reports the interfaces' addresses to the core.
    fn report_interfaces(&mut self) {
        if let Ok(local) = self.udp.local_addr() {
            self.endpoint
                .set_local_addresses(&local_addresses(local, self.dual_stack));
        }
    }

    fn open_link(&mut self) {
        let Some(relay) = self.relay.clone() else {
            return;
        };
        let dual_stack = self.dual_stack;
        let hook = self.hook.clone();
        let resolver = self.resolver.clone();
        self.connecting = Some(Box::pin(async move {
            let (at, other) = resolve(resolver.as_ref(), &relay.host, dual_stack).await?;
            let socket = if at.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            hand(hook.as_ref(), handle_of(&socket))?;
            let stream = socket.connect(at).await?;
            let _ = stream.set_nodelay(true);
            Ok((wrap(stream, &relay).await?, at, other))
        }));
    }

    /// Carries out one output: the packet in `out[..len]` on the path the core
    /// named, or the event to the application. `from`: the source of the
    /// packet being answered, for [`To::Source`].
    async fn execute(&mut self, output: Owned, from: Option<SocketAddr>) {
        match output {
            Owned::Nothing => {}
            #[cfg(feature = "stream")]
            Owned::Frame {
                peer,
                context,
                kind,
                data,
                connected,
            } => {
                let now = self.now();
                self.channels.handle_frame(peer, context, kind, &data, now);
                if connected {
                    self.emit(context, ContextEvent::Connected { peer });
                }
            }
            Owned::Datagram {
                context,
                peer,
                data,
                relayed,
                connected,
            } => {
                if self.per_peer(&context) {
                    if connected {
                        self.emit(context, ContextEvent::Connected { peer });
                    }
                    self.receive_datagram(context, peer, data, relayed);
                } else {
                    // The application learns of the connection with the
                    // datagram itself.
                    self.emit(
                        context,
                        ContextEvent::Datagram {
                            peer,
                            data,
                            relayed,
                        },
                    );
                }
            }
            Owned::Node(event) => self.emit_node(event),
            Owned::Context(context, event) => {
                #[cfg(feature = "stream")]
                match event {
                    ContextEvent::Closed { peer, code, .. } => {
                        self.channels.session_closed(peer, context, code);
                    }
                    ContextEvent::ReopenFailed { peer, error } => {
                        self.channels.reopen_failed(peer, context, error);
                    }
                    _ => {}
                }
                if let ContextEvent::Closed {
                    peer,
                    code,
                    by_peer,
                } = event
                {
                    self.close_receiver(context, peer, SessionClosed { code, by_peer });
                }
                self.emit(context, event);
            }
            Owned::Transmit { to, len } => {
                // A packet for the relay over UDP, with no address for it: the
                // relay's host is resolved again, once this one is gone.
                let resolve = matches!(to, To::Relay(path) if !matches!(path, RelayPath::Tcp))
                    && self.relay_udp.is_none();
                let Some(packet) = self.out.get(..len) else {
                    return;
                };
                match to {
                    To::Source => {
                        if let Some(from) = from.or(self.last_from) {
                            self.stats.core_udp_outputs += 1;
                            send_udp(&self.udp, self.dual_stack, &mut self.stats, packet, from)
                                .await;
                        }
                    }
                    To::Direct(key) => {
                        if let Some(at) = key.as_direct().and_then(address::decode) {
                            self.stats.core_udp_outputs += 1;
                            send_udp(&self.udp, self.dual_stack, &mut self.stats, packet, at).await;
                        }
                    }
                    To::Relay(path) => {
                        let udp = match path {
                            RelayPath::Udp | RelayPath::Both => self.relay_udp,
                            // Dropped without an address in the other family:
                            // it is a keep-alive, carrying nothing.
                            RelayPath::UdpOther => self.relay_other,
                            RelayPath::Tcp => None,
                        };
                        if let Some(relay) = udp {
                            self.stats.core_udp_outputs += 1;
                            send_udp(&self.udp, self.dual_stack, &mut self.stats, packet, relay)
                                .await;
                        }
                        if matches!(path, RelayPath::Tcp | RelayPath::Both) {
                            self.stats.core_link_outputs += 1;
                            let mut framed = vec![0u8; packet.len() + 2];
                            if let Some(n) = framing::frame(packet, &mut framed) {
                                self.stats.frames_sent += 1;
                                write_link(
                                    &mut self.link,
                                    &mut self.stats,
                                    framed.get(..n).unwrap_or_default(),
                                )
                                .await;
                            }
                        }
                    }
                    To::RelayKeepAlive => {
                        self.stats.core_link_outputs += 1;
                        self.stats.keepalives_sent += 1;
                        write_link(&mut self.link, &mut self.stats, &KEEPALIVE).await;
                    }
                }
                if resolve {
                    self.resolve_relay();
                }
            }
        }
    }
}

/// The core's access for the driver's: `None` for a dial-only context, which
/// the core does not serve.
const fn core_access(access: &Access) -> Option<handshake::Access> {
    match access {
        Access::Everyone | Access::Admit(_) => Some(handshake::Access::Policy),
        Access::Bound(peer) => Some(handshake::Access::Bound(*peer)),
        Access::DialOnly => None,
    }
}

/// Sends a datagram; on a dual-stack socket, to an IPv4 address as the
/// IPv4-mapped IPv6 address the socket takes.
async fn send_udp(
    udp: &UdpSocket,
    dual_stack: bool,
    stats: &mut Stats,
    packet: &[u8],
    to: SocketAddr,
) {
    let to = match to.ip() {
        IpAddr::V4(v4) if dual_stack => SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), to.port()),
        _ => to,
    };
    if udp.send_to(packet, to).await.is_ok() {
        stats.udp_sent += 1;
        stats.udp_sent_bytes += packet.len() as u64;
    }
}

async fn write_link(link: &mut Option<LinkIo>, stats: &mut Stats, bytes: &[u8]) {
    if let Some(io) = link.as_mut()
        && io.stream.write_all(bytes).await.is_ok()
    {
        stats.link_sent_bytes += bytes.len() as u64;
    }
}

async fn read_link(link: &mut Option<LinkIo>, buf: &mut [u8]) -> std::io::Result<usize> {
    match link {
        Some(io) => io.stream.read(buf).await,
        None => std::future::pending().await,
    }
}

/// The link's stream for `relay`: the connection itself, or, when the relay
/// asks for it, TLS over it, with any certificate accepted.
#[allow(
    clippy::unused_async,
    reason = "awaits the TLS handshake with the feature"
)]
async fn wrap(stream: TcpStream, relay: &RelayLocation) -> std::io::Result<Box<dyn LinkStream>> {
    #[cfg(feature = "tls")]
    if relay.tls {
        let wrapped = crate::tls::connector()
            .connect(crate::tls::server_name(&relay.host), stream)
            .await?;
        return Ok(Box::new(wrapped));
    }
    let _ = relay;
    Ok(Box::new(stream))
}

/// A resolution of the relay's host under way: the host, and its answer.
type Resolving = Pin<Box<dyn Future<Output = (String, std::io::Result<RelayAddresses>)> + Send>>;

async fn poll_resolving(
    resolving: &mut Option<Resolving>,
) -> (String, std::io::Result<RelayAddresses>) {
    match resolving {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

async fn poll_connecting(connecting: &mut Option<Connecting>) -> std::io::Result<Linked> {
    match connecting {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::net::SocketAddr;

    use super::{interface_addresses, pick};

    fn a(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// The relay is resolved in both families: the first address the system
    /// gives is the one used, the first in the other family is kept for
    /// `RelayPath::UdpOther`; a socket without IPv6 keeps IPv4 alone.
    #[test]
    fn the_relay_is_resolved_in_both_families() {
        let resolved = [
            a("[2001:db8::1]:7400"),
            a("[2001:db8::2]:7400"),
            a("192.0.2.1:7400"),
        ];
        assert_eq!(
            pick(&resolved, true),
            Some((a("[2001:db8::1]:7400"), Some(a("192.0.2.1:7400"))))
        );
        assert_eq!(pick(&resolved, false), Some((a("192.0.2.1:7400"), None)));
        assert_eq!(
            pick(&[a("[::ffff:192.0.2.1]:7400")], true),
            Some((a("192.0.2.1:7400"), None)),
            "an IPv4-mapped address is IPv4"
        );
        assert_eq!(pick(&[a("[2001:db8::1]:7400")], false), None);
    }

    /// Scenario: the core receives every interface address. Every address of
    /// an interface that is not loopback is handed over, with the socket's
    /// port; IPv6 ones only on a dual-stack socket.
    #[test]
    fn every_interface_address_but_loopback_is_reported() {
        let expected: Vec<SocketAddr> = if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .filter(|interface| !interface.is_loopback())
            .map(|interface| SocketAddr::new(interface.ip(), 7500))
            .collect();
        assert_eq!(interface_addresses(7500, true), expected);
        let v4: Vec<SocketAddr> = expected.into_iter().filter(SocketAddr::is_ipv4).collect();
        assert_eq!(interface_addresses(7500, false), v4);
        assert!(
            interface_addresses(7500, true)
                .iter()
                .all(|address| !address.ip().is_loopback())
        );
        std::println!("interfaces: {:?}", interface_addresses(7500, true));
    }
}
