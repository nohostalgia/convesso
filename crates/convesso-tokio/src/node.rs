//! An endpoint on tokio: the [`Node`] handle and the task that owns the core.
//!
//! ```text
//!  Node (cloneable) --- commands ---> task: Endpoint<Server>  <--- one UDP socket, both families
//!  application <------ events (bounded) ----   |              <--- the relay's TCP link
//!                                              +-- sleep until the core's next deadline
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
//! at each deadline. It never waits on the application (`DESIGN.md §5`): while
//! the event channel is full, it stops reading the socket and the relay link,
//! and keeps its timers, acknowledgements, keep-alives and commands going.
//! Events its timers produce meanwhile wait aside, one per peer and kind, the
//! latest replacing the earlier, so an application that reads late sees the
//! latest state. In the per-peer delivery mode, datagrams and messages go to a
//! [`Receiver`] per peer instead, and the socket is always read.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant as Clock;

use convesso_core::dos::Source;
use convesso_core::endpoint::{
    Endpoint, Event, ExcludeError, HintTooLong, Output, Poll, RelayError, RelayPath, SendError,
    Target, To,
};
use convesso_core::handshake::ChannelBinding;
use convesso_core::handshake::{Admission, Decision, DialError, ResponderError};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::paths::{Candidate, PathInfo, PathKind};
use convesso_core::relay::Link;
use convesso_core::relay::framing::{self, Deframed, Deframer, KEEPALIVE, PREAMBLE};
use convesso_core::storage::Server;
use convesso_core::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Notify, mpsc, oneshot};

use crate::address;
use crate::entropy::{EntropyError, OsEntropy, SystemEntropy};
use crate::receiver::{ELEMENT_COST, Receiver, SessionClosed, Shared};

#[cfg(feature = "stream")]
use convesso_core::endpoint::FrameKind;
#[cfg(feature = "stream")]
use convesso_core::handshake::Context;
#[cfg(feature = "stream")]
use convesso_stream::config::Server as StreamServer;
#[cfg(feature = "stream")]
use convesso_stream::{Channels, Event as StreamEvent, Poll as StreamPoll};

/// The largest datagram a direct path is given: a UDP payload that fits a
/// 1,500-byte IPv6 path.
pub const DIRECT_PATH_MAX: usize = 1452;

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

/// How to start a node.
pub struct Config {
    /// The local UDP address to bind: `[::]:0` by default, a dual-stack
    /// socket; an IPv4 address binds IPv4 only.
    pub bind: SocketAddr,
    /// The application's context.
    pub context: Vec<u8>,
    /// The relay to pin, if any.
    pub relay: Option<RelayLocation>,
    /// How many events wait for the application before the node stops reading.
    pub events: usize,
    /// Whom to admit. Everyone, when unset.
    pub admission: Option<Box<dyn Admission + Send>>,
    /// Given every socket the node opens, before it is used.
    pub socket_hook: Option<SocketHook>,
    /// Where peers' messages and datagrams go: the event stream, or a
    /// [`Receiver`] per peer.
    pub delivery: Delivery,
}

/// Where peers' messages and datagrams go.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Delivery {
    /// To the event stream, with every other event.
    #[default]
    Events,
    /// To a [`Receiver`] per peer, opened with [`Node::receiver`], each
    /// holding at most `messages` bytes of messages and `datagrams` bytes of
    /// datagrams, every element costing its length plus
    /// [`crate::ELEMENT_COST`]. A peer's channel is granted only the free room
    /// of its receiver, so a receiver that is not read holds back its own
    /// sender alone (`DESIGN.md §8`). A datagram that does not fit, or for a
    /// peer with no receiver open, is dropped and counted in
    /// [`Stats::datagrams_dropped`].
    PerPeer {
        /// The message budget, at least the largest message's cost.
        messages: usize,
        /// The datagram budget.
        datagrams: usize,
    },
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            context: b"app".to_vec(),
            relay: None,
            events: 256,
            admission: None,
            socket_hook: None,
            delivery: Delivery::Events,
        }
    }
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
    /// The relay's host could not be resolved.
    Resolve(std::io::Error),
    /// The core refused the configuration.
    Core(ResponderError),
    /// The per-peer message budget is below the cost of the largest message,
    /// which could then never be delivered.
    Budget {
        /// The budget given.
        budget: usize,
        /// The cost of the largest message.
        needed: usize,
    },
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Entropy(error) => error.fmt(f),
            Self::Bind(error) => write!(f, "binding the UDP socket: {error}"),
            Self::Hook(error) => write!(f, "the socket hook: {error}"),
            Self::Resolve(error) => write!(f, "resolving the relay: {error}"),
            Self::Core(error) => write!(f, "the core: {error}"),
            Self::Budget { budget, needed } => write!(
                f,
                "a message budget of {budget} bytes is below the {needed} a largest message costs"
            ),
        }
    }
}

impl std::error::Error for StartError {}

/// Why a command failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    /// The core refused it, with its named error.
    Send(SendError),
    /// The hint is not a usable address.
    Hint(HintTooLong),
    /// The prefix could not be excluded, with the core's named error.
    Exclude(ExcludeError),
    /// The node's task has ended.
    Stopped,
    /// A receiver asked for while the node delivers to its event stream.
    NotPerPeer,
    /// A receiver asked for a peer that already has one open.
    ReceiverOpen,
    /// The stream layer refused a message, with its named error.
    #[cfg(feature = "stream")]
    Message(convesso_stream::SendError),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Send(error) => error.fmt(f),
            Self::Hint(error) => error.fmt(f),
            Self::Exclude(error) => error.fmt(f),
            Self::Stopped => f.write_str("the node has stopped"),
            Self::NotPerPeer => f.write_str("the node delivers to its event stream, not per peer"),
            Self::ReceiverOpen => f.write_str("the peer already has a receiver open"),
            #[cfg(feature = "stream")]
            Self::Message(error) => write!(f, "the message was refused: {error:?}"),
        }
    }
}

impl std::error::Error for NodeError {}

/// Something the application should know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    /// A first session with a peer.
    Connected {
        /// The peer.
        peer: PeerId,
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
    /// The relay session could not be opened, or ended.
    RelayUnavailable {
        /// Why.
        error: RelayError,
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
    /// Datagrams dropped in the per-peer mode: for a peer with no receiver
    /// open, or beyond its receiver's budget.
    pub datagrams_dropped: u64,
}

enum Command {
    Send(Address, Vec<u8>, oneshot::Sender<Result<(), NodeError>>),
    SendToPeer(PeerId, Vec<u8>, oneshot::Sender<Result<(), NodeError>>),
    Hint(PeerId, SocketAddr, oneshot::Sender<Result<(), NodeError>>),
    Reachable(bool),
    Close(PeerId, u16),
    ClosePeer(PeerId, u16),
    NetworkChanged,
    Stats(oneshot::Sender<Stats>),
    Path(PeerId, oneshot::Sender<Option<PathInfo>>),
    Candidates(oneshot::Sender<Vec<Candidate>>),
    Exclude(
        Vec<(IpAddr, u8)>,
        bool,
        oneshot::Sender<Result<(), NodeError>>,
    ),
    Binding(PeerId, oneshot::Sender<Option<ChannelBinding>>),
    RelayUdpProven(oneshot::Sender<bool>),
    Receiver(PeerId, oneshot::Sender<Result<Receiver, NodeError>>),
    #[cfg(feature = "stream")]
    SendMessage(Parked),
}

/// A handle on a running node. Cloneable; the node stops when every handle
/// and the [`Events`] are dropped.
#[derive(Clone)]
pub struct Node {
    commands: mpsc::Sender<Command>,
    local: SocketAddr,
    address: Address,
    dual_stack: bool,
}

/// The node's events, in order.
pub struct Events(mpsc::Receiver<NodeEvent>);

impl Events {
    /// The next event, or `None` once the node has stopped.
    pub async fn next(&mut self) -> Option<NodeEvent> {
        self.0.recv().await
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

    /// The path to `peer`, and how it got there; `None` without a session.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn path(&self, peer: PeerId) -> Result<Option<PathInfo>, NodeError> {
        let (reply, answer) = oneshot::channel();
        self.ask(Command::Path(peer, reply)).await?;
        answer.await.map_err(|_| NodeError::Stopped)
    }

    /// Whether UDP to the relay is proven now; otherwise the relay is reached
    /// over its TCP link, if at all.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn relay_udp_proven(&self) -> Result<bool, NodeError> {
        let (reply, answer) = oneshot::channel();
        self.ask(Command::RelayUdpProven(reply)).await?;
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
        self.ask(Command::Candidates(reply)).await?;
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
        self.ask(Command::Binding(peer, reply)).await?;
        answer.await.map_err(|_| NodeError::Stopped)
    }

    async fn ask(&self, command: Command) -> Result<(), NodeError> {
        self.commands
            .send(command)
            .await
            .map_err(|_| NodeError::Stopped)
    }

    async fn answer(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<(), NodeError>>) -> Command,
    ) -> Result<(), NodeError> {
        let (reply, answer) = oneshot::channel();
        self.ask(make(reply)).await?;
        answer.await.map_err(|_| NodeError::Stopped)?
    }

    /// Sends a datagram to the peer at `to`: through its session, or a new
    /// one, by the path the core chooses.
    ///
    /// # Errors
    ///
    /// The core's [`SendError`], or [`NodeError::Stopped`].
    pub async fn send(&self, to: Address, data: Vec<u8>) -> Result<(), NodeError> {
        self.answer(|reply| Command::Send(to, data, reply)).await
    }

    /// Sends a datagram to a peer by its identity: only while a session with
    /// it has keys, or its handshake is pending here.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    pub async fn send_to_peer(&self, to: PeerId, data: Vec<u8>) -> Result<(), NodeError> {
        self.answer(|reply| Command::SendToPeer(to, data, reply))
            .await
    }

    /// Gives the core a direct address for `peer`.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`]; an address is always short enough.
    pub async fn set_hint(&self, peer: PeerId, at: SocketAddr) -> Result<(), NodeError> {
        self.answer(|reply| Command::Hint(peer, at, reply)).await
    }

    /// Asks to stay reachable through the relay, keeping a link to it, or not.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn set_reachable(&self, reachable: bool) -> Result<(), NodeError> {
        self.ask(Command::Reachable(reachable)).await
    }

    /// Closes the session with `peer`, with `code`.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn close(&self, peer: PeerId, code: u16) -> Result<(), NodeError> {
        self.ask(Command::Close(peer, code)).await
    }

    /// Revokes `peer`: closes every session with it.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn close_peer(&self, peer: PeerId, code: u16) -> Result<(), NodeError> {
        self.ask(Command::ClosePeer(peer, code)).await
    }

    /// Tells the core the network changed: a reachable node replaces its
    /// relay link at once.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn network_changed(&self) -> Result<(), NodeError> {
        self.ask(Command::NetworkChanged).await
    }

    /// Sends a reliable message to the peer at `to` (feature `stream`): it
    /// arrives whole, once and in order, or the channel is reset. Waits while
    /// the channel's send buffer is full.
    ///
    /// # Errors
    ///
    /// [`NodeError::Message`] for a message that can never be sent, or
    /// [`NodeError::Stopped`].
    #[cfg(feature = "stream")]
    pub async fn send_message(&self, to: Address, data: Vec<u8>) -> Result<(), NodeError> {
        self.answer(|reply| Command::SendMessage((to.peer_id(), Some(to), data, reply)))
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
        self.answer(|reply| Command::SendMessage((to, None, data, reply)))
            .await
    }

    /// Opens the receiver of `peer`'s messages and datagrams, in the per-peer
    /// delivery mode; before its session exists, too. Open it when the peer
    /// connects: until then its messages wait in its channel, and its
    /// datagrams are dropped.
    ///
    /// # Errors
    ///
    /// [`NodeError::NotPerPeer`] in the event-stream mode,
    /// [`NodeError::ReceiverOpen`] while the peer has one open, or
    /// [`NodeError::Stopped`].
    pub async fn receiver(&self, peer: PeerId) -> Result<Receiver, NodeError> {
        let (reply, answer) = oneshot::channel();
        self.ask(Command::Receiver(peer, reply)).await?;
        answer.await.map_err(|_| NodeError::Stopped)?
    }

    /// What the node's sockets have carried so far.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`].
    pub async fn stats(&self) -> Result<Stats, NodeError> {
        let (reply, answer) = oneshot::channel();
        self.ask(Command::Stats(reply)).await?;
        answer.await.map_err(|_| NodeError::Stopped)
    }
}

/// Starts a node for `identity`, with entropy from the operating system.
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
    mut config: Config,
    mut entropy: E,
) -> Result<(Node, Events), StartError> {
    entropy.check().map_err(StartError::Entropy)?;
    #[cfg(feature = "stream")]
    if let Delivery::PerPeer { messages, .. } = config.delivery {
        use convesso_stream::config::StreamConfig;
        let needed = StreamServer::MAX_MESSAGE + ELEMENT_COST;
        if messages < needed {
            return Err(StartError::Budget {
                budget: messages,
                needed,
            });
        }
    }
    let address = *identity.address();
    let mut endpoint = Endpoint::<Server>::new(identity, &[config.context.as_slice()])
        .map_err(StartError::Core)?;
    let clock = Clock::now();
    let hook = config.socket_hook.take();
    let (udp, dual_stack) =
        bind_udp(config.bind, hook.as_ref()).map_err(|failure| match failure {
            Failure::Hook(error) => StartError::Hook(error),
            Failure::Socket(error) => StartError::Bind(error),
        })?;
    let local = udp.local_addr().map_err(StartError::Bind)?;
    let relay_udp = match &config.relay {
        Some(relay) => {
            endpoint
                .pin_relay(relay.address, Instant::from_millis(0))
                .map_err(StartError::Core)?;
            Some(
                resolve(&relay.host, dual_stack)
                    .await
                    .map_err(StartError::Resolve)?,
            )
        }
        None => None,
    };
    endpoint.set_local_addresses(&local_addresses(local, dual_stack));
    if let Some((primary, other)) = relay_udp {
        endpoint.set_relay_families(primary.is_ipv6(), other.is_some());
    }
    let (commands_tx, commands) = mpsc::channel(64);
    let (events_tx, events) = mpsc::channel(config.events.max(1));
    let task = Task {
        endpoint,
        context: std::mem::take(&mut config.context),
        policy: Policy(config.admission.take()),
        entropy,
        udp,
        dual_stack,
        relay: config.relay.take(),
        relay_udp: relay_udp.map(|(primary, _)| primary),
        relay_other: relay_udp.and_then(|(_, other)| other),
        link: None,
        connecting: None,
        events: events_tx,
        commands,
        stats: Stats::default(),
        clock,
        rx: vec![0; 2048],
        out: vec![0; 2048],
        link_rx: vec![0; 4096],
        waiting_room: false,
        hook,
        delivery: config.delivery,
        receivers: HashMap::new(),
        receivers_wake: Arc::new(Notify::new()),
        held: VecDeque::new(),
        #[cfg(feature = "stream")]
        channels: Box::new(match config.delivery {
            Delivery::Events => Channels::new(),
            Delivery::PerPeer { .. } => Channels::with_credit(),
        }),
        #[cfg(feature = "stream")]
        frame: vec![0; convesso_stream::frame::MAX_DATA_LEN],
        #[cfg(feature = "stream")]
        parked: Vec::new(),
    };
    tokio::spawn(task.run());
    Ok((
        Node {
            commands: commands_tx,
            local,
            address,
            dual_stack,
        },
        Events(events),
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
    host: &str,
    dual_stack: bool,
) -> std::io::Result<(SocketAddr, Option<SocketAddr>)> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host(host).await?.collect();
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

/// The application's policy, or everyone.
struct Policy(Option<Box<dyn Admission + Send>>);

impl Admission for Policy {
    fn admit(&mut self, peer: &PeerId, context: &[u8]) -> Decision {
        match &mut self.0 {
            Some(policy) => policy.admit(peer, context),
            None => Decision::Accept { psk: None },
        }
    }

    fn psk(&mut self, peer: &PeerId, context: &[u8]) -> Option<convesso_core::handshake::Psk> {
        self.0.as_mut().and_then(|policy| policy.psk(peer, context))
    }
}

struct LinkIo {
    stream: TcpStream,
    deframer: Box<Deframer>,
}

type Connecting = Pin<
    Box<dyn Future<Output = std::io::Result<(TcpStream, SocketAddr, Option<SocketAddr>)>> + Send>,
>;

/// An output of the core, owning nothing, so that the task is free again.
enum Owned {
    Transmit {
        to: To,
        len: usize,
    },
    Event(NodeEvent),
    /// A datagram, with whether it also confirmed a first session: in the
    /// per-peer mode, the connection is told on the event stream apart.
    Datagram {
        peer: PeerId,
        data: Vec<u8>,
        relayed: bool,
        connected: bool,
    },
    /// A stream frame, for the channels.
    #[cfg(feature = "stream")]
    Frame {
        peer: PeerId,
        context: Context,
        kind: FrameKind,
        data: Vec<u8>,
        connected: bool,
    },
    Nothing,
}

fn own(output: Output<'_>) -> Owned {
    match output {
        Output::Transmit { to, len } => Owned::Transmit { to, len },
        #[cfg(feature = "stream")]
        Output::Event(Event::Frame {
            peer,
            context,
            kind,
            data,
            connected,
            ..
        }) => Owned::Frame {
            peer,
            context,
            kind,
            data: data.to_vec(),
            connected,
        },
        Output::Event(event) => owned_event(event),
        Output::Nothing => Owned::Nothing,
    }
}

/// A core event the task keeps: a datagram with its connection flag, any
/// other as the application's event.
fn owned_event(event: Event<'_>) -> Owned {
    match event {
        Event::Datagram {
            peer,
            data,
            relayed,
            connected,
            ..
        } => Owned::Datagram {
            peer,
            data: data.to_vec(),
            relayed,
            connected,
        },
        event => event_of(event).map_or(Owned::Nothing, Owned::Event),
    }
}

fn event_of(event: Event<'_>) -> Option<NodeEvent> {
    Some(match event {
        Event::Connected { peer, .. } => NodeEvent::Connected { peer },
        Event::Datagram {
            peer,
            data,
            relayed,
            ..
        } => NodeEvent::Datagram {
            peer,
            data: data.to_vec(),
            relayed,
        },
        Event::Closed {
            peer,
            code,
            by_peer,
            ..
        } => NodeEvent::Closed {
            peer,
            code,
            by_peer,
        },
        Event::ReopenFailed { peer, error, .. } => NodeEvent::ReopenFailed { peer, error },
        Event::PeerNotAtRelay { peer } => NodeEvent::PeerNotAtRelay { peer },
        Event::ObservedAddress { link, address } => NodeEvent::ObservedAddress { link, address },
        Event::RelayUnavailable { error } => NodeEvent::RelayUnavailable { error },
        Event::PathChanged { peer, path, .. } => NodeEvent::PathChanged { peer, path },
        // Without the stream layer, a frame is not the application's: only
        // the connection it may confirm is.
        Event::Frame {
            peer, connected, ..
        } => {
            if !connected {
                return None;
            }
            NodeEvent::Connected { peer }
        }
        // Only the relay context accepts payloads, and the core consumes them.
        Event::Payload { .. } => return None,
    })
}

struct Task<E> {
    endpoint: Endpoint<Server>,
    context: Vec<u8>,
    policy: Policy,
    entropy: E,
    udp: UdpSocket,
    dual_stack: bool,
    relay: Option<RelayLocation>,
    /// The relay's UDP address the node uses, and the one in the other
    /// family, where `RelayPath::UdpOther` goes.
    relay_udp: Option<SocketAddr>,
    relay_other: Option<SocketAddr>,
    link: Option<LinkIo>,
    connecting: Option<Connecting>,
    events: mpsc::Sender<NodeEvent>,
    commands: mpsc::Receiver<Command>,
    stats: Stats,
    clock: Clock,
    rx: Vec<u8>,
    out: Vec<u8>,
    link_rx: Vec<u8>,
    /// Whether messages wait in the channels for room in the event channel:
    /// the task then also wakes when the application reads.
    waiting_room: bool,
    /// Given every TCP connection to the relay before it connects.
    hook: Option<SocketHook>,
    delivery: Delivery,
    /// The open receivers, in the per-peer mode.
    receivers: HashMap<PeerId, Arc<Shared>>,
    /// Woken by a receiver that freed room or was dropped.
    receivers_wake: Arc<Notify>,
    /// Events waiting for room in the event channel, in order; those of a
    /// peer and kind coalesced, the latest replacing the earlier.
    held: VecDeque<(Option<Held>, NodeEvent)>,
    /// The message channels, and the frame they write.
    #[cfg(feature = "stream")]
    channels: Box<Channels<StreamServer>>,
    #[cfg(feature = "stream")]
    frame: Vec<u8>,
    /// Messages waiting for room in their channel, in order.
    #[cfg(feature = "stream")]
    parked: Vec<Parked>,
}

/// A message for a peer, with its address when known and the sender's reply.
#[cfg(feature = "stream")]
type Parked = (
    PeerId,
    Option<Address>,
    Vec<u8>,
    oneshot::Sender<Result<(), NodeError>>,
);

/// What woke the task.
enum Wake {
    Udp(std::io::Result<(usize, SocketAddr)>),
    Link(std::io::Result<usize>),
    Connected(std::io::Result<(TcpStream, SocketAddr, Option<SocketAddr>)>),
    Command(Option<Command>),
    Deadline,
    /// The application read: room for an event that waited.
    Room,
    /// A receiver freed room, or was dropped.
    Receivers,
}

/// What a waiting event is coalesced by: its peer, or none for the relay's
/// reports, and its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held(Option<PeerId>, Kind);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Connected,
    Closed,
    ReopenFailed,
    NotAtRelay,
    Observed(Link),
    RelayUnavailable,
    PathChanged,
    #[cfg(feature = "stream")]
    ChannelReset,
}

/// The key an event is coalesced by; `None` for one that carries data.
fn held_key(event: &NodeEvent) -> Option<Held> {
    Some(match *event {
        NodeEvent::Connected { peer } => Held(Some(peer), Kind::Connected),
        NodeEvent::Closed { peer, .. } => Held(Some(peer), Kind::Closed),
        NodeEvent::ReopenFailed { peer, .. } => Held(Some(peer), Kind::ReopenFailed),
        NodeEvent::PeerNotAtRelay { peer } => Held(Some(peer), Kind::NotAtRelay),
        NodeEvent::ObservedAddress { link, .. } => Held(None, Kind::Observed(link)),
        NodeEvent::RelayUnavailable { .. } => Held(None, Kind::RelayUnavailable),
        NodeEvent::PathChanged { peer, .. } => Held(Some(peer), Kind::PathChanged),
        #[cfg(feature = "stream")]
        NodeEvent::ChannelReset { peer, .. } => Held(Some(peer), Kind::ChannelReset),
        NodeEvent::Datagram { .. } => return None,
        #[cfg(feature = "stream")]
        NodeEvent::Message { .. } => return None,
    })
}

impl<E: SystemEntropy> Task<E> {
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
            let reading = self.reading();
            let waiting = self.waiting_room || !self.held.is_empty();
            let wake = tokio::select! {
                r = self.udp.recv_from(&mut self.rx), if reading => Wake::Udp(r),
                r = read_link(&mut self.link, &mut self.link_rx), if reading && self.link.is_some() => Wake::Link(r),
                r = poll_connecting(&mut self.connecting), if self.connecting.is_some() => Wake::Connected(r),
                c = self.commands.recv() => Wake::Command(c),
                () = &mut sleep, if armed.is_some() => Wake::Deadline,
                () = room(&self.events, waiting) => Wake::Room,
                () = self.receivers_wake.notified() => Wake::Receivers,
            };
            match wake {
                Wake::Udp(Ok((len, from))) => self.udp_packet(len, from).await,
                Wake::Udp(Err(_)) => {}
                Wake::Link(Ok(0) | Err(_)) => {
                    self.link = None;
                    let now = self.now();
                    self.endpoint.relay_link_closed(now);
                }
                Wake::Link(Ok(len)) => self.link_bytes(len).await,
                Wake::Connected(result) => self.connected(result).await,
                Wake::Command(None) => return,
                Wake::Command(Some(command)) => self.command(command).await,
                // An elapsed timer is ready at every poll: armed again below.
                Wake::Deadline => armed = None,
                Wake::Room => self.flush(),
                Wake::Receivers => self.settle_receivers(),
            }
            self.take_ready().await;
            deadline = self.drain().await;
            if self.events.is_closed() && self.commands.is_closed() {
                return;
            }
        }
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
            if self.reading()
                && let Ok((len, from)) = self.udp.try_recv_from(&mut self.rx)
            {
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
                &mut self.policy,
                &mut self.entropy,
                &mut self.out,
            ))
        } else {
            let (source, source_len) = address::encode(from);
            own(self.endpoint.handle_packet(
                packet,
                Source::Direct(source.get(..source_len).unwrap_or_default()),
                now,
                &mut self.policy,
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
                &mut self.policy,
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

    async fn connected(
        &mut self,
        result: std::io::Result<(TcpStream, SocketAddr, Option<SocketAddr>)>,
    ) {
        self.connecting = None;
        let now = self.now();
        let opened = match result {
            Ok((mut stream, at, other)) => {
                let _ = stream.set_nodelay(true);
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

    async fn command(&mut self, command: Command) {
        let now = self.now();
        match command {
            Command::Send(to, data, reply) => {
                let result = self.endpoint.send(
                    Target::Address(&to),
                    &self.context,
                    &data,
                    DIRECT_PATH_MAX,
                    now,
                    &mut self.policy,
                    &mut self.entropy,
                    &mut self.out,
                );
                self.sent(result, reply).await;
            }
            Command::SendToPeer(to, data, reply) => {
                let result = self.endpoint.send(
                    Target::Peer(to),
                    &self.context,
                    &data,
                    DIRECT_PATH_MAX,
                    now,
                    &mut self.policy,
                    &mut self.entropy,
                    &mut self.out,
                );
                self.sent(result, reply).await;
            }
            Command::Hint(peer, at, reply) => {
                let (bytes, len) = address::encode(at);
                let result = self
                    .endpoint
                    .set_hint(peer, bytes.get(..len).unwrap_or_default(), now)
                    .map_err(NodeError::Hint);
                let _ = reply.send(result);
            }
            Command::Reachable(on) => self.endpoint.set_reachable(on, now),
            Command::Close(peer, code) => {
                let output =
                    own(self
                        .endpoint
                        .close(peer, &self.context, code, now, &mut self.out));
                self.execute(output, None).await;
                #[cfg(feature = "stream")]
                self.close_channel(peer, code);
                self.close_receiver(
                    peer,
                    SessionClosed {
                        code,
                        by_peer: false,
                    },
                );
            }
            Command::ClosePeer(peer, code) => {
                self.endpoint.close_peer(peer, code);
                #[cfg(feature = "stream")]
                self.close_channel(peer, code);
                self.close_receiver(
                    peer,
                    SessionClosed {
                        code,
                        by_peer: false,
                    },
                );
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
            Command::Binding(peer, reply) => {
                let _ = reply.send(self.endpoint.channel_binding(&peer, &self.context));
            }
            Command::Stats(reply) => {
                let _ = reply.send(self.stats);
            }
            Command::Path(peer, reply) => {
                let _ = reply.send(self.endpoint.path_info(&peer, &self.context));
            }
            Command::RelayUdpProven(reply) => {
                let _ = reply.send(self.endpoint.relay_udp_proven(now));
            }
            Command::Receiver(peer, reply) => {
                let _ = reply.send(self.open_receiver(peer, now));
            }
            #[cfg(feature = "stream")]
            Command::SendMessage(parked) => {
                // Behind those already waiting for the same peer: in order.
                if self.parked.iter().any(|(p, ..)| *p == parked.0) {
                    self.parked.push(parked);
                } else {
                    self.offer(parked, now);
                }
            }
        }
    }

    /// This side closed the session with `peer`. The core raises no event for
    /// it: the channel is reset here, as the peer's is on the close
    /// (DESIGN.md §8).
    #[cfg(feature = "stream")]
    fn close_channel(&mut self, peer: PeerId, code: u16) {
        if let Ok(context) = Context::new(&self.context) {
            self.channels.session_closed(peer, context, code);
        }
    }

    /// Whether to read the socket and the relay link: in the event-stream
    /// mode, only while the event channel has room and nothing waits aside,
    /// since datagrams cannot be coalesced; always in the per-peer mode,
    /// whose event stream carries none.
    fn reading(&self) -> bool {
        match self.delivery {
            Delivery::Events => self.held.is_empty() && self.events.capacity() > 0,
            Delivery::PerPeer { .. } => true,
        }
    }

    /// Hands an event to the application without ever waiting for it: into
    /// the event channel, or aside while it is full (`DESIGN.md §5`).
    fn emit(&mut self, event: NodeEvent) {
        let event = if self.held.is_empty() {
            match self.events.try_send(event) {
                Ok(()) | Err(TrySendError::Closed(_)) => return,
                Err(TrySendError::Full(event)) => event,
            }
        } else {
            event
        };
        let key = held_key(&event);
        if key.is_some() {
            self.held.retain(|(k, _)| *k != key);
        }
        self.held.push_back((key, event));
    }

    /// Moves what waits aside into the event channel, in order, as far as
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

    /// Opens `peer`'s receiver, granting its channel the message budget. A
    /// receiver dropped and not yet settled is settled first.
    fn open_receiver(&mut self, peer: PeerId, now: Instant) -> Result<Receiver, NodeError> {
        let Delivery::PerPeer { messages, .. } = self.delivery else {
            return Err(NodeError::NotPerPeer);
        };
        if let Some(shared) = self.receivers.get(&peer) {
            if !shared.lock().dropped {
                return Err(NodeError::ReceiverOpen);
            }
            self.settle_receivers_at(now);
        }
        let shared = Shared::new(self.receivers_wake.clone());
        #[cfg(feature = "stream")]
        self.channels
            .grant(peer, &self.context, messages)
            .map_err(NodeError::Message)?;
        #[cfg(not(feature = "stream"))]
        let _ = messages;
        self.receivers.insert(peer, shared.clone());
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
        for (&peer, shared) in &self.receivers {
            #[cfg_attr(not(feature = "stream"), allow(unused_mut))]
            let mut state = shared.lock();
            if state.dropped {
                dropped.push(peer);
                continue;
            }
            #[cfg(feature = "stream")]
            {
                let freed = std::mem::take(&mut state.freed);
                drop(state);
                if freed > 0 {
                    let _ = self.channels.grant(peer, &self.context, freed);
                }
            }
        }
        for peer in dropped {
            self.receivers.remove(&peer);
            #[cfg(feature = "stream")]
            if let Ok(context) = Context::new(&self.context) {
                self.channels.reset_here(peer, context, now);
            }
        }
        #[cfg(not(feature = "stream"))]
        let _ = now;
    }

    /// The session with `peer` ended: its receiver says so once it has been
    /// read up to here, and stays closed.
    fn close_receiver(&mut self, peer: PeerId, closed: SessionClosed) {
        if let Some(shared) = self.receivers.remove(&peer) {
            shared.lock().closed.get_or_insert(closed);
            shared.closed();
        }
    }

    /// A datagram, in the per-peer mode: to its receiver, or dropped.
    fn receive_datagram(&mut self, peer: PeerId, data: Vec<u8>, relayed: bool) {
        let Delivery::PerPeer { datagrams, .. } = self.delivery else {
            return;
        };
        if let Some(shared) = self.receivers.get(&peer) {
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

    /// A message, in the per-peer mode: to its receiver, whose room the
    /// channel's credit reserved.
    #[cfg(feature = "stream")]
    fn receive_message(&mut self, peer: PeerId, data: Vec<u8>) {
        // Credit is granted only for an open receiver, and goes with it: a
        // message for none was meant for one just dropped, whose channel is
        // about to be reset.
        if let Some(shared) = self.receivers.get(&peer) {
            let mut state = shared.lock();
            if !state.dropped {
                state.held += data.len() + ELEMENT_COST;
                state.items.push_back(crate::receiver::Item::Message(data));
                drop(state);
                shared.messages_ready();
            }
        }
    }

    /// A channel reset, in the per-peer mode: to its receiver after the
    /// messages before it, and the channel granted the receiver's free room
    /// again, since the reset left it no credit.
    #[cfg(feature = "stream")]
    fn receive_reset(&mut self, peer: PeerId, reason: convesso_stream::Reason) {
        let Delivery::PerPeer { messages, .. } = self.delivery else {
            return;
        };
        let Some(shared) = self.receivers.get(&peer) else {
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
        let _ = self.channels.grant(peer, &self.context, room);
    }

    /// Offers a message to its channel: accepted or refused, the sender is
    /// answered; without room, it waits for the channel's `Writable`.
    #[cfg(feature = "stream")]
    fn offer(&mut self, parked: Parked, now: Instant) -> bool {
        let (peer, address, data, reply) = parked;
        // A sender that went away no longer wants its message sent.
        if reply.is_closed() {
            return true;
        }
        let result = self.channels.send_message(
            peer,
            address.as_ref(),
            &self.context,
            &data,
            now,
            &mut self.entropy,
        );
        match result {
            Err(convesso_stream::SendError::Full) => {
                self.parked.push((peer, address, data, reply));
                false
            }
            other => {
                let _ = reply.send(other.map_err(NodeError::Message));
                true
            }
        }
    }

    /// Room opened in `peer`'s channel: offers its waiting messages, in order.
    #[cfg(feature = "stream")]
    fn retry_parked(&mut self, peer: PeerId, now: Instant) {
        let (mine, others): (Vec<_>, Vec<_>) = std::mem::take(&mut self.parked)
            .into_iter()
            .partition(|(p, ..)| *p == peer);
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
            // A message is handed out only when the application can take it:
            // otherwise the channel keeps it and its window closes.
            let deliver = match self.delivery {
                Delivery::Events => self.held.is_empty() && self.events.capacity() > 0,
                Delivery::PerPeer { .. } => true,
            };
            self.waiting_room = !deliver;
            let output = match self.channels.poll(now, deliver, &mut self.frame) {
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
                        &mut self.policy,
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
                        &mut self.policy,
                        &mut self.entropy,
                        &mut self.out,
                    )
                    .map_or(Owned::Nothing, own),
                StreamPoll::Event(StreamEvent::Message { peer, data, .. }) => {
                    let data = data.to_vec();
                    if matches!(self.delivery, Delivery::PerPeer { .. }) {
                        self.receive_message(peer, data);
                        Owned::Nothing
                    } else {
                        Owned::Event(NodeEvent::Message { peer, data })
                    }
                }
                StreamPoll::Event(StreamEvent::Reset { peer, reason, .. }) => {
                    if matches!(self.delivery, Delivery::PerPeer { .. }) {
                        self.receive_reset(peer, reason);
                        Owned::Nothing
                    } else {
                        Owned::Event(NodeEvent::ChannelReset { peer, reason })
                    }
                }
                StreamPoll::Event(StreamEvent::Writable { peer, .. }) => {
                    self.retry_parked(peer, now);
                    Owned::Nothing
                }
                StreamPoll::Wait(at) => return (Some(at), worked),
                StreamPoll::Idle => return (None, worked),
            };
            worked = true;
            self.execute(output, None).await;
        }
    }

    /// Calls the core until it has nothing due; returns its next deadline.
    async fn drain_core(&mut self) -> Option<Instant> {
        loop {
            let now = self.now();
            let poll = self
                .endpoint
                .poll(now, &mut self.policy, &mut self.entropy, &mut self.out);
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
        self.connecting = Some(Box::pin(async move {
            let (at, other) = resolve(&relay.host, dual_stack).await?;
            let socket = if at.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            hand(hook.as_ref(), handle_of(&socket))?;
            let stream = socket.connect(at).await?;
            Ok((stream, at, other))
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
                    let _ = self.events.send(NodeEvent::Connected { peer }).await;
                }
            }
            Owned::Datagram {
                peer,
                data,
                relayed,
                connected,
            } => {
                if matches!(self.delivery, Delivery::PerPeer { .. }) {
                    if connected {
                        self.emit(NodeEvent::Connected { peer });
                    }
                    self.receive_datagram(peer, data, relayed);
                } else {
                    // The application learns of the connection with the
                    // datagram itself.
                    self.emit(NodeEvent::Datagram {
                        peer,
                        data,
                        relayed,
                    });
                }
            }
            Owned::Event(event) => {
                #[cfg(feature = "stream")]
                if let Ok(context) = Context::new(&self.context) {
                    match event {
                        NodeEvent::Closed { peer, code, .. } => {
                            self.channels.session_closed(peer, context, code);
                        }
                        NodeEvent::ReopenFailed { peer, error } => {
                            self.channels.reopen_failed(peer, context, error);
                        }
                        _ => {}
                    }
                }
                if matches!(self.delivery, Delivery::PerPeer { .. })
                    && let NodeEvent::Closed {
                        peer,
                        code,
                        by_peer,
                    } = event
                {
                    self.close_receiver(peer, SessionClosed { code, by_peer });
                }
                self.emit(event);
            }
            Owned::Transmit { to, len } => {
                let Some(packet) = self.out.get(..len) else {
                    return;
                };
                match to {
                    To::Source => {
                        if let Some(from) = from {
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
            }
        }
    }
}

/// Resolves once the event channel has room, when `waiting`; never otherwise.
async fn room(events: &mpsc::Sender<NodeEvent>, waiting: bool) {
    if waiting {
        // The permit is dropped at once: only the wake is wanted.
        let _ = events.reserve().await;
    } else {
        std::future::pending::<()>().await;
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

async fn poll_connecting(
    connecting: &mut Option<Connecting>,
) -> std::io::Result<(TcpStream, SocketAddr, Option<SocketAddr>)> {
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
