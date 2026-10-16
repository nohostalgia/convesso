//! The driver: a [`Runner`] that owns the relay link and drives the core, a
//! [`Node`] handle for the application, its [`Events`], and a [`Context`]
//! handle with its [`ContextEvents`] for each context the application opens.
//!
//! ```text
//! Context::send     lock link_out -> lock inner -> core.send
//!                     -> UDP: the datagram socket, through &self
//!                     -> TCP: framed into link_out, for the runner
//! Runner::run       select(datagram in | link connect or read | core deadline | signal)
//!                     lock inner -> core.handle / core.poll -> send, write the link
//! Events::next      the node's oldest event
//! ContextEvents::next  the context's oldest event, from the integrator's slot
//! ```
//!
//! The order of the locks (link_out, then inner, then a context's slot) is the
//! same everywhere, and the runner never waits for link_out while it holds
//! inner: no deadlock. The runner never stops reading for the application: a
//! datagram for a context whose queue has no room is dropped and counted; a
//! context's messages wait in their channel until its queue has room.

use core::cell::RefCell;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use convesso_core::dos::{Source, decode_ip, encode_ip};
use convesso_core::endpoint::{Endpoint, Output, Poll, RelayPath, Target, To};
use convesso_core::handshake::Context as Name;
use convesso_core::handshake::{self, Admission, ChannelBinding, Decision, Psk, ResponderError};
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::paths::{Candidate, PathInfo};
use convesso_core::relay::Link;
use convesso_core::relay::framing::{self, Deframed, Deframer, KEEPALIVE, MAX_FRAME, PREAMBLE};
use convesso_core::storage::{Config as Tables, Table};
use convesso_core::time::Instant;
use embassy_futures::select::{Either4, select, select4};
use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::{Mutex, MutexGuard};
use embassy_sync::signal::Signal;
use embassy_time::Timer;

use crate::events::{
    ContextEvent, ENTRIES, Event, EventQueue, HELD, NODE_ENTRIES, NODE_HELD, NodeError, NodeEvent,
    from_core,
};
use crate::rng::{Checked, RngFailed, SecureRng};
use crate::socket::{Datagrams, Interfaces, Streams, canonical};

/// The largest datagram a direct path is given: a UDP payload that fits a
/// 1,500-byte IPv6 path.
pub const DIRECT_PATH_MAX: usize = 1452;

/// The output buffer: a first contact with a payload, or a relay forward
/// around the largest packet. Also the largest event.
pub(crate) const OUT_LEN: usize = 2048;

/// A size for a context's event buffer: one event of the largest size and a
/// thousand bytes of others.
pub const EVENTS_LEN: usize = OUT_LEN + 1024;

/// The code a context's sessions are closed with when its handle is dropped
/// without [`Context::close_context`]: the core's default code.
pub const DROPPED: u16 = 1;

/// The most interface addresses reported to the core.
const LOCAL_MAX: usize = 8;

/// Where the relay is: its key, which is what is trusted, and its addresses.
/// No name is resolved: an integrator whose network has a name server resolves
/// the relay's name itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLocation {
    /// The relay's address (its key).
    pub address: Address,
    /// The address its UDP and its TCP link are reached at.
    pub primary: SocketAddr,
    /// Its address in the other family, if any: where the question over the
    /// other family goes.
    pub other: Option<SocketAddr>,
}

/// How to start the driver. It serves no context until the application opens
/// one with [`Node::context`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Config {
    /// The relay to pin, if any.
    pub relay: Option<RelayLocation>,
}

/// Who may reach this node in a context.
#[derive(Default)]
pub enum Access<'d> {
    /// Every peer.
    #[default]
    Everyone,
    /// The peers this policy admits, asked for each first contact.
    Admit(&'d mut dyn Admission),
    /// This peer alone: a first contact from any other meets silence.
    Bound(PeerId),
    /// No one: the context is not served, and only dialled in.
    DialOnly,
}

/// How to open a context. Every buffer is the integrator's.
pub struct ContextOptions<'d, M: RawMutex> {
    /// Who may reach this node in it.
    pub access: Access<'d>,
    /// Where its events wait for the application, datagrams' and messages'
    /// data included: at least one largest datagram, or message, and some.
    pub events: &'d mut [u8],
    /// Its state, a `static` on a microcontroller: one per context open at
    /// once.
    pub slot: &'d ContextSlot<'d, M>,
    /// With the `stream` feature, delivery credit: a peer's messages are
    /// handed out only as far as [`Context::grant`] allows, so that a peer the
    /// application takes slowly holds back only its own sender
    /// (`DESIGN.md §8`).
    #[cfg(feature = "stream")]
    pub credit: bool,
    /// Its largest message, at most the `Mcu` configuration's; that one when
    /// unset (feature `stream`).
    #[cfg(feature = "stream")]
    pub max_message: Option<usize>,
}

/// A context's state, which its handle, its events and the runner share:
/// given by the integrator when the context is opened.
pub struct ContextSlot<'d, M: RawMutex> {
    state: BlockingMutex<M, RefCell<Option<SlotState<'d>>>>,
    /// An event was queued, or the context closed.
    ready: Signal<M, ()>,
    /// Room opened in one of its channels' send buffers (feature `stream`).
    #[cfg(feature = "stream")]
    writable: Signal<M, ()>,
}

struct SlotState<'d> {
    events: EventQueue<'d, ENTRIES, HELD>,
    /// The handle asked for the context to be closed, with this code.
    close: Option<u16>,
    /// The context is closed: its events end once read.
    closed: bool,
}

impl<M: RawMutex> Default for ContextSlot<'_, M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'d, M: RawMutex> ContextSlot<'d, M> {
    /// An empty slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: BlockingMutex::new(RefCell::new(None)),
            ready: Signal::new(),
            #[cfg(feature = "stream")]
            writable: Signal::new(),
        }
    }

    /// `f` on the state, if the slot is in use.
    fn with<R>(&self, f: impl FnOnce(&mut SlotState<'d>) -> R) -> Option<R> {
        self.state.lock(|state| state.borrow_mut().as_mut().map(f))
    }

    /// Queues an event; returns whether it was dropped for want of room.
    fn push(&self, event: Event<'_>) -> bool {
        let dropped = self
            .with(|state| state.events.push_or_hold(event))
            .unwrap_or(false);
        self.ready.signal(());
        dropped
    }
}

/// Why the driver did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    /// The hardware generator could not be read.
    Rng(RngFailed),
    /// The core refused the configuration.
    Core(ResponderError),
}

impl core::fmt::Display for StartError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rng(error) => error.fmt(f),
            Self::Core(error) => write!(f, "the core: {error:?}"),
        }
    }
}

impl core::error::Error for StartError {}

/// What the driver's sockets carried, counted where they are written: what an
/// idle device's traffic is measured with.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Datagrams sent.
    pub datagrams_sent: u32,
    /// Datagrams the core output that the socket could not send.
    pub datagrams_not_sent: u32,
    /// Packets written on the relay link, framed.
    pub link_frames_sent: u32,
    /// Keep-alives written on the relay link.
    pub keepalives_sent: u32,
    /// Datagrams dropped for a context whose events had no room.
    pub datagrams_dropped: u32,
}

impl Stats {
    fn count(&mut self, sent: Result<(), crate::socket::SocketError>) {
        match sent {
            Ok(()) => self.datagrams_sent += 1,
            Err(_) => self.datagrams_not_sent += 1,
        }
    }
}

impl SecureRng for &mut dyn SecureRng {
    fn try_fill(&mut self, dest: &mut [u8]) -> Result<(), RngFailed> {
        (**self).try_fill(dest)
    }
}

/// The message channels' configuration (feature `stream`).
#[cfg(feature = "stream")]
type StreamConfig = convesso_stream::config::Mcu;

/// The largest message of the `Mcu` stream configuration.
#[cfg(feature = "stream")]
const MAX_MESSAGE: usize = <StreamConfig as convesso_stream::config::StreamConfig>::MAX_MESSAGE;

/// An open context, as the driver keeps it.
struct Open<'d, M: RawMutex> {
    slot: &'d ContextSlot<'d, M>,
    policy: Option<&'d mut dyn Admission>,
    #[cfg(feature = "stream")]
    max_message: usize,
}

/// The open contexts, in a table of the storage profile's.
type Contexts<'d, M, T> = <T as Tables>::Contexts<Name, Open<'d, M>>;

/// The core's one admission: each context's question goes to its own
/// policy; a context without one admits everyone (its access may still bind
/// it to one peer, which the core checks first).
struct Policies<'a, 'd, M: RawMutex, T: Tables>(&'a mut Contexts<'d, M, T>);

impl<'d, M: RawMutex, T: Tables> Policies<'_, 'd, M, T> {
    fn of(&mut self, context: &[u8]) -> Option<&mut (dyn Admission + 'd)> {
        let context = Name::new(context).ok()?;
        self.0
            .get_mut(&context)
            .and_then(|open| open.policy.as_deref_mut())
    }
}

impl<M: RawMutex, T: Tables> Admission for Policies<'_, '_, M, T> {
    fn admit(&mut self, peer: &PeerId, context: &[u8]) -> Decision {
        match self.of(context) {
            Some(policy) => policy.admit(peer, context),
            None => Decision::Accept { psk: None },
        }
    }

    fn psk(&mut self, peer: &PeerId, context: &[u8]) -> Option<Psk> {
        self.of(context)
            .and_then(|policy| policy.psk(peer, context))
    }
}

/// What the core and its buffers are, behind one lock.
struct Inner<'d, M: RawMutex, T: Tables> {
    endpoint: Endpoint<T>,
    contexts: Contexts<'d, M, T>,
    entropy: Checked<&'d mut dyn SecureRng>,
    out: [u8; OUT_LEN],
    /// The node's own events.
    events: EventQueue<'d, NODE_ENTRIES, NODE_HELD>,
    relay: Option<RelayLocation>,
    /// The source of the packet handled last, for `To::Source`.
    last_from: Option<SocketAddr>,
    /// Whether the runner owes the core its interfaces again: the network
    /// changed, or excluded prefixes were replaced.
    report_interfaces: bool,
    stats: Stats,
    /// The message channels, and the frame they write (feature `stream`).
    #[cfg(feature = "stream")]
    channels: convesso_stream::Channels<StreamConfig>,
    #[cfg(feature = "stream")]
    frame: [u8; convesso_stream::frame::MAX_DATA_LEN],
}

/// Calls the core with the contexts' policies: `$call` is a method of the
/// endpoint taking the admission, the entropy and the output buffer last.
macro_rules! with_policies {
    ($inner:expr, $method:ident($($arg:expr),* $(,)?)) => {{
        let inner = &mut *$inner;
        inner.endpoint.$method(
            $($arg,)*
            &mut Policies::<M, T>(&mut inner.contexts),
            &mut inner.entropy,
            &mut inner.out,
        )
    }};
}

impl<'d, M: RawMutex, T: Tables> Inner<'d, M, T> {
    /// Hands an event to the node's queue or to its context's; a datagram
    /// that finds no room is dropped and counted, and an event of a context
    /// no longer open is dropped.
    fn deliver(&mut self, node_ready: &Signal<M, ()>, context: Option<Name>, event: Event<'_>) {
        match context {
            None => {
                self.events.push_or_hold(event);
                node_ready.signal(());
            }
            Some(context) => {
                if let Some(open) = self.contexts.get(&context)
                    && open.slot.push(event)
                {
                    self.stats.datagrams_dropped += 1;
                }
            }
        }
    }

    /// Tells the channels what the core's event means for them: a session
    /// closed, or a dial failed.
    #[cfg(feature = "stream")]
    fn tell_channels(&mut self, context: Option<Name>, event: &Event<'_>) {
        let Some(context) = context else {
            return;
        };
        match *event {
            Event::Context(ContextEvent::Closed { peer, code, .. }) => {
                self.channels.session_closed(peer, context, code);
            }
            Event::Context(ContextEvent::ReopenFailed { peer, error }) => {
                self.channels.reopen_failed(peer, context, error);
            }
            _ => {}
        }
    }

    /// Closes `context`: its sessions with `code`, its channels; its events
    /// end once read.
    fn close_context(&mut self, context: Name, code: u16) {
        let Some(open) = self.contexts.remove(&context) else {
            return;
        };
        let _ = self.endpoint.close_context(context.as_bytes(), code);
        #[cfg(feature = "stream")]
        {
            self.channels.context_closed(context, code);
            open.slot.writable.signal(());
        }
        open.slot.with(|state| state.closed = true);
        open.slot.ready.signal(());
    }

    /// The first context whose handle asked for it to be closed.
    fn close_asked(&self) -> Option<(Name, u16)> {
        let mut asked = None;
        self.contexts.for_each(|context, open| {
            if asked.is_none()
                && let Some(code) = open.slot.with(|state| state.close).flatten()
            {
                asked = Some((*context, code));
            }
        });
        asked
    }
}

/// A framed packet for the relay link, from the application's side.
struct LinkOut {
    bytes: [u8; MAX_FRAME + 2],
    len: usize,
}

/// The state the runner, the handles and the events share. Lives in a slot
/// the integrator gives (a `static` on a microcontroller).
pub struct Shared<'d, M: RawMutex, T: Tables, D: Datagrams> {
    inner: Mutex<M, Inner<'d, M, T>>,
    link_out: Mutex<M, LinkOut>,
    datagrams: &'d D,
    /// A handle asks the runner to look again.
    wake: Signal<M, ()>,
    /// An event of the node's was queued.
    events_ready: Signal<M, ()>,
    /// The application read an event: room, perhaps, for a message.
    events_room: Signal<M, ()>,
    link_room: Signal<M, ()>,
}

/// How a packet the core output goes.
enum Plan {
    Udp(SocketAddr),
    Tcp,
    UdpAndTcp(SocketAddr),
    KeepAlive,
    Nothing,
}

fn plan(relay: Option<&RelayLocation>, last_from: Option<SocketAddr>, to: To) -> Plan {
    match to {
        To::Source => last_from.map_or(Plan::Nothing, Plan::Udp),
        To::Direct(key) => key
            .as_direct()
            .and_then(decode_ip)
            .map_or(Plan::Nothing, Plan::Udp),
        To::Relay(path) => match (path, relay) {
            (RelayPath::Udp, Some(relay)) => Plan::Udp(relay.primary),
            (RelayPath::UdpOther, Some(relay)) => relay.other.map_or(Plan::Nothing, Plan::Udp),
            (RelayPath::Both, Some(relay)) => Plan::UdpAndTcp(relay.primary),
            (RelayPath::Tcp, _) => Plan::Tcp,
            (_, None) => Plan::Nothing,
        },
        To::RelayKeepAlive => Plan::KeepAlive,
    }
}

fn now() -> Instant {
    Instant::from_millis(embassy_time::Instant::now().as_millis())
}

/// Starts the driver for `identity`: the handle, the runner to spawn, and the
/// node's events. It serves no context until the application opens one with
/// [`Node::context`]. Every buffer is the integrator's: `events` holds the
/// node's events (they carry no data, so it may be empty), `slot` the shared
/// state.
///
/// # Errors
///
/// [`StartError::Rng`] before anything else, when the generator cannot be
/// read; [`StartError::Core`] when the core refuses the relay.
#[allow(
    clippy::too_many_arguments,
    reason = "the integrator's parts: identity, sockets, generator, buffers"
)]
#[allow(
    clippy::type_complexity,
    reason = "the three halves of one driver, each generic as the integrator's parts are"
)]
pub fn start<'d, M, T, D, L, I>(
    identity: Identity,
    config: Config,
    datagrams: &'d D,
    link: L,
    interfaces: I,
    rng: &'d mut dyn SecureRng,
    events: &'d mut [u8],
    slot: &'d mut Option<Shared<'d, M, T, D>>,
) -> Result<
    (
        Node<'d, M, T, D>,
        Runner<'d, M, T, D, L, I>,
        Events<'d, M, T, D>,
    ),
    StartError,
>
where
    M: RawMutex,
    T: Tables,
    D: Datagrams,
    L: Streams,
    I: Interfaces,
{
    let entropy = Checked::new(rng).map_err(StartError::Rng)?;
    let mut endpoint = Endpoint::<T>::new(identity, &[]).map_err(StartError::Core)?;
    if let Some(relay) = config.relay {
        endpoint
            .pin_relay(relay.address, now())
            .map_err(StartError::Core)?;
        endpoint.set_relay_families(relay.primary.is_ipv6(), relay.other.is_some());
    }
    endpoint.set_local_addresses(&local_addresses(&interfaces, datagrams.local_port()).0[..]);
    let shared = &*slot.insert(Shared {
        inner: Mutex::new(Inner {
            endpoint,
            contexts: Default::default(),
            entropy,
            out: [0; OUT_LEN],
            events: EventQueue::new(events),
            relay: config.relay,
            last_from: None,
            report_interfaces: false,
            stats: Stats::default(),
            #[cfg(feature = "stream")]
            channels: convesso_stream::Channels::new(),
            #[cfg(feature = "stream")]
            frame: [0; convesso_stream::frame::MAX_DATA_LEN],
        }),
        link_out: Mutex::new(LinkOut {
            bytes: [0; MAX_FRAME + 2],
            len: 0,
        }),
        datagrams,
        wake: Signal::new(),
        events_ready: Signal::new(),
        events_room: Signal::new(),
        link_room: Signal::new(),
    });
    Ok((
        Node { shared },
        Runner {
            shared,
            link,
            interfaces,
            link_state: LinkState::Closed,
            deframer: Deframer::default(),
            rx: [0; OUT_LEN],
            link_rx: [0; 512],
            link_pending: (0, 0),
        },
        Events { shared },
    ))
}

/// Up to [`LOCAL_MAX`] interface addresses with the socket's port.
struct Locals([SocketAddr; LOCAL_MAX], usize);

impl core::ops::Index<core::ops::RangeFull> for Locals {
    type Output = [SocketAddr];
    fn index(&self, _: core::ops::RangeFull) -> &[SocketAddr] {
        self.0.get(..self.1).unwrap_or_default()
    }
}

fn local_addresses<I: Interfaces>(interfaces: &I, port: u16) -> Locals {
    let mut ips = [IpAddr::V4(Ipv4Addr::UNSPECIFIED); LOCAL_MAX];
    let count = interfaces.local_addresses(&mut ips).min(LOCAL_MAX);
    let mut out = [SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0); LOCAL_MAX];
    for (slot, ip) in out.iter_mut().zip(ips.iter().take(count)) {
        *slot = SocketAddr::new(*ip, port);
    }
    Locals(out, count)
}

/// The application's handle on the node: cheap to copy.
pub struct Node<'d, M: RawMutex, T: Tables, D: Datagrams> {
    shared: &'d Shared<'d, M, T, D>,
}

impl<M: RawMutex, T: Tables, D: Datagrams> Clone for Node<'_, M, T, D> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M: RawMutex, T: Tables, D: Datagrams> Copy for Node<'_, M, T, D> {}

impl<'d, M: RawMutex, T: Tables, D: Datagrams> Node<'d, M, T, D> {
    /// This node's address, which peers send to.
    pub async fn address(&self) -> Address {
        *self.shared.inner.lock().await.endpoint.identity().address()
    }

    /// Opens the context `name` while the node runs: serves it under the
    /// options' access, and returns its handle and its events. The context
    /// lives as long as the handle: dropping it closes the context.
    ///
    /// # Errors
    ///
    /// [`NodeError::Context`] with the core's error for a name already open,
    /// the relay context, or one context more than the storage profile
    /// holds; `NodeError::Message` (feature `stream`) for a largest message
    /// over the configuration's. The context is then not open.
    pub async fn context(
        &self,
        name: &[u8],
        options: ContextOptions<'d, M>,
    ) -> Result<(Context<'d, M, T, D>, ContextEvents<'d, M, T, D>), NodeError> {
        let context = Name::new(name)
            .map_err(|error| NodeError::Context(ResponderError::ContextTooLong(error)))?;
        if name == convesso_core::relay::CONTEXT {
            return Err(NodeError::Context(ResponderError::RelayContext));
        }
        let ContextOptions {
            access,
            events,
            slot,
            #[cfg(feature = "stream")]
            credit,
            #[cfg(feature = "stream")]
            max_message,
        } = options;
        let mut guard = self.shared.inner.lock().await;
        let inner = &mut *guard;
        if inner.contexts.get(&context).is_some() {
            return Err(NodeError::Context(ResponderError::AlreadyServed));
        }
        #[cfg(feature = "stream")]
        let largest = {
            let largest = max_message.unwrap_or(MAX_MESSAGE);
            if largest > MAX_MESSAGE {
                return Err(NodeError::Message(convesso_stream::SendError::TooLarge {
                    size: largest,
                    max: MAX_MESSAGE,
                }));
            }
            largest
        };
        let (core, policy) = match access {
            Access::Everyone => (Some(handshake::Access::Policy), None),
            Access::Admit(policy) => (Some(handshake::Access::Policy), Some(policy)),
            Access::Bound(peer) => (Some(handshake::Access::Bound(peer)), None),
            Access::DialOnly => (None, None),
        };
        let open = Open {
            slot,
            policy,
            #[cfg(feature = "stream")]
            max_message: largest,
        };
        if let Err(full) = inner.contexts.insert(context, open) {
            return Err(NodeError::Context(ResponderError::TooManyContexts {
                capacity: full.capacity,
            }));
        }
        if let Some(core) = core
            && let Err(error) = inner.endpoint.serve(name, core)
        {
            let _ = inner.contexts.remove(&context);
            return Err(NodeError::Context(error));
        }
        #[cfg(feature = "stream")]
        if let Err(error) = inner.channels.set_context(name, max_message, credit) {
            let _ = inner.contexts.remove(&context);
            let _ = inner.endpoint.close_context(name, DROPPED);
            return Err(NodeError::Message(error));
        }
        slot.state.lock(|state| {
            *state.borrow_mut() = Some(SlotState {
                events: EventQueue::new(events),
                close: None,
                closed: false,
            });
        });
        drop(guard);
        Ok((
            Context {
                shared: self.shared,
                name: context,
                slot,
            },
            ContextEvents {
                shared: self.shared,
                slot,
            },
        ))
    }

    /// Gives the core a direct address for `peer`, in every context: the
    /// first attempt of a dial goes there.
    ///
    /// # Errors
    ///
    /// [`NodeError::Hint`].
    pub async fn set_hint(&self, peer: PeerId, at: SocketAddr) -> Result<(), NodeError> {
        let (bytes, len) = encode_ip(at);
        let mut inner = self.shared.inner.lock().await;
        inner
            .endpoint
            .set_hint(peer, bytes.get(..len).unwrap_or_default(), now())
            .map_err(|_| NodeError::Hint)
    }

    /// Asks to be reachable through the relay, keeping a link to it, or not.
    pub async fn set_reachable(&self, reachable: bool) {
        self.shared
            .inner
            .lock()
            .await
            .endpoint
            .set_reachable(reachable, now());
        self.shared.wake.signal(());
    }

    /// Revokes `peer`: closes every session with it, in every context.
    pub async fn close_peer(&self, peer: PeerId, code: u16) {
        let mut guard = self.shared.inner.lock().await;
        let inner = &mut *guard;
        inner.endpoint.close_peer(peer, code);
        // The core raises no event for a close of this side's: the channels
        // are reset here, as the peer's are on the close (DESIGN.md §8).
        #[cfg(feature = "stream")]
        {
            let channels = &mut inner.channels;
            inner.contexts.for_each(|context, _| {
                channels.session_closed(peer, *context, code);
            });
        }
        drop(guard);
        self.shared.wake.signal(());
    }

    /// The network changed: the runner reports the interfaces again, and the
    /// core replaces its link and checks its direct paths.
    pub async fn network_changed(&self) {
        let mut inner = self.shared.inner.lock().await;
        inner.report_interfaces = true;
        inner.endpoint.network_changed(now());
        drop(inner);
        self.shared.wake.signal(());
    }

    /// Excludes the IP prefix `ip/len` from direct paths: no address in it is
    /// a candidate, probed, or a path (`PROTOCOL.md §7`).
    ///
    /// # Errors
    ///
    /// [`NodeError::Exclude`] with the core's error.
    pub async fn exclude_prefix(&self, ip: IpAddr, len: u8) -> Result<(), NodeError> {
        let mut inner = self.shared.inner.lock().await;
        inner
            .endpoint
            .exclude_prefix(ip, len)
            .map_err(NodeError::Exclude)
    }

    /// Replaces every excluded prefix with `prefixes`: one no longer excluded
    /// is allowed again, its interface a candidate again.
    ///
    /// # Errors
    ///
    /// As [`Self::exclude_prefix`]; a set refused leaves the old one.
    pub async fn set_excluded(&self, prefixes: &[(IpAddr, u8)]) -> Result<(), NodeError> {
        let mut inner = self.shared.inner.lock().await;
        inner
            .endpoint
            .set_excluded(prefixes)
            .map_err(NodeError::Exclude)?;
        inner.report_interfaces = true;
        drop(inner);
        self.shared.wake.signal(());
        Ok(())
    }

    /// This node's candidates as peers are told them, written into `out`;
    /// returns how many.
    pub async fn candidates(&self, out: &mut [Candidate]) -> usize {
        let inner = self.shared.inner.lock().await;
        let candidates = inner.endpoint.candidates();
        for (slot, candidate) in out.iter_mut().zip(candidates) {
            *slot = *candidate;
        }
        candidates.len().min(out.len())
    }

    /// Whether UDP to the relay is proven now.
    pub async fn relay_udp_proven(&self) -> bool {
        self.shared
            .inner
            .lock()
            .await
            .endpoint
            .relay_udp_proven(now())
    }

    /// What the sockets carried, and what was dropped.
    pub async fn stats(&self) -> Stats {
        self.shared.inner.lock().await.stats
    }
}

/// The node's own events, in order.
pub struct Events<'d, M: RawMutex, T: Tables, D: Datagrams> {
    shared: &'d Shared<'d, M, T, D>,
}

impl<M: RawMutex, T: Tables, D: Datagrams> Events<'_, M, T, D> {
    /// The next event.
    pub async fn next(&mut self) -> NodeEvent {
        loop {
            let popped = self.shared.inner.lock().await.events.pop(&mut []);
            if let Some(Event::Node(event)) = popped {
                return event;
            }
            self.shared.events_ready.wait().await;
        }
    }
}

/// A handle on one context of the node: every operation acts in it, and its
/// [`ContextEvents`] carry its events alone. Dropping it closes the context,
/// as [`Self::close_context`] does with [`DROPPED`].
pub struct Context<'d, M: RawMutex, T: Tables, D: Datagrams> {
    shared: &'d Shared<'d, M, T, D>,
    name: Name,
    slot: &'d ContextSlot<'d, M>,
}

impl<M: RawMutex, T: Tables, D: Datagrams> Drop for Context<'_, M, T, D> {
    fn drop(&mut self) {
        self.slot.with(|state| {
            if !state.closed {
                state.close.get_or_insert(DROPPED);
            }
        });
        self.shared.wake.signal(());
    }
}

impl<'d, M: RawMutex, T: Tables, D: Datagrams> Context<'d, M, T, D> {
    /// The context's name.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    /// Closes the context: its sessions closed with `code`, its dials and
    /// pending handshakes discarded, its slot freed.
    pub fn close_context(self, code: u16) {
        self.slot.with(|state| state.close = Some(code));
    }

    /// The lock on the core, while the context is open.
    async fn open(&self) -> Result<MutexGuard<'d, M, Inner<'d, M, T>>, NodeError> {
        let guard = self.shared.inner.lock().await;
        if guard.contexts.get(&self.name).is_none() {
            return Err(NodeError::ContextClosed);
        }
        Ok(guard)
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
    /// cannot be served, or [`NodeError::ContextClosed`].
    pub async fn set_access(&self, access: Access<'d>, code: u16) -> Result<(), NodeError> {
        let mut guard = self.open().await?;
        let inner = &mut *guard;
        let (core, policy) = match access {
            Access::Everyone => (Some(handshake::Access::Policy), None),
            Access::Admit(policy) => (Some(handshake::Access::Policy), Some(policy)),
            Access::Bound(peer) => (Some(handshake::Access::Bound(peer)), None),
            Access::DialOnly => (None, None),
        };
        let previous = inner
            .contexts
            .get_mut(&self.name)
            .and_then(|open| core::mem::replace(&mut open.policy, policy));
        let result = inner
            .endpoint
            .set_access(
                self.name.as_bytes(),
                core,
                code,
                &mut Policies::<M, T>(&mut inner.contexts),
            )
            .map_err(NodeError::Context);
        if result.is_err()
            && let Some(open) = inner.contexts.get_mut(&self.name)
        {
            // Refused: the context keeps the access it had.
            open.policy = previous;
        }
        drop(guard);
        self.shared.wake.signal(());
        result
    }

    /// Sends `data` to the peer at `to`, opening a session if needed.
    ///
    /// # Errors
    ///
    /// [`NodeError::Send`] with the core's named error, or
    /// [`NodeError::ContextClosed`].
    pub async fn send(&self, to: &Address, data: &[u8]) -> Result<(), NodeError> {
        self.send_target(Target::Address(to), data).await
    }

    /// Sends `data` to `peer`, which must have a session with keys.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    pub async fn send_to_peer(&self, peer: PeerId, data: &[u8]) -> Result<(), NodeError> {
        self.send_target(Target::Peer(peer), data).await
    }

    async fn send_target(&self, target: Target<'_>, data: &[u8]) -> Result<(), NodeError> {
        let mut link_out = self.link_out().await;
        let mut guard = self.open().await?;
        let inner = &mut *guard;
        let output = with_policies!(
            inner,
            send(target, self.name.as_bytes(), data, DIRECT_PATH_MAX, now())
        )
        .map_err(NodeError::Send)?;
        match output {
            Output::Transmit { to, len } => {
                let packet = inner.out.get(..len).unwrap_or_default();
                match plan(inner.relay.as_ref(), inner.last_from, to) {
                    Plan::Udp(at) => {
                        inner
                            .stats
                            .count(self.shared.datagrams.send_to(packet, at).await);
                    }
                    Plan::UdpAndTcp(at) => {
                        inner
                            .stats
                            .count(self.shared.datagrams.send_to(packet, at).await);
                        link_out.len = framing::frame(packet, &mut link_out.bytes).unwrap_or(0);
                    }
                    Plan::Tcp => {
                        link_out.len = framing::frame(packet, &mut link_out.bytes).unwrap_or(0);
                    }
                    Plan::KeepAlive | Plan::Nothing => {}
                }
            }
            Output::Event(event) => {
                if let Some((context, event)) = from_core(event) {
                    inner.deliver(&self.shared.events_ready, context, event);
                }
            }
            Output::Nothing => {}
        }
        drop(guard);
        drop(link_out);
        self.shared.wake.signal(());
        Ok(())
    }

    /// The link's outgoing slot, once it is free.
    async fn link_out(&self) -> MutexGuard<'d, M, LinkOut> {
        loop {
            let link_out = self.shared.link_out.lock().await;
            if link_out.len == 0 {
                return link_out;
            }
            drop(link_out);
            self.shared.link_room.wait().await;
        }
    }

    /// Closes the session with `peer`, sending one authenticated close.
    pub async fn close(&self, peer: PeerId, code: u16) {
        let mut link_out = self.link_out().await;
        let Ok(mut guard) = self.open().await else {
            return;
        };
        let inner = &mut *guard;
        if let Output::Transmit { to, len } =
            inner
                .endpoint
                .close(peer, self.name.as_bytes(), code, now(), &mut inner.out)
        {
            let packet = inner.out.get(..len).unwrap_or_default();
            match plan(inner.relay.as_ref(), inner.last_from, to) {
                Plan::Udp(at) | Plan::UdpAndTcp(at) => {
                    inner
                        .stats
                        .count(self.shared.datagrams.send_to(packet, at).await);
                }
                Plan::Tcp => {
                    link_out.len = framing::frame(packet, &mut link_out.bytes).unwrap_or(0);
                }
                Plan::KeepAlive | Plan::Nothing => {}
            }
        }
        // The core raises no event for a close of this side's: the channel is
        // reset here, as the peer's is on the close (DESIGN.md §8).
        #[cfg(feature = "stream")]
        inner.channels.session_closed(peer, self.name, code);
        drop(guard);
        drop(link_out);
        self.shared.wake.signal(());
    }

    /// The path to `peer`, and how it got there; `None` without a session.
    pub async fn path(&self, peer: PeerId) -> Option<PathInfo> {
        let inner = self.shared.inner.lock().await;
        inner.endpoint.path_info(&peer, self.name.as_bytes())
    }

    /// The channel binding of the session with `peer`: the hash of the
    /// handshake that opened it, the same at both ends and kept across key
    /// renewals (`PROTOCOL.md §5`). `None` without a session with
    /// keys.
    pub async fn channel_binding(&self, peer: PeerId) -> Option<ChannelBinding> {
        let inner = self.shared.inner.lock().await;
        inner.endpoint.channel_binding(&peer, self.name.as_bytes())
    }

    /// Sends a reliable message to the peer at `to` (feature `stream`): it
    /// arrives whole, once and in order, or the channel is reset. Waits while
    /// the channel's send buffer is full.
    ///
    /// # Errors
    ///
    /// [`NodeError::Message`] for a message that can never be sent, larger
    /// than the context's largest message included; or
    /// [`NodeError::ContextClosed`].
    #[cfg(feature = "stream")]
    pub async fn send_message(&self, to: &Address, data: &[u8]) -> Result<(), NodeError> {
        self.offer(to.peer_id(), Some(to), data).await
    }

    /// Sends a reliable message to a peer by its identity (feature `stream`):
    /// without its address, a dormant session waits for the peer to reopen it.
    ///
    /// # Errors
    ///
    /// As [`Self::send_message`].
    #[cfg(feature = "stream")]
    pub async fn send_message_to_peer(&self, peer: PeerId, data: &[u8]) -> Result<(), NodeError> {
        self.offer(peer, None, data).await
    }

    /// Lets `peer`'s channel hand out `bytes` more of its messages (feature
    /// `stream`, with [`ContextOptions::credit`]): each message spends its
    /// length plus [`convesso_stream::ELEMENT_COST`]. A channel starts with
    /// none, and returns to none at its reset and at the session's close, so
    /// the application grants again after those events. Nothing with credit
    /// off.
    ///
    /// # Errors
    ///
    /// [`NodeError::Message`] with the table-full error when no channel slot
    /// is free, or [`NodeError::ContextClosed`].
    #[cfg(feature = "stream")]
    pub async fn grant(&self, peer: PeerId, bytes: usize) -> Result<(), NodeError> {
        let mut guard = self.open().await?;
        let result = guard
            .channels
            .grant(peer, self.name.as_bytes(), bytes)
            .map_err(NodeError::Message);
        drop(guard);
        // A message held for want of credit may go now.
        self.shared.wake.signal(());
        result
    }

    #[cfg(feature = "stream")]
    async fn offer(
        &self,
        peer: PeerId,
        address: Option<&Address>,
        data: &[u8],
    ) -> Result<(), NodeError> {
        loop {
            {
                let mut guard = self.open().await?;
                let inner = &mut *guard;
                match inner.channels.send_message(
                    peer,
                    address,
                    self.name.as_bytes(),
                    data,
                    now(),
                    &mut inner.entropy,
                ) {
                    Ok(()) => {
                        self.shared.wake.signal(());
                        return Ok(());
                    }
                    Err(convesso_stream::SendError::Full) => {}
                    Err(error) => return Err(NodeError::Message(error)),
                }
            }
            self.slot.writable.wait().await;
        }
    }
}

/// A context's events, in order.
pub struct ContextEvents<'d, M: RawMutex, T: Tables, D: Datagrams> {
    shared: &'d Shared<'d, M, T, D>,
    slot: &'d ContextSlot<'d, M>,
}

impl<M: RawMutex, T: Tables, D: Datagrams> ContextEvents<'_, M, T, D> {
    /// The next event, or `None` once the context is closed and every event
    /// before the close was read. A datagram's or a message's data is copied
    /// into `buf`, cut to its length: give a buffer as large as the largest
    /// expected.
    pub async fn next<'b>(&mut self, buf: &'b mut [u8]) -> Option<ContextEvent<'b>> {
        loop {
            // Waiting: nothing queued and the context open.
            let waiting = self
                .slot
                .with(|state| state.events.is_empty() && !state.closed)
                .unwrap_or(false);
            if !waiting {
                break;
            }
            self.slot.ready.wait().await;
        }
        let popped = self
            .slot
            .state
            .lock(|state| match state.borrow_mut().as_mut() {
                Some(state) => state.events.pop(buf),
                None => None,
            });
        self.shared.events_room.signal(());
        match popped {
            Some(Event::Context(event)) => Some(event),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkState {
    Closed,
    Connecting,
    Open,
}

/// The driver's task: spawn [`Runner::run`] from a task of the integrator's.
pub struct Runner<'d, M: RawMutex, T: Tables, D: Datagrams, L: Streams, I: Interfaces> {
    shared: &'d Shared<'d, M, T, D>,
    link: L,
    interfaces: I,
    link_state: LinkState,
    deframer: Deframer,
    rx: [u8; OUT_LEN],
    link_rx: [u8; 512],
    /// The link's bytes read and not yet given to the deframer.
    link_pending: (usize, usize),
}

/// What woke the runner.
enum Woken {
    Datagram(Result<(usize, SocketAddr), crate::socket::SocketError>),
    Connected(Result<(), crate::socket::SocketError>),
    LinkRead(usize),
    LinkFailed,
    Deadline,
    Signal,
}

impl<'d, M: RawMutex, T: Tables, D: Datagrams, L: Streams, I: Interfaces>
    Runner<'d, M, T, D, L, I>
{
    /// Runs the driver. Never returns.
    pub async fn run(mut self) -> ! {
        loop {
            self.close_asked().await;
            self.flush_link_out().await;
            self.deframe().await;
            self.report_network().await;
            #[cfg(feature = "stream")]
            let deadline = self.drain().await;
            #[cfg(not(feature = "stream"))]
            let deadline = self.drain_core().await;
            let woken = self.wait(deadline).await;
            match woken {
                Woken::Datagram(Ok((len, from))) => self.datagram(len, from).await,
                Woken::Datagram(Err(_)) | Woken::Deadline | Woken::Signal => {}
                Woken::Connected(result) => self.connected(result).await,
                Woken::LinkRead(len) => self.link_pending = (0, len),
                Woken::LinkFailed => self.link_gone().await,
            }
        }
    }

    /// Closes the contexts whose handles asked for it.
    async fn close_asked(&mut self) {
        let mut inner = self.shared.inner.lock().await;
        while let Some((context, code)) = inner.close_asked() {
            inner.close_context(context, code);
        }
    }

    /// Waits for the next thing to do. The socket and the link are read
    /// whatever the application reads.
    async fn wait(&mut self, deadline: Option<Instant>) -> Woken {
        let link_idle = self.link_pending.0 >= self.link_pending.1;
        let relay = self.shared.inner.lock().await.relay;
        let Self {
            shared,
            link,
            link_state,
            rx,
            link_rx,
            ..
        } = self;
        let datagrams = shared.datagrams;
        let recv = datagrams.recv_from(rx);
        let link_op = async {
            match (*link_state, relay) {
                (LinkState::Connecting, Some(relay)) => {
                    Woken::Connected(link.connect(relay.primary).await)
                }
                (LinkState::Open, _) if link_idle => match link.read(link_rx).await {
                    Ok(0) | Err(_) => Woken::LinkFailed,
                    Ok(len) => Woken::LinkRead(len),
                },
                _ => core::future::pending().await,
            }
        };
        let timer = async {
            match deadline {
                Some(at) => Timer::at(embassy_time::Instant::from_millis(at.as_millis())).await,
                None => core::future::pending().await,
            }
        };
        let signal = select(shared.wake.wait(), shared.events_room.wait());
        match select4(recv, link_op, timer, signal).await {
            Either4::First(result) => Woken::Datagram(result),
            Either4::Second(woken) => woken,
            Either4::Third(()) => Woken::Deadline,
            Either4::Fourth(_) => Woken::Signal,
        }
    }

    /// A datagram from `from`, in `rx[..len]`.
    async fn datagram(&mut self, len: usize, from: SocketAddr) {
        let from = canonical(from);
        let mut guard = self.shared.inner.lock().await;
        let inner = &mut *guard;
        inner.last_from = Some(from);
        let is_relay = inner
            .relay
            .is_some_and(|relay| relay.primary == from || relay.other == Some(from));
        let packet = self.rx.get_mut(..len).unwrap_or_default();
        let output = if is_relay {
            with_policies!(inner, handle_relay_packet(packet, Link::Udp, now()))
        } else {
            let (source, source_len) = encode_ip(from);
            with_policies!(
                inner,
                handle_packet(
                    packet,
                    Source::Direct(source.get(..source_len).unwrap_or_default()),
                    now()
                )
            )
        };
        Self::execute(
            self.shared,
            &mut self.link,
            &mut self.link_state,
            inner,
            output,
        )
        .await;
    }

    /// Carries out one output of a handled packet.
    async fn execute(
        shared: &'d Shared<'d, M, T, D>,
        link: &mut L,
        link_state: &mut LinkState,
        inner: &mut Inner<'d, M, T>,
        output: Output<'_>,
    ) {
        match output {
            Output::Transmit { to, len } => {
                let plan = plan(inner.relay.as_ref(), inner.last_from, to);
                Self::carry(shared, link, link_state, inner, plan, len).await;
            }
            #[cfg(feature = "stream")]
            Output::Event(convesso_core::endpoint::Event::Frame {
                peer,
                context,
                kind,
                data,
                connected,
                ..
            }) => {
                inner
                    .channels
                    .handle_frame(peer, context, kind, data, now());
                if connected {
                    inner.deliver(
                        &shared.events_ready,
                        Some(context),
                        Event::Context(ContextEvent::Connected { peer }),
                    );
                }
            }
            Output::Event(event) => {
                if let Some((context, event)) = from_core(event) {
                    #[cfg(feature = "stream")]
                    inner.tell_channels(context, &event);
                    inner.deliver(&shared.events_ready, context, event);
                }
            }
            Output::Nothing => {}
        }
    }

    /// Sends `inner.out[..len]` as `plan` says.
    async fn carry(
        shared: &'d Shared<'d, M, T, D>,
        link: &mut L,
        link_state: &mut LinkState,
        inner: &mut Inner<'d, M, T>,
        plan: Plan,
        len: usize,
    ) {
        let packet = inner.out.get(..len).unwrap_or_default();
        let udp = match plan {
            Plan::Udp(at) | Plan::UdpAndTcp(at) => Some(at),
            _ => None,
        };
        if let Some(at) = udp {
            inner
                .stats
                .count(shared.datagrams.send_to(packet, at).await);
        }
        let bytes_ok = match plan {
            Plan::Tcp | Plan::UdpAndTcp(_) if *link_state == LinkState::Open => {
                let mut framed = [0u8; MAX_FRAME + 2];
                match framing::frame(packet, &mut framed) {
                    Some(n) => {
                        inner.stats.link_frames_sent += 1;
                        link.write_all(framed.get(..n).unwrap_or_default())
                            .await
                            .is_ok()
                    }
                    None => true,
                }
            }
            Plan::KeepAlive if *link_state == LinkState::Open => {
                inner.stats.keepalives_sent += 1;
                link.write_all(&KEEPALIVE).await.is_ok()
            }
            _ => true,
        };
        if !bytes_ok {
            link.close();
            *link_state = LinkState::Closed;
            inner.endpoint.relay_link_closed(now());
        }
    }

    /// Calls the core, and the channels, until neither has anything due;
    /// returns the earlier of their next deadlines.
    #[cfg(feature = "stream")]
    async fn drain(&mut self) -> Option<Instant> {
        loop {
            let core = self.drain_core().await;
            let (stream, worked) = self.drain_stream().await;
            if !worked {
                return [core, stream].into_iter().flatten().min();
            }
        }
    }

    /// Calls the channels until they have nothing due: each frame and each
    /// dial to the core, each event to its context. Returns their deadline,
    /// and whether they did anything.
    #[cfg(feature = "stream")]
    async fn drain_stream(&mut self) -> (Option<Instant>, bool) {
        use convesso_stream::{Event as StreamEvent, Poll as StreamPoll};
        let mut worked = false;
        loop {
            let mut guard = self.shared.inner.lock().await;
            let inner = &mut *guard;
            // A context's message is handed out only with room for it in its
            // queue: otherwise its channel keeps it, and its window closes;
            // the other contexts go on.
            let contexts = &inner.contexts;
            let deliver = |context: &Name| {
                contexts.get(context).is_some_and(|open| {
                    open.slot
                        .with(|state| state.events.deliverable(open.max_message))
                        .unwrap_or(false)
                })
            };
            let output = match inner.channels.poll_with(now(), deliver, &mut inner.frame) {
                StreamPoll::SendFrame {
                    peer,
                    context,
                    kind,
                    len,
                } => {
                    let frame = inner.frame.get(..len).unwrap_or_default();
                    match inner.endpoint.send_frame(
                        peer,
                        context.as_bytes(),
                        kind,
                        frame,
                        now(),
                        &mut Policies::<M, T>(&mut inner.contexts),
                        &mut inner.entropy,
                        &mut inner.out,
                    ) {
                        Ok(output) => Some(output),
                        Err(_) => {
                            inner.channels.frame_refused(now());
                            None
                        }
                    }
                }
                StreamPoll::Dial { address, context } => inner
                    .endpoint
                    .connect(
                        &address,
                        context.as_bytes(),
                        now(),
                        &mut Policies::<M, T>(&mut inner.contexts),
                        &mut inner.entropy,
                        &mut inner.out,
                    )
                    .ok(),
                StreamPoll::Event(StreamEvent::Message {
                    peer,
                    context,
                    data,
                }) => {
                    if let Some(open) = inner.contexts.get(&context) {
                        open.slot
                            .push(Event::Context(ContextEvent::Message { peer, data }));
                    }
                    None
                }
                StreamPoll::Event(StreamEvent::Reset {
                    peer,
                    context,
                    reason,
                }) => {
                    if let Some(open) = inner.contexts.get(&context) {
                        open.slot
                            .push(Event::Context(ContextEvent::ChannelReset { peer, reason }));
                    }
                    None
                }
                StreamPoll::Event(StreamEvent::Writable { context, .. }) => {
                    if let Some(open) = inner.contexts.get(&context) {
                        open.slot.writable.signal(());
                    }
                    None
                }
                StreamPoll::Wait(at) => return (Some(at), worked),
                StreamPoll::Idle => return (None, worked),
            };
            worked = true;
            if let Some(Output::Transmit { to, len }) = output {
                let plan = plan(inner.relay.as_ref(), inner.last_from, to);
                Self::carry(
                    self.shared,
                    &mut self.link,
                    &mut self.link_state,
                    inner,
                    plan,
                    len,
                )
                .await;
            }
        }
    }

    /// Calls the core until it has nothing due; returns its next deadline.
    async fn drain_core(&mut self) -> Option<Instant> {
        loop {
            let mut guard = self.shared.inner.lock().await;
            let inner = &mut *guard;
            let poll = with_policies!(inner, poll(now()));
            match poll {
                Poll::Transmit { to, len } => {
                    let plan = plan(inner.relay.as_ref(), inner.last_from, to);
                    Self::carry(
                        self.shared,
                        &mut self.link,
                        &mut self.link_state,
                        inner,
                        plan,
                        len,
                    )
                    .await;
                }
                Poll::Event(event) => {
                    if let Some((context, event)) = from_core(event) {
                        #[cfg(feature = "stream")]
                        inner.tell_channels(context, &event);
                        inner.deliver(&self.shared.events_ready, context, event);
                    }
                }
                Poll::OpenRelayLink => self.link_state = LinkState::Connecting,
                Poll::CloseRelayLink => {
                    self.link.close();
                    self.link_state = LinkState::Closed;
                    self.link_pending = (0, 0);
                }
                Poll::Wait(at) => return Some(at),
                Poll::Idle => return None,
            }
        }
    }

    /// The link the core asked for opened, or did not.
    async fn connected(&mut self, result: Result<(), crate::socket::SocketError>) {
        let opened = result.is_ok() && self.link.write_all(&PREAMBLE).await.is_ok();
        let mut inner = self.shared.inner.lock().await;
        if opened {
            self.link_state = LinkState::Open;
            self.deframer = Deframer::default();
            self.link_pending = (0, 0);
            inner.endpoint.relay_link_opened(now());
        } else {
            self.link.close();
            self.link_state = LinkState::Closed;
            inner.endpoint.relay_link_closed(now());
        }
    }

    /// The link closed or failed.
    async fn link_gone(&mut self) {
        self.link.close();
        self.link_state = LinkState::Closed;
        self.link_pending = (0, 0);
        self.shared
            .inner
            .lock()
            .await
            .endpoint
            .relay_link_closed(now());
    }

    /// Gives the core the link's packets read so far.
    async fn deframe(&mut self) {
        while self.link_pending.0 < self.link_pending.1 {
            let (start, end) = self.link_pending;
            let (used, result) = self
                .deframer
                .feed(self.link_rx.get(start..end).unwrap_or_default());
            self.link_pending.0 = start + used;
            match result {
                Deframed::NeedMore => break,
                Deframed::KeepAlive => {
                    self.shared
                        .inner
                        .lock()
                        .await
                        .endpoint
                        .relay_keepalive_received(now());
                }
                Deframed::Closed(_) => {
                    self.link_gone().await;
                    break;
                }
                Deframed::Packet(packet) => {
                    let len = packet.len();
                    if let Some(rx) = self.rx.get_mut(..len) {
                        rx.copy_from_slice(packet);
                    }
                    let mut guard = self.shared.inner.lock().await;
                    let inner = &mut *guard;
                    let packet = self.rx.get_mut(..len).unwrap_or_default();
                    let output =
                        with_policies!(inner, handle_relay_packet(packet, Link::Tcp, now()));
                    Self::execute(
                        self.shared,
                        &mut self.link,
                        &mut self.link_state,
                        inner,
                        output,
                    )
                    .await;
                }
            }
        }
    }

    /// Writes what the application framed for the link.
    async fn flush_link_out(&mut self) {
        let mut link_out = self.shared.link_out.lock().await;
        if link_out.len == 0 {
            return;
        }
        let ok = self.link_state == LinkState::Open
            && self
                .link
                .write_all(link_out.bytes.get(..link_out.len).unwrap_or_default())
                .await
                .is_ok();
        link_out.len = 0;
        drop(link_out);
        self.shared.link_room.signal(());
        if ok {
            self.shared.inner.lock().await.stats.link_frames_sent += 1;
        }
        if !ok && self.link_state == LinkState::Open {
            self.link_gone().await;
        }
    }

    /// Reports the interfaces again, when the application said the network
    /// changed.
    async fn report_network(&mut self) {
        let mut inner = self.shared.inner.lock().await;
        if inner.report_interfaces {
            inner.report_interfaces = false;
            let locals = local_addresses(&self.interfaces, self.shared.datagrams.local_port());
            inner.endpoint.set_local_addresses(&locals[..]);
        }
    }
}
