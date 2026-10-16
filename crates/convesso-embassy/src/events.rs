//! The events waiting for the application: bounded in bytes, in order, with
//! no allocator.
//!
//! ```text
//! entries   a ring of ENTRIES small events, in order; a datagram's entry holds
//!           its peer, how it came, and its length
//! bytes     the datagrams' data, in the same order, in the integrator's buffer
//! ```
//!
//! The node's events and each context's wait apart. The driver never waits for
//! room, nor stops reading for it (`DESIGN.md §5`): a datagram for a context
//! whose queue has no room is dropped and counted; an event without data that
//! finds the queue full waits aside, in a fixed table, one per peer and kind,
//! the latest replacing the earlier; reading an event moves what waits aside
//! into the queue, in order. A context's messages are taken from the stream
//! layer only with room for them.

use core::net::SocketAddr;

use convesso_core::endpoint::{RelayError, SendError};
use convesso_core::handshake::{DialError, ResponderError};
use convesso_core::identity::PeerId;
use convesso_core::paths::PathKind;
use convesso_core::relay::Link;

/// How many events can wait at once in a context's queue, datagrams
/// included.
pub const ENTRIES: usize = 16;

/// How many of the node's events can wait at once in its queue: they carry no
/// data, and what waits aside coalesces.
pub const NODE_ENTRIES: usize = 4;

/// How many of a context's events can wait aside while its queue is full: one
/// per peer and kind for the five kinds without data (a connection, a close, a
/// failed reopening, a change of path, a channel reset), for every peer the
/// microcontroller tables name at once (4 sessions and 2 dials).
pub const HELD: usize = (4 + 2) * 5;

/// How many of the node's events can wait aside while its queue is full: a
/// peer not at the relay, for every peer the tables name; the observed
/// address on each link; and the relay's availability.
pub const NODE_HELD: usize = (4 + 2) + 2 + 1;

/// Something about the node the application should know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEvent {
    /// The relay cannot reach a peer.
    PeerNotAtRelay {
        /// The peer.
        peer: PeerId,
    },
    /// The address the relay sees this device at, on a link.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextEvent<'a> {
    /// A first session with a peer.
    Connected {
        /// The peer.
        peer: PeerId,
    },
    /// A datagram. Its data is cut to the buffer given to
    /// [`crate::ContextEvents::next`] when longer.
    Datagram {
        /// The peer.
        peer: PeerId,
        /// The data.
        data: &'a [u8],
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
    /// The path to a peer changed.
    PathChanged {
        /// The peer.
        peer: PeerId,
        /// The new path.
        path: PathKind,
    },
    /// A reliable message, whole and in order (feature `stream`). Its data
    /// is cut to the buffer given to [`crate::ContextEvents::next`] when
    /// longer: give one of the largest message's size.
    #[cfg(feature = "stream")]
    Message {
        /// The peer.
        peer: PeerId,
        /// The message.
        data: &'a [u8],
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

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    /// The core refused it, with its named error.
    Send(SendError),
    /// The socket could not send it.
    Socket(crate::socket::SocketError),
    /// A hint that is not an address the core can use.
    Hint,
    /// The prefix could not be excluded, with the core's named error.
    Exclude(convesso_core::endpoint::ExcludeError),
    /// The context could not be opened, or its access changed, with the
    /// core's named error: open already, the relay context, or one more than
    /// the storage profile holds.
    Context(ResponderError),
    /// The context was closed.
    ContextClosed,
    /// The stream layer refused a message, a grant or a context's largest
    /// message, with its named error.
    #[cfg(feature = "stream")]
    Message(convesso_stream::SendError),
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Send(error) => error.fmt(f),
            Self::Socket(error) => error.fmt(f),
            Self::Hint => f.write_str("the hint is not a usable address"),
            Self::Exclude(error) => error.fmt(f),
            Self::Context(error) => write!(f, "the context: {error}"),
            Self::ContextClosed => f.write_str("the context was closed"),
            #[cfg(feature = "stream")]
            Self::Message(error) => write!(f, "the message was refused: {error:?}"),
        }
    }
}

impl core::error::Error for NodeError {}

/// An event as the queues hold it: the node's and a context's alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event<'a> {
    Node(NodeEvent),
    Context(ContextEvent<'a>),
}

/// An event as it waits: a datagram's or a message's data lives in the byte
/// ring.
#[derive(Debug, Clone, Copy)]
enum Entry {
    Datagram {
        peer: PeerId,
        relayed: bool,
        len: usize,
    },
    #[cfg(feature = "stream")]
    Message {
        peer: PeerId,
        len: usize,
    },
    Other(Event<'static>),
}

/// A queue of `E` events over the integrator's byte buffer, with `H` events
/// waiting aside at most.
pub(crate) struct EventQueue<'d, const E: usize, const H: usize> {
    entries: [Option<Entry>; E],
    first: usize,
    count: usize,
    bytes: &'d mut [u8],
    start: usize,
    used: usize,
    /// Events waiting aside, oldest first.
    held: [Option<Event<'static>>; H],
    held_count: usize,
}

impl<'d, const E: usize, const H: usize> EventQueue<'d, E, H> {
    pub(crate) fn new(bytes: &'d mut [u8]) -> Self {
        Self {
            entries: [None; E],
            first: 0,
            count: 0,
            bytes,
            start: 0,
            used: 0,
            held: [None; H],
            held_count: 0,
        }
    }

    /// Whether an event with up to `data` bytes of data fits.
    pub(crate) fn has_room(&self, data: usize) -> bool {
        self.count < E && self.bytes.len() - self.used >= data
    }

    /// Whether a message of up to `data` bytes may be taken from the stream
    /// layer: after what waits aside, and with room.
    #[cfg(feature = "stream")]
    pub(crate) fn deliverable(&self, data: usize) -> bool {
        self.held_count == 0 && self.has_room(data)
    }

    /// Whether something waits aside.
    #[cfg(test)]
    pub(crate) const fn holding(&self) -> bool {
        self.held_count > 0
    }

    /// Adds an event, or holds it aside when the queue is full or something
    /// already waits there. An event with data is never held: one that does
    /// not fit, or would overtake what waits aside, is dropped. Returns
    /// whether it was dropped.
    pub(crate) fn push_or_hold(&mut self, event: Event<'_>) -> bool {
        let data = matches!(event, Event::Context(ContextEvent::Datagram { .. }));
        #[cfg(feature = "stream")]
        let data = data || matches!(event, Event::Context(ContextEvent::Message { .. }));
        if data {
            return self.held_count > 0 || !self.push(event);
        }
        if self.held_count > 0 || !self.push(event) {
            self.hold(owned(event));
        }
        false
    }

    fn hold(&mut self, event: Event<'static>) {
        let wanted = key(&event);
        let same = (0..self.held_count)
            .find(|&i| self.held.get(i).copied().flatten().map(|e| key(&e)) == Some(wanted));
        // The table holds every peer and kind the tables can name; were it
        // full all the same, the oldest change of state goes before a close.
        let evicted = same.or_else(|| {
            (self.held_count >= H).then(|| {
                (0..self.held_count)
                    .find(|&i| {
                        !matches!(
                            self.held.get(i).copied().flatten(),
                            Some(Event::Context(ContextEvent::Closed { .. }))
                        )
                    })
                    .unwrap_or(0)
            })
        });
        if let Some(i) = evicted {
            self.held.copy_within(i + 1..self.held_count, i);
            self.held_count -= 1;
        }
        if let Some(slot) = self.held.get_mut(self.held_count) {
            *slot = Some(event);
            self.held_count += 1;
        }
    }

    /// Moves what waits aside into the queue, in order, as far as it fits.
    fn flush(&mut self) {
        while self.held_count > 0 && self.count < E {
            if let Some(event) = self.held.first().copied().flatten() {
                self.push_entry(Entry::Other(event));
            }
            self.held.copy_within(1..self.held_count, 0);
            self.held_count -= 1;
        }
    }

    /// Whether nothing waits.
    pub(crate) const fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn push_entry(&mut self, entry: Entry) {
        let at = (self.first + self.count) % E;
        if let Some(slot) = self.entries.get_mut(at) {
            *slot = Some(entry);
            self.count += 1;
        }
    }

    /// Copies `data` to the end of the byte ring; `false` when it does not
    /// fit with an entry.
    fn push_bytes(&mut self, data: &[u8]) -> bool {
        if !self.has_room(data.len()) {
            return false;
        }
        let capacity = self.bytes.len();
        for (i, byte) in data.iter().enumerate() {
            if let Some(slot) = self.bytes.get_mut((self.start + self.used + i) % capacity) {
                *slot = *byte;
            }
        }
        self.used += data.len();
        true
    }

    /// Adds an event; `false` when it does not fit, and nothing was added.
    pub(crate) fn push(&mut self, event: Event<'_>) -> bool {
        match event {
            Event::Context(ContextEvent::Datagram {
                peer,
                data,
                relayed,
            }) => {
                if !self.push_bytes(data) {
                    return false;
                }
                self.push_entry(Entry::Datagram {
                    peer,
                    relayed,
                    len: data.len(),
                });
                true
            }
            #[cfg(feature = "stream")]
            Event::Context(ContextEvent::Message { peer, data }) => {
                if !self.push_bytes(data) {
                    return false;
                }
                self.push_entry(Entry::Message {
                    peer,
                    len: data.len(),
                });
                true
            }
            other => {
                if self.count >= E {
                    return false;
                }
                self.push_entry(Entry::Other(owned(other)));
                true
            }
        }
    }

    /// Takes the oldest event; a datagram's or a message's data is copied
    /// into `buf`, cut to its length.
    pub(crate) fn pop<'b>(&mut self, buf: &'b mut [u8]) -> Option<Event<'b>> {
        if self.count == 0 {
            return None;
        }
        let entry = self.entries.get_mut(self.first).and_then(Option::take)?;
        self.first = (self.first + 1) % E;
        self.count -= 1;
        self.flush();
        Some(match entry {
            Entry::Other(event) => event,
            Entry::Datagram { peer, relayed, len } => {
                let kept = self.pop_bytes(len, buf);
                Event::Context(ContextEvent::Datagram {
                    peer,
                    data: buf.get(..kept).unwrap_or_default(),
                    relayed,
                })
            }
            #[cfg(feature = "stream")]
            Entry::Message { peer, len } => {
                let kept = self.pop_bytes(len, buf);
                Event::Context(ContextEvent::Message {
                    peer,
                    data: buf.get(..kept).unwrap_or_default(),
                })
            }
        })
    }

    /// Copies the oldest `len` bytes of the ring into `buf`, as many as fit,
    /// and releases them; returns how many were copied.
    fn pop_bytes(&mut self, len: usize, buf: &mut [u8]) -> usize {
        let capacity = self.bytes.len();
        let kept = len.min(buf.len());
        for i in 0..kept {
            if let (Some(slot), Some(byte)) =
                (buf.get_mut(i), self.bytes.get((self.start + i) % capacity))
            {
                *slot = *byte;
            }
        }
        self.start = (self.start + len) % capacity.max(1);
        self.used -= len;
        kept
    }
}

/// What an event waiting aside is coalesced by: its peer, if any, and its
/// kind.
fn key(event: &Event<'static>) -> (Option<PeerId>, u8) {
    match *event {
        Event::Context(ContextEvent::Connected { peer }) => (Some(peer), 0),
        Event::Context(ContextEvent::Closed { peer, .. }) => (Some(peer), 1),
        Event::Context(ContextEvent::ReopenFailed { peer, .. }) => (Some(peer), 2),
        Event::Node(NodeEvent::PeerNotAtRelay { peer }) => (Some(peer), 3),
        Event::Node(NodeEvent::ObservedAddress { link, .. }) => {
            (None, 4 + u8::from(link == Link::Tcp))
        }
        // The relay's state: whether it is available, the latest only.
        Event::Node(NodeEvent::RelayUnavailable { .. } | NodeEvent::RelayAvailable) => (None, 6),
        Event::Context(ContextEvent::PathChanged { peer, .. }) => (Some(peer), 7),
        Event::Context(ContextEvent::Datagram { peer, .. }) => (Some(peer), 8),
        #[cfg(feature = "stream")]
        Event::Context(ContextEvent::Message { peer, .. }) => (Some(peer), 9),
        #[cfg(feature = "stream")]
        Event::Context(ContextEvent::ChannelReset { peer, .. }) => (Some(peer), 10),
    }
}

/// An event that borrows nothing, as the static lifetime.
fn owned(event: Event<'_>) -> Event<'static> {
    let context = match event {
        Event::Node(event) => return Event::Node(event),
        Event::Context(event) => event,
    };
    Event::Context(match context {
        ContextEvent::Connected { peer } => ContextEvent::Connected { peer },
        ContextEvent::Closed {
            peer,
            code,
            by_peer,
        } => ContextEvent::Closed {
            peer,
            code,
            by_peer,
        },
        ContextEvent::ReopenFailed { peer, error } => ContextEvent::ReopenFailed { peer, error },
        ContextEvent::PathChanged { peer, path } => ContextEvent::PathChanged { peer, path },
        // Datagrams and messages go through the byte ring, never here.
        ContextEvent::Datagram { peer, .. } => ContextEvent::Connected { peer },
        #[cfg(feature = "stream")]
        ContextEvent::Message { peer, .. } => ContextEvent::Connected { peer },
        #[cfg(feature = "stream")]
        ContextEvent::ChannelReset { peer, reason } => ContextEvent::ChannelReset { peer, reason },
    })
}

/// The application's event from the core's, with the context it is in when
/// it is a context's.
pub(crate) fn from_core(
    event: convesso_core::endpoint::Event<'_>,
) -> Option<(Option<convesso_core::handshake::Context>, Event<'_>)> {
    use convesso_core::endpoint::Event as Core;
    Some(match event {
        Core::Connected { peer, context } => (
            Some(context),
            Event::Context(ContextEvent::Connected { peer }),
        ),
        Core::Datagram {
            peer,
            context,
            data,
            relayed,
            ..
        } => (
            Some(context),
            Event::Context(ContextEvent::Datagram {
                peer,
                data,
                relayed,
            }),
        ),
        Core::Closed {
            peer,
            context,
            code,
            by_peer,
        } => (
            Some(context),
            Event::Context(ContextEvent::Closed {
                peer,
                code,
                by_peer,
            }),
        ),
        Core::ReopenFailed {
            peer,
            context,
            error,
        } => (
            Some(context),
            Event::Context(ContextEvent::ReopenFailed { peer, error }),
        ),
        Core::PathChanged {
            peer,
            context,
            path,
        } => (
            Some(context),
            Event::Context(ContextEvent::PathChanged { peer, path }),
        ),
        Core::PeerNotAtRelay { peer } => (None, Event::Node(NodeEvent::PeerNotAtRelay { peer })),
        Core::ObservedAddress { link, address } => (
            None,
            Event::Node(NodeEvent::ObservedAddress { link, address }),
        ),
        Core::RelayUnavailable { error } => {
            (None, Event::Node(NodeEvent::RelayUnavailable { error }))
        }
        Core::RelayAvailable => (None, Event::Node(NodeEvent::RelayAvailable)),
        // Without the stream layer, a frame is not the application's: only
        // the connection it may confirm is.
        Core::Frame {
            peer,
            context,
            connected,
            ..
        } => {
            if !connected {
                return None;
            }
            (
                Some(context),
                Event::Context(ContextEvent::Connected { peer }),
            )
        }
        // Only the relay context accepts payloads, and the core consumes them.
        Core::Payload { .. } => return None,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    extern crate std;

    /// The peer of key `n` of `identity.json`.
    fn peer(n: usize) -> PeerId {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../convesso-core/vectors/identity.json"))
                .unwrap();
        let text = vectors["keys"][n]["address"].as_str().unwrap();
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        convesso_core::identity::Address::parse(bytes)
            .unwrap()
            .peer_id()
    }

    fn context(event: ContextEvent<'_>) -> Event<'_> {
        Event::Context(event)
    }

    fn not_at_relay(n: usize) -> Event<'static> {
        Event::Node(NodeEvent::PeerNotAtRelay { peer: peer(n) })
    }

    type Queue<'d> = EventQueue<'d, ENTRIES, HELD>;

    #[test]
    fn events_come_out_in_order_and_datagrams_whole() {
        let mut bytes = [0u8; 10];
        let mut queue = Queue::new(&mut bytes);
        assert!(queue.push(context(ContextEvent::Connected { peer: peer(1) })));
        assert!(queue.push(context(ContextEvent::Datagram {
            peer: peer(1),
            data: b"abcdef",
            relayed: true
        })));
        assert!(!queue.has_room(5), "6 of 10 bytes used");
        assert!(!queue.push(context(ContextEvent::Datagram {
            peer: peer(2),
            data: b"12345",
            relayed: false
        })));
        let mut buf = [0u8; 16];
        assert_eq!(
            queue.pop(&mut buf),
            Some(context(ContextEvent::Connected { peer: peer(1) }))
        );
        assert_eq!(
            queue.pop(&mut buf),
            Some(context(ContextEvent::Datagram {
                peer: peer(1),
                data: b"abcdef",
                relayed: true
            }))
        );
        // The ring wraps.
        assert!(queue.push(context(ContextEvent::Datagram {
            peer: peer(2),
            data: b"123456789",
            relayed: false
        })));
        assert_eq!(
            queue.pop(&mut buf),
            Some(context(ContextEvent::Datagram {
                peer: peer(2),
                data: b"123456789",
                relayed: false
            }))
        );
        assert!(queue.is_empty());
        assert_eq!(queue.pop(&mut buf), None);
    }

    #[test]
    fn the_entries_are_bounded_too() {
        let mut bytes = [0u8; 4];
        let mut queue = Queue::new(&mut bytes);
        for _ in 0..ENTRIES {
            assert!(queue.push(not_at_relay(1)));
        }
        assert!(!queue.push(not_at_relay(1)));
        assert!(!queue.has_room(0));
    }

    fn full(queue: &mut Queue<'_>) {
        for _ in 0..ENTRIES {
            assert!(queue.push(not_at_relay(1)));
        }
    }

    /// While the queue is full, events wait aside, one per peer and kind, the
    /// latest replacing the earlier and taking its place at the back; reading
    /// moves them in, in that order. A datagram that finds no room is dropped,
    /// and so is one that would overtake what waits aside.
    #[test]
    fn events_wait_aside_coalesced_and_come_after_the_queue() {
        let mut bytes = [0u8; 64];
        let mut queue = Queue::new(&mut bytes);
        full(&mut queue);
        let relayed = context(ContextEvent::PathChanged {
            peer: peer(2),
            path: PathKind::Relayed,
        });
        let direct = context(ContextEvent::PathChanged {
            peer: peer(2),
            path: PathKind::Direct("192.0.2.1:7500".parse().unwrap()),
        });
        let closed = context(ContextEvent::Closed {
            peer: peer(3),
            code: 4,
            by_peer: true,
        });
        let datagram = context(ContextEvent::Datagram {
            peer: peer(2),
            data: b"late",
            relayed: false,
        });
        assert!(!queue.push_or_hold(direct));
        assert!(!queue.push_or_hold(closed));
        assert!(queue.push_or_hold(datagram), "no room: dropped");
        assert!(!queue.push_or_hold(relayed));
        assert!(queue.holding());
        let mut buf = [0u8; 4];
        let _ = queue.pop(&mut buf);
        assert!(
            queue.push_or_hold(datagram),
            "it would overtake what waits aside: dropped"
        );
        for _ in 1..ENTRIES {
            assert_eq!(queue.pop(&mut buf), Some(not_at_relay(1)));
        }
        assert_eq!(queue.pop(&mut buf), Some(closed));
        assert_eq!(queue.pop(&mut buf), Some(relayed), "the latest path");
        assert_eq!(queue.pop(&mut buf), None);
        assert!(!queue.holding());
    }

    /// The relay's two events are one state: while the queue is full, only the
    /// latest of them waits.
    #[test]
    fn the_relays_events_coalesce_as_one_state() {
        let mut bytes = [0u8; 4];
        let mut queue: EventQueue<'_, NODE_ENTRIES, NODE_HELD> = EventQueue::new(&mut bytes);
        for _ in 0..NODE_ENTRIES {
            assert!(queue.push(not_at_relay(1)));
        }
        let lost = RelayError::Link(convesso_core::endpoint::LinkFailure::Lost);
        let dead = RelayError::Link(convesso_core::endpoint::LinkFailure::Dead);
        queue.push_or_hold(Event::Node(NodeEvent::RelayUnavailable { error: lost }));
        queue.push_or_hold(Event::Node(NodeEvent::RelayAvailable));
        queue.push_or_hold(Event::Node(NodeEvent::RelayUnavailable { error: dead }));
        let mut buf = [0u8; 4];
        let mut out = std::vec::Vec::new();
        while let Some(event) = queue.pop(&mut buf) {
            out.push(owned(event));
        }
        assert_eq!(
            out.last(),
            Some(&Event::Node(NodeEvent::RelayUnavailable { error: dead }))
        );
        assert_eq!(out.len(), NODE_ENTRIES + 1, "one relay state waited");
    }

    /// An event that arrives while others wait aside goes behind them, even
    /// when the queue has room again.
    #[test]
    fn a_new_event_never_overtakes_one_waiting_aside() {
        let mut bytes = [0u8; 4];
        let mut queue = Queue::new(&mut bytes);
        full(&mut queue);
        let first = context(ContextEvent::Connected { peer: peer(2) });
        queue.push_or_hold(first);
        let mut buf = [0u8; 4];
        // One place frees, and the waiting event takes it.
        let _ = queue.pop(&mut buf);
        let second = context(ContextEvent::Connected { peer: peer(3) });
        queue.push_or_hold(second);
        let mut out = std::vec::Vec::new();
        while let Some(event) = queue.pop(&mut buf) {
            out.push(owned(event));
        }
        assert_eq!(&out[out.len() - 2..], &[first, second]);
    }

    /// The table holds every peer and kind the microcontroller tables name;
    /// beyond, the oldest change of state goes before a close.
    #[test]
    fn a_full_table_keeps_its_closes() {
        let mut bytes = [0u8; 4];
        let mut queue = Queue::new(&mut bytes);
        full(&mut queue);
        let closed = context(ContextEvent::Closed {
            peer: peer(1),
            code: 4,
            by_peer: false,
        });
        queue.push_or_hold(closed);
        for i in 0..HELD {
            queue.push_or_hold(context(ContextEvent::PathChanged {
                peer: peer(i % 4 + 1),
                path: PathKind::Direct(std::net::SocketAddr::from((
                    [192, 0, 2, 1],
                    7000 + i as u16,
                ))),
            }));
            queue.push_or_hold(context(ContextEvent::ReopenFailed {
                peer: peer(i % 4 + 1),
                error: DialError::NoResponse,
            }));
        }
        let mut buf = [0u8; 4];
        let mut out = std::vec::Vec::new();
        while let Some(event) = queue.pop(&mut buf) {
            out.push(owned(event));
        }
        assert!(out.contains(&closed), "the close is kept");
        assert!(out.len() <= ENTRIES + HELD);
    }
}
