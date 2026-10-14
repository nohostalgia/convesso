//! The events waiting for the application: bounded in bytes, in order, with
//! no allocator.
//!
//! ```text
//! entries   a ring of ENTRIES small events, in order; a datagram's entry holds
//!           its peer, how it came, and its length
//! bytes     the datagrams' data, in the same order, in the integrator's buffer
//! ```
//!
//! The driver reads from the network only while there is room for one more
//! event of the largest size ([`EventQueue::has_room`]): what a slow reader
//! costs is left on the network, where the protocol expects losses, never
//! dropped here.

use core::net::SocketAddr;

use convesso_core::endpoint::{RelayError, SendError};
use convesso_core::handshake::DialError;
use convesso_core::identity::PeerId;
use convesso_core::paths::PathKind;
use convesso_core::relay::Link;

/// How many events can wait at once, datagrams included.
pub const ENTRIES: usize = 16;

/// Something the application should know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEvent<'a> {
    /// A first session with a peer.
    Connected {
        /// The peer.
        peer: PeerId,
    },
    /// A datagram. Its data is cut to the buffer given to
    /// [`crate::Events::next`] when longer.
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
    /// The relay session could not be opened, or ended.
    RelayUnavailable {
        /// Why.
        error: RelayError,
    },
    /// The path to a peer changed.
    PathChanged {
        /// The peer.
        peer: PeerId,
        /// The new path.
        path: PathKind,
    },
    /// A reliable message, whole and in order (feature `stream`). Its data
    /// is cut to the buffer given to [`crate::Events::next`] when longer:
    /// give one of the largest message's size.
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

/// Why a send failed.
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
    /// The stream layer refused a message, with its named error.
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
            #[cfg(feature = "stream")]
            Self::Message(error) => write!(f, "the message was refused: {error:?}"),
        }
    }
}

impl core::error::Error for NodeError {}

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
    Other(NodeEvent<'static>),
}

/// The queue of events, over the integrator's byte buffer.
pub(crate) struct EventQueue<'d> {
    entries: [Option<Entry>; ENTRIES],
    first: usize,
    count: usize,
    bytes: &'d mut [u8],
    start: usize,
    used: usize,
}

impl<'d> EventQueue<'d> {
    pub(crate) fn new(bytes: &'d mut [u8]) -> Self {
        Self {
            entries: [None; ENTRIES],
            first: 0,
            count: 0,
            bytes,
            start: 0,
            used: 0,
        }
    }

    /// Whether an event with up to `data` bytes of data fits.
    pub(crate) fn has_room(&self, data: usize) -> bool {
        self.count < ENTRIES && self.bytes.len() - self.used >= data
    }

    /// Whether nothing waits.
    pub(crate) const fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn push_entry(&mut self, entry: Entry) {
        let at = (self.first + self.count) % ENTRIES;
        if let Some(slot) = self.entries.get_mut(at) {
            *slot = Some(entry);
            self.count += 1;
        }
    }

    /// Copies `data` to the end of the byte ring; `false` when it does not
    /// fit with an entry.
    #[cfg(feature = "stream")]
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
    pub(crate) fn push(&mut self, event: NodeEvent<'_>) -> bool {
        match event {
            NodeEvent::Datagram {
                peer,
                data,
                relayed,
            } => {
                if !self.has_room(data.len()) {
                    return false;
                }
                let capacity = self.bytes.len();
                for (i, byte) in data.iter().enumerate() {
                    if let Some(slot) = self.bytes.get_mut((self.start + self.used + i) % capacity)
                    {
                        *slot = *byte;
                    }
                }
                self.used += data.len();
                self.push_entry(Entry::Datagram {
                    peer,
                    relayed,
                    len: data.len(),
                });
                true
            }
            #[cfg(feature = "stream")]
            NodeEvent::Message { peer, data } => {
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
                if self.count >= ENTRIES {
                    return false;
                }
                self.push_entry(Entry::Other(owned(other)));
                true
            }
        }
    }

    /// Takes the oldest event; a datagram's data is copied into `buf`, cut to
    /// its length.
    pub(crate) fn pop<'b>(&mut self, buf: &'b mut [u8]) -> Option<NodeEvent<'b>> {
        if self.count == 0 {
            return None;
        }
        let entry = self.entries.get_mut(self.first).and_then(Option::take)?;
        self.first = (self.first + 1) % ENTRIES;
        self.count -= 1;
        Some(match entry {
            Entry::Other(event) => event,
            Entry::Datagram { peer, relayed, len } => {
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
                NodeEvent::Datagram {
                    peer,
                    data: buf.get(..kept).unwrap_or_default(),
                    relayed,
                }
            }
            #[cfg(feature = "stream")]
            Entry::Message { peer, len } => {
                let kept = self.pop_bytes(len, buf);
                NodeEvent::Message {
                    peer,
                    data: buf.get(..kept).unwrap_or_default(),
                }
            }
        })
    }

    /// Copies the oldest `len` bytes of the ring into `buf`, as many as fit,
    /// and releases them; returns how many were copied.
    #[cfg(feature = "stream")]
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

/// An event that borrows nothing, as the static lifetime.
fn owned(event: NodeEvent<'_>) -> NodeEvent<'static> {
    match event {
        NodeEvent::Connected { peer } => NodeEvent::Connected { peer },
        NodeEvent::Closed {
            peer,
            code,
            by_peer,
        } => NodeEvent::Closed {
            peer,
            code,
            by_peer,
        },
        NodeEvent::ReopenFailed { peer, error } => NodeEvent::ReopenFailed { peer, error },
        NodeEvent::PeerNotAtRelay { peer } => NodeEvent::PeerNotAtRelay { peer },
        NodeEvent::ObservedAddress { link, address } => {
            NodeEvent::ObservedAddress { link, address }
        }
        NodeEvent::RelayUnavailable { error } => NodeEvent::RelayUnavailable { error },
        NodeEvent::PathChanged { peer, path } => NodeEvent::PathChanged { peer, path },
        // Datagrams go through the byte ring, never here.
        NodeEvent::Datagram { peer, .. } => NodeEvent::Connected { peer },
        #[cfg(feature = "stream")]
        NodeEvent::Message { peer, .. } => NodeEvent::Connected { peer },
        #[cfg(feature = "stream")]
        NodeEvent::ChannelReset { peer, reason } => NodeEvent::ChannelReset { peer, reason },
    }
}

/// The application's event, from the core's.
pub(crate) fn from_core(event: convesso_core::endpoint::Event<'_>) -> Option<NodeEvent<'_>> {
    use convesso_core::endpoint::Event;
    Some(match event {
        Event::Connected { peer, .. } => NodeEvent::Connected { peer },
        Event::Datagram {
            peer,
            data,
            relayed,
            ..
        } => NodeEvent::Datagram {
            peer,
            data,
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

    #[test]
    fn events_come_out_in_order_and_datagrams_whole() {
        let mut bytes = [0u8; 10];
        let mut queue = EventQueue::new(&mut bytes);
        assert!(queue.push(NodeEvent::Connected { peer: peer(1) }));
        assert!(queue.push(NodeEvent::Datagram {
            peer: peer(1),
            data: b"abcdef",
            relayed: true
        }));
        assert!(!queue.has_room(5), "6 of 10 bytes used");
        assert!(!queue.push(NodeEvent::Datagram {
            peer: peer(2),
            data: b"12345",
            relayed: false
        }));
        let mut buf = [0u8; 16];
        assert_eq!(
            queue.pop(&mut buf),
            Some(NodeEvent::Connected { peer: peer(1) })
        );
        assert_eq!(
            queue.pop(&mut buf),
            Some(NodeEvent::Datagram {
                peer: peer(1),
                data: b"abcdef",
                relayed: true
            })
        );
        // The ring wraps.
        assert!(queue.push(NodeEvent::Datagram {
            peer: peer(2),
            data: b"123456789",
            relayed: false
        }));
        assert_eq!(
            queue.pop(&mut buf),
            Some(NodeEvent::Datagram {
                peer: peer(2),
                data: b"123456789",
                relayed: false
            })
        );
        assert!(queue.is_empty());
        assert_eq!(queue.pop(&mut buf), None);
    }

    #[test]
    fn the_entries_are_bounded_too() {
        let mut bytes = [0u8; 4];
        let mut queue = EventQueue::new(&mut bytes);
        for _ in 0..ENTRIES {
            assert!(queue.push(NodeEvent::PeerNotAtRelay { peer: peer(1) }));
        }
        assert!(!queue.push(NodeEvent::PeerNotAtRelay { peer: peer(1) }));
        assert!(!queue.has_room(0));
    }
}
