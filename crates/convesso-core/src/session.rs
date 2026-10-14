//! A session's state (`PROTOCOL.md §5`): its key pairs, its
//! queue, and its timers. The [`Endpoint`](crate::endpoint::Endpoint) drives
//! it; this module holds the parts that do not need the endpoint's tables.
//!
//! ```text
//! current   send + receive
//! previous  receive only, until its 180 s: packets in flight are not lost
//! next      a pending handshake (the responder's) or a dial (the initiator's)
//! ```

use core::time::Duration;

use crate::dos::SourceKey;
use crate::handshake::ChannelBinding;
use crate::identity::Address;
use crate::paths::PeerPaths;
use crate::time::Instant;
use crate::transport::{MAX_COUNTER, ReplayWindow};

/// A side that sends under keys at least this old starts a new handshake.
pub const REKEY_AFTER: Duration = Duration::from_secs(120);

/// Keys at least this old are used for nothing: no send, no receive.
pub const KEYS_EXPIRE_AFTER: Duration = Duration::from_secs(180);

/// When enabled, a session sends a keepalive this long after received data
/// if it sent nothing since.
pub const PASSIVE_KEEPALIVE_AFTER: Duration = Duration::from_secs(10);

/// A datagram the queue could not take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull {
    /// The queue's bound, in bytes.
    pub limit: usize,
}

/// Datagrams waiting for a session's keys, bounded in bytes.
pub trait DatagramQueue: Default {
    /// The bound, in bytes of datagrams plus 2 bytes of bookkeeping each.
    const LIMIT: usize;

    /// Appends a datagram.
    ///
    /// # Errors
    ///
    /// [`QueueFull`] when it would take the queue past [`Self::LIMIT`]; the
    /// datagrams already queued are kept.
    fn push(&mut self, datagram: &[u8]) -> Result<(), QueueFull>;

    /// The oldest datagram, if any.
    fn front(&self) -> Option<&[u8]>;

    /// Removes the oldest datagram.
    fn pop(&mut self);

    /// Removes every datagram.
    fn clear(&mut self);

    /// Whether the queue holds nothing.
    fn is_empty(&self) -> bool {
        self.front().is_none()
    }
}

/// A queue in a fixed buffer of `N` bytes: each datagram is stored behind its
/// 2-byte length.
pub struct FixedQueue<const N: usize> {
    buffer: [u8; N],
    used: usize,
}

impl<const N: usize> Default for FixedQueue<N> {
    fn default() -> Self {
        Self {
            buffer: [0; N],
            used: 0,
        }
    }
}

impl<const N: usize> FixedQueue<N> {
    fn front_len(&self) -> Option<usize> {
        let len: [u8; 2] = self
            .buffer
            .get(..2)
            .filter(|_| self.used >= 2)?
            .try_into()
            .ok()?;
        Some(usize::from(u16::from_le_bytes(len)))
    }
}

impl<const N: usize> DatagramQueue for FixedQueue<N> {
    const LIMIT: usize = N;

    fn push(&mut self, datagram: &[u8]) -> Result<(), QueueFull> {
        let full = QueueFull { limit: N };
        let len = u16::try_from(datagram.len()).map_err(|_| full)?;
        let end = self.used + 2 + datagram.len();
        let slot = self.buffer.get_mut(self.used..end).ok_or(full)?;
        let (head, body) = slot.split_at_mut(2);
        head.copy_from_slice(&len.to_le_bytes());
        body.copy_from_slice(datagram);
        self.used = end;
        Ok(())
    }

    fn front(&self) -> Option<&[u8]> {
        let len = self.front_len()?;
        self.buffer.get(2..2 + len)
    }

    fn pop(&mut self) {
        if let Some(len) = self.front_len() {
            let taken = 2 + len;
            self.buffer.copy_within(taken..self.used, 0);
            self.used -= taken;
        }
    }

    fn clear(&mut self) {
        self.used = 0;
    }
}

/// A queue allocated only while it holds something, bounded at `LIMIT` bytes.
/// Only with `alloc`.
#[cfg(feature = "alloc")]
#[derive(Default)]
pub struct GrowableQueue<const LIMIT: usize> {
    datagrams: alloc::collections::VecDeque<alloc::vec::Vec<u8>>,
    used: usize,
}

#[cfg(feature = "alloc")]
impl<const LIMIT: usize> DatagramQueue for GrowableQueue<LIMIT> {
    const LIMIT: usize = LIMIT;

    fn push(&mut self, datagram: &[u8]) -> Result<(), QueueFull> {
        let cost = 2 + datagram.len();
        if self.used + cost > LIMIT {
            return Err(QueueFull { limit: LIMIT });
        }
        self.datagrams.push_back(datagram.to_vec());
        self.used += cost;
        Ok(())
    }

    fn front(&self) -> Option<&[u8]> {
        self.datagrams.front().map(alloc::vec::Vec::as_slice)
    }

    fn pop(&mut self) {
        if let Some(datagram) = self.datagrams.pop_front() {
            self.used -= 2 + datagram.len();
        }
        if self.datagrams.is_empty() {
            // Give the memory back: a dormant session holds no queue.
            self.datagrams = alloc::collections::VecDeque::new();
        }
    }

    fn clear(&mut self) {
        self.datagrams = alloc::collections::VecDeque::new();
        self.used = 0;
    }
}

/// One handshake's keys, as a session uses them.
pub(crate) struct KeyPair<W> {
    pub(crate) send: [u8; 32],
    pub(crate) recv: [u8; 32],
    /// The index the peer puts in packets to us.
    pub(crate) local_index: u32,
    /// The index we put in packets to the peer.
    pub(crate) remote_index: u32,
    pub(crate) created: Instant,
    pub(crate) next_counter: u64,
    pub(crate) received: u64,
    pub(crate) window: W,
}

impl<W> Drop for KeyPair<W> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.send.zeroize();
        self.recv.zeroize();
    }
}

impl<W: ReplayWindow> KeyPair<W> {
    pub(crate) fn new(
        (send, recv): ([u8; 32], [u8; 32]),
        local_index: u32,
        remote_index: u32,
        created: Instant,
    ) -> Self {
        Self {
            send,
            recv,
            local_index,
            remote_index,
            created,
            next_counter: 0,
            received: 0,
            window: W::default(),
        }
    }

    /// Whether the keys may still be used at `now`.
    pub(crate) fn live(&self, now: Instant) -> bool {
        now < self.created.saturating_add(KEYS_EXPIRE_AFTER)
            && self.next_counter < MAX_COUNTER
            && self.received < MAX_COUNTER
    }

    /// Whether sending at `now` should start a new handshake.
    pub(crate) fn wants_rekey(&self, now: Instant) -> bool {
        now >= self.created.saturating_add(REKEY_AFTER)
    }

    pub(crate) fn expires_at(&self) -> Instant {
        self.created.saturating_add(KEYS_EXPIRE_AFTER)
    }
}

/// A session with one peer in one context.
pub(crate) struct Session<W, Q> {
    pub(crate) address: Option<Address>,
    pub(crate) current: Option<KeyPair<W>>,
    pub(crate) previous: Option<KeyPair<W>>,
    pub(crate) queue: Q,
    pub(crate) last_source: Option<SourceKey>,
    /// Set when this side completed a handshake as initiator and owes the
    /// responder its confirming packet.
    pub(crate) confirm: bool,
    /// Set when a send found the keys old enough to renew.
    pub(crate) rekey: bool,
    /// A close to send, with its code, before the session is removed.
    pub(crate) closing: Option<u16>,
    pub(crate) passive_keepalive: bool,
    pub(crate) last_received_data: Option<Instant>,
    pub(crate) last_sent: Option<Instant>,
    /// The last time the session was used, to choose which dormant session a
    /// full table forgets.
    pub(crate) last_used: Instant,
    /// Whether the application was told of a connection with this peer in this
    /// context: later handshakes are silent rekeys.
    pub(crate) ever_connected: bool,
    /// Whether the dial in progress carries the head of the queue in its first
    /// contacts (the relay context): established, the head was delivered.
    pub(crate) carried: bool,
    /// The peer's candidates, and what it was told of ours
    /// (`PROTOCOL.md §7`). Forgotten with the keys.
    pub(crate) paths: PeerPaths,
    /// The channel binding of the handshake that gave the session keys when
    /// it had none (`PROTOCOL.md §5`). Forgotten with the keys.
    pub(crate) binding: Option<ChannelBinding>,
}

impl<W: ReplayWindow, Q: DatagramQueue> Session<W, Q> {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            address: None,
            current: None,
            previous: None,
            queue: Q::default(),
            last_source: None,
            confirm: false,
            rekey: false,
            closing: None,
            passive_keepalive: false,
            last_received_data: None,
            last_sent: None,
            last_used: now,
            ever_connected: false,
            carried: false,
            paths: PeerPaths::new(),
            binding: None,
        }
    }

    /// Deletes every key pair past its life. Returns the local indices freed.
    pub(crate) fn expire(&mut self, now: Instant) -> [Option<u32>; 2] {
        let mut freed = [None, None];
        if self.previous.as_ref().is_some_and(|keys| !keys.live(now)) {
            freed[0] = self.previous.take().map(|keys| keys.local_index);
        }
        if self.current.as_ref().is_some_and(|keys| !keys.live(now)) {
            freed[1] = self.current.take().map(|keys| keys.local_index);
        }
        if self.dormant() {
            // A direct source learned through an attempt is a NAT's hole,
            // gone by the time the session reopens: it reopens through its
            // hint or the relay.
            if self.paths.exchanged
                && self
                    .last_source
                    .is_some_and(|source| source.relayed_from().is_none())
            {
                self.last_source = None;
            }
            self.paths = PeerPaths::new();
            self.binding = None;
        }
        freed
    }

    /// Makes `keys` current; the old current becomes previous, and the old
    /// previous is deleted. A session without live keys takes `binding` as
    /// its own; a renewal keeps the one it has. Returns the local index freed, if
    /// any.
    pub(crate) fn promote(&mut self, keys: KeyPair<W>, binding: &ChannelBinding) -> Option<u32> {
        let renewal = [&self.current, &self.previous]
            .into_iter()
            .flatten()
            .any(|old| old.live(keys.created));
        if !renewal || self.binding.is_none() {
            self.binding = Some(*binding);
        }
        let dropped = self.previous.take().map(|old| old.local_index);
        self.previous = self.current.take();
        self.current = Some(keys);
        self.rekey = false;
        self.paths.new_keys();
        dropped
    }

    /// Whether the session has no keys: it sends nothing and sets no deadline.
    pub(crate) fn dormant(&self) -> bool {
        self.current.is_none() && self.previous.is_none()
    }

    /// When the passive keepalive falls due, if enabled and owed.
    pub(crate) fn passive_keepalive_due(&self) -> Option<Instant> {
        if !self.passive_keepalive || self.current.is_none() {
            return None;
        }
        let received = self.last_received_data?;
        if self.last_sent.is_some_and(|sent| sent >= received) {
            return None;
        }
        Some(received.saturating_add(PASSIVE_KEEPALIVE_AFTER))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::{DatagramQueue, FixedQueue, QueueFull};

    #[test]
    fn a_fixed_queue_keeps_order_and_its_bound() {
        let mut queue: FixedQueue<16> = FixedQueue::default();
        queue.push(b"abc").unwrap();
        queue.push(b"defgh").unwrap();
        // 2 + 3 + 2 + 5 = 12 bytes used; 2 + 3 more would be 17.
        assert_eq!(queue.push(b"ijk"), Err(QueueFull { limit: 16 }));
        assert_eq!(queue.front(), Some(&b"abc"[..]));
        queue.pop();
        assert_eq!(queue.front(), Some(&b"defgh"[..]));
        queue.push(b"ij").unwrap();
        queue.pop();
        assert_eq!(queue.front(), Some(&b"ij"[..]));
        queue.clear();
        assert!(queue.is_empty());
    }
}
