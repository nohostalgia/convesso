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

    /// Puts `datagram` where the first datagram after the first `skip` that
    /// `old` matches was, and removes the other matches after the first
    /// `skip`; appends it when none matches. The order of the rest is kept.
    /// `old` may be asked more than once about a datagram.
    ///
    /// # Errors
    ///
    /// [`QueueFull`] when the result would take the queue past
    /// [`Self::LIMIT`]; the queue is then left as it was.
    fn replace(
        &mut self,
        skip: usize,
        old: impl FnMut(&[u8]) -> bool,
        datagram: &[u8],
    ) -> Result<(), QueueFull>;

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
        self.len_at(0)
    }

    /// The length of the datagram stored at `at`, if one is.
    fn len_at(&self, at: usize) -> Option<usize> {
        let len: [u8; 2] = self
            .buffer
            .get(at..at + 2)
            .filter(|_| self.used >= at + 2)?
            .try_into()
            .ok()?;
        Some(usize::from(u16::from_le_bytes(len)))
    }

    /// The datagram stored at `at`, behind its length.
    fn datagram_at(&self, at: usize, len: usize) -> &[u8] {
        self.buffer.get(at + 2..at + 2 + len).unwrap_or_default()
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

    fn replace(
        &mut self,
        skip: usize,
        mut old: impl FnMut(&[u8]) -> bool,
        datagram: &[u8],
    ) -> Result<(), QueueFull> {
        let full = QueueFull { limit: N };
        let len = u16::try_from(datagram.len()).map_err(|_| full)?;
        let mut start = 0;
        for _ in 0..skip {
            match self.len_at(start) {
                Some(len) => start += 2 + len,
                None => break,
            }
        }
        // What the matches take, to refuse before anything moves.
        let mut matched = 0;
        let mut at = start;
        while let Some(len) = self.len_at(at) {
            if old(self.datagram_at(at, len)) {
                matched += 2 + len;
            }
            at += 2 + len;
        }
        let cost = 2 + datagram.len();
        let used = self.used - matched + cost;
        if used > N {
            return Err(full);
        }
        // The matches compacted away, noting where the first was.
        let (mut read, mut write, mut first) = (start, start, None);
        while let Some(len) = self.len_at(read) {
            let taken = 2 + len;
            if old(self.datagram_at(read, len)) {
                first.get_or_insert(write);
            } else {
                self.buffer.copy_within(read..read + taken, write);
                write += taken;
            }
            read += taken;
        }
        let at = first.unwrap_or(write);
        self.buffer.copy_within(at..write, at + cost);
        let slot = self.buffer.get_mut(at..at + cost).ok_or(full)?;
        let (head, body) = slot.split_at_mut(2);
        head.copy_from_slice(&len.to_le_bytes());
        body.copy_from_slice(datagram);
        self.used = used;
        Ok(())
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

    fn replace(
        &mut self,
        skip: usize,
        mut old: impl FnMut(&[u8]) -> bool,
        datagram: &[u8],
    ) -> Result<(), QueueFull> {
        let matched: usize = self
            .datagrams
            .iter()
            .skip(skip)
            .filter(|queued| old(queued))
            .map(|queued| 2 + queued.len())
            .sum();
        let used = self.used - matched + 2 + datagram.len();
        if used > LIMIT {
            return Err(QueueFull { limit: LIMIT });
        }
        let mut first = None;
        let mut i = skip;
        while let Some(hit) = self.datagrams.get(i).map(|queued| old(queued)) {
            if hit {
                self.datagrams.remove(i);
                first.get_or_insert(i);
            } else {
                i += 1;
            }
        }
        let at = first.unwrap_or(self.datagrams.len());
        self.datagrams.insert(at, datagram.to_vec());
        self.used = used;
        Ok(())
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
    /// Whether the application was told of this session's connection and not
    /// yet that it went idle (`PROTOCOL.md §5`): a handshake while it is set
    /// is a silent renewal.
    pub(crate) connected: bool,
    /// Whether this side answered the handshake that gave the current keys:
    /// admission was asked for it, and a change of access judges it again.
    pub(crate) accepted: bool,
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
    pub(crate) fn new() -> Self {
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
            connected: false,
            accepted: false,
            carried: false,
            paths: PeerPaths::new(),
            binding: None,
        }
    }

    /// Deletes every key pair past its life. Returns the local indices freed.
    /// A session that loses its last key pair here forgets what it knew of its
    /// paths and its binding, once.
    pub(crate) fn expire(&mut self, now: Instant) -> [Option<u32>; 2] {
        let had_keys = !self.dormant();
        let mut freed = [None, None];
        if self.previous.as_ref().is_some_and(|keys| !keys.live(now)) {
            freed[0] = self.previous.take().map(|keys| keys.local_index);
        }
        if self.current.as_ref().is_some_and(|keys| !keys.live(now)) {
            freed[1] = self.current.take().map(|keys| keys.local_index);
        }
        if had_keys && self.dormant() {
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
    /// any, and whether it was a renewal.
    pub(crate) fn promote(
        &mut self,
        keys: KeyPair<W>,
        binding: &ChannelBinding,
    ) -> (Option<u32>, bool) {
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
        (dropped, renewal)
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

    extern crate std;

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

    /// A queue holding `items`, in order.
    fn queue_of<Q: DatagramQueue>(items: &[&[u8]]) -> Q {
        let mut queue = Q::default();
        for item in items {
            queue.push(item).unwrap();
        }
        queue
    }

    /// Everything in `queue`, in order, emptying it.
    fn drain<Q: DatagramQueue>(queue: &mut Q) -> std::vec::Vec<std::vec::Vec<u8>> {
        let mut items = std::vec::Vec::new();
        while let Some(item) = queue.front() {
            items.push(item.to_vec());
            queue.pop();
        }
        items
    }

    /// `replace` on `items`, returning the queue's contents after.
    fn replaced<Q: DatagramQueue>(
        items: &[&[u8]],
        skip: usize,
        new: &[u8],
    ) -> std::vec::Vec<std::vec::Vec<u8>> {
        let mut queue: Q = queue_of(items);
        queue
            .replace(skip, |queued| queued.first() == Some(&b'x'), new)
            .unwrap();
        drain(&mut queue)
    }

    fn v(items: &[&[u8]]) -> std::vec::Vec<std::vec::Vec<u8>> {
        items.iter().map(|item| item.to_vec()).collect()
    }

    /// The datagrams starting with `x` are the old ones.
    fn replaces_in_place<Q: DatagramQueue>() {
        // A match at the head, in the middle, at the tail.
        assert_eq!(
            replaced::<Q>(&[b"x1", b"a", b"b"], 0, b"x9"),
            v(&[b"x9", b"a", b"b"])
        );
        assert_eq!(
            replaced::<Q>(&[b"a", b"x1", b"b"], 0, b"x9"),
            v(&[b"a", b"x9", b"b"])
        );
        assert_eq!(
            replaced::<Q>(&[b"a", b"b", b"x1"], 0, b"x9"),
            v(&[b"a", b"b", b"x9"])
        );
        // Several matches leave one entry, where the first was.
        assert_eq!(
            replaced::<Q>(&[b"a", b"x1", b"b", b"x2", b"c", b"x3"], 0, b"x9"),
            v(&[b"a", b"x9", b"b", b"c"])
        );
        // No match appends.
        assert_eq!(
            replaced::<Q>(&[b"a", b"b"], 0, b"x9"),
            v(&[b"a", b"b", b"x9"])
        );
        assert_eq!(replaced::<Q>(&[], 0, b"x9"), v(&[b"x9"]));
        // A skipped head stays; the new one goes where the next match was.
        assert_eq!(
            replaced::<Q>(&[b"x0", b"a", b"x1", b"b", b"x2"], 1, b"x9"),
            v(&[b"x0", b"a", b"x9", b"b"])
        );
        assert_eq!(
            replaced::<Q>(&[b"x0", b"a"], 1, b"x9"),
            v(&[b"x0", b"a", b"x9"])
        );
        assert_eq!(replaced::<Q>(&[b"x0"], 1, b"x9"), v(&[b"x0", b"x9"]));
        assert_eq!(replaced::<Q>(&[], 1, b"x9"), v(&[b"x9"]));
        // Longer and shorter than the one replaced.
        assert_eq!(
            replaced::<Q>(&[b"a", b"x1", b"b"], 0, b"x123456"),
            v(&[b"a", b"x123456", b"b"])
        );
        assert_eq!(
            replaced::<Q>(&[b"a", b"x123456", b"b", b"x2"], 0, b"x"),
            v(&[b"a", b"x", b"b"])
        );
        // The queue stays usable after.
        let mut queue: Q = queue_of(&[b"x1", b"a"]);
        queue
            .replace(0, |q| q.first() == Some(&b'x'), b"x2")
            .unwrap();
        queue.push(b"b").unwrap();
        assert_eq!(drain(&mut queue), v(&[b"x2", b"a", b"b"]));
    }

    /// A result past the bound is refused, and the queue is left as it was;
    /// the bytes the matches free count.
    fn replace_keeps_the_bound<Q: DatagramQueue>() {
        // 16 bytes: (2 + 4) * 2 = 12 used.
        let mut queue: Q = queue_of(&[b"aaaa", b"xbbb"]);
        let old = |q: &[u8]| q.first() == Some(&b'x');
        // Freeing 6 and taking 2 + 8 = 10 gives 16: fits.
        queue.replace(0, old, b"x1234567").unwrap();
        assert_eq!(drain(&mut queue), v(&[b"aaaa", b"x1234567"]));
        let mut queue: Q = queue_of(&[b"aaaa", b"xbbb"]);
        // 2 + 9 = 11 would give 17.
        assert_eq!(
            queue.replace(0, old, b"x12345678"),
            Err(QueueFull { limit: Q::LIMIT })
        );
        // Skipping the match frees nothing: 12 + 6 = 18.
        assert_eq!(
            queue.replace(1, |q| q == b"aaaa", b"x123"),
            Err(QueueFull { limit: Q::LIMIT })
        );
        assert_eq!(drain(&mut queue), v(&[b"aaaa", b"xbbb"]));
    }

    #[test]
    fn a_fixed_queue_replaces_in_place() {
        replaces_in_place::<FixedQueue<64>>();
        replace_keeps_the_bound::<FixedQueue<16>>();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn a_growable_queue_replaces_in_place() {
        replaces_in_place::<super::GrowableQueue<64>>();
        replace_keeps_the_bound::<super::GrowableQueue<16>>();
    }
}
