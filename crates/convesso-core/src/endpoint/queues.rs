//! The queues of the sessions reopening with datagrams waiting
//! (`PROTOCOL.md §5`): lent to a session when it first queues a datagram,
//! given back when its queue empties, so that a microcontroller holds room
//! for the few sessions that reopen at once rather than one queue per session.

use super::Key;
use crate::session::{DatagramQueue, QueueFull};
use crate::storage::{Config, Table};

/// The queues lent to sessions, by session.
pub(super) struct Queues<C: Config> {
    lent: C::Queues<Key, C::Queue>,
}

impl<C: Config> Queues<C> {
    /// No queue lent, built at compile time.
    pub(super) const EMPTY: Self = Self {
        lent: <C::Queues<Key, C::Queue> as Table<Key, C::Queue>>::EMPTY,
    };

    /// What a full queue, or the lack of a free one, is refused with.
    const FULL: QueueFull = QueueFull {
        limit: <C::Queue as DatagramQueue>::LIMIT,
    };

    /// Makes room for `queues` queues, once.
    pub(super) fn reserve(&mut self, queues: usize) {
        self.lent.reserve(queues);
    }

    /// Whether `key`'s session has nothing queued.
    pub(super) fn is_empty(&self, key: &Key) -> bool {
        self.lent.get(key).is_none_or(DatagramQueue::is_empty)
    }

    /// The oldest datagram `key`'s session queued, if any.
    pub(super) fn front(&self, key: &Key) -> Option<&[u8]> {
        self.lent.get(key)?.front()
    }

    /// Queues `datagram` for `key`'s session, lending it a queue when it holds
    /// none.
    ///
    /// # Errors
    ///
    /// [`QueueFull`] when its queue is full, or none is free to lend; what was
    /// queued is kept.
    pub(super) fn push(&mut self, key: Key, datagram: &[u8]) -> Result<(), QueueFull> {
        let queue = self.lent.insert_empty(key).map_err(|_| Self::FULL)?;
        let pushed = queue.push(datagram);
        self.give_back_if_empty(&key);
        pushed
    }

    /// As [`DatagramQueue::replace`], on `key`'s session's queue, lending it
    /// one when it holds none.
    ///
    /// # Errors
    ///
    /// As [`Self::push`].
    pub(super) fn replace(
        &mut self,
        key: Key,
        skip: usize,
        old: impl FnMut(&[u8]) -> bool,
        datagram: &[u8],
    ) -> Result<(), QueueFull> {
        let queue = self.lent.insert_empty(key).map_err(|_| Self::FULL)?;
        let replaced = queue.replace(skip, old, datagram);
        self.give_back_if_empty(&key);
        replaced
    }

    /// Removes the oldest datagram of `key`'s session; its queue goes back
    /// when that was the last.
    pub(super) fn pop(&mut self, key: &Key) {
        if let Some(queue) = self.lent.get_mut(key) {
            queue.pop();
        }
        self.give_back_if_empty(key);
    }

    /// Discards everything `key`'s session queued, and gives its queue back.
    pub(super) fn clear(&mut self, key: &Key) {
        self.lent.discard(key);
    }

    /// The queues lent at present.
    #[cfg(test)]
    pub(super) fn lent(&self) -> usize {
        self.lent.len()
    }

    fn give_back_if_empty(&mut self, key: &Key) {
        if self.lent.get(key).is_some_and(DatagramQueue::is_empty) {
            self.lent.discard(key);
        }
    }
}
