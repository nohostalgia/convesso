//! Where a channel's memory comes from (`PROTOCOL.md §8`): a
//! configuration names its buffers, as the core's `Config` names its tables.
//!
//! [`Mcu`] keeps everything in fixed arrays; [`Server`], behind the `alloc`
//! feature, in buffers that grow on demand up to a bound and are released
//! when they empty. An integrator can define its own.

use convesso_core::handshake::Context;
use convesso_core::identity::PeerId;
use convesso_core::storage::{FixedTable, Table};

use crate::channel::{Sent, Stored};

/// A channel's key: the session's peer and context.
pub type Key = (PeerId, Context);

/// The memory and the limits of every channel.
pub trait StreamConfig {
    /// The largest message, in bytes.
    const MAX_MESSAGE: usize;
    /// The messages waiting to be sent or acknowledged, as bytes.
    type SendQueue: ByteQueue;
    /// The lengths of those messages, in order.
    type Lengths: Slots<u32>;
    /// The fragments sent and not yet acknowledged, in sequence order.
    type InFlight: Slots<Sent>;
    /// Where a receiver assembles a message and holds fragments that came
    /// early.
    type ReceiveArena: Arena;
    /// The fragments that came early.
    type Stored: Slots<Stored>;
    /// The channels, by session.
    type Channels<V>: Table<Key, V> + Default;
}

/// The microcontroller configuration: messages up to 2,048 bytes, 2,048
/// bytes of send buffer and 2,048 of receive buffer per channel, 4 channels,
/// all in fixed arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mcu;

impl StreamConfig for Mcu {
    const MAX_MESSAGE: usize = 2048;
    type SendQueue = FixedQueue<2048>;
    type Lengths = FixedSlots<u32, 32>;
    type InFlight = FixedSlots<Sent, 16>;
    type ReceiveArena = FixedArena<2048>;
    type Stored = FixedSlots<Stored, 16>;
    type Channels<V> = FixedTable<Key, V, 4>;
}

/// The server configuration: messages up to 262,144 bytes (peerfectly's
/// largest payload), buffers that grow to twice that per channel and are
/// released when they empty. Only with the `alloc` feature.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Server;

#[cfg(feature = "alloc")]
impl StreamConfig for Server {
    const MAX_MESSAGE: usize = 262_144;
    type SendQueue = GrowableQueue<524_288>;
    type Lengths = GrowableSlots<u32, 4096>;
    type InFlight = GrowableSlots<Sent, 1024>;
    type ReceiveArena = GrowableArena<524_288>;
    type Stored = GrowableSlots<Stored, 1024>;
    type Channels<V> = convesso_core::storage::GrowableTable<Key, V>;
}

/// A queue of bytes: appended at the back, read anywhere, released from the
/// front.
pub trait ByteQueue: Default {
    /// The most bytes it ever holds.
    fn capacity(&self) -> usize;
    /// The bytes it holds.
    fn len(&self) -> usize;
    /// Whether it holds nothing.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Appends `bytes` whole, or nothing; returns whether it did.
    fn push(&mut self, bytes: &[u8]) -> bool;
    /// Copies the bytes at `from`, counted from the front, into `dest`;
    /// returns false when they are not all held.
    fn copy_out(&self, from: usize, dest: &mut [u8]) -> bool;
    /// Releases `count` bytes from the front.
    fn pop(&mut self, count: usize);
}

/// A byte arena of bounded capacity, written and read anywhere.
pub trait Arena: Default {
    /// The most bytes it ever holds.
    fn capacity(&self) -> usize;
    /// The first `len` bytes, if held.
    fn get(&self, len: usize) -> Option<&[u8]>;
    /// The first `len` bytes to write, if `len` is within the capacity.
    fn get_mut(&mut self, len: usize) -> Option<&mut [u8]>;
    /// Nothing in the arena is needed any more: a growable one lets its
    /// memory go.
    fn release(&mut self);
}

/// An ordered list of bounded length.
pub trait Slots<T: Copy>: Default {
    /// The most items it ever holds.
    fn capacity(&self) -> usize;
    /// The items it holds.
    fn len(&self) -> usize;
    /// Whether it holds nothing.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The item at `i`.
    fn get(&self, i: usize) -> Option<&T>;
    /// The item at `i`, mutably.
    fn get_mut(&mut self, i: usize) -> Option<&mut T>;
    /// Inserts `item` at `i`, shifting the rest; false when full or out of
    /// range.
    fn insert(&mut self, i: usize, item: T) -> bool;
    /// Removes the item at `i`, shifting the rest.
    fn remove(&mut self, i: usize) -> Option<T>;
    /// Appends `item`; false when full.
    fn push(&mut self, item: T) -> bool {
        self.insert(self.len(), item)
    }
    /// Removes the first `count` items.
    fn drain_front(&mut self, count: usize) {
        for _ in 0..count.min(self.len()) {
            let _ = self.remove(0);
        }
    }
    /// Removes every item.
    fn clear(&mut self);
}

/// A [`ByteQueue`] in a fixed array: a ring.
#[derive(Debug, Clone)]
pub struct FixedQueue<const N: usize> {
    bytes: [u8; N],
    head: usize,
    len: usize,
}

impl<const N: usize> Default for FixedQueue<N> {
    fn default() -> Self {
        Self {
            bytes: [0; N],
            head: 0,
            len: 0,
        }
    }
}

impl<const N: usize> ByteQueue for FixedQueue<N> {
    fn capacity(&self) -> usize {
        N
    }

    fn len(&self) -> usize {
        self.len
    }

    fn push(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > N - self.len {
            return false;
        }
        let tail = (self.head + self.len) % N.max(1);
        let first = bytes.len().min(N - tail);
        let (now, wrapped) = bytes.split_at(first);
        if let Some(slot) = self.bytes.get_mut(tail..tail + first) {
            slot.copy_from_slice(now);
        }
        if let Some(slot) = self.bytes.get_mut(..wrapped.len()) {
            slot.copy_from_slice(wrapped);
        }
        self.len += bytes.len();
        true
    }

    fn copy_out(&self, from: usize, dest: &mut [u8]) -> bool {
        if from + dest.len() > self.len {
            return false;
        }
        let start = (self.head + from) % N.max(1);
        let first = dest.len().min(N - start);
        let (now, wrapped) = dest.split_at_mut(first);
        let (Some(a), Some(b)) = (
            self.bytes.get(start..start + first),
            self.bytes.get(..wrapped.len()),
        ) else {
            return false;
        };
        now.copy_from_slice(a);
        wrapped.copy_from_slice(b);
        true
    }

    fn pop(&mut self, count: usize) {
        let count = count.min(self.len);
        self.head = (self.head + count) % N.max(1);
        self.len -= count;
        if self.len == 0 {
            self.head = 0;
        }
    }
}

/// An [`Arena`] in a fixed array.
#[derive(Debug, Clone)]
pub struct FixedArena<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Default for FixedArena<N> {
    fn default() -> Self {
        Self { bytes: [0; N] }
    }
}

impl<const N: usize> Arena for FixedArena<N> {
    fn capacity(&self) -> usize {
        N
    }

    fn get(&self, len: usize) -> Option<&[u8]> {
        self.bytes.get(..len)
    }

    fn get_mut(&mut self, len: usize) -> Option<&mut [u8]> {
        self.bytes.get_mut(..len)
    }

    fn release(&mut self) {}
}

/// [`Slots`] in a fixed array.
#[derive(Debug, Clone)]
pub struct FixedSlots<T, const N: usize> {
    items: [T; N],
    len: usize,
}

impl<T: Copy + Default, const N: usize> Default for FixedSlots<T, N> {
    fn default() -> Self {
        Self {
            items: [T::default(); N],
            len: 0,
        }
    }
}

impl<T: Copy + Default, const N: usize> Slots<T> for FixedSlots<T, N> {
    fn capacity(&self) -> usize {
        N
    }

    fn len(&self) -> usize {
        self.len
    }

    fn get(&self, i: usize) -> Option<&T> {
        self.items.get(..self.len)?.get(i)
    }

    fn get_mut(&mut self, i: usize) -> Option<&mut T> {
        self.items.get_mut(..self.len)?.get_mut(i)
    }

    fn insert(&mut self, i: usize, item: T) -> bool {
        if self.len >= N || i > self.len {
            return false;
        }
        if let Some(moved) = self.items.get_mut(i..=self.len) {
            moved.rotate_right(1);
        }
        if let Some(slot) = self.items.get_mut(i) {
            *slot = item;
        }
        self.len += 1;
        true
    }

    fn remove(&mut self, i: usize) -> Option<T> {
        if i >= self.len {
            return None;
        }
        let item = *self.items.get(i)?;
        if let Some(moved) = self.items.get_mut(i..self.len) {
            moved.rotate_left(1);
        }
        self.len -= 1;
        Some(item)
    }

    fn drain_front(&mut self, count: usize) {
        let count = count.min(self.len);
        if let Some(moved) = self.items.get_mut(..self.len) {
            moved.rotate_left(count);
        }
        self.len -= count;
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

/// A [`ByteQueue`] that grows up to `CAP` bytes and lets its memory go when
/// it empties.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Default)]
pub struct GrowableQueue<const CAP: usize> {
    bytes: alloc::collections::VecDeque<u8>,
}

#[cfg(feature = "alloc")]
impl<const CAP: usize> ByteQueue for GrowableQueue<CAP> {
    fn capacity(&self) -> usize {
        CAP
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn push(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > CAP - self.bytes.len() {
            return false;
        }
        self.bytes.extend(bytes.iter().copied());
        true
    }

    fn copy_out(&self, from: usize, dest: &mut [u8]) -> bool {
        if from + dest.len() > self.bytes.len() {
            return false;
        }
        let end = from + dest.len();
        for (d, s) in dest.iter_mut().zip(self.bytes.range(from..end)) {
            *d = *s;
        }
        true
    }

    fn pop(&mut self, count: usize) {
        let count = count.min(self.bytes.len());
        self.bytes.drain(..count);
        if self.bytes.is_empty() {
            self.bytes = alloc::collections::VecDeque::new();
        }
    }
}

/// An [`Arena`] that grows up to `CAP` bytes and lets its memory go when
/// released.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Default)]
pub struct GrowableArena<const CAP: usize> {
    bytes: alloc::vec::Vec<u8>,
}

#[cfg(feature = "alloc")]
impl<const CAP: usize> Arena for GrowableArena<CAP> {
    fn capacity(&self) -> usize {
        CAP
    }

    fn get(&self, len: usize) -> Option<&[u8]> {
        // Only what was written is read; beyond it there is nothing.
        self.bytes.get(..len)
    }

    fn get_mut(&mut self, len: usize) -> Option<&mut [u8]> {
        if len > CAP {
            return None;
        }
        if len > self.bytes.len() {
            self.bytes.resize(len, 0);
        }
        self.bytes.get_mut(..len)
    }

    fn release(&mut self) {
        self.bytes = alloc::vec::Vec::new();
    }
}

/// [`Slots`] that grow up to `CAP` items.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct GrowableSlots<T, const CAP: usize> {
    items: alloc::vec::Vec<T>,
}

#[cfg(feature = "alloc")]
impl<T, const CAP: usize> Default for GrowableSlots<T, CAP> {
    fn default() -> Self {
        Self {
            items: alloc::vec::Vec::new(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<T: Copy, const CAP: usize> Slots<T> for GrowableSlots<T, CAP> {
    fn capacity(&self) -> usize {
        CAP
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn get(&self, i: usize) -> Option<&T> {
        self.items.get(i)
    }

    fn get_mut(&mut self, i: usize) -> Option<&mut T> {
        self.items.get_mut(i)
    }

    fn insert(&mut self, i: usize, item: T) -> bool {
        if self.items.len() >= CAP || i > self.items.len() {
            return false;
        }
        self.items.insert(i, item);
        true
    }

    fn remove(&mut self, i: usize) -> Option<T> {
        (i < self.items.len()).then(|| self.items.remove(i))
    }

    fn drain_front(&mut self, count: usize) {
        let count = count.min(self.items.len());
        self.items.drain(..count);
        if self.items.is_empty() {
            self.items = alloc::vec::Vec::new();
        }
    }

    fn clear(&mut self) {
        self.items = alloc::vec::Vec::new();
    }
}
