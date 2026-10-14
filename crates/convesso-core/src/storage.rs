//! Where the core keeps its tables, chosen by whoever builds it.
//!
//! The core never calls the allocator. A table it needs (sessions, known peers)
//! is a [`Table`], and which one is decided by a [`Config`]:
//!
//! - [`FixedTable`] holds at most `N` entries in an array. Its memory is known
//!   when the firmware is linked, so the footprint budget can measure it, and it
//!   never fragments a heap that a device running for months does not have.
//! - [`GrowableTable`], behind the `alloc` feature, grows with what it holds, so
//!   a server is not made to refuse its 1,025th device because someone guessed
//!   1,024.
//!
//! The protocol logic is the same code over either. A full fixed table refuses
//! a new key with [`CapacityExhausted`], which hands the entry back: it never
//! allocates, never panics, and never evicts an entry to make room, because an
//! entry silently evicted is a session silently dropped.

/// A key-value table the core keeps its state in.
pub trait Table<K: Ord, V> {
    /// Inserts `value` under `key`.
    ///
    /// Returns the value previously under `key`, if any; replacing an entry
    /// never needs room. A new key that does not fit is refused, and the entry
    /// comes back in the error so that nothing is lost.
    fn insert(&mut self, key: K, value: V) -> Result<Option<V>, CapacityExhausted<K, V>>;

    /// The value under `key`.
    fn get(&self, key: &K) -> Option<&V>;

    /// The value under `key`, mutably.
    fn get_mut(&mut self, key: &K) -> Option<&mut V>;

    /// Removes and returns the value under `key`.
    fn remove(&mut self, key: &K) -> Option<V>;

    /// How many entries the table holds.
    fn len(&self) -> usize;

    /// Whether the table holds no entry.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The most entries the table can hold, or `None` when it grows without limit.
    fn capacity(&self) -> Option<usize>;

    /// Calls `f` on every entry, in no particular order.
    fn for_each(&self, f: impl FnMut(&K, &V));

    /// Keeps only the entries for which `keep` returns `true`.
    fn retain(&mut self, keep: impl FnMut(&K, &mut V) -> bool);
}

/// A new key was refused because the table is full.
///
/// Carries the refused entry back to the caller, and the capacity that was
/// reached, so the refusal can be reported with its cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityExhausted<K, V> {
    /// The key that was refused.
    pub key: K,
    /// The value that was refused.
    pub value: V,
    /// The capacity of the table that refused it.
    pub capacity: usize,
}

impl<K, V> core::fmt::Display for CapacityExhausted<K, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "table capacity exhausted: all {} entries are in use",
            self.capacity
        )
    }
}

impl<K: core::fmt::Debug, V: core::fmt::Debug> core::error::Error for CapacityExhausted<K, V> {}

/// A table of at most `N` entries, held in an array.
///
/// Lookups scan the array: for the handful of entries a microcontroller holds,
/// that is smaller and as fast as anything that indexes.
pub struct FixedTable<K, V, const N: usize> {
    slots: [Option<(K, V)>; N],
    len: usize,
}

impl<K, V, const N: usize> FixedTable<K, V, N> {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            len: 0,
        }
    }
}

impl<K, V, const N: usize> Default for FixedTable<K, V, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord, V, const N: usize> Table<K, V> for FixedTable<K, V, N> {
    fn insert(&mut self, key: K, value: V) -> Result<Option<V>, CapacityExhausted<K, V>> {
        if let Some(existing) = self.get_mut(&key) {
            return Ok(Some(core::mem::replace(existing, value)));
        }
        match self.slots.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some((key, value));
                self.len += 1;
                Ok(None)
            }
            None => Err(CapacityExhausted {
                key,
                value,
                capacity: N,
            }),
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.slots
            .iter()
            .flatten()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.slots
            .iter_mut()
            .flatten()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| matches!(slot, Some((k, _)) if k == key))?;
        let (_, value) = slot.take()?;
        self.len -= 1;
        Some(value)
    }

    fn len(&self) -> usize {
        self.len
    }

    fn capacity(&self) -> Option<usize> {
        Some(N)
    }

    fn for_each(&self, mut f: impl FnMut(&K, &V)) {
        for (k, v) in self.slots.iter().flatten() {
            f(k, v);
        }
    }

    fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        for slot in &mut self.slots {
            let drop = match slot.as_mut() {
                Some((k, v)) => !keep(k, v),
                None => false,
            };
            if drop {
                *slot = None;
                self.len -= 1;
            }
        }
    }
}

/// A table that grows with what it holds, up to `LIMIT` entries.
///
/// Only with the `alloc` feature. The allocation is this type's, not the
/// protocol logic's: the core asks a [`Table`] for room and does not know
/// where it comes from. `LIMIT` defaults to no limit; a table that strangers
/// can fill, such as pending handshakes, sets one, so that growing never means
/// growing without bound.
#[cfg(feature = "alloc")]
pub struct GrowableTable<K, V, const LIMIT: usize = { usize::MAX }> {
    entries: alloc::collections::BTreeMap<K, V>,
}

#[cfg(feature = "alloc")]
impl<K, V, const LIMIT: usize> GrowableTable<K, V, LIMIT> {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: alloc::collections::BTreeMap::new(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<K, V, const LIMIT: usize> Default for GrowableTable<K, V, LIMIT> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl<K: Ord, V, const LIMIT: usize> Table<K, V> for GrowableTable<K, V, LIMIT> {
    fn insert(&mut self, key: K, value: V) -> Result<Option<V>, CapacityExhausted<K, V>> {
        if self.entries.len() >= LIMIT && !self.entries.contains_key(&key) {
            return Err(CapacityExhausted {
                key,
                value,
                capacity: LIMIT,
            });
        }
        Ok(self.entries.insert(key, value))
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key)
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn capacity(&self) -> Option<usize> {
        (LIMIT != usize::MAX).then_some(LIMIT)
    }

    fn for_each(&self, mut f: impl FnMut(&K, &V)) {
        for (k, v) in &self.entries {
            f(k, v);
        }
    }

    fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        self.entries.retain(|k, v| keep(k, v));
    }
}

/// The tables a build of the core uses.
///
/// One trait rather than a const parameter on every type: an integrator names
/// a configuration, usually one of the ready-made ones, rather than a list of
/// numbers.
pub trait Config {
    /// Where open sessions are kept.
    type Sessions<K: Ord, V>: Table<K, V> + Default;
    /// Where known peers are kept.
    type Peers<K: Ord, V>: Table<K, V> + Default;
    /// Where a responder keeps handshakes it accepted and that are not yet
    /// confirmed. Strangers who know the address can fill it, so it is always
    /// bounded.
    type Pending<K: Ord, V>: Table<K, V> + Default;
    /// Where a responder remembers the ephemeral keys of recent first contacts.
    /// Bounded: forgetting one costs at most one Diffie-Hellman.
    type RecentEphemerals<K: Ord, V>: Table<K, V> + Default;
    /// Where a responder under load keeps each source's rate. Bounded:
    /// forgetting one lets that source restart its burst.
    type SourceRates<K: Ord, V>: Table<K, V> + Default;
    /// A receiver's anti-replay window, per key pair.
    type ReplayWindow: crate::transport::ReplayWindow;
    /// Datagrams a session holds while it has no keys, bounded in bytes.
    type Queue: crate::session::DatagramQueue;
    /// Where an endpoint keeps the dials it is making.
    type Dials<K: Ord, V>: Table<K, V> + Default;
    /// Where an endpoint maps the indices peers put in packets to their session
    /// or dial.
    type Indices<K: Ord, V>: Table<K, V> + Default;
    /// Where an endpoint keeps the direct address hints applications give for
    /// peers. Bounded: a full table forgets the hint used least recently.
    type Hints<K: Ord, V>: Table<K, V> + Default;
    /// Where an endpoint keeps the IP prefixes an application excluded from
    /// direct paths (`PROTOCOL.md §7`). Bounded.
    type Excluded<K: Ord, V>: Table<K, V> + Default;
    /// First contacts a responder takes to the Diffie-Hellman per second before
    /// it is under load.
    const LOAD_RATE_PER_SECOND: u32;
    /// How many such first contacts may arrive at once.
    const LOAD_BURST: u32;
}

/// A microcontroller: 4 sessions, 16 known peers, 4 pending handshakes, 8
/// recent ephemerals and 8 source rates, in fixed arrays; under load beyond 5
/// first contacts a second.
///
/// The load rate is provisional: a responder runs four X25519 operations and a
/// torsion check per first contact, tens of milliseconds on a 32-bit
/// microcontroller. Stage 3 measures it on hardware.
pub struct Mcu;

impl Config for Mcu {
    type Sessions<K: Ord, V> = FixedTable<K, V, 4>;
    type Peers<K: Ord, V> = FixedTable<K, V, 16>;
    type Pending<K: Ord, V> = FixedTable<K, V, 4>;
    type RecentEphemerals<K: Ord, V> = FixedTable<K, V, 8>;
    type SourceRates<K: Ord, V> = FixedTable<K, V, 8>;
    /// 256 counters: a device that sends little never reorders more.
    type ReplayWindow = crate::transport::Window<5>;
    /// 1 KB: a waking sensor's reading leaves with its first handshake.
    type Queue = crate::session::FixedQueue<1024>;
    type Dials<K: Ord, V> = FixedTable<K, V, 2>;
    type Indices<K: Ord, V> = FixedTable<K, V, 12>;
    /// 4: a device that talks to a handful of peers.
    type Hints<K: Ord, V> = FixedTable<K, V, 4>;
    /// 4: an overlay's prefix and a few more.
    type Excluded<K: Ord, V> = FixedTable<K, V, 4>;
    const LOAD_RATE_PER_SECOND: u32 = 5;
    const LOAD_BURST: u32 = 5;
}

/// A server: tables that grow with what they hold; at most 4,096 pending
/// handshakes, recent ephemerals and source rates; under load beyond 1,000
/// first contacts a second. Only with `alloc`.
#[cfg(feature = "alloc")]
pub struct Server;

#[cfg(feature = "alloc")]
impl Config for Server {
    type Sessions<K: Ord, V> = GrowableTable<K, V>;
    type Peers<K: Ord, V> = GrowableTable<K, V>;
    type Pending<K: Ord, V> = GrowableTable<K, V, 4096>;
    type RecentEphemerals<K: Ord, V> = GrowableTable<K, V, 4096>;
    type SourceRates<K: Ord, V> = GrowableTable<K, V, 4096>;
    /// 8,192 counters: high throughput over paths that reorder.
    type ReplayWindow = crate::transport::Window<129>;
    /// 64 KB, allocated only while a session reopens.
    type Queue = crate::session::GrowableQueue<65536>;
    type Dials<K: Ord, V> = GrowableTable<K, V, 4096>;
    type Indices<K: Ord, V> = GrowableTable<K, V, 16384>;
    type Hints<K: Ord, V> = GrowableTable<K, V, 4096>;
    type Excluded<K: Ord, V> = GrowableTable<K, V, 16>;
    const LOAD_RATE_PER_SECOND: u32 = 1000;
    const LOAD_BURST: u32 = 1000;
}
