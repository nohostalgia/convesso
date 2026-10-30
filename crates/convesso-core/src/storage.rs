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

    /// The entry with the smallest key: what an index ordered by time holds
    /// next.
    fn first(&self) -> Option<(&K, &V)>;
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

    fn first(&self) -> Option<(&K, &V)> {
        self.slots
            .iter()
            .flatten()
            .min_by(|(a, _), (b, _)| a.cmp(b))
            .map(|(k, v)| (k, v))
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

    fn first(&self) -> Option<(&K, &V)> {
        self.entries.first_key_value()
    }
}

/// The tables a build of the core uses.
///
/// One trait rather than a const parameter on every type: an integrator names
/// a configuration, usually one of the ready-made ones, rather than a list of
/// numbers. To change only some sizes, [`profile!`](crate::profile) derives a
/// configuration from [`Mcu`] or [`Server`], naming only those.
pub trait Config {
    /// Where the contexts the endpoint serves are kept, the relay's included.
    /// Only the application fills it, never a peer.
    type Contexts<K: Ord, V>: Table<K, V> + Default;
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

/// Every size of a configuration: how many entries each table holds, or for a
/// growable one the most it grows to (`usize::MAX`: as memory allows).
///
/// A configuration derived with [`profile!`](crate::profile) starts from its
/// base's and changes only the fields it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sizes {
    /// Contexts served, the relay's included.
    pub contexts: usize,
    /// Open sessions.
    pub sessions: usize,
    /// Known peers.
    pub peers: usize,
    /// Pending handshakes.
    pub pending: usize,
    /// Recent ephemeral keys.
    pub recent_ephemerals: usize,
    /// Source rates under load.
    pub source_rates: usize,
    /// The anti-replay window, in 64-bit words: `(replay_words - 1) * 64`
    /// counters.
    pub replay_words: usize,
    /// The datagrams a session holds without keys, in bytes.
    pub queue_bytes: usize,
    /// Dials in progress.
    pub dials: usize,
    /// Indices of sessions and dials.
    pub indices: usize,
    /// Direct address hints.
    pub hints: usize,
    /// Excluded IP prefixes.
    pub excluded: usize,
    /// First contacts a second before the responder is under load.
    pub load_rate_per_second: u32,
    /// First contacts that may arrive at once.
    pub load_burst: u32,
}

/// Derives a configuration from [`Mcu`] or [`Server`], naming only the sizes
/// that change; every other one is the base's ([`Sizes`] lists them).
///
/// ```
/// convesso_core::profile! {
///     /// A device with two contexts and eight sessions.
///     pub Device: Mcu { contexts: 2, sessions: 8 }
/// }
/// use convesso_core::storage::Mcu;
/// assert_eq!(Device::SIZES.contexts, 2);
/// assert_eq!(Device::SIZES.peers, Mcu::SIZES.peers);
/// ```
///
/// A name that is not a size fails to build:
///
/// ```compile_fail,E0560
/// convesso_core::profile! { pub Device: Mcu { contxts: 2 } }
/// ```
#[macro_export]
macro_rules! profile {
    ($(#[$meta:meta])* $vis:vis $name:ident : Mcu { $($field:ident : $value:expr),* $(,)? }) => {
        $(#[$meta])*
        $vis struct $name;
        impl $name {
            /// This configuration's sizes.
            $vis const SIZES: $crate::storage::Sizes = $crate::storage::Sizes {
                $($field: $value,)*
                ..$crate::storage::Mcu::SIZES
            };
        }
        $crate::__fixed_config!($name);
    };
    ($(#[$meta:meta])* $vis:vis $name:ident : Server { $($field:ident : $value:expr),* $(,)? }) => {
        $(#[$meta])*
        $vis struct $name;
        impl $name {
            /// This configuration's sizes.
            $vis const SIZES: $crate::storage::Sizes = $crate::storage::Sizes {
                $($field: $value,)*
                ..$crate::storage::Server::SIZES
            };
        }
        $crate::__growable_config!($name);
    };
}

/// The [`Config`] of a type with fixed-size tables, from its `SIZES`.
#[doc(hidden)]
#[macro_export]
macro_rules! __fixed_config {
    ($name:ident) => {
        impl $crate::storage::Config for $name {
            type Contexts<K: Ord, V> = $crate::storage::FixedTable<K, V, { $name::SIZES.contexts }>;
            type Sessions<K: Ord, V> = $crate::storage::FixedTable<K, V, { $name::SIZES.sessions }>;
            type Peers<K: Ord, V> = $crate::storage::FixedTable<K, V, { $name::SIZES.peers }>;
            type Pending<K: Ord, V> = $crate::storage::FixedTable<K, V, { $name::SIZES.pending }>;
            type RecentEphemerals<K: Ord, V> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.recent_ephemerals }>;
            type SourceRates<K: Ord, V> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.source_rates }>;
            type ReplayWindow = $crate::transport::Window<{ $name::SIZES.replay_words }>;
            type Queue = $crate::session::FixedQueue<{ $name::SIZES.queue_bytes }>;
            type Dials<K: Ord, V> = $crate::storage::FixedTable<K, V, { $name::SIZES.dials }>;
            type Indices<K: Ord, V> = $crate::storage::FixedTable<K, V, { $name::SIZES.indices }>;
            type Hints<K: Ord, V> = $crate::storage::FixedTable<K, V, { $name::SIZES.hints }>;
            type Excluded<K: Ord, V> = $crate::storage::FixedTable<K, V, { $name::SIZES.excluded }>;
            const LOAD_RATE_PER_SECOND: u32 = $name::SIZES.load_rate_per_second;
            const LOAD_BURST: u32 = $name::SIZES.load_burst;
        }
    };
}

/// The [`Config`] of a type with growable tables, from its `SIZES`.
#[doc(hidden)]
#[macro_export]
macro_rules! __growable_config {
    ($name:ident) => {
        impl $crate::storage::Config for $name {
            type Contexts<K: Ord, V> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.contexts }>;
            type Sessions<K: Ord, V> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.sessions }>;
            type Peers<K: Ord, V> = $crate::storage::GrowableTable<K, V, { $name::SIZES.peers }>;
            type Pending<K: Ord, V> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.pending }>;
            type RecentEphemerals<K: Ord, V> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.recent_ephemerals }>;
            type SourceRates<K: Ord, V> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.source_rates }>;
            type ReplayWindow = $crate::transport::Window<{ $name::SIZES.replay_words }>;
            type Queue = $crate::session::GrowableQueue<{ $name::SIZES.queue_bytes }>;
            type Dials<K: Ord, V> = $crate::storage::GrowableTable<K, V, { $name::SIZES.dials }>;
            type Indices<K: Ord, V> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.indices }>;
            type Hints<K: Ord, V> = $crate::storage::GrowableTable<K, V, { $name::SIZES.hints }>;
            type Excluded<K: Ord, V> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.excluded }>;
            const LOAD_RATE_PER_SECOND: u32 = $name::SIZES.load_rate_per_second;
            const LOAD_BURST: u32 = $name::SIZES.load_burst;
        }
    };
}

/// A microcontroller: 4 contexts, the relay's included; 4 sessions, 16 known
/// peers, 4 pending handshakes, 8 recent ephemerals and 8 source rates, in
/// fixed arrays; under load beyond 5 first contacts a second.
///
/// The load rate is provisional: a responder runs four X25519 operations and a
/// torsion check per first contact, tens of milliseconds on a 32-bit
/// microcontroller. Stage 3 measures it on hardware.
pub struct Mcu;

impl Mcu {
    /// This configuration's sizes.
    pub const SIZES: Sizes = Sizes {
        contexts: 4,
        sessions: 4,
        peers: 16,
        pending: 4,
        recent_ephemerals: 8,
        source_rates: 8,
        // 256 counters: a device that sends little never reorders more.
        replay_words: 5,
        // 1 KB: a waking sensor's reading leaves with its first handshake.
        queue_bytes: 1024,
        dials: 2,
        indices: 12,
        // 4: a device that talks to a handful of peers.
        hints: 4,
        // 4: an overlay's prefix and a few more.
        excluded: 4,
        load_rate_per_second: 5,
        load_burst: 5,
    };
}

crate::__fixed_config!(Mcu);

/// A server: tables that grow with what they hold, contexts and sessions as
/// memory allows; at most 4,096 pending handshakes, recent ephemerals and
/// source rates; under load beyond 1,000 first contacts a second. Only with
/// `alloc`.
#[cfg(feature = "alloc")]
pub struct Server;

#[cfg(feature = "alloc")]
impl Server {
    /// This configuration's sizes.
    pub const SIZES: Sizes = Sizes {
        contexts: usize::MAX,
        sessions: usize::MAX,
        peers: usize::MAX,
        pending: 4096,
        recent_ephemerals: 4096,
        source_rates: 4096,
        // 8,192 counters: high throughput over paths that reorder.
        replay_words: 129,
        // 64 KB, allocated only while a session reopens.
        queue_bytes: 65536,
        dials: 4096,
        indices: 16384,
        hints: 4096,
        excluded: 16,
        load_rate_per_second: 1000,
        load_burst: 1000,
    };
}

#[cfg(feature = "alloc")]
crate::__growable_config!(Server);
