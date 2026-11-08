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

/// A value with an empty state, built at compile time: what a table makes in
/// its own room ([`Table::insert_empty`]) before the caller fills it in place.
///
/// The compiler copies a constant straight into its destination, while it
/// assembles a value made at run time on the stack first, whatever the code
/// that makes it: so an entry of a few kilobytes is made from its `EMPTY`, and
/// never crosses the stack.
pub trait Empty {
    /// The empty value.
    const EMPTY: Self;
}

macro_rules! empty_is_zero {
    ($($t:ty),*) => {$(
        impl Empty for $t {
            const EMPTY: Self = 0;
        }
    )*};
}
empty_is_zero!(u8, u16, u32, u64, usize);

impl Empty for () {
    const EMPTY: Self = ();
}

impl Empty for bool {
    const EMPTY: Self = false;
}

impl Empty for char {
    const EMPTY: Self = '\0';
}

impl Empty for &str {
    const EMPTY: Self = "";
}

impl<T: Empty, const N: usize> Empty for [T; N] {
    const EMPTY: Self = [const { T::EMPTY }; N];
}

impl<T> Empty for Maybe<T> {
    const EMPTY: Self = Self::None;
}

impl Empty for crate::time::Instant {
    const EMPTY: Self = Self::from_millis(0);
}

/// A key-value table the core keeps its state in.
///
/// A table is built empty at compile time ([`Table::EMPTY`]), so that it can
/// live in a `static`, and its entries are made and dropped where they are
/// held ([`Table::insert_empty`], [`Table::discard`]): on a microcontroller, an
/// entry of a few kilobytes never crosses the stack on its way in or out.
pub trait Table<K: Ord, V> {
    /// An empty table: what a `static` holds before anything is inserted.
    const EMPTY: Self;

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

    /// The entry under `key`, made [`Empty`] in the table's own room when
    /// there is none, for the caller to fill in place. An entry already under
    /// `key` is returned as it is. A new key that does not fit is refused, and
    /// no entry is made.
    ///
    /// # Errors
    ///
    /// [`TableFull`] when the key is new and the table holds as many entries
    /// as its capacity.
    fn insert_empty(&mut self, key: K) -> Result<&mut V, TableFull>
    where
        V: Empty;

    /// Drops the entry under `key` where it is held; whether there was one.
    fn discard(&mut self, key: &K) -> bool;

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

    /// Makes room for `capacity` entries, once, for a table sized when the
    /// endpoint starts ([`BootTable`]); a table sized when it is built, or
    /// that grows, ignores it.
    fn reserve(&mut self, _capacity: usize) {}
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

/// A new key was refused by [`Table::insert_empty`] because the table is full;
/// its entry was never made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableFull {
    /// The capacity of the table that refused it.
    pub capacity: usize,
}

impl core::fmt::Display for TableFull {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "table capacity exhausted: all {} entries are in use",
            self.capacity
        )
    }
}

impl core::error::Error for TableFull {}

/// An `Option` whose tag is a byte of its own, `0` when empty: what a value
/// built at compile time holds where it would hold an `Option`.
///
/// An `Option` marks `None` in a spare value of what it holds when it can (a
/// `bool` set to 2, an enum's unused tag), and that byte is not zero. A
/// constant with a non-zero byte is copied from flash, where an all-zero one
/// is written with a `memset`, and a `static` of it lands in `.bss`: so the
/// empty state of every type built at compile time is all zero bytes
/// (`DESIGN.md §2`), and holds `Maybe`s. It offers `Option`'s methods, and
/// converts to and from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Maybe<T> {
    /// Nothing: a zero byte.
    #[default]
    None = 0,
    /// A value.
    Some(T) = 1,
}

impl<T> From<Option<T>> for Maybe<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => Self::Some(value),
            None => Self::None,
        }
    }
}

impl<T> From<Maybe<T>> for Option<T> {
    fn from(value: Maybe<T>) -> Self {
        match value {
            Maybe::Some(value) => Some(value),
            Maybe::None => None,
        }
    }
}

impl<T> IntoIterator for Maybe<T> {
    type Item = T;
    type IntoIter = core::option::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        Option::from(self).into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Maybe<T> {
    type Item = &'a T;
    type IntoIter = core::option::IntoIter<&'a T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_ref().into_iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Maybe<T> {
    type Item = &'a mut T;
    type IntoIter = core::option::IntoIter<&'a mut T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_mut().into_iter()
    }
}

impl<T> Maybe<T> {
    /// As [`Option::as_ref`].
    #[must_use]
    pub const fn as_ref(&self) -> Option<&T> {
        match self {
            Self::Some(value) => Some(value),
            Self::None => None,
        }
    }

    /// As [`Option::as_mut`].
    pub const fn as_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Some(value) => Some(value),
            Self::None => None,
        }
    }

    /// As [`Option::is_some`].
    #[must_use]
    pub const fn is_some(&self) -> bool {
        matches!(self, Self::Some(_))
    }

    /// As [`Option::is_none`].
    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// As [`Option::take`].
    pub fn take(&mut self) -> Option<T> {
        core::mem::take(self).into()
    }

    /// As [`Option::replace`].
    pub fn replace(&mut self, value: T) -> Option<T> {
        core::mem::replace(self, Self::Some(value)).into()
    }

    /// As [`Option::insert`].
    pub fn insert(&mut self, value: T) -> &mut T {
        *self = Self::Some(value);
        match self {
            Self::Some(value) => value,
            Self::None => unreachable!("just set"),
        }
    }

    /// As [`Option::get_or_insert_with`].
    pub fn get_or_insert_with(&mut self, make: impl FnOnce() -> T) -> &mut T {
        if let Self::Some(value) = self {
            return value;
        }
        self.insert(make())
    }

    /// The value, as an `Option` of it, for a value that is `Copy`.
    #[must_use]
    pub const fn get(&self) -> Option<T>
    where
        T: Copy,
    {
        match self {
            Self::Some(value) => Some(*value),
            Self::None => None,
        }
    }

    /// As [`Option::is_some_and`].
    pub fn is_some_and(self, f: impl FnOnce(T) -> bool) -> bool {
        Option::from(self).is_some_and(f)
    }

    /// As [`Option::is_none_or`].
    pub fn is_none_or(self, f: impl FnOnce(T) -> bool) -> bool {
        Option::from(self).is_none_or(f)
    }

    /// As [`Option::map`].
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Option<U> {
        Option::from(self).map(f)
    }

    /// As [`Option::and_then`].
    pub fn and_then<U>(self, f: impl FnOnce(T) -> Option<U>) -> Option<U> {
        Option::from(self).and_then(f)
    }

    /// As [`Option::map_or`].
    pub fn map_or<U>(self, default: U, f: impl FnOnce(T) -> U) -> U {
        Option::from(self).map_or(default, f)
    }

    /// As [`Option::filter`].
    pub fn filter(self, keep: impl FnOnce(&T) -> bool) -> Option<T> {
        Option::from(self).filter(keep)
    }

    /// As [`Option::unwrap_or`].
    pub fn unwrap_or(self, default: T) -> T {
        Option::from(self).unwrap_or(default)
    }
}

/// Where a [`Slotted`] table keeps its keys or its values: one slot per
/// entry it can hold, each made from [`Empty`] while free.
pub trait SlotStorage: Empty {
    /// What each slot holds.
    type Item;
    /// The slots.
    fn slots(&self) -> &[Self::Item];
    /// The slots, mutably.
    fn slots_mut(&mut self) -> &mut [Self::Item];
    /// Makes `capacity` slots, once: a storage sized when it is built
    /// ignores it, and so does one already sized.
    fn reserve(&mut self, capacity: usize);
}

impl<T: Empty, const N: usize> SlotStorage for [T; N] {
    type Item = T;

    fn slots(&self) -> &[T] {
        self
    }

    fn slots_mut(&mut self) -> &mut [T] {
        self
    }

    fn reserve(&mut self, _capacity: usize) {}
}

#[cfg(feature = "alloc")]
impl<T> Empty for alloc::vec::Vec<T> {
    const EMPTY: Self = Self::new();
}

#[cfg(feature = "alloc")]
impl<T: Empty> SlotStorage for alloc::vec::Vec<T> {
    type Item = T;

    fn slots(&self) -> &[T] {
        self
    }

    fn slots_mut(&mut self) -> &mut [T] {
        self
    }

    fn reserve(&mut self, capacity: usize) {
        if !self.is_empty() {
            return;
        }
        self.reserve_exact(capacity);
        for _ in 0..capacity {
            self.push(T::EMPTY);
        }
    }
}

/// A table of as many entries as it has slots, in a storage of slots for
/// its keys and one for its values: arrays ([`FixedTable`]), or vectors made
/// once when the endpoint starts ([`BootTable`]).
///
/// Lookups scan the slots: for the handful of entries a microcontroller holds,
/// that is smaller and as fast as anything that indexes. A key's position
/// holds its value; a free position holds the value's [`Empty`] state, so
/// that an empty table of arrays is all zero bytes, and an entry is made by
/// copying that constant straight into its slot, a `memset` (`DESIGN.md §2`).
/// A key and a value made together, or a value wrapped in an `Option`, would
/// be assembled on the stack first.
pub struct Slotted<KS, VS> {
    keys: KS,
    values: VS,
    len: usize,
}

/// A table of at most `N` entries, held in arrays.
pub type FixedTable<K, V, const N: usize> = Slotted<[Maybe<K>; N], [V; N]>;

/// A table whose number of entries is given when the endpoint starts
/// ([`Table::reserve`]), held in vectors allocated then, once, and never
/// grown or freed: for a library shipped built, whose integrator chooses its
/// sizes. Until reserved it holds nothing, and refuses every new key. Only
/// with `alloc`.
#[cfg(feature = "alloc")]
pub type BootTable<K, V> = Slotted<alloc::vec::Vec<Maybe<K>>, alloc::vec::Vec<V>>;

impl<KS: Empty, VS: Empty> Slotted<KS, VS> {
    /// An empty table, built at compile time: all zero bytes for arrays.
    pub const EMPTY: Self = Self {
        keys: KS::EMPTY,
        values: VS::EMPTY,
        len: 0,
    };

    /// An empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self::EMPTY
    }
}

impl<KS: Empty, VS: Empty> Default for Slotted<KS, VS> {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl<K: Ord, V, KS: SlotStorage<Item = Maybe<K>>, VS: SlotStorage<Item = V>> Slotted<KS, VS> {
    /// Where `key` is held.
    fn position(&self, key: &K) -> Option<usize> {
        self.keys
            .slots()
            .iter()
            .position(|k| k.as_ref() == Some(key))
    }

    /// A free slot.
    fn free(&self) -> Option<usize> {
        self.keys.slots().iter().position(Maybe::is_none)
    }

    fn full(&self) -> TableFull {
        TableFull {
            capacity: self.keys.slots().len(),
        }
    }
}

impl<K: Ord, V: Empty, KS, VS> Table<K, V> for Slotted<KS, VS>
where
    KS: SlotStorage<Item = Maybe<K>>,
    VS: SlotStorage<Item = V>,
{
    const EMPTY: Self = Self::EMPTY;

    fn insert(&mut self, key: K, value: V) -> Result<Option<V>, CapacityExhausted<K, V>> {
        if let Some(existing) = self.get_mut(&key) {
            return Ok(Some(core::mem::replace(existing, value)));
        }
        let capacity = self.keys.slots().len();
        let free = self.free();
        let (keys, values) = (self.keys.slots_mut(), self.values.slots_mut());
        match free.and_then(|at| Some((keys.get_mut(at)?, values.get_mut(at)?))) {
            Some((slot, held)) => {
                *slot = Maybe::Some(key);
                *held = value;
                self.len += 1;
                Ok(None)
            }
            None => Err(CapacityExhausted {
                key,
                value,
                capacity,
            }),
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.values.slots().get(self.position(key)?)
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let at = self.position(key)?;
        self.values.slots_mut().get_mut(at)
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        let at = self.position(key)?;
        *self.keys.slots_mut().get_mut(at)? = Maybe::None;
        self.len -= 1;
        Some(core::mem::replace(
            self.values.slots_mut().get_mut(at)?,
            V::EMPTY,
        ))
    }

    fn insert_empty(&mut self, key: K) -> Result<&mut V, TableFull> {
        let full = self.full();
        if let Some(at) = self.position(&key) {
            return self.values.slots_mut().get_mut(at).ok_or(full);
        }
        let at = self.free().ok_or(full)?;
        let (Some(slot), Some(held)) = (
            self.keys.slots_mut().get_mut(at),
            self.values.slots_mut().get_mut(at),
        ) else {
            return Err(full);
        };
        *slot = Maybe::Some(key);
        // The empty value, copied from its constant straight into the slot:
        // all zero bytes, a `memset`, and nothing on the stack.
        *held = V::EMPTY;
        self.len += 1;
        Ok(held)
    }

    fn discard(&mut self, key: &K) -> bool {
        let Some(at) = self.position(key) else {
            return false;
        };
        if let (Some(slot), Some(held)) = (
            self.keys.slots_mut().get_mut(at),
            self.values.slots_mut().get_mut(at),
        ) {
            *slot = Maybe::None;
            // Dropped where it is held, and left empty.
            *held = V::EMPTY;
            self.len -= 1;
        }
        true
    }

    fn len(&self) -> usize {
        self.len
    }

    fn capacity(&self) -> Option<usize> {
        Some(self.keys.slots().len())
    }

    fn for_each(&self, mut f: impl FnMut(&K, &V)) {
        for (k, v) in self.keys.slots().iter().zip(self.values.slots()) {
            if let Some(k) = k.as_ref() {
                f(k, v);
            }
        }
    }

    fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        let (keys, values) = (self.keys.slots_mut(), self.values.slots_mut());
        for (slot, held) in keys.iter_mut().zip(values) {
            let drop = match slot.as_ref() {
                Some(k) => !keep(k, held),
                None => false,
            };
            if drop {
                *slot = Maybe::None;
                *held = V::EMPTY;
                self.len -= 1;
            }
        }
    }

    fn first(&self) -> Option<(&K, &V)> {
        self.keys
            .slots()
            .iter()
            .zip(self.values.slots())
            .filter_map(|(k, v)| Some((k.as_ref()?, v)))
            .min_by(|(a, _), (b, _)| a.cmp(b))
    }

    fn reserve(&mut self, capacity: usize) {
        if self.len == 0 {
            self.keys.reserve(capacity);
            self.values.reserve(capacity);
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
    /// An empty table, built at compile time.
    pub const EMPTY: Self = Self {
        entries: alloc::collections::BTreeMap::new(),
    };

    /// An empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self::EMPTY
    }
}

#[cfg(feature = "alloc")]
impl<K, V, const LIMIT: usize> Default for GrowableTable<K, V, LIMIT> {
    fn default() -> Self {
        Self::EMPTY
    }
}

#[cfg(feature = "alloc")]
impl<K: Ord, V, const LIMIT: usize> Table<K, V> for GrowableTable<K, V, LIMIT> {
    const EMPTY: Self = Self::EMPTY;

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

    fn insert_empty(&mut self, key: K) -> Result<&mut V, TableFull>
    where
        V: Empty,
    {
        if self.entries.len() >= LIMIT && !self.entries.contains_key(&key) {
            return Err(TableFull { capacity: LIMIT });
        }
        Ok(self.entries.entry(key).or_insert(V::EMPTY))
    }

    fn discard(&mut self, key: &K) -> bool {
        self.entries.remove(key).is_some()
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
    type Contexts<K: Ord, V: Empty>: Table<K, V> + Default;
    /// Where open sessions are kept.
    type Sessions<K: Ord, V: Empty>: Table<K, V> + Default;
    /// Where known peers are kept.
    type Peers<K: Ord, V: Empty>: Table<K, V> + Default;
    /// Where a responder keeps handshakes it accepted and that are not yet
    /// confirmed. Strangers who know the address can fill it, so it is always
    /// bounded.
    type Pending<K: Ord, V: Empty>: Table<K, V> + Default;
    /// Where a responder remembers the ephemeral keys of recent first contacts.
    /// Bounded: forgetting one costs at most one Diffie-Hellman.
    type RecentEphemerals<K: Ord, V: Empty>: Table<K, V> + Default;
    /// Where a responder under load keeps each source's rate. Bounded:
    /// forgetting one lets that source restart its burst.
    type SourceRates<K: Ord, V: Empty>: Table<K, V> + Default;
    /// A receiver's anti-replay window, per key pair.
    type ReplayWindow: crate::transport::ReplayWindow;
    /// Datagrams a session holds while it has no keys, bounded in bytes.
    type Queue: crate::session::DatagramQueue + Empty;
    /// Where the sessions reopening with datagrams waiting keep their queue:
    /// lent while they wait, given back when it empties.
    type Queues<K: Ord, V: Empty>: Table<K, V> + Default;
    /// Where an endpoint keeps the dials it is making.
    type Dials<K: Ord, V: Empty>: Table<K, V> + Default;
    /// Where an endpoint maps the indices peers put in packets to their session
    /// or dial, when [`Self::INDEXED`]; otherwise a table of no entries, never
    /// used.
    type Indices<K: Ord, V: Empty>: Table<K, V> + Default;
    /// Whether the endpoint keeps a table of indices. A bounded profile does
    /// not: it finds an index's owner among its sessions and dials, which hold
    /// their indices, so that no index outlives its owner and no size is kept
    /// in step with theirs. A growable one does, for its thousands of sessions.
    const INDEXED: bool;
    /// Where an endpoint keeps the direct address hints applications give for
    /// peers. Bounded: a full table forgets the hint used least recently.
    type Hints<K: Ord, V: Empty>: Table<K, V> + Default;
    /// Where an endpoint keeps the IP prefixes an application excluded from
    /// direct paths (`PROTOCOL.md §7`). Bounded.
    type Excluded<K: Ord, V: Empty>: Table<K, V> + Default;
    /// First contacts a responder takes to the Diffie-Hellman per second before
    /// it is under load.
    const LOAD_RATE_PER_SECOND: u32;
    /// How many such first contacts may arrive at once.
    const LOAD_BURST: u32;
    /// Where an endpoint keeps the closes of the sessions it evicted, until
    /// the next polls send them (`PROTOCOL.md §5`). Bounded.
    type Farewells<K: Ord, V: Empty>: Table<K, V> + Default;
    /// Unknown-index signals an endpoint sends a second (`PROTOCOL.md §5`).
    const SIGNAL_RATE_PER_SECOND: u32;
    /// How many such signals may leave at once.
    const SIGNAL_BURST: u32;
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
    /// Sessions that may hold queued datagrams at once, each up to
    /// `queue_bytes`: a session holds one only while it reopens with
    /// datagrams waiting.
    pub queues: usize,
    /// Direct address hints.
    pub hints: usize,
    /// Excluded IP prefixes.
    pub excluded: usize,
    /// First contacts a second before the responder is under load.
    pub load_rate_per_second: u32,
    /// First contacts that may arrive at once.
    pub load_burst: u32,
    /// Sessions that may be evicted between two polls, their closes waiting.
    pub farewells: usize,
    /// Unknown-index signals a second.
    pub signal_rate_per_second: u32,
    /// Unknown-index signals that may leave at once.
    pub signal_burst: u32,
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
            type Contexts<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.contexts }>;
            type Sessions<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.sessions }>;
            type Peers<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.peers }>;
            type Pending<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.pending }>;
            type RecentEphemerals<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.recent_ephemerals }>;
            type SourceRates<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.source_rates }>;
            type ReplayWindow = $crate::transport::Window<{ $name::SIZES.replay_words }>;
            type Queue = $crate::session::FixedQueue<{ $name::SIZES.queue_bytes }>;
            type Queues<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.queues }>;
            type Dials<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.dials }>;
            type Indices<K: Ord, V: $crate::storage::Empty> = $crate::storage::FixedTable<K, V, 0>;
            const INDEXED: bool = false;
            type Hints<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.hints }>;
            type Excluded<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.excluded }>;
            const LOAD_RATE_PER_SECOND: u32 = $name::SIZES.load_rate_per_second;
            const LOAD_BURST: u32 = $name::SIZES.load_burst;
            type Farewells<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::FixedTable<K, V, { $name::SIZES.farewells }>;
            const SIGNAL_RATE_PER_SECOND: u32 = $name::SIZES.signal_rate_per_second;
            const SIGNAL_BURST: u32 = $name::SIZES.signal_burst;
        }
    };
}

/// The [`Config`] of a type with growable tables, from its `SIZES`.
#[doc(hidden)]
#[macro_export]
macro_rules! __growable_config {
    ($name:ident) => {
        impl $crate::storage::Config for $name {
            type Contexts<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.contexts }>;
            type Sessions<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.sessions }>;
            type Peers<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.peers }>;
            type Pending<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.pending }>;
            type RecentEphemerals<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.recent_ephemerals }>;
            type SourceRates<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.source_rates }>;
            type ReplayWindow = $crate::transport::Window<{ $name::SIZES.replay_words }>;
            type Queue = $crate::session::GrowableQueue<{ $name::SIZES.queue_bytes }>;
            type Queues<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.queues }>;
            type Dials<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.dials }>;
            type Indices<K: Ord, V: $crate::storage::Empty> = $crate::storage::GrowableTable<K, V>;
            const INDEXED: bool = true;
            type Hints<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.hints }>;
            type Excluded<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.excluded }>;
            const LOAD_RATE_PER_SECOND: u32 = $name::SIZES.load_rate_per_second;
            const LOAD_BURST: u32 = $name::SIZES.load_burst;
            type Farewells<K: Ord, V: $crate::storage::Empty> =
                $crate::storage::GrowableTable<K, V, { $name::SIZES.farewells }>;
            const SIGNAL_RATE_PER_SECOND: u32 = $name::SIZES.signal_rate_per_second;
            const SIGNAL_BURST: u32 = $name::SIZES.signal_burst;
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
        // 2: the sessions reopening at once with datagrams waiting.
        queues: 2,
        // 4: a device that talks to a handful of peers.
        hints: 4,
        // 4: an overlay's prefix and a few more.
        excluded: 4,
        load_rate_per_second: 5,
        load_burst: 5,
        // 4: every session but the relay's evicted before a poll, at most.
        farewells: 4,
        // 20 a second, 5 at once: a peer that lost its session learns it
        // within a round trip, and a board reflects little.
        signal_rate_per_second: 20,
        signal_burst: 5,
    };
}

crate::__fixed_config!(Mcu);

/// A device whose sizes are given when its endpoint starts
/// (`Endpoint::reserve`), not when it is built: every table a
/// [`BootTable`], allocated once then and never grown or freed, so that a
/// library shipped built lets its integrator choose them. The queue's bound,
/// the replay window, the load rate and the rate of unknown-index signals are
/// [`Mcu`]'s, fixed when it is built.
/// Only with `alloc`.
#[cfg(feature = "alloc")]
pub struct Boot;

#[cfg(feature = "alloc")]
impl Boot {
    /// The sizes a `Boot` endpoint is usually given: [`Mcu`]'s. Of these,
    /// `queue_bytes`, `replay_words`, the load rate and the signal rate are
    /// fixed when it is built; every other one is read when it starts.
    pub const SIZES: Sizes = Mcu::SIZES;
}

#[cfg(feature = "alloc")]
impl Config for Boot {
    type Contexts<K: Ord, V: Empty> = BootTable<K, V>;
    type Sessions<K: Ord, V: Empty> = BootTable<K, V>;
    type Peers<K: Ord, V: Empty> = BootTable<K, V>;
    type Pending<K: Ord, V: Empty> = BootTable<K, V>;
    type RecentEphemerals<K: Ord, V: Empty> = BootTable<K, V>;
    type SourceRates<K: Ord, V: Empty> = BootTable<K, V>;
    type ReplayWindow = crate::transport::Window<{ Mcu::SIZES.replay_words }>;
    type Queue = crate::session::FixedQueue<{ Mcu::SIZES.queue_bytes }>;
    type Queues<K: Ord, V: Empty> = BootTable<K, V>;
    type Dials<K: Ord, V: Empty> = BootTable<K, V>;
    type Indices<K: Ord, V: Empty> = FixedTable<K, V, 0>;
    const INDEXED: bool = false;
    type Hints<K: Ord, V: Empty> = BootTable<K, V>;
    type Excluded<K: Ord, V: Empty> = BootTable<K, V>;
    const LOAD_RATE_PER_SECOND: u32 = Mcu::SIZES.load_rate_per_second;
    const LOAD_BURST: u32 = Mcu::SIZES.load_burst;
    type Farewells<K: Ord, V: Empty> = BootTable<K, V>;
    const SIGNAL_RATE_PER_SECOND: u32 = Mcu::SIZES.signal_rate_per_second;
    const SIGNAL_BURST: u32 = Mcu::SIZES.signal_burst;
}

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
        queues: usize::MAX,
        hints: 4096,
        excluded: 16,
        load_rate_per_second: 1000,
        load_burst: 1000,
        // A table without bound never evicts.
        farewells: 0,
        // A server restarted under thousands of sessions tells them fast.
        signal_rate_per_second: 1000,
        signal_burst: 1000,
    };
}

#[cfg(feature = "alloc")]
crate::__growable_config!(Server);
