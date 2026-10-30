//! The channels, and the index of what is due among them: a poll costs the
//! channels that changed or whose deadline came, not every channel held.
//!
//! The only way to change a channel is through [`Indexed`]: `get_mut`,
//! `insert` and `retain` mark what they reach as touched, and the next
//! [`Indexed::refresh`] fires the timers of those, and of the channels whose
//! deadline came, and makes them ready. A poll searches the ready ones, and a
//! channel that has nothing leaves them.

use convesso_core::storage::{CapacityExhausted, Table};
use convesso_core::time::Instant;

use crate::channel::Channel;
use crate::config::{Key, StreamConfig};

/// The channels, and their index.
pub(crate) struct Indexed<C: StreamConfig> {
    table: C::Channels<Channel<C>>,
    /// Channels changed since the index last looked at them.
    touched: C::Channels<()>,
    /// Channels that may have an output now: a poll searches these.
    ready: C::Channels<()>,
    /// One entry per channel with a deadline, ordered by it.
    due: C::Deadlines<()>,
}

impl<C: StreamConfig> Default for Indexed<C> {
    fn default() -> Self {
        Self {
            table: Default::default(),
            touched: Default::default(),
            ready: Default::default(),
            due: Default::default(),
        }
    }
}

impl<C: StreamConfig> Indexed<C> {
    pub(crate) fn get(&self, key: &Key) -> Option<&Channel<C>> {
        self.table.get(key)
    }

    /// The channel for `key`, to change: it is looked at again.
    pub(crate) fn get_mut(&mut self, key: &Key) -> Option<&mut Channel<C>> {
        let channel = self.table.get_mut(key)?;
        // Room: one entry per channel, and this one exists.
        let _ = self.touched.insert(*key, ());
        Some(channel)
    }

    #[allow(
        clippy::result_large_err,
        reason = "as `Table::insert`: the refused channel comes back, to take a spent one's slot"
    )]
    pub(crate) fn insert(
        &mut self,
        key: Key,
        channel: Channel<C>,
    ) -> Result<Option<Channel<C>>, CapacityExhausted<Key, Channel<C>>> {
        let replaced = self.table.insert(key, channel)?;
        if let Some(old) = replaced.as_ref() {
            self.unindex(&key, old);
        }
        let _ = self.touched.insert(key, ());
        Ok(replaced)
    }

    pub(crate) fn remove(&mut self, key: &Key) -> Option<Channel<C>> {
        let channel = self.table.remove(key)?;
        self.unindex(key, &channel);
        Some(channel)
    }

    pub(crate) fn len(&self) -> usize {
        self.table.len()
    }

    pub(crate) fn for_each(&self, f: impl FnMut(&Key, &Channel<C>)) {
        self.table.for_each(f);
    }

    /// As [`Table::retain`]: every channel kept is looked at again.
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&Key, &mut Channel<C>) -> bool) {
        let (touched, ready, due) = (&mut self.touched, &mut self.ready, &mut self.due);
        self.table.retain(|key, channel| {
            if keep(key, channel) {
                let _ = touched.insert(*key, ());
                true
            } else {
                touched.remove(key);
                ready.remove(key);
                if let Some(at) = channel.indexed {
                    due.remove(&(at, *key));
                }
                false
            }
        });
    }

    /// Fires the timers of the channels touched and of those whose deadline
    /// came by `now`, and makes them ready.
    pub(crate) fn refresh(&mut self, now: Instant) {
        while let Some(&(at, key)) = self.due.first().map(|(entry, ())| entry) {
            if at > now {
                break;
            }
            self.due.remove(&(at, key));
            if let Some(channel) = self.table.get_mut(&key) {
                channel.indexed = None;
            }
            let _ = self.touched.insert(key, ());
        }
        while let Some(&key) = self.touched.first().map(|(key, ())| key) {
            self.touched.remove(&key);
            let Some(channel) = self.table.get_mut(&key) else {
                continue;
            };
            channel.tick(now);
            reindex(&mut self.due, &key, channel);
            let _ = self.ready.insert(key, ());
        }
    }

    /// The first ready channel after `cursor`, round to it, for which `visit`
    /// gives an output. A channel it gives none leaves the ready ones, unless
    /// `visit` says it stays: a message that waits for the reader to have
    /// room, which nothing in the channel tells.
    pub(crate) fn find<T>(
        &mut self,
        cursor: Option<Key>,
        mut visit: impl FnMut(&Key, &mut Channel<C>) -> Result<T, bool>,
    ) -> Option<(Key, T)> {
        let mut found = None;
        for after in [true, false] {
            let (table, due) = (&mut self.table, &mut self.due);
            self.ready.retain(|key, ()| {
                let turn = cursor.is_none_or(|c| *key > c) == after;
                if found.is_some() || !turn {
                    return true;
                }
                let Some(channel) = table.get_mut(key) else {
                    return false;
                };
                let visited = visit(key, channel);
                // An output can move a deadline: a probe armed.
                reindex(due, key, channel);
                match visited {
                    Ok(output) => {
                        found = Some((*key, output));
                        true
                    }
                    Err(stays) => stays,
                }
            });
            if found.is_some() || cursor.is_none() {
                break;
            }
        }
        found
    }

    /// The earliest deadline of any channel.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.due.first().map(|(&(at, _), ())| at)
    }

    fn unindex(&mut self, key: &Key, channel: &Channel<C>) {
        self.touched.remove(key);
        self.ready.remove(key);
        if let Some(at) = channel.indexed {
            self.due.remove(&(at, *key));
        }
    }

    /// Asserts that a walk of every channel finds what the index found, when
    /// a poll found nothing: `output` says whether a channel has an output,
    /// as the poll asks it; then each channel's deadline is the one indexed.
    #[cfg(test)]
    pub(crate) fn check(&mut self, mut output: impl FnMut(&Key, &mut Channel<C>) -> bool) {
        assert!(self.touched.is_empty(), "channels left touched");
        let due = &self.due;
        let mut with_deadline = 0;
        self.table.retain(|key, channel| {
            assert!(!output(key, channel), "{key:?}: an output the index missed");
            let deadline = channel.deadline();
            assert_eq!(channel.indexed, deadline, "{key:?}: its deadline");
            if let Some(at) = deadline {
                with_deadline += 1;
                assert!(due.get(&(at, *key)).is_some(), "{key:?}: not due");
            }
            true
        });
        assert_eq!(self.due.len(), with_deadline, "deadlines of no channel");
    }
}

/// Moves `key`'s entry in `due` to the channel's deadline now.
fn reindex<C: StreamConfig>(due: &mut C::Deadlines<()>, key: &Key, channel: &mut Channel<C>) {
    let deadline = channel.deadline();
    if channel.indexed == deadline {
        return;
    }
    if let Some(at) = channel.indexed {
        due.remove(&(at, *key));
    }
    if let Some(at) = deadline {
        // Room: one entry per channel.
        let _ = due.insert((at, *key), ());
    }
    channel.indexed = deadline;
}
