//! What the relay remembers of the forwards it could not carry (`PROTOCOL.md
//! §6`): for each pair of sender and recipient, when the sender was last told
//! that the recipient is not connected, and whether it is seeking the
//! recipient, to be told when it arrives.
//!
//! Bounded per sender, in total and in time, whatever the clients send: a
//! pair asked for least recently gives way, and every pair is forgotten
//! [`ASKED_FOR`] after the latest forward that asked for it. One function
//! forgets a pair, whatever the cause, so that the four maps always agree.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Duration;

use convesso_core::identity::PeerId;
use convesso_core::time::Instant;

/// How long a pair is remembered after the latest forward that asked for it:
/// a dial's life, after which no dial is left to tell of an arrival.
pub(crate) const ASKED_FOR: Duration = convesso_core::handshake::GIVE_UP_AFTER;

type Key = (PeerId, [u8; 32]);

#[derive(Debug, Clone, Copy)]
struct Pair {
    /// When it was last asked for, and the order of that among all pairs.
    touched: (Instant, u64),
    /// When the sender was last told the recipient is not connected.
    noticed: Option<Instant>,
    /// Until when the sender is told of the recipient's arrival.
    seeking_until: Option<Instant>,
}

/// The bounds of the table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bounds {
    pub(crate) per_sender: usize,
    pub(crate) total: usize,
    /// Seekers per recipient; 0 makes none.
    pub(crate) seekers_per_recipient: usize,
}

/// The pairs, and the indices that bound them.
#[derive(Debug, Default)]
pub(crate) struct Asked {
    pairs: HashMap<Key, Pair>,
    /// Every pair once, by when it was last asked for.
    order: BTreeMap<(Instant, u64), Key>,
    /// Each sender's recipients, least recently asked for first.
    senders: HashMap<PeerId, VecDeque<[u8; 32]>>,
    /// Each recipient's seekers.
    seekers: HashMap<[u8; 32], Vec<PeerId>>,
    seq: u64,
}

impl Asked {
    /// `sender` forwarded to `recipient`, which is not connected: the pair is
    /// asked for now, and, when `seeking`, the sender is told of its arrival
    /// for [`ASKED_FOR`]. Returns whether a not-connected frame is due: none
    /// was sent for the pair within `every`.
    pub(crate) fn ask(
        &mut self,
        sender: PeerId,
        recipient: [u8; 32],
        seeking: bool,
        bounds: Bounds,
        every: Duration,
        now: Instant,
    ) -> bool {
        let key = (sender, recipient);
        self.seq += 1;
        let touched = (now, self.seq);
        if let Some(pair) = self.pairs.get_mut(&key) {
            self.order.remove(&pair.touched);
            pair.touched = touched;
            self.order.insert(touched, key);
            if let Some(queue) = self.senders.get_mut(&sender)
                && let Some(at) = queue.iter().position(|r| *r == recipient)
            {
                queue.remove(at);
                queue.push_back(recipient);
            }
        } else {
            // Room first, so that the new pair is never the one given way.
            if self
                .senders
                .get(&sender)
                .is_some_and(|queue| queue.len() >= bounds.per_sender.max(1))
                && let Some(oldest) = self.senders.get(&sender).and_then(|q| q.front().copied())
            {
                self.forget(&(sender, oldest));
            }
            if self.pairs.len() >= bounds.total.max(1)
                && let Some((_, oldest)) = self.order.first_key_value().map(|(k, v)| (*k, *v))
            {
                self.forget(&oldest);
            }
            self.pairs.insert(
                key,
                Pair {
                    touched,
                    noticed: None,
                    seeking_until: None,
                },
            );
            self.order.insert(touched, key);
            self.senders.entry(sender).or_default().push_back(recipient);
        }
        if seeking && bounds.seekers_per_recipient > 0 {
            self.seek(key, bounds.seekers_per_recipient, now);
        }
        let Some(pair) = self.pairs.get_mut(&key) else {
            return false;
        };
        let due = pair
            .noticed
            .is_none_or(|at| now >= at.saturating_add(every));
        if due {
            pair.noticed = Some(now);
        }
        due
    }

    /// The pair seeks its recipient until [`ASKED_FOR`] from now; over the
    /// recipient's bound, the seeker that sought it least recently gives way.
    fn seek(&mut self, key: Key, most: usize, now: Instant) {
        let until = now.saturating_add(ASKED_FOR);
        let already = self
            .pairs
            .get(&key)
            .is_some_and(|pair| pair.seeking_until.is_some());
        if !already {
            let seekers = self.seekers.entry(key.1).or_default();
            if seekers.len() >= most {
                let pairs = &self.pairs;
                let oldest = seekers
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, seeker)| {
                        pairs
                            .get(&(**seeker, key.1))
                            .and_then(|pair| pair.seeking_until)
                    })
                    .map(|(at, seeker)| (at, *seeker));
                if let Some((at, seeker)) = oldest {
                    seekers.swap_remove(at);
                    if let Some(pair) = self.pairs.get_mut(&(seeker, key.1)) {
                        pair.seeking_until = None;
                    }
                }
            }
            self.seekers.entry(key.1).or_default().push(key.0);
        }
        if let Some(pair) = self.pairs.get_mut(&key) {
            pair.seeking_until = Some(until);
        }
    }

    /// `recipient` arrived: the clients still seeking it, which are told now
    /// and seek it no more.
    pub(crate) fn arrived(&mut self, recipient: &[u8; 32], now: Instant) -> Vec<PeerId> {
        let Some(seekers) = self.seekers.remove(recipient) else {
            return Vec::new();
        };
        seekers
            .into_iter()
            .filter(|seeker| {
                self.pairs
                    .get_mut(&(*seeker, *recipient))
                    .and_then(|pair| pair.seeking_until.take())
                    .is_some_and(|until| now < until)
            })
            .collect()
    }

    /// Forgets every pair last asked for [`ASKED_FOR`] ago or more.
    pub(crate) fn prune(&mut self, now: Instant) {
        while let Some((&(at, _), &key)) = self.order.first_key_value() {
            if now < at.saturating_add(ASKED_FOR) {
                break;
            }
            self.forget(&key);
        }
    }

    /// Forgets a pair, from every map.
    fn forget(&mut self, key: &Key) {
        let Some(pair) = self.pairs.remove(key) else {
            return;
        };
        self.order.remove(&pair.touched);
        if let Some(queue) = self.senders.get_mut(&key.0) {
            queue.retain(|recipient| *recipient != key.1);
            if queue.is_empty() {
                self.senders.remove(&key.0);
            }
        }
        if pair.seeking_until.is_some()
            && let Some(seekers) = self.seekers.get_mut(&key.1)
        {
            seekers.retain(|seeker| *seeker != key.0);
            if seekers.is_empty() {
                self.seekers.remove(&key.1);
            }
        }
    }

    /// How many pairs it remembers.
    pub(crate) fn len(&self) -> usize {
        self.pairs.len()
    }

    /// How many pairs it remembers for `sender`.
    #[cfg(test)]
    pub(crate) fn of_sender(&self, sender: &PeerId) -> usize {
        self.senders.get(sender).map_or(0, VecDeque::len)
    }

    /// Whether the four maps agree, and are within `bounds`.
    #[cfg(test)]
    pub(crate) fn check(&self, bounds: Bounds) {
        assert!(self.pairs.len() <= bounds.total);
        assert_eq!(self.order.len(), self.pairs.len());
        let in_queues: usize = self.senders.values().map(VecDeque::len).sum();
        assert_eq!(in_queues, self.pairs.len());
        for (sender, queue) in &self.senders {
            assert!(!queue.is_empty() && queue.len() <= bounds.per_sender);
            for recipient in queue {
                assert!(self.pairs.contains_key(&(*sender, *recipient)));
            }
        }
        let seeking = self
            .pairs
            .values()
            .filter(|pair| pair.seeking_until.is_some())
            .count();
        let in_seekers: usize = self.seekers.values().map(Vec::len).sum();
        assert_eq!(in_seekers, seeking);
        for (recipient, seekers) in &self.seekers {
            assert!(!seekers.is_empty() && seekers.len() <= bounds.seekers_per_recipient);
            for seeker in seekers {
                assert!(
                    self.pairs
                        .get(&(*seeker, *recipient))
                        .is_some_and(|pair| pair.seeking_until.is_some())
                );
            }
        }
    }

    /// Whether it holds nothing at all.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.pairs.is_empty()
            && self.order.is_empty()
            && self.senders.is_empty()
            && self.seekers.is_empty()
    }
}

/// The bytes one pair costs, about: its entries in the four maps, each map's
/// control byte and spare room (a hash map is at most 7/8 full, and may be
/// half empty after it grows), and a B-tree's nodes at least half full.
#[cfg(test)]
pub(crate) fn bytes_per_pair() -> usize {
    use core::mem::size_of;
    let pairs = (size_of::<Key>() + size_of::<Pair>() + 1) * 2;
    let order = (size_of::<(Instant, u64)>() + size_of::<Key>()) * 2;
    let senders = size_of::<[u8; 32]>() * 2;
    let seekers = size_of::<PeerId>() * 2;
    pairs + order + senders + seekers
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

    use super::*;
    use crate::tests::world::identity;

    const EVERY: Duration = Duration::from_secs(1);
    const BOUNDS: Bounds = Bounds {
        per_sender: 64,
        total: 1_000,
        seekers_per_recipient: 32,
    };

    fn t(ms: u64) -> Instant {
        Instant::from_millis(ms)
    }

    fn made_up(i: u32) -> [u8; 32] {
        let mut key = [0xA5; 32];
        key[..4].copy_from_slice(&i.to_le_bytes());
        key
    }

    #[test]
    fn one_sender_keeps_its_newest_within_its_bound() {
        let mut asked = Asked::default();
        let sender = identity(1).peer_id();
        for i in 0..10_000 {
            asked.ask(
                sender,
                made_up(i),
                true,
                BOUNDS,
                EVERY,
                t(u64::from(i) / 10),
            );
            asked.check(BOUNDS);
        }
        assert_eq!(asked.of_sender(&sender), 64);
        let told = (9_936..10_000)
            .filter(|i| asked.arrived(&made_up(*i), t(1000)) == vec![sender])
            .count();
        assert_eq!(told, 64, "the newest 64 are told");
        assert!(asked.arrived(&made_up(9_935), t(1000)).is_empty());
        asked.check(BOUNDS);
    }

    #[test]
    fn the_total_keeps_the_newest() {
        let bounds = Bounds {
            total: 100,
            ..BOUNDS
        };
        let mut asked = Asked::default();
        let mut now = 0;
        for s in 0..10 {
            let sender = identity(s + 1).peer_id();
            for i in 0..64 {
                now += 1;
                asked.ask(sender, made_up(i), true, bounds, EVERY, t(now));
                asked.check(bounds);
            }
        }
        assert_eq!(asked.len(), 100);
        // The last sender's 64 and the 36 before them.
        let last = identity(10).peer_id();
        assert_eq!(asked.of_sender(&last), 64);
        assert_eq!(asked.of_sender(&identity(9).peer_id()), 36);
    }

    #[test]
    fn nothing_outlives_its_time() {
        let mut asked = Asked::default();
        for s in 0..5 {
            for i in 0..20 {
                asked.ask(
                    identity(s + 1).peer_id(),
                    made_up(i),
                    i % 2 == 0,
                    BOUNDS,
                    EVERY,
                    t(0),
                );
            }
        }
        asked.prune(t(14_999));
        assert_eq!(asked.len(), 100);
        asked.prune(t(15_000));
        assert!(asked.is_empty());
    }

    #[test]
    fn a_notice_is_due_once_per_interval() {
        let mut asked = Asked::default();
        let sender = identity(1).peer_id();
        assert!(asked.ask(sender, made_up(0), false, BOUNDS, EVERY, t(0)));
        assert!(!asked.ask(sender, made_up(0), false, BOUNDS, EVERY, t(999)));
        assert!(asked.ask(sender, made_up(0), false, BOUNDS, EVERY, t(1000)));
    }

    #[test]
    fn only_a_seeker_is_told_and_only_while_seeking() {
        let mut asked = Asked::default();
        let (a, b) = (identity(1).peer_id(), identity(2).peer_id());
        asked.ask(a, made_up(7), true, BOUNDS, EVERY, t(0));
        asked.ask(b, made_up(7), false, BOUNDS, EVERY, t(0));
        assert_eq!(asked.arrived(&made_up(7), t(100)), vec![a]);
        assert!(asked.arrived(&made_up(7), t(200)).is_empty(), "told once");
        asked.check(BOUNDS);
    }

    #[test]
    fn a_recipient_keeps_its_newest_seekers() {
        let bounds = Bounds {
            seekers_per_recipient: 3,
            ..BOUNDS
        };
        let mut asked = Asked::default();
        for s in 0..5 {
            asked.ask(
                identity(s + 1).peer_id(),
                made_up(0),
                true,
                bounds,
                EVERY,
                t(s as u64),
            );
            asked.check(bounds);
        }
        let mut told = asked.arrived(&made_up(0), t(10));
        told.sort_unstable_by_key(|id| *id.as_bytes());
        let mut newest: Vec<PeerId> = (3..6).map(|s| identity(s).peer_id()).collect();
        newest.sort_unstable_by_key(|id| *id.as_bytes());
        assert_eq!(told, newest);
        asked.check(bounds);
    }

    /// The default total keeps the table at about 100 MB.
    #[test]
    fn the_default_total_is_about_a_hundred_megabytes() {
        let bytes = bytes_per_pair();
        let total = crate::Config::default().asked_total * bytes;
        eprintln!(
            "[asked] about {bytes} bytes a pair, {} MB at the default total",
            total / 1_000_000
        );
        assert!((80_000_000..=120_000_000).contains(&total), "{total}");
    }
}
