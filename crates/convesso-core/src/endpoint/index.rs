//! The sessions, and the index of what is due among them: a poll costs the
//! sessions that changed or whose deadline came, not every session held.
//!
//! The only way to change a session is through [`Sessions`]: `get_mut`,
//! `insert` and `retain` mark what they reach as touched, and the next
//! [`Sessions::refresh`] looks at those again, with the sessions whose
//! deadline came. Each table takes the sessions' table type, so it holds at
//! most one entry per session and needs no size of its own.

use super::{Key, SessionOf};
use crate::storage::{Config, Table};
use crate::time::Instant;

/// What the endpoint makes of a session the index looks at.
pub(super) enum Look {
    /// Nothing in progress and no keys: the session is forgotten.
    Forget,
    /// The session stays, with its next deadline, and whether it may have
    /// something to do now.
    Keep {
        deadline: Option<Instant>,
        ready: bool,
    },
}

/// The sessions, and their index.
pub(super) struct Sessions<C: Config> {
    table: C::Sessions<Key, SessionOf<C>>,
    /// Sessions changed since the index last looked at them.
    touched: C::Sessions<Key, ()>,
    /// Sessions that may have something to do now: a poll searches these.
    ready: C::Sessions<Key, ()>,
    /// One entry per session with a deadline, ordered by it.
    due: C::Sessions<(Instant, Key), ()>,
}

impl<C: Config> Default for Sessions<C> {
    fn default() -> Self {
        Self {
            table: Default::default(),
            touched: Default::default(),
            ready: Default::default(),
            due: Default::default(),
        }
    }
}

impl<C: Config> Sessions<C> {
    pub(super) fn get(&self, key: &Key) -> Option<&SessionOf<C>> {
        self.table.get(key)
    }

    /// The session for `key`, to change: it is looked at again.
    pub(super) fn get_mut(&mut self, key: &Key) -> Option<&mut SessionOf<C>> {
        let session = self.table.get_mut(key)?;
        // Room: one entry per session, and this one exists.
        let _ = self.touched.insert(*key, ());
        Some(session)
    }

    /// Inserts `session` under `key`; false when the table is full.
    pub(super) fn insert(&mut self, key: Key, session: SessionOf<C>) -> bool {
        let Ok(replaced) = self.table.insert(key, session) else {
            return false;
        };
        if let Some(old) = replaced.as_ref() {
            self.unindex(&key, old);
        }
        let _ = self.touched.insert(key, ());
        true
    }

    pub(super) fn remove(&mut self, key: &Key) -> Option<SessionOf<C>> {
        let session = self.table.remove(key)?;
        self.unindex(key, &session);
        Some(session)
    }

    pub(super) fn len(&self) -> usize {
        self.table.len()
    }

    #[cfg(test)]
    pub(super) fn capacity(&self) -> Option<usize> {
        self.table.capacity()
    }

    pub(super) fn for_each(&self, f: impl FnMut(&Key, &SessionOf<C>)) {
        self.table.for_each(f);
    }

    /// As [`Table::retain`]: every session kept is looked at again. For the
    /// events that reach every session: a change of network, a context
    /// closed.
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&Key, &mut SessionOf<C>) -> bool) {
        let (touched, ready, due) = (&mut self.touched, &mut self.ready, &mut self.due);
        self.table.retain(|key, session| {
            if keep(key, session) {
                let _ = touched.insert(*key, ());
                true
            } else {
                touched.remove(key);
                ready.remove(key);
                if let Some(at) = session.deadline {
                    due.remove(&(at, *key));
                }
                false
            }
        });
    }

    /// Marks `key`'s session to be looked at again: something it depends on
    /// outside it changed, such as a dial.
    pub(super) fn touch(&mut self, key: &Key) {
        if self.table.get(key).is_some() {
            let _ = self.touched.insert(*key, ());
        }
    }

    /// Marks every session to be looked at again: what each depends on
    /// changed for all, such as this endpoint's candidates.
    pub(super) fn touch_all(&mut self) {
        let touched = &mut self.touched;
        self.table.for_each(|key, _| {
            let _ = touched.insert(*key, ());
        });
    }

    /// Looks again at the sessions touched and those whose deadline came by
    /// `now`: `look` says whether each is forgotten, its deadline, and
    /// whether it may have something to do.
    pub(super) fn refresh(
        &mut self,
        now: Instant,
        mut look: impl FnMut(&Key, &mut SessionOf<C>) -> Look,
    ) {
        while let Some(&(at, key)) = self.due.first().map(|(entry, ())| entry) {
            if at > now {
                break;
            }
            self.due.remove(&(at, key));
            if let Some(session) = self.table.get_mut(&key) {
                session.deadline = None;
            }
            let _ = self.touched.insert(key, ());
        }
        while let Some(&key) = self.touched.first().map(|(key, ())| key) {
            self.touched.remove(&key);
            let Some(session) = self.table.get_mut(&key) else {
                continue;
            };
            match look(&key, session) {
                Look::Forget => {
                    let _ = self.remove(&key);
                }
                Look::Keep { deadline, ready } => {
                    if session.deadline != deadline {
                        if let Some(at) = session.deadline {
                            self.due.remove(&(at, key));
                        }
                        if let Some(at) = deadline {
                            let _ = self.due.insert((at, key), ());
                        }
                        session.deadline = deadline;
                    }
                    if ready {
                        let _ = self.ready.insert(key, ());
                    }
                }
            }
        }
    }

    /// Calls `f` on each session that may have something to do.
    pub(super) fn for_each_ready(&self, mut f: impl FnMut(&Key, &SessionOf<C>)) {
        let table = &self.table;
        self.ready.for_each(|key, ()| {
            if let Some(session) = table.get(key) {
                f(key, session);
            }
        });
    }

    /// Keeps among the sessions that may have something to do those for
    /// which `keep` says so.
    pub(super) fn retain_ready(&mut self, mut keep: impl FnMut(&Key, &SessionOf<C>) -> bool) {
        let table = &self.table;
        self.ready
            .retain(|key, ()| table.get(key).is_some_and(|session| keep(key, session)));
    }

    /// The earliest deadline of any session.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.due.first().map(|(&(at, _), ())| at)
    }

    fn unindex(&mut self, key: &Key, session: &SessionOf<C>) {
        self.touched.remove(key);
        self.ready.remove(key);
        if let Some(at) = session.deadline {
            self.due.remove(&(at, *key));
        }
    }

    /// Asserts that the index finds what a walk of every session finds, as
    /// it stands after [`Self::refresh`]: `look` judges each session as the
    /// refresh does, without changing it.
    #[cfg(any(test, feature = "testing"))]
    pub(super) fn check(&self, now: Instant, mut look: impl FnMut(&Key, &SessionOf<C>) -> Look) {
        assert!(self.touched.is_empty(), "sessions left touched");
        let mut with_deadline = 0;
        self.table.for_each(|key, session| {
            for pair in [session.current.as_ref(), session.previous.as_ref()]
                .into_iter()
                .flatten()
            {
                assert!(pair.live(now), "{key:?}: keys past their life");
            }
            let judged = look(key, session);
            assert!(
                !matches!(judged, Look::Forget),
                "{key:?}: a session to forget is held"
            );
            if let Look::Keep { deadline, ready } = judged {
                assert_eq!(session.deadline, deadline, "{key:?}: its deadline");
                if let Some(at) = deadline {
                    with_deadline += 1;
                    assert!(self.due.get(&(at, *key)).is_some(), "{key:?}: not due");
                }
                if ready {
                    assert!(self.ready.get(key).is_some(), "{key:?}: not ready");
                }
            }
        });
        assert_eq!(self.due.len(), with_deadline, "deadlines of no session");
    }
}
