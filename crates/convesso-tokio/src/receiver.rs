//! The receiver per peer, in the per-peer delivery mode (`DESIGN.md §8`).
//!
//! ```text
//!  task: channel --message--> Receiver queue --recv()--> application
//!          ^                                         |
//!          +------- credit: the bytes recv() freed --+
//! ```
//!
//! A peer's messages and datagrams wait in its own receiver, each kind within
//! a budget in bytes, where every element costs its length plus
//! [`ELEMENT_COST`]. The free room of the message budget is the peer's
//! channel credit, so a receiver the application stops reading slows down
//! that peer's sender alone. Dropping a receiver resets the peer's channel on
//! this side, which tells the sender at once.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use convesso_core::identity::PeerId;
use tokio::sync::Notify;

/// What an element held by a receiver costs beyond its bytes: the stream
/// layer's cost per message, applied to datagrams too.
pub const ELEMENT_COST: usize = 64;

/// How a session ended, as a receiver reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionClosed {
    /// The close code.
    pub code: u16,
    /// Whether the peer closed it, rather than this side.
    pub by_peer: bool,
}

/// What [`Receiver::recv`] yields, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// A reliable message, whole and in order (feature `stream`).
    #[cfg(feature = "stream")]
    Message(Vec<u8>),
    /// The message channel was reset here, after the messages before it:
    /// what was in flight is gone, both ways (feature `stream`).
    #[cfg(feature = "stream")]
    Reset(convesso_stream::Reason),
    /// The session ended. Every later read says so again.
    Closed(SessionClosed),
}

/// What waits in a receiver, shared by the application and the node's task.
#[derive(Default)]
pub(crate) struct State {
    #[cfg(feature = "stream")]
    pub(crate) items: VecDeque<Item>,
    /// The cost of the messages in `items`.
    #[cfg(feature = "stream")]
    pub(crate) held: usize,
    /// Bytes the application freed, not yet granted to the channel.
    #[cfg(feature = "stream")]
    pub(crate) freed: usize,
    pub(crate) datagrams: VecDeque<(Vec<u8>, bool)>,
    /// The cost of the datagrams waiting.
    pub(crate) datagram_bytes: usize,
    /// The session's close, reported once everything before it is read.
    pub(crate) closed: Option<SessionClosed>,
    /// The application dropped its receiver.
    pub(crate) dropped: bool,
}

#[cfg(feature = "stream")]
pub(crate) enum Item {
    Message(Vec<u8>),
    Reset(convesso_stream::Reason),
}

pub(crate) struct Shared {
    state: Mutex<State>,
    messages_ready: Notify,
    datagrams_ready: Notify,
    /// Wakes the node's task: room was freed, or the receiver was dropped.
    task: Arc<Notify>,
}

impl Shared {
    pub(crate) fn new(task: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            messages_ready: Notify::new(),
            datagrams_ready: Notify::new(),
            task,
        })
    }

    /// The state; a reader that panicked while holding it left nothing
    /// half-written that matters, so a poisoned lock is taken as it is.
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(feature = "stream")]
    pub(crate) fn messages_ready(&self) {
        self.messages_ready.notify_one();
    }

    pub(crate) fn datagrams_ready(&self) {
        self.datagrams_ready.notify_one();
    }

    /// Both readers: the session closed.
    pub(crate) fn closed(&self) {
        self.messages_ready.notify_one();
        self.datagrams_ready.notify_one();
    }
}

/// A peer's messages and datagrams, in the per-peer delivery mode: opened with
/// [`crate::Node::receiver`].
///
/// Read it as long as the session lives: a receiver that is not read holds
/// back its peer's sender, and drops its datagrams once their budget is
/// full. Dropping it resets the peer's message channel on this side: the
/// sender is told at once, what the receiver held is discarded, and the
/// messages this side had not yet had acknowledged to that peer are dropped
/// too, as the reset drops both ways. To stop hearing from a peer for good,
/// close its session.
pub struct Receiver {
    peer: PeerId,
    shared: Arc<Shared>,
}

impl Receiver {
    pub(crate) const fn new(peer: PeerId, shared: Arc<Shared>) -> Self {
        Self { peer, shared }
    }

    /// The peer this receiver belongs to.
    #[must_use]
    pub const fn peer(&self) -> PeerId {
        self.peer
    }

    /// The bytes this receiver holds, each element counted at its cost:
    /// its messages (with the feature `stream`), and its datagrams. At most
    /// the budgets of [`crate::Delivery::PerPeer`]: what a receiver that is not
    /// read costs.
    #[must_use]
    pub fn held(&self) -> (usize, usize) {
        let state = self.shared.lock();
        #[cfg(feature = "stream")]
        let messages = state.held;
        #[cfg(not(feature = "stream"))]
        let messages = 0;
        (messages, state.datagram_bytes)
    }

    /// The next message, channel reset or close, in order; waits for one.
    /// After the close, it returns the close again at once.
    pub async fn recv(&self) -> Received {
        loop {
            {
                #[cfg_attr(not(feature = "stream"), allow(unused_mut))]
                let mut state = self.shared.lock();
                #[cfg(feature = "stream")]
                if let Some(item) = state.items.pop_front() {
                    return match item {
                        Item::Message(data) => {
                            let cost = data.len() + ELEMENT_COST;
                            state.held = state.held.saturating_sub(cost);
                            state.freed += cost;
                            drop(state);
                            self.shared.task.notify_one();
                            Received::Message(data)
                        }
                        Item::Reset(reason) => Received::Reset(reason),
                    };
                }
                if let Some(closed) = state.closed {
                    return Received::Closed(closed);
                }
            }
            // A notification sent between the check and here is kept as a
            // permit, so none is lost.
            self.shared.messages_ready.notified().await;
        }
    }

    /// The next datagram, with whether it came through the relay; waits for
    /// one. Once the session is closed and every datagram before the close
    /// is read, the close.
    ///
    /// # Errors
    ///
    /// The session's close.
    pub async fn recv_datagram(&self) -> Result<(Vec<u8>, bool), SessionClosed> {
        loop {
            {
                let mut state = self.shared.lock();
                if let Some((data, relayed)) = state.datagrams.pop_front() {
                    state.datagram_bytes = state
                        .datagram_bytes
                        .saturating_sub(data.len() + ELEMENT_COST);
                    return Ok((data, relayed));
                }
                if let Some(closed) = state.closed {
                    return Err(closed);
                }
            }
            self.shared.datagrams_ready.notified().await;
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.shared.lock().dropped = true;
        self.shared.task.notify_one();
    }
}

impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver")
            .field("peer", &self.peer)
            .finish()
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests {
    /// The cost per element is the stream layer's, so a budget means the same
    /// in both.
    #[test]
    fn the_element_cost_is_the_stream_layers() {
        assert_eq!(super::ELEMENT_COST, convesso_stream::ELEMENT_COST);
    }
}
