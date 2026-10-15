//! Reliable messages over convesso sessions (`PROTOCOL.md §8`).
//!
//! One ordered channel per session (peer and context): messages arrive whole,
//! once and in order, beside the session's datagrams, which never wait for
//! them. The channel is carried by two inner types of the session's packets,
//! `0x06` (data) and `0x07` (acknowledgement), which the core carries without
//! reading.
//!
//! ```text
//!  application --> Channels --frames--> Endpoint (core) --packets--> network
//!                     ^                                      |
//!                     +------------ Event::Frame ------------+
//! ```
//!
//! Optional, sans-IO and `no_std`: time comes in, frames and deadlines go
//! out. Every buffer comes from a [`config::StreamConfig`]: fixed arrays on a
//! microcontroller, growable behind the `alloc` feature on a server. An
//! application that does not link this crate pays nothing for it.
//!
//! The algorithms are standard ones: the retransmission timeout of RFC 6298,
//! NewReno (RFC 5681, RFC 6582), loss detected at three later fragments
//! acknowledged (RFC 6675), the initial window of RFC 6928, serial-number
//! arithmetic (RFC 1982). Only the frames are this crate's own.
//!
//! A driver holds a [`Channels`] beside its endpoint:
//! - [`Channels::send_message`] for the application;
//! - every core `Event::Frame` to [`Channels::handle_frame`];
//! - [`Channels::poll`] until it says [`Poll::Wait`] or [`Poll::Idle`]: each
//!   [`Poll::SendFrame`] to the core's `Endpoint::send_frame`, and a refusal
//!   back to [`Channels::frame_refused`]; each [`Poll::Dial`] to the core's
//!   `Endpoint::connect`;
//! - the core's `Closed` and `ReopenFailed` to [`Channels::session_closed`] and
//!   [`Channels::reopen_failed`].
//!
//! A reader that takes different peers' messages at different speeds makes
//! its `Channels` [`Channels::with_credit`] and grants each channel the bytes
//! it can take with [`Channels::grant`] (`DESIGN.md §8`). A channel short of
//! credit keeps its message and its window closes, so only its own sender
//! waits.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod channel;
pub mod config;
pub mod frame;

use convesso_core::endpoint::FrameKind;
use convesso_core::handshake::{Context, DialError, Entropy};
use convesso_core::identity::{Address, PeerId};
use convesso_core::storage::Table;
use convesso_core::time::Instant;

pub use channel::{
    ACK_DELAY, ChannelState, ELEMENT_COST, INITIAL_PEER_WINDOW, INITIAL_RTO, INITIAL_WINDOW,
    KEYS_RETRY, KEYS_RETRY_MAX, MAX_RTO, MIN_RTO, NO_PROGRESS, RESET_ANSWER_EVERY, Reason,
    SendError, Sent, Stored,
};
use channel::{Channel, Emitted, Output};
use config::{Key, StreamConfig};

/// Something the application should know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// A whole message, in order.
    Message {
        /// The peer.
        peer: PeerId,
        /// The context.
        context: Context,
        /// Its bytes, valid until the next call.
        data: &'a [u8],
    },
    /// Room opened in a send buffer that refused a message.
    Writable {
        /// The peer.
        peer: PeerId,
        /// The context.
        context: Context,
    },
    /// A channel was reset: everything it held is gone, both ways.
    Reset {
        /// The peer.
        peer: PeerId,
        /// The context.
        context: Context,
        /// Why.
        reason: Reason,
    },
}

/// What [`Channels::poll`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll<'a> {
    /// Send the first `len` bytes of the output buffer as a stream frame of
    /// `kind`, with the core's `Endpoint::send_frame`.
    SendFrame {
        /// The peer.
        peer: PeerId,
        /// The context.
        context: Context,
        /// Which frame.
        kind: FrameKind,
        /// How many bytes.
        len: usize,
    },
    /// Tell the application.
    Event(Event<'a>),
    /// Reopen the session, with the core's `Endpoint::connect`.
    Dial {
        /// The peer's address.
        address: Address,
        /// The context.
        context: Context,
    },
    /// Nothing until this instant, unless something arrives.
    Wait(Instant),
    /// Nothing until something arrives: no channel has anything to deliver
    /// or to acknowledge.
    Idle,
}

/// Every channel of an endpoint.
pub struct Channels<C: StreamConfig> {
    table: C::Channels<Channel<C>>,
    /// The frame handed out by the last poll, until the next call.
    emitted: Option<(Key, Emitted)>,
    /// Where the last poll stopped, so that every channel gets its turn.
    cursor: Option<Key>,
    /// Whether delivery credit is on.
    credit: bool,
}

impl<C: StreamConfig> Default for Channels<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: StreamConfig> Channels<C> {
    /// No channel yet; every message is handed out as soon as the driver can
    /// deliver it.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: <C::Channels<Channel<C>> as Default>::default(),
            emitted: None,
            cursor: None,
            credit: false,
        }
    }

    /// No channel yet, with delivery credit on: a channel hands out a message
    /// only when its credit covers the message's length plus
    /// [`ELEMENT_COST`], and spends that. A channel starts with no credit,
    /// and returns to none when it is reset or its session closes.
    #[must_use]
    pub fn with_credit() -> Self {
        Self {
            credit: true,
            ..Self::new()
        }
    }

    /// The frame handed out last left: its channel's session has keys.
    fn confirm(&mut self) {
        if let Some((key, _)) = self.emitted.take()
            && let Some(channel) = self.table.get_mut(&key)
        {
            channel.sent();
        }
    }

    /// The channel of `key`, made if there is none: in a free slot, or in
    /// the slot of a channel that holds nothing but a past reset.
    fn channel(&mut self, key: Key) -> Result<&mut Channel<C>, SendError> {
        if self.table.get(&key).is_none()
            && let Err(full) = self.table.insert(key, Channel::new(self.credit))
        {
            let mut spent = None;
            self.table.for_each(|k, channel| {
                if spent.is_none() && channel.is_spent() {
                    spent = Some(*k);
                }
            });
            let Some(spent) = spent else {
                return Err(SendError::TableFull);
            };
            let _ = self.table.remove(&spent);
            if self.table.insert(full.key, full.value).is_err() {
                return Err(SendError::TableFull);
            }
        }
        self.table.get_mut(&key).ok_or(SendError::TableFull)
    }

    /// Accepts `message` for `peer` in `context`. With `address`, the channel
    /// can reopen the session when it falls dormant; without, it waits for
    /// the peer to reopen it, as the core does for datagrams.
    ///
    /// # Errors
    ///
    /// [`SendError::TooLarge`] for a message over this side's or the peer's
    /// maximum, [`SendError::Empty`], [`SendError::Full`] when the send
    /// buffer has no room ([`Event::Writable`] follows),
    /// [`SendError::TableFull`] when every channel slot is in use, and
    /// [`SendError::ContextTooLong`].
    #[allow(
        clippy::too_many_arguments,
        reason = "the sans-IO inputs: peer, address, context, message, time, entropy"
    )]
    pub fn send_message(
        &mut self,
        peer: PeerId,
        address: Option<&Address>,
        context: &[u8],
        message: &[u8],
        now: Instant,
        entropy: &mut impl Entropy,
    ) -> Result<(), SendError> {
        self.confirm();
        let context = Context::new(context).map_err(|_| SendError::ContextTooLong)?;
        let channel = self.channel((peer, context))?;
        if let Some(address) = address {
            channel.set_address(*address);
        }
        channel.send(message, now, entropy)
    }

    /// Adds `bytes` to the delivery credit of `peer`'s channel in `context`,
    /// making the channel if there is none. Nothing with credit off.
    ///
    /// # Errors
    ///
    /// [`SendError::TableFull`] when no channel slot is free, and
    /// [`SendError::ContextTooLong`], as for [`Channels::send_message`].
    pub fn grant(&mut self, peer: PeerId, context: &[u8], bytes: usize) -> Result<(), SendError> {
        self.confirm();
        let context = Context::new(context).map_err(|_| SendError::ContextTooLong)?;
        if !self.credit {
            return Ok(());
        }
        self.channel((peer, context))?.grant(bytes);
        Ok(())
    }

    /// Takes a stream frame the core handed up. A malformed frame is ignored
    /// whole; outputs come from [`Channels::poll`].
    pub fn handle_frame(
        &mut self,
        peer: PeerId,
        context: Context,
        kind: FrameKind,
        frame: &[u8],
        now: Instant,
    ) {
        self.confirm();
        let key = (peer, context);
        match kind {
            FrameKind::Data => {
                let Ok(data) = frame::Data::decode(frame) else {
                    return;
                };
                if let Ok(channel) = self.channel(key) {
                    channel.handle_data(&data, now);
                }
            }
            FrameKind::Ack => {
                let Ok(ack) = frame::Ack::decode(frame) else {
                    return;
                };
                if let Some(channel) = self.table.get_mut(&key) {
                    channel.handle_ack(&ack, now);
                }
            }
        }
    }

    /// The core refused the frame of the last [`Poll::SendFrame`]: its
    /// session has no keys. The channel tries again shortly, and asks for a
    /// dial when it knows the peer's address.
    pub fn frame_refused(&mut self, now: Instant) {
        if let Some((key, emitted)) = self.emitted.take()
            && let Some(channel) = self.table.get_mut(&key)
        {
            channel.refused(emitted, now);
        }
    }

    /// The bytes a channel holds, both ways, if it exists: what its
    /// configuration bounds.
    #[must_use]
    pub fn memory(&self, peer: PeerId, context: Context) -> Option<usize> {
        self.table
            .get(&(peer, context))
            .map(channel::Channel::memory)
    }

    /// A snapshot of a channel's state, if it exists: for tests and
    /// diagnostics.
    #[must_use]
    pub fn inspect(&self, peer: PeerId, context: Context) -> Option<ChannelState> {
        self.table
            .get(&(peer, context))
            .map(channel::Channel::state)
    }

    /// The session closed: its channel is reset.
    pub fn session_closed(&mut self, peer: PeerId, context: Context, code: u16) {
        self.confirm();
        if let Some(channel) = self.table.get_mut(&(peer, context)) {
            channel.reset(Reason::SessionClosed { code });
        }
    }

    /// Resets `peer`'s channel in `context` on this side, as a reader that
    /// gives it up does: everything it holds is dropped, both ways, its
    /// credit returns to none, and no event is raised here. The peer, if it
    /// has sent on the channel, is told with an acknowledgement carrying
    /// RESET, sent again at most once a second while it goes on sending on
    /// that incarnation. Nothing if there is no channel.
    pub fn reset_here(&mut self, peer: PeerId, context: Context, now: Instant) {
        self.confirm();
        if let Some(channel) = self.table.get_mut(&(peer, context)) {
            channel.reset_here(now);
        }
    }

    /// A dial of the session failed. A channel waiting for the session's keys
    /// is reset; one whose session still has keys, its renewal having failed,
    /// is not.
    pub fn reopen_failed(&mut self, peer: PeerId, context: Context, error: DialError) {
        self.confirm();
        if let Some(channel) = self.table.get_mut(&(peer, context)) {
            channel.reopen_failed(error);
        }
    }

    /// The next thing to do at `now`: a frame written in `out` (at least
    /// [`frame::MAX_DATA_LEN`] bytes), an event, a dial, or how long to wait.
    ///
    /// Without `deliver`, no message is handed out: a driver whose event
    /// buffer has no room for one says so, and the messages wait here. The
    /// receive window closes and the sender waits, while acknowledgements,
    /// resets and every other output go on.
    pub fn poll(&mut self, now: Instant, deliver: bool, out: &mut [u8]) -> Poll<'_> {
        self.confirm();
        self.table.retain(|_, channel| {
            channel.tick(now);
            true
        });
        let cursor = self.cursor;
        let mut found = None;
        for pass in [true, false] {
            self.table.retain(|key, channel| {
                if found.is_none() && (!pass || cursor.is_none_or(|c| *key > c)) {
                    match channel.output(now, deliver, out) {
                        Output::Nothing => {}
                        output => found = Some((*key, output)),
                    }
                }
                true
            });
            if found.is_some() {
                break;
            }
        }
        let Some(((peer, context), output)) = found else {
            let mut earliest: Option<Instant> = None;
            self.table.for_each(|_, channel| {
                if let Some(deadline) = channel.deadline() {
                    earliest = Some(earliest.map_or(deadline, |e| e.min(deadline)));
                }
            });
            return earliest.map_or(Poll::Idle, Poll::Wait);
        };
        self.cursor = Some((peer, context));
        match output {
            Output::Frame { kind, len, emitted } => {
                self.emitted = Some(((peer, context), emitted));
                Poll::SendFrame {
                    peer,
                    context,
                    kind,
                    len,
                }
            }
            Output::Message(length) => {
                let data = self
                    .table
                    .get(&(peer, context))
                    .map_or(&[][..], |channel| channel.message(length));
                Poll::Event(Event::Message {
                    peer,
                    context,
                    data,
                })
            }
            Output::Writable => Poll::Event(Event::Writable { peer, context }),
            Output::Reset(reason) => Poll::Event(Event::Reset {
                peer,
                context,
                reason,
            }),
            Output::Dial(address) => Poll::Dial { address, context },
            Output::Nothing => Poll::Idle,
        }
    }
}
