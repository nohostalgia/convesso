//! One channel: a sender and a receiver, their timers, and their resets
//! (`PROTOCOL.md §8`).
//!
//! ```text
//! sender    queue of messages --fragments--> in flight --ack--> released
//!           RFC 6298 timeout, NewReno, loss at three later fragments acked
//! receiver  in-order fragments --> assembly --> one whole message to deliver
//!           early fragments held in the window, acknowledged as ranges
//! ```
//!
//! A channel runs a timer only while it has something to deliver or to
//! acknowledge: with everything acknowledged, [`Channel::deadline`] is `None`.

use core::time::Duration;

use convesso_core::handshake::{DialError, Entropy};
use convesso_core::identity::Address;
use convesso_core::time::Instant;

use crate::config::{Arena, ByteQueue, Slots, StreamConfig};
use crate::frame::{self, Ack, Data, Incarnation, MAX_FRAGMENT, Range, after};

/// The retransmission timeout before the first round-trip sample (RFC 6298).
pub const INITIAL_RTO: Duration = Duration::from_secs(1);
/// The shortest retransmission timeout: as Linux and QUIC (RFC 9002), which
/// RFC 8961 allows; RFC 6298's 1 s would cost a second per loss on a LAN.
pub const MIN_RTO: Duration = Duration::from_millis(200);
/// The longest retransmission timeout, and the longest wait between probes of
/// a closed window: two expiries fit within [`NO_PROGRESS`].
pub const MAX_RTO: Duration = Duration::from_secs(15);
/// How long data may wait with no acknowledgement before the channel resets.
pub const NO_PROGRESS: Duration = Duration::from_secs(30);
/// The longest an acknowledgement is delayed (QUIC's default).
pub const ACK_DELAY: Duration = Duration::from_millis(25);
/// The fewest seconds between two RESET answers for one unknown incarnation.
pub const RESET_ANSWER_EVERY: Duration = Duration::from_secs(1);
/// The first wait before trying again a frame the core refused for want of
/// keys; doubled up to [`KEYS_RETRY_MAX`]. Local only: a refused frame costs
/// no packet.
pub const KEYS_RETRY: Duration = Duration::from_millis(50);
/// The longest wait between two tries of a refused frame.
pub const KEYS_RETRY_MAX: Duration = Duration::from_secs(1);
/// The initial congestion window, in fragments (RFC 6928).
pub const INITIAL_WINDOW: usize = 10;
/// The receive window assumed before the peer's first acknowledgement: the
/// smallest default profile's receive buffer.
pub const INITIAL_PEER_WINDOW: u32 = 2048;
/// How many later fragments acknowledged make a fragment lost (RFC 6675).
const DUP_THRESHOLD: usize = 3;
/// The round trip assumed before the first sample, for the time threshold
/// (RFC 9002's kInitialRtt).
const INITIAL_RTT: Duration = Duration::from_millis(333);
/// The farthest ahead of the cumulative point a held fragment may be.
const SEQUENCE_WINDOW: u32 = 1 << 16;
/// Retired incarnations remembered, so that their late frames change nothing.
const RETIRED: usize = 4;

const MSS: usize = MAX_FRAGMENT;

/// A fragment sent and not yet acknowledged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sent {
    /// Where its bytes start, counted from the channel's first byte.
    at: u64,
    len: u16,
    /// With FIRST, the message's length; otherwise 0.
    length: u32,
    last: bool,
    sent_at: Instant,
    retransmitted: bool,
    sacked: bool,
    lost: bool,
}

/// A fragment that came early, held until the ones before it arrive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stored {
    seq: u32,
    /// Where its bytes are, from the start of the region of early fragments.
    at: u32,
    len: u16,
    /// With FIRST, the message's length; otherwise 0.
    length: u32,
    last: bool,
}

/// Why a channel was reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Data waited 30 s and no acknowledgement came.
    NoProgress,
    /// The peer opened a new incarnation: it restarted, or reset its side.
    PeerRestarted,
    /// The peer said the channel is reset on its side.
    ResetByPeer,
    /// The peer announced a message longer than this side accepts.
    MessageTooLarge,
    /// The session closed, with this code.
    SessionClosed {
        /// The close code.
        code: u16,
    },
    /// Reopening the dormant session failed.
    ReopenFailed(DialError),
}

/// Why a message was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// Longer than the largest message this side, or the peer, accepts.
    TooLarge {
        /// The message's length.
        size: usize,
        /// The largest accepted.
        max: usize,
    },
    /// An empty message: a message is at least one byte.
    Empty,
    /// The send buffer has no room now; [`crate::Event::Writable`] follows.
    Full,
    /// Every channel slot is in use.
    TableFull,
    /// The context is longer than the core accepts.
    ContextTooLong,
}

/// A snapshot of a channel's state, for tests and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelState {
    /// The oldest sequence not acknowledged, and the next one to send.
    pub una: u32,
    /// The next sequence to send.
    pub next_seq: u32,
    /// Fragments sent and not acknowledged; of them, held at the peer, and
    /// taken for lost.
    pub in_flight: usize,
    /// Of those, acknowledged in ranges.
    pub sacked: usize,
    /// Of those, taken for lost.
    pub lost: usize,
    /// The congestion window, and the peer's window, in bytes.
    pub cwnd: usize,
    /// The peer's window.
    pub peer_window: u32,
    /// The retransmission timeout, in milliseconds.
    pub rto_ms: u64,
    /// Messages queued, bytes queued.
    pub queued_messages: usize,
    /// The next sequence expected by the receiver.
    pub rcv_next: u32,
    /// Bytes assembled of the current message, and its length.
    pub assembled: usize,
    /// The length of the message being assembled.
    pub assembling: Option<u32>,
    /// Fragments held early, and the first of them.
    pub early: usize,
    /// The first early fragment's sequence.
    pub early_first: Option<u32>,
    /// A whole message waiting to be delivered.
    pub ready: Option<usize>,
    /// Waiting for the session's keys.
    pub waiting_keys: bool,
}

/// What a channel just put in the output buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Emitted {
    /// A data frame of this sequence.
    Data(u32),
    /// An acknowledgement.
    Ack,
    /// A RESET answer.
    ResetAnswer,
}

/// What a channel has for its driver now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Output {
    /// A frame of `len` bytes in the output buffer.
    Frame {
        kind: convesso_core::endpoint::FrameKind,
        len: usize,
        emitted: Emitted,
    },
    /// A whole message, the first `len` bytes of the arena.
    Message(usize),
    /// Room opened in the send buffer.
    Writable,
    /// The channel was reset.
    Reset(Reason),
    /// Reopen the session with this address.
    Dial(Address),
    /// Nothing now.
    Nothing,
}

/// One channel.
pub(crate) struct Channel<C: StreamConfig> {
    address: Option<Address>,

    // --- sender ---
    send_incarnation: Option<Incarnation>,
    acked_any: bool,
    queue: C::SendQueue,
    lengths: C::Lengths,
    /// Bytes released from the queue's front since the incarnation began.
    popped: u64,
    in_flight: C::InFlight,
    /// The sequence of `in_flight[0]`.
    una: u32,
    next_seq: u32,
    /// The message the next new fragment belongs to, and the offset in it.
    next_msg: usize,
    next_off: u32,
    next_abs: u64,
    cwnd: usize,
    ssthresh: usize,
    recovery_until: Option<u32>,
    srtt: Option<Duration>,
    rttvar: Duration,
    latest_rtt: Option<Duration>,
    rto: Duration,
    rto_deadline: Option<Instant>,
    /// When a fragment overtaken by a later acknowledged one becomes lost by
    /// the time threshold.
    loss_deadline: Option<Instant>,
    probe_deadline: Option<Instant>,
    probe_now: bool,
    probe_backoff: Duration,
    waiting_since: Option<Instant>,
    peer_window: u32,
    peer_max: Option<u32>,
    blocked: bool,
    writable: bool,
    keys_retry: Option<Instant>,
    keys_backoff: Duration,
    dialled: bool,
    dial_due: bool,

    // --- receiver ---
    receive_incarnation: Option<Incarnation>,
    rcv_next: u32,
    arena: C::ReceiveArena,
    asm_len: usize,
    asm_length: Option<u32>,
    early: C::Stored,
    early_len: usize,
    ready: Option<usize>,
    delivered: bool,
    unacked: usize,
    ack_now: bool,
    ack_deadline: Option<Instant>,
    advertised_closed: bool,

    // --- resets ---
    retired: [Option<Incarnation>; RETIRED],
    reset_answer: Option<Incarnation>,
    answered: [Option<(Incarnation, Instant)>; 2],
    event: Option<Reason>,
    ever_reset: bool,
}

impl<C: StreamConfig> Channel<C> {
    pub(crate) fn new() -> Self {
        Self {
            address: None,
            send_incarnation: None,
            acked_any: false,
            queue: C::SendQueue::default(),
            lengths: C::Lengths::default(),
            popped: 0,
            in_flight: C::InFlight::default(),
            una: 0,
            next_seq: 0,
            next_msg: 0,
            next_off: 0,
            next_abs: 0,
            cwnd: INITIAL_WINDOW * MSS,
            ssthresh: usize::MAX,
            recovery_until: None,
            srtt: None,
            rttvar: Duration::ZERO,
            latest_rtt: None,
            rto: INITIAL_RTO,
            rto_deadline: None,
            loss_deadline: None,
            probe_deadline: None,
            probe_now: false,
            probe_backoff: INITIAL_RTO,
            waiting_since: None,
            peer_window: INITIAL_PEER_WINDOW,
            peer_max: None,
            blocked: false,
            writable: false,
            keys_retry: None,
            keys_backoff: KEYS_RETRY,
            dialled: false,
            dial_due: false,
            receive_incarnation: None,
            rcv_next: 0,
            arena: C::ReceiveArena::default(),
            asm_len: 0,
            asm_length: None,
            early: C::Stored::default(),
            early_len: 0,
            ready: None,
            delivered: false,
            unacked: 0,
            ack_now: false,
            ack_deadline: None,
            advertised_closed: false,
            retired: [None; RETIRED],
            reset_answer: None,
            answered: [None; 2],
            event: None,
            ever_reset: false,
        }
    }

    pub(crate) fn set_address(&mut self, address: Address) {
        self.address = Some(address);
    }

    /// Whether this channel holds nothing but the memory of a reset: its slot
    /// can go to another session.
    pub(crate) fn is_spent(&self) -> bool {
        self.ever_reset
            && self.send_incarnation.is_none()
            && self.receive_incarnation.is_none()
            && self.event.is_none()
            && self.reset_answer.is_none()
            && !self.writable
    }

    // --- sending ------------------------------------------------------------------------

    /// Accepts `message` for sending.
    pub(crate) fn send(
        &mut self,
        message: &[u8],
        now: Instant,
        entropy: &mut impl Entropy,
    ) -> Result<(), SendError> {
        self.settle();
        if message.is_empty() {
            return Err(SendError::Empty);
        }
        if message.len() > C::MAX_MESSAGE {
            return Err(SendError::TooLarge {
                size: message.len(),
                max: C::MAX_MESSAGE,
            });
        }
        if let Some(max) = self.peer_max.map(|max| max as usize)
            && message.len() > max
        {
            return Err(SendError::TooLarge {
                size: message.len(),
                max,
            });
        }
        let Ok(length) = u32::try_from(message.len()) else {
            return Err(SendError::TooLarge {
                size: message.len(),
                max: C::MAX_MESSAGE,
            });
        };
        let room = self.queue.capacity() - self.queue.len();
        if message.len() > room || self.lengths.len() >= self.lengths.capacity() {
            self.blocked = true;
            return Err(SendError::Full);
        }
        if self.send_incarnation.is_none() {
            let mut incarnation = [0u8; frame::INCARNATION_LEN];
            entropy.fill(&mut incarnation);
            self.send_incarnation = Some(incarnation);
        }
        if !self.queue.push(message) || !self.lengths.push(length) {
            self.blocked = true;
            return Err(SendError::Full);
        }
        self.waiting_since.get_or_insert(now);
        Ok(())
    }

    /// Bytes sent and not acknowledged, held or lost: what counts against
    /// the congestion window.
    fn flight(&self) -> usize {
        (0..self.in_flight.len())
            .filter_map(|i| self.in_flight.get(i))
            .filter(|s| !s.sacked && !s.lost)
            .map(|s| usize::from(s.len))
            .sum()
    }

    /// Bytes sent beyond the cumulative point, held at the peer or not: what
    /// counts against the peer's window.
    fn beyond_una(&self) -> usize {
        (0..self.in_flight.len())
            .filter_map(|i| self.in_flight.get(i))
            .map(|s| usize::from(s.len))
            .sum()
    }

    /// The next new fragment: its length, and whether it is a FIRST (with the
    /// message's length) and a LAST.
    fn next_fragment(&self) -> Option<(usize, Option<u32>, bool)> {
        let length = *self.lengths.get(self.next_msg)?;
        let left = length.checked_sub(self.next_off)? as usize;
        let len = left.min(MSS);
        let first = (self.next_off == 0).then_some(length);
        Some((len, first, len == left))
    }

    fn lost_index(&self) -> Option<usize> {
        (0..self.in_flight.len()).find(|&i| self.in_flight.get(i).is_some_and(|s| s.lost))
    }

    /// Writes data frame `seq` into `out`, its bytes from the queue.
    fn write_data(&self, seq: u32, sent: &Sent, out: &mut [u8]) -> Option<usize> {
        let incarnation = self.send_incarnation?;
        let header = frame::encode_data_header(
            &incarnation,
            seq,
            (sent.length != 0).then_some(sent.length),
            sent.last,
            !self.acked_any,
            usize::from(sent.len),
            out,
        )
        .ok()?;
        let from = usize::try_from(sent.at.checked_sub(self.popped)?).ok()?;
        let body = out.get_mut(header..header + usize::from(sent.len))?;
        self.queue
            .copy_out(from, body)
            .then_some(header + body.len())
    }

    fn emit_retransmission(&mut self, i: usize, now: Instant, out: &mut [u8]) -> Option<Output> {
        let seq = self.una.wrapping_add(u32::try_from(i).ok()?);
        let sent = *self.in_flight.get(i)?;
        let len = self.write_data(seq, &sent, out)?;
        let slot = self.in_flight.get_mut(i)?;
        slot.lost = false;
        slot.retransmitted = true;
        slot.sent_at = now;
        self.rto_deadline
            .get_or_insert(now.saturating_add(self.rto));
        Some(Output::Frame {
            kind: convesso_core::endpoint::FrameKind::Data,
            len,
            emitted: Emitted::Data(seq),
        })
    }

    fn emit_new(&mut self, now: Instant, probing: bool, out: &mut [u8]) -> Option<Output> {
        let (len, first, last) = self.next_fragment()?;
        if self.in_flight.len() >= self.in_flight.capacity() {
            return None;
        }
        if !probing
            && (self.flight() + len > self.cwnd
                || self.beyond_una() + len > self.peer_window as usize)
        {
            return None;
        }
        let sent = Sent {
            at: self.next_abs,
            len: u16::try_from(len).ok()?,
            length: first.unwrap_or(0),
            last,
            sent_at: now,
            retransmitted: false,
            sacked: false,
            lost: false,
        };
        let seq = self.next_seq;
        let written = self.write_data(seq, &sent, out)?;
        if !self.in_flight.push(sent) {
            return None;
        }
        self.next_seq = self.next_seq.wrapping_add(1);
        self.next_abs += len as u64;
        if last {
            self.next_msg += 1;
            self.next_off = 0;
        } else {
            self.next_off += u32::try_from(len).ok()?;
        }
        self.rto_deadline
            .get_or_insert(now.saturating_add(self.rto));
        Some(Output::Frame {
            kind: convesso_core::endpoint::FrameKind::Data,
            len: written,
            emitted: Emitted::Data(seq),
        })
    }

    /// Whether new data is held back by the peer's window alone.
    fn window_closed(&self) -> bool {
        self.next_fragment().is_some_and(|(len, _, _)| {
            self.beyond_una() + len > self.peer_window as usize && self.in_flight.is_empty()
        })
    }

    // --- acknowledgements received ------------------------------------------------------

    pub(crate) fn handle_ack(&mut self, ack: &Ack, now: Instant) {
        self.settle();
        if Some(ack.incarnation) != self.send_incarnation {
            return;
        }
        if ack.reset {
            self.reset(Reason::ResetByPeer);
            return;
        }
        // Believed only for what was sent.
        if after(ack.cumulative, self.next_seq)
            || after(self.una, ack.cumulative)
            || ack.ranges().iter().any(|r| after(r.end, self.next_seq))
        {
            return;
        }
        self.acked_any = true;
        self.peer_window = ack.window;
        self.peer_max = Some(ack.max_message);
        let mut acked = 0usize;
        let mut sample = None;
        // An acknowledgement that covers retransmitted data gives no sample:
        // which copy it answers is unknown, and the newest original it covers
        // may have waited for losses to be repaired (as Linux,
        // FLAG_RETRANS_DATA_ACKED).
        let mut ambiguous = false;

        // The cumulative point.
        let count = ack.cumulative.wrapping_sub(self.una) as usize;
        for i in 0..count {
            let Some(sent) = self.in_flight.get(i).copied() else {
                break;
            };
            // A round-trip sample comes only from the newest fragment this
            // acknowledgement is the first to acknowledge, never from one
            // acknowledged before in a range (its time is stale) nor from a
            // retransmission (Karn): as QUIC (RFC 9002, 5.1).
            if !sent.sacked {
                acked += usize::from(sent.len);
                if sent.retransmitted {
                    ambiguous = true;
                } else {
                    sample = Some(sent.sent_at);
                }
            }
            if sent.last {
                let length = self.lengths.get(0).copied().unwrap_or(0) as usize;
                self.queue.pop(length);
                self.popped += length as u64;
                let _ = self.lengths.remove(0);
                self.next_msg = self.next_msg.saturating_sub(1);
            }
        }
        self.in_flight.drain_front(count);
        let advanced = count > 0;
        self.una = ack.cumulative;

        // The ranges.
        for range in ack.ranges() {
            for i in 0..self.in_flight.len() {
                let seq = self.una.wrapping_add(i as u32);
                if !in_range(seq, range) {
                    continue;
                }
                if let Some(sent) = self.in_flight.get_mut(i)
                    && !sent.sacked
                {
                    sent.sacked = true;
                    sent.lost = false;
                    acked += usize::from(sent.len);
                    if sent.retransmitted {
                        ambiguous = true;
                    } else {
                        sample = Some(sent.sent_at);
                    }
                }
            }
        }
        if let Some(sent_at) = sample.filter(|_| !ambiguous) {
            self.sample_rtt(now, sent_at);
        }

        // Congestion: out of recovery once everything sent before it is
        // acknowledged; otherwise grow.
        if let Some(until) = self.recovery_until
            && !after(until, self.una)
        {
            self.recovery_until = None;
            self.cwnd = self.ssthresh.max(MSS);
        }
        if self.recovery_until.is_none() && acked > 0 {
            if self.cwnd < self.ssthresh {
                self.cwnd += acked;
            } else {
                self.cwnd += (MSS * acked / self.cwnd).max(1);
            }
        }
        self.detect_losses(now);

        // An acknowledgement of new data ends the backoff, as in QUIC (RFC
        // 9002, 6.2.1): otherwise, once every fragment acknowledged is a
        // retransmission (Karn's rule takes no sample from it), the doubled
        // timeout would never come down.
        if advanced {
            self.rto = self.computed_rto();
        }

        // Timers.
        self.waiting_since = (!self.queue.is_empty()).then_some(now);
        if self.in_flight.is_empty() {
            self.rto_deadline = None;
            self.probe_backoff = self.rto;
        } else if advanced {
            self.rto_deadline = Some(now.saturating_add(self.rto));
        }
        if self.window_closed() {
            self.probe_deadline
                .get_or_insert(now.saturating_add(self.probe_backoff));
        } else {
            self.probe_deadline = None;
            self.probe_backoff = self.rto;
        }
        if advanced && self.blocked {
            self.blocked = false;
            self.writable = true;
        }
    }

    fn sample_rtt(&mut self, now: Instant, sent_at: Instant) {
        let r = Duration::from_millis(now.as_millis().saturating_sub(sent_at.as_millis()));
        self.latest_rtt = Some(r);
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                let delta = srtt.abs_diff(r);
                self.rttvar = self.rttvar * 3 / 4 + delta / 4;
                self.srtt = Some(srtt * 7 / 8 + r / 8);
            }
        }
        self.rto = self.computed_rto();
    }

    /// The retransmission timeout without backoff (RFC 6298): SRTT plus four
    /// RTTVAR, within [`MIN_RTO`] and [`MAX_RTO`]; [`INITIAL_RTO`] before the
    /// first sample.
    fn computed_rto(&self) -> Duration {
        self.srtt.map_or(INITIAL_RTO, |srtt| {
            let variance = (self.rttvar * 4).max(Duration::from_millis(1));
            (srtt + variance).clamp(MIN_RTO, MAX_RTO)
        })
    }

    /// A fragment is lost when three sent after it are acknowledged (RFC
    /// 6675), or when one sent after it is acknowledged and 9/8 of the round
    /// trip has passed since it was sent (RFC 9002, 6.1.2): with a window of a
    /// few fragments, as on a microcontroller, three later ones may never
    /// exist. Sets the loss timer for those not lost yet.
    fn detect_losses(&mut self, now: Instant) {
        let rtt = self
            .srtt
            .unwrap_or(INITIAL_RTT)
            .max(self.latest_rtt.unwrap_or(Duration::ZERO));
        let threshold = (rtt * 9 / 8).max(Duration::from_millis(1));
        let mut later = 0;
        let mut newly_lost = false;
        let mut deadline: Option<Instant> = None;
        for i in (0..self.in_flight.len()).rev() {
            let Some(sent) = self.in_flight.get_mut(i) else {
                continue;
            };
            if sent.sacked {
                later += 1;
            } else if !sent.lost && later > 0 {
                let due = sent.sent_at.saturating_add(threshold);
                if later >= DUP_THRESHOLD || now >= due {
                    sent.lost = true;
                    newly_lost = true;
                } else {
                    deadline = Some(deadline.map_or(due, |d| d.min(due)));
                }
            }
        }
        self.loss_deadline = deadline;
        if newly_lost && self.recovery_until.is_none() {
            self.ssthresh = (self.flight() / 2).max(2 * MSS);
            self.cwnd = self.ssthresh;
            self.recovery_until = Some(self.next_seq);
        }
    }

    // --- data received ------------------------------------------------------------------

    pub(crate) fn handle_data(&mut self, data: &Data<'_>, now: Instant) {
        self.settle();
        if self.retired.contains(&Some(data.incarnation)) {
            return;
        }
        if Some(data.incarnation) != self.receive_incarnation {
            if !data.start {
                // A channel this side does not know: it was forgotten here.
                self.answer_reset(data.incarnation, now);
                return;
            }
            if self.receive_incarnation.is_some() {
                self.reset(Reason::PeerRestarted);
            }
            self.receive_incarnation = Some(data.incarnation);
            self.rcv_next = 0;
        }
        if let Some(length) = data.length
            && length as usize > C::MAX_MESSAGE
        {
            self.reset_answer = Some(data.incarnation);
            self.reset(Reason::MessageTooLarge);
            return;
        }
        self.unacked += 1;
        if !after(data.sequence, self.rcv_next.wrapping_sub(1)) {
            // Already received: say so again, the acknowledgement was lost.
            self.ack_now = true;
            return;
        }
        let in_order = data.sequence == self.rcv_next;
        if in_order && self.ready.is_none() && self.accept_in_order(data) {
            self.rcv_next = self.rcv_next.wrapping_add(1);
            self.pull_early();
        } else {
            self.hold_early(data);
            self.ack_now = true;
        }
        if self.unacked >= 2 || !self.early.is_empty() {
            self.ack_now = true;
        } else {
            self.ack_deadline
                .get_or_insert(now.saturating_add(ACK_DELAY));
        }
    }

    fn answer_reset(&mut self, incarnation: Incarnation, now: Instant) {
        let recent = self
            .answered
            .iter()
            .flatten()
            .any(|(i, at)| *i == incarnation && now < at.saturating_add(RESET_ANSWER_EVERY));
        if recent {
            return;
        }
        let slot = self
            .answered
            .iter_mut()
            .min_by_key(|entry| entry.map_or(Instant::from_millis(0), |(_, at)| at));
        if let Some(slot) = slot {
            *slot = Some((incarnation, now));
        }
        self.reset_answer = Some(incarnation);
    }

    fn free(&self) -> usize {
        self.arena.capacity() - self.asm_len - self.early_len
    }

    /// Appends an in-order fragment to the message being assembled; false
    /// when it does not fit the message (a peer that broke the format).
    fn accept_in_order(&mut self, data: &Data<'_>) -> bool {
        let length = match (self.asm_length, data.length) {
            (None, Some(length)) => length,
            (Some(length), None) => length,
            _ => return false,
        } as usize;
        let len = data.bytes.len();
        let end = self.asm_len + len;
        if end > length || (data.last != (end == length)) {
            return false;
        }
        // Room: an in-order fragment comes first; early ones give way.
        while self.free() < len {
            if !self.drop_last_early() {
                return false;
            }
        }
        let used = self.asm_len + self.early_len;
        let Some(arena) = self.arena.get_mut(used + len) else {
            return false;
        };
        arena.copy_within(self.asm_len..used, self.asm_len + len);
        if let Some(slot) = arena.get_mut(self.asm_len..end) {
            slot.copy_from_slice(data.bytes);
        }
        self.asm_len = end;
        self.asm_length = Some(u32::try_from(length).unwrap_or(u32::MAX));
        if data.last {
            self.ready = Some(length);
            self.asm_length = None;
        }
        true
    }

    /// Holds a fragment that came early, if the window has room for it.
    fn hold_early(&mut self, data: &Data<'_>) {
        let distance = data.sequence.wrapping_sub(self.rcv_next);
        if distance >= SEQUENCE_WINDOW || data.bytes.len() > self.free() {
            return;
        }
        let mut index = self.early.len();
        for i in 0..self.early.len() {
            let Some(stored) = self.early.get(i) else {
                continue;
            };
            if stored.seq == data.sequence {
                return;
            }
            if stored.seq.wrapping_sub(self.rcv_next) > distance {
                index = i;
                break;
            }
        }
        let used = self.asm_len + self.early_len;
        let len = data.bytes.len();
        let record = Stored {
            seq: data.sequence,
            at: u32::try_from(self.early_len).unwrap_or(u32::MAX),
            len: u16::try_from(len).unwrap_or(u16::MAX),
            length: data.length.unwrap_or(0),
            last: data.last,
        };
        if self.early.len() >= self.early.capacity() {
            return;
        }
        let Some(arena) = self.arena.get_mut(used + len) else {
            return;
        };
        if let Some(slot) = arena.get_mut(used..used + len) {
            slot.copy_from_slice(data.bytes);
        }
        if self.early.insert(index, record) {
            self.early_len += len;
        }
    }

    /// Removes early fragment `i` and its bytes, closing the gap.
    fn remove_early(&mut self, i: usize) -> Option<Stored> {
        let stored = self.early.remove(i)?;
        let start = self.asm_len + stored.at as usize;
        let len = usize::from(stored.len);
        let used = self.asm_len + self.early_len;
        if let Some(arena) = self.arena.get_mut(used) {
            arena.copy_within(start + len..used, start);
        }
        self.early_len -= len;
        for j in 0..self.early.len() {
            if let Some(other) = self.early.get_mut(j)
                && other.at > stored.at
            {
                other.at -= u32::from(stored.len);
            }
        }
        Some(stored)
    }

    /// Gives up the farthest early fragment to make room; the sender
    /// retransmits it at its timeout, which forgets what was acknowledged in
    /// ranges.
    fn drop_last_early(&mut self) -> bool {
        let Some(last) = self.early.len().checked_sub(1) else {
            return false;
        };
        self.remove_early(last).is_some()
    }

    /// Moves early fragments that are now in order into the assembly.
    fn pull_early(&mut self) {
        let mut bytes = [0u8; MAX_FRAGMENT];
        while self.ready.is_none() {
            let Some(first) = self.early.get(0).copied() else {
                return;
            };
            if first.seq != self.rcv_next {
                return;
            }
            let start = self.asm_len + first.at as usize;
            let len = usize::from(first.len);
            let copied = match (
                self.arena.get(start + len).and_then(|a| a.get(start..)),
                bytes.get_mut(..len),
            ) {
                (Some(source), Some(dest)) => {
                    dest.copy_from_slice(source);
                    true
                }
                _ => false,
            };
            let _ = self.remove_early(0);
            if !copied {
                return;
            }
            let data = Data {
                incarnation: [0; frame::INCARNATION_LEN],
                sequence: first.seq,
                length: (first.length != 0).then_some(first.length),
                last: first.last,
                start: false,
                bytes: bytes.get(..len).unwrap_or_default(),
            };
            if !self.accept_in_order(&data) {
                return;
            }
            self.rcv_next = self.rcv_next.wrapping_add(1);
        }
    }

    /// Releases a message handed out by the last call.
    pub(crate) fn settle(&mut self) {
        if !self.delivered {
            return;
        }
        self.delivered = false;
        let Some(length) = self.ready.take() else {
            return;
        };
        let used = self.asm_len + self.early_len;
        if let Some(arena) = self.arena.get_mut(used) {
            arena.copy_within(length..used, 0);
        }
        self.asm_len -= length;
        if self.advertised_closed {
            self.ack_now = true;
        }
        self.pull_early();
        if self.asm_len + self.early_len == 0 {
            self.arena.release();
        }
    }

    fn ack(&mut self, out: &mut [u8]) -> Option<usize> {
        let incarnation = self.receive_incarnation?;
        let window = u32::try_from(self.free()).unwrap_or(u32::MAX);
        let mut ack = Ack::new(
            incarnation,
            false,
            self.rcv_next,
            window,
            u32::try_from(C::MAX_MESSAGE).unwrap_or(u32::MAX),
        );
        let mut range: Option<Range> = None;
        for i in 0..self.early.len() {
            let Some(stored) = self.early.get(i) else {
                continue;
            };
            // In order, held while a whole message waits to be delivered:
            // not beyond the cumulative point, so not a range.
            if !after(stored.seq, self.rcv_next) {
                continue;
            }
            match range.as_mut() {
                Some(r) if r.end == stored.seq => r.end = r.end.wrapping_add(1),
                _ => {
                    if let Some(r) = range.take()
                        && !ack.push_range(r)
                    {
                        break;
                    }
                    range = Some(Range {
                        start: stored.seq,
                        end: stored.seq.wrapping_add(1),
                    });
                }
            }
        }
        if let Some(r) = range {
            let _ = ack.push_range(r);
        }
        let len = ack.encode(out).ok()?;
        self.advertised_closed = (window as usize) < MSS;
        self.unacked = 0;
        self.ack_now = false;
        self.ack_deadline = None;
        Some(len)
    }

    // --- resets -------------------------------------------------------------------------

    fn retire(&mut self, incarnation: Option<Incarnation>) {
        let Some(incarnation) = incarnation else {
            return;
        };
        if self.retired.contains(&Some(incarnation)) {
            return;
        }
        self.retired.rotate_right(1);
        if let Some(slot) = self.retired.first_mut() {
            *slot = Some(incarnation);
        }
    }

    /// Drops everything the channel holds, both ways, and reports `reason`.
    /// In place: a channel is too large to rebuild on a microcontroller's
    /// stack.
    pub(crate) fn reset(&mut self, reason: Reason) {
        self.retire(self.receive_incarnation);
        self.retire(self.send_incarnation);
        let had = self.send_incarnation.is_some() || self.receive_incarnation.is_some();

        self.send_incarnation = None;
        self.acked_any = false;
        let queued = self.queue.len();
        self.queue.pop(queued);
        self.lengths.clear();
        self.popped = 0;
        self.in_flight.clear();
        self.una = 0;
        self.next_seq = 0;
        self.next_msg = 0;
        self.next_off = 0;
        self.next_abs = 0;
        self.cwnd = INITIAL_WINDOW * MSS;
        self.ssthresh = usize::MAX;
        self.recovery_until = None;
        self.rto_deadline = None;
        self.loss_deadline = None;
        self.probe_deadline = None;
        self.probe_now = false;
        self.probe_backoff = self.rto;
        self.waiting_since = None;
        self.peer_window = INITIAL_PEER_WINDOW;
        self.peer_max = None;
        self.writable = self.blocked;
        self.blocked = false;
        self.keys_retry = None;
        self.keys_backoff = KEYS_RETRY;
        self.dialled = false;
        self.dial_due = false;

        self.receive_incarnation = None;
        self.rcv_next = 0;
        self.arena.release();
        self.asm_len = 0;
        self.asm_length = None;
        self.early.clear();
        self.early_len = 0;
        self.ready = None;
        self.delivered = false;
        self.unacked = 0;
        self.ack_now = false;
        self.ack_deadline = None;
        self.advertised_closed = false;

        self.ever_reset = true;
        if self.event.is_none() && had {
            self.event = Some(reason);
        }
    }

    // --- refusals and timers ------------------------------------------------------------

    /// The core refused the frame just emitted: the session has no keys.
    pub(crate) fn refused(&mut self, emitted: Emitted, now: Instant) {
        match emitted {
            Emitted::Data(seq) => {
                let i = seq.wrapping_sub(self.una) as usize;
                if let Some(sent) = self.in_flight.get_mut(i) {
                    // Not a loss on the network: no congestion response.
                    sent.lost = true;
                }
            }
            Emitted::Ack => self.ack_now = true,
            Emitted::ResetAnswer => {}
        }
        self.keys_retry = Some(now.saturating_add(self.keys_backoff));
        self.keys_backoff = (self.keys_backoff * 2).min(KEYS_RETRY_MAX);
        if !self.dialled && self.address.is_some() {
            self.dialled = true;
            self.dial_due = true;
        }
    }

    /// Fires the timers due at `now`.
    pub(crate) fn tick(&mut self, now: Instant) {
        self.settle();
        if let Some(since) = self.waiting_since
            && now >= since.saturating_add(NO_PROGRESS)
        {
            self.reset(Reason::NoProgress);
            return;
        }
        if self.keys_retry.is_some_and(|at| now >= at) {
            self.keys_retry = None;
        }
        if self.ack_deadline.is_some_and(|at| now >= at) {
            self.ack_now = true;
        }
        if self.loss_deadline.is_some_and(|at| now >= at) {
            self.detect_losses(now);
        }
        if self.rto_deadline.is_some_and(|at| now >= at) && !self.in_flight.is_empty() {
            self.ssthresh = (self.flight() / 2).max(2 * MSS);
            self.cwnd = MSS;
            // Everything not held at the peer is lost; and the oldest even if
            // held, since a receiver short of room gives up early fragments.
            for i in 0..self.in_flight.len() {
                if let Some(sent) = self.in_flight.get_mut(i)
                    && (i == 0 || !sent.sacked)
                {
                    sent.lost = true;
                    sent.sacked = false;
                }
            }
            self.recovery_until = Some(self.next_seq);
            self.rto = (self.rto * 2).min(MAX_RTO);
            self.rto_deadline = Some(now.saturating_add(self.rto));
        }
        if self.probe_deadline.is_some_and(|at| now >= at) {
            self.probe_deadline = None;
            if self.window_closed() {
                self.probe_now = true;
                self.probe_backoff = (self.probe_backoff * 2).min(MAX_RTO);
            }
        }
    }

    /// The channel's next deadline; `None` when it has nothing to deliver or
    /// to acknowledge.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        [
            self.waiting_since
                .map(|since| since.saturating_add(NO_PROGRESS)),
            self.keys_retry,
            self.ack_deadline,
            self.rto_deadline.filter(|_| !self.in_flight.is_empty()),
            self.loss_deadline.filter(|_| !self.in_flight.is_empty()),
            self.probe_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// What the channel has for its driver now, its frame written in `out`.
    /// Without `deliver`, a whole message stays here: the receive window
    /// closes, and acknowledgements keep telling the sender so.
    pub(crate) fn output(&mut self, now: Instant, deliver: bool, out: &mut [u8]) -> Output {
        self.settle();
        if let Some(reason) = self.event.take() {
            return Output::Reset(reason);
        }
        if let Some(length) = self.ready.filter(|_| deliver && !self.delivered) {
            self.delivered = true;
            return Output::Message(length);
        }
        if self.writable {
            self.writable = false;
            return Output::Writable;
        }
        if self.dial_due {
            self.dial_due = false;
            if let Some(address) = self.address {
                return Output::Dial(address);
            }
        }
        if self.keys_retry.is_some() {
            return Output::Nothing;
        }
        if let Some(incarnation) = self.reset_answer.take() {
            let ack = Ack::new(incarnation, true, 0, 0, 0);
            if let Ok(len) = ack.encode(out) {
                return Output::Frame {
                    kind: convesso_core::endpoint::FrameKind::Ack,
                    len,
                    emitted: Emitted::ResetAnswer,
                };
            }
        }
        if self.ack_now
            && let Some(len) = self.ack(out)
        {
            return Output::Frame {
                kind: convesso_core::endpoint::FrameKind::Ack,
                len,
                emitted: Emitted::Ack,
            };
        }
        if let Some(i) = self.lost_index()
            && self.flight() + self.in_flight.get(i).map_or(0, |s| usize::from(s.len)) <= self.cwnd
            && let Some(output) = self.emit_retransmission(i, now, out)
        {
            return output;
        }
        if let Some(output) = self.emit_new(now, false, out) {
            return output;
        }
        if self.probe_now {
            self.probe_now = false;
            if let Some(output) = self.emit_new(now, true, out) {
                return output;
            }
        }
        if self.window_closed() {
            self.probe_deadline
                .get_or_insert(now.saturating_add(self.probe_backoff));
        }
        Output::Nothing
    }

    /// The bytes of a message handed out by [`Channel::output`].
    pub(crate) fn message(&self, length: usize) -> &[u8] {
        self.arena.get(length).unwrap_or_default()
    }

    /// The bytes the channel holds, both ways: for the memory bounds.
    pub(crate) fn memory(&self) -> usize {
        self.queue.len() + self.asm_len + self.early_len
    }

    /// Bytes in flight against the congestion window, the window, and bytes
    /// beyond the cumulative point against the peer's window: for tests.
    #[cfg(test)]
    pub(crate) fn windows(&self) -> (usize, usize, usize, usize) {
        (
            self.flight(),
            self.cwnd,
            self.beyond_una(),
            self.peer_window as usize,
        )
    }

    pub(crate) fn state(&self) -> ChannelState {
        let flight = (0..self.in_flight.len()).filter_map(|i| self.in_flight.get(i));
        ChannelState {
            una: self.una,
            next_seq: self.next_seq,
            in_flight: self.in_flight.len(),
            sacked: flight.clone().filter(|s| s.sacked).count(),
            lost: flight.filter(|s| s.lost).count(),
            cwnd: self.cwnd,
            peer_window: self.peer_window,
            rto_ms: u64::try_from(self.rto.as_millis()).unwrap_or(u64::MAX),
            queued_messages: self.lengths.len(),
            rcv_next: self.rcv_next,
            assembled: self.asm_len,
            assembling: self.asm_length,
            early: self.early.len(),
            early_first: self.early.get(0).map(|s| s.seq),
            ready: self.ready,
            waiting_keys: self.keys_retry.is_some(),
        }
    }

    /// A dial of the session failed. Only a channel waiting for the session's
    /// keys is reset: a failed renewal, while the current keys still carry
    /// the session, takes nothing from the channel.
    pub(crate) fn reopen_failed(&mut self, error: DialError) {
        if self.dialled || self.keys_retry.is_some() {
            self.reset(Reason::ReopenFailed(error));
        }
    }

    /// Whether a send succeeded: the frame left, so keys are back.
    pub(crate) fn sent(&mut self) {
        self.keys_backoff = KEYS_RETRY;
        self.dialled = false;
    }
}

fn in_range(seq: u32, range: &Range) -> bool {
    !after(range.start, seq) && after(range.end, seq)
}

#[cfg(test)]
mod tests;
