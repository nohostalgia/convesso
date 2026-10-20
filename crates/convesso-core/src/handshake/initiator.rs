//! The initiator's side of version 1's handshake: a [`Dial`].
//!
//! A dial sends a first contact at its start and, while nothing has answered,
//! a new one with a fresh ephemeral key and index at each of
//! [`ATTEMPT_OFFSETS`](super::ATTEMPT_OFFSETS); it gives up at
//! [`GIVE_UP_AFTER`](super::GIVE_UP_AFTER). A response to any attempt completes
//! it. Anything that does not decrypt under an attempt is ignored, so a forged
//! response cannot end a dial; a genuine refusal, or a genuine "version not
//! supported", does.
//!
//! A responder under load answers with a cookie reply instead
//! (`PROTOCOL.md §4`). A dial keeps a cookie that decrypts under the
//! dialled address and an attempt's `mac1` for [`COOKIE_LIFETIME`], and puts
//! the matching `mac2` in its next scheduled first contacts. It never sends
//! sooner because of a cookie.
//!
//! A dial can carry a payload in its first contacts (type `0x05`), for a
//! responder whose context accepts one. The dial does not keep it: the caller
//! gives it again at each step, so that a retry carries it under a fresh
//! ephemeral key without the dial holding a buffer.

use core::time::Duration;

use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use super::messages::{self, INITIATION_NOISE_LEN, RESPONSE_NOISE_LEN, WireDecision};
use super::{
    ATTEMPT_OFFSETS, ChannelBinding, Context, ContextTooLong, Entropy, GIVE_UP_AFTER, MAX_PAYLOAD,
    NO_PSK, PROLOGUE_MAX, Psk, RefusalCode,
};
use crate::dos::{self, COOKIE_LIFETIME, Cookie};
use crate::identity::{Address, Identity, PeerId};
use crate::noise::{self, Completed, InitiatorAwaiting};
use crate::time::Instant;
use crate::wire::{
    self, Classified, Mac, Mac1Key, PendingFirstContact, UnsupportedVersion, Version,
    VersionNotSupported,
};

/// Why a dial ended without a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialError {
    /// The context is longer than allowed.
    ContextTooLong(ContextTooLong),
    /// The responder refused, with this code.
    Refused(RefusalCode),
    /// Nothing answered within [`GIVE_UP_AFTER`](super::GIVE_UP_AFTER). A PSK
    /// that does not match the responder's looks like this too.
    NoResponse,
    /// The payload is longer than [`MAX_PAYLOAD`](super::MAX_PAYLOAD), or the
    /// output buffer cannot hold the first contact.
    PayloadTooLong,
    /// The responder does not speak version 1; it names what it speaks.
    UnsupportedVersion(UnsupportedVersion),
}

impl core::fmt::Display for DialError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ContextTooLong(error) => error.fmt(f),
            Self::Refused(code) => write!(f, "refused by the peer with code {:#06x}", code.get()),
            Self::NoResponse => f.write_str("the peer did not answer"),
            Self::PayloadTooLong => write!(
                f,
                "a first contact carries at most {MAX_PAYLOAD} bytes of payload"
            ),
            Self::UnsupportedVersion(error) => error.fmt(f),
        }
    }
}

impl core::error::Error for DialError {}

/// What a dial wants done next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialPoll {
    /// Send the first `n` bytes of the output buffer to the peer.
    Send(usize),
    /// Call again at this instant, or when a packet arrives.
    Wait(Instant),
    /// The dial is over.
    Failed(DialError),
}

/// What a received packet did to a dial.
pub enum DialEvent {
    /// Nothing: not for this dial, forged, or too late.
    Ignored,
    /// The responder accepted.
    Established(Established),
    /// The dial is over.
    Failed(DialError),
}

/// A completed handshake on the initiator's side.
pub struct Established {
    peer: PeerId,
    local_index: u32,
    remote_index: u32,
    context: Context,
    completed: Completed,
}

impl Established {
    /// The responder's identity.
    #[must_use]
    pub const fn peer(&self) -> &PeerId {
        &self.peer
    }

    /// This initiator's index for the session.
    #[must_use]
    pub const fn local_index(&self) -> u32 {
        self.local_index
    }

    /// The responder's index for the session.
    #[must_use]
    pub const fn remote_index(&self) -> u32 {
        self.remote_index
    }

    /// The context the handshake is bound to.
    #[must_use]
    pub const fn context(&self) -> &Context {
        &self.context
    }

    /// The channel binding, equal to the responder's.
    #[must_use]
    pub const fn channel_binding(&self) -> &ChannelBinding {
        &self.completed.handshake_hash
    }

    #[cfg(test)]
    pub(crate) fn completed_mut(&mut self) -> &mut Completed {
        &mut self.completed
    }

    /// The keys this handshake gives the session: the initiator sends with the
    /// first `Split()` output and receives with the second.
    pub(crate) fn keys(&self) -> Option<([u8; 32], [u8; 32])> {
        Some((
            self.completed.transport.send.key()?,
            self.completed.transport.recv.key()?,
        ))
    }
}

struct Attempt {
    index: u32,
    mac1: Mac,
    awaiting: InitiatorAwaiting,
}

/// A dial in progress towards one address.
pub struct Dial {
    remote: Address,
    mac1_key: Mac1Key,
    context: Context,
    psk: Psk,
    started: Instant,
    attempts: [Option<Attempt>; ATTEMPT_OFFSETS.len()],
    sent: usize,
    over: bool,
    cookie: Option<(Cookie, Instant)>,
    /// The next attempt is due at this instant instead of at its offset: the
    /// peer was given new address hints (`PROTOCOL.md §3`).
    hurry: Option<Instant>,
}

impl Dial {
    /// Starts a dial to `remote` at `now`, writing the first contact into
    /// `out`, which must hold at least
    /// [`FIRST_CONTACT_LEN`](super::FIRST_CONTACT_LEN) bytes, and returning its
    /// length.
    ///
    /// # Errors
    ///
    /// [`DialError::ContextTooLong`] when the context is too long; nothing is
    /// sent then.
    pub fn start(
        identity: &Identity,
        remote: &Address,
        context: &[u8],
        psk: Option<Psk>,
        now: Instant,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<(Self, usize), DialError> {
        Self::start_with_payload(identity, remote, context, psk, &[], now, entropy, out)
    }

    /// [`Self::start`], with a first contact carrying `payload` (type `0x05`)
    /// when it is not empty. `out` must hold
    /// `FIRST_CONTACT_LEN + payload.len()` bytes.
    ///
    /// # Errors
    ///
    /// [`DialError::ContextTooLong`], or [`DialError::PayloadTooLong`] for a
    /// payload beyond [`MAX_PAYLOAD`] or an `out` too small for it; nothing is
    /// sent then.
    #[allow(
        clippy::too_many_arguments,
        reason = "the sans-IO inputs of a dial, and its payload"
    )]
    pub fn start_with_payload(
        identity: &Identity,
        remote: &Address,
        context: &[u8],
        psk: Option<Psk>,
        payload: &[u8],
        now: Instant,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> Result<(Self, usize), DialError> {
        if payload.len() > MAX_PAYLOAD || out.len() < super::FIRST_CONTACT_LEN + payload.len() {
            return Err(DialError::PayloadTooLong);
        }
        let mut dial = Self {
            remote: *remote,
            mac1_key: Mac1Key::for_address(remote.as_bytes()),
            context: Context::new(context).map_err(DialError::ContextTooLong)?,
            psk: psk.unwrap_or(NO_PSK),
            started: now,
            attempts: [const { None }; ATTEMPT_OFFSETS.len()],
            sent: 0,
            over: false,
            cookie: None,
            hurry: None,
        };
        let len = dial.send_attempt(identity, payload, now, entropy, out);
        Ok((dial, len))
    }

    /// What to do at `now`: send a retry, wait, or give up.
    pub fn poll(
        &mut self,
        identity: &Identity,
        now: Instant,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> DialPoll {
        self.poll_with_payload(identity, &[], now, entropy, out)
    }

    /// [`Self::poll`], with a retry carrying `payload` when it is not empty and
    /// fits [`MAX_PAYLOAD`] and `out`; otherwise the retry carries none.
    pub fn poll_with_payload(
        &mut self,
        identity: &Identity,
        payload: &[u8],
        now: Instant,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> DialPoll {
        let give_up = self.started.saturating_add(GIVE_UP_AFTER);
        if self.over || now >= give_up {
            self.finish();
            return DialPoll::Failed(DialError::NoResponse);
        }
        if let Some(offset) = ATTEMPT_OFFSETS.get(self.sent) {
            let due = self.attempt_due(*offset);
            if now >= due {
                return match self.send_attempt(identity, payload, now, entropy, out) {
                    0 => DialPoll::Wait(give_up),
                    len => DialPoll::Send(len),
                };
            }
            return DialPoll::Wait(due.min(give_up));
        }
        DialPoll::Wait(give_up)
    }

    /// Handles a packet received at `now`.
    pub fn handle(&mut self, identity: &Identity, packet: &[u8], now: Instant) -> DialEvent {
        if self.over {
            return DialEvent::Ignored;
        }
        if now >= self.started.saturating_add(GIVE_UP_AFTER) {
            self.finish();
            return DialEvent::Ignored;
        }
        match wire::classify(packet) {
            Classified::VersionNotSupported => self.version_not_supported(packet),
            Classified::Version(Version::V1) if packet.get(1) == Some(&dos::TYPE_COOKIE_REPLY) => {
                self.cookie_reply(packet, now)
            }
            Classified::Version(Version::V1) => self.response(identity, packet),
            Classified::Version(_) | Classified::Drop => DialEvent::Ignored,
        }
    }

    fn response(&mut self, identity: &Identity, packet: &[u8]) -> DialEvent {
        let Ok(response) = messages::parse_response(packet) else {
            return DialEvent::Ignored;
        };
        let Some(attempt) = self
            .attempts
            .iter()
            .flatten()
            .find(|attempt| attempt.index == response.initiator_index)
        else {
            return DialEvent::Ignored;
        };
        let mut buffer: [u8; RESPONSE_NOISE_LEN] = *response.noise;
        let Ok((completed, len)) =
            noise::read_response(&attempt.awaiting, identity.secret(), &self.psk, &mut buffer)
        else {
            return DialEvent::Ignored;
        };
        let Some(plaintext) = buffer.get(32..32 + len) else {
            return DialEvent::Ignored;
        };
        match messages::decode_decision(plaintext) {
            Ok(WireDecision::Accept) => {
                let established = Established {
                    peer: self.remote.peer_id(),
                    local_index: attempt.index,
                    remote_index: response.responder_index,
                    context: self.context,
                    completed,
                };
                self.finish();
                DialEvent::Established(established)
            }
            Ok(WireDecision::Refuse(code)) => {
                self.finish();
                DialEvent::Failed(DialError::Refused(code))
            }
            Err(_) => DialEvent::Ignored,
        }
    }

    /// Keeps the cookie a genuine cookie reply carries. Sends nothing: the next
    /// scheduled attempt carries the `mac2`.
    fn cookie_reply(&mut self, packet: &[u8], now: Instant) -> DialEvent {
        let Ok(reply) = dos::parse_cookie_reply(packet) else {
            return DialEvent::Ignored;
        };
        let Some(attempt) = self
            .attempts
            .iter()
            .flatten()
            .find(|attempt| attempt.index == reply.initiator_index)
        else {
            return DialEvent::Ignored;
        };
        if let Some(cookie) = dos::open_cookie_reply(&reply, self.remote.as_bytes(), &attempt.mac1)
        {
            self.cookie = Some((cookie, now));
        }
        DialEvent::Ignored
    }

    /// The cookie this dial would use at `now`, if it holds one younger than
    /// [`COOKIE_LIFETIME`].
    #[must_use]
    pub fn cookie_at(&self, now: Instant) -> Option<&Cookie> {
        self.cookie
            .as_ref()
            .filter(|(_, received)| now < received.saturating_add(COOKIE_LIFETIME))
            .map(|(cookie, _)| cookie)
    }

    fn version_not_supported(&mut self, packet: &[u8]) -> DialEvent {
        let Ok(answer) = VersionNotSupported::decode(packet) else {
            return DialEvent::Ignored;
        };
        let mut pending = [PendingFirstContact {
            version: Version::V1,
            mac1: [0; 16],
        }; ATTEMPT_OFFSETS.len()];
        let mut count = 0;
        for (slot, attempt) in pending.iter_mut().zip(self.attempts.iter().flatten()) {
            slot.mac1 = attempt.mac1;
            count += 1;
        }
        match wire::match_answer(&answer, pending.get(..count).unwrap_or_default()) {
            Some((_, error)) => {
                self.finish();
                DialEvent::Failed(DialError::UnsupportedVersion(error))
            }
            None => DialEvent::Ignored,
        }
    }

    /// Writes a new first contact with a fresh ephemeral key and index, carrying
    /// `payload` if it is not empty and fits, returning its length, or 0 when
    /// none could be written.
    fn send_attempt(
        &mut self,
        identity: &Identity,
        payload: &[u8],
        now: Instant,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> usize {
        self.hurry = None;
        let fits =
            payload.len() <= MAX_PAYLOAD && out.len() >= super::FIRST_CONTACT_LEN + payload.len();
        let payload = if fits { payload } else { &[] };
        let attempt = self.sent;
        if attempt >= ATTEMPT_OFFSETS.len() {
            return 0;
        }
        self.sent += 1;

        let index = loop {
            let mut bytes = [0u8; 4];
            entropy.fill(&mut bytes);
            let index = u32::from_le_bytes(bytes);
            if !self.attempts.iter().flatten().any(|a| a.index == index) {
                break index;
            }
        };
        let mut ephemeral = [0u8; 32];
        entropy.fill(&mut ephemeral);
        let e = StaticSecret::from(ephemeral);
        ephemeral.zeroize();

        let mut prologue = [0u8; PROLOGUE_MAX];
        let prologue = self.context.prologue(&mut prologue);
        let mut noise_out = [0u8; INITIATION_NOISE_LEN + MAX_PAYLOAD];
        let Ok((awaiting, noise_len)) = noise::write_initiation(
            identity.secret(),
            self.remote.peer_id().as_bytes(),
            e,
            prologue,
            payload,
            &mut noise_out,
        ) else {
            return 0;
        };
        let cookie = self.cookie_at(now).copied();
        let Some(len) = noise_out.get(..noise_len).and_then(|noise| {
            messages::write_first_contact_into(out, index, noise, &self.mac1_key, cookie.as_ref())
        }) else {
            return 0;
        };
        let Some(mac1) = out.get(..len).and_then(wire::carried_mac1) else {
            return 0;
        };
        if let Some(slot) = self.attempts.get_mut(attempt) {
            *slot = Some(Attempt {
                index,
                mac1,
                awaiting,
            });
        }
        len
    }

    fn finish(&mut self) {
        self.over = true;
        self.attempts = [const { None }; ATTEMPT_OFFSETS.len()];
    }

    /// When the dial started.
    #[must_use]
    pub const fn started(&self) -> Instant {
        self.started
    }

    /// The indices of the attempts in progress, which responses name.
    pub(crate) fn attempt_indices(&self) -> impl Iterator<Item = u32> + '_ {
        self.attempts.iter().flatten().map(|attempt| attempt.index)
    }

    /// The address being dialled.
    pub(crate) const fn remote(&self) -> &Address {
        &self.remote
    }

    /// When [`Self::poll`] next has something to do, or `None` once the dial is
    /// over. Asking changes nothing.
    pub(crate) fn next_due(&self) -> Option<Instant> {
        if self.over {
            return None;
        }
        let give_up = self.started.saturating_add(GIVE_UP_AFTER);
        Some(
            ATTEMPT_OFFSETS
                .get(self.sent)
                .map_or(give_up, |offset| self.attempt_due(*offset).min(give_up)),
        )
    }

    /// Sends the next attempt at `now` rather than at its offset: the peer has
    /// new address hints, which the attempt will reach. The attempts after it
    /// keep their offsets; a dial with its four attempts sent sends nothing
    /// more.
    pub(crate) fn hurry(&mut self, now: Instant) {
        if !self.over && self.sent > 0 && self.sent < ATTEMPT_OFFSETS.len() {
            self.hurry = Some(now);
        }
    }

    /// When the attempt at `offset` is due: then, or sooner when hurried.
    fn attempt_due(&self, offset: Duration) -> Instant {
        let due = self.started.saturating_add(offset);
        self.hurry.map_or(due, |hurry| hurry.min(due))
    }

    /// Whether one of this dial's attempts carried `mac1`: what a "version not
    /// supported" echoes.
    pub(crate) fn sent_mac1(&self, mac1: &Mac) -> bool {
        self.attempts
            .iter()
            .flatten()
            .any(|attempt| attempt.mac1 == *mac1)
    }
}
