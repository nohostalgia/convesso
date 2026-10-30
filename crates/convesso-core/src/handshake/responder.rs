//! The responder's side of version 1's handshake.
//!
//! Every check that can fail without a Diffie-Hellman comes first, and any
//! failure before admission is met with silence and leaves no state:
//!
//! 1. byte 0: an unknown version is answered by the wire invariants, or not;
//! 2. the first contact's length and type (a payload's length included);
//! 3. `mac1`, for the cost of a hash;
//! 4. the ephemeral key: an exact replay of a recent first contact stops here;
//! 5. the load bucket: under load, `mac2` must be valid for the packet's
//!    source, or the answer is a cookie reply; then the source's rate
//!    (`PROTOCOL.md §4`);
//! 6. one `es` Diffie-Hellman, then decryption under each context served;
//! 7. the initiator's static key in its one canonical, torsion-free form;
//! 8. a context bound to one `PeerId` meets every other with silence;
//! 9. the application's admission decision, by `PeerId`.
//!
//! A first contact with a payload (type `0x05`) is tried only under the
//! contexts that accept one. Its payload reaches the application only after
//! admission accepts, written after the response in the output buffer: it is
//! authenticated as the initiator's, but unconfirmed, because Noise's first
//! payload can be replayed.
//!
//! An accepted handshake becomes [`Pending`]: keys exist, no event is raised,
//! and nothing replaces a confirmed session until the initiator's first
//! transport packet confirms it (`PROTOCOL.md §5`). Pending handshakes are
//! bounded per `PeerId` and in total, and expire after [`PENDING_LIFETIME`].

use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use super::messages::{
    self, DECISION_LEN, INITIATION_NOISE_LEN, RESPONSE_NOISE_LEN, TYPE_INITIATION_PAYLOAD,
    WireDecision,
};
use super::{
    Admission, ChannelBinding, Context, ContextTooLong, Decision, Entropy, MAX_PAYLOAD, NO_PSK,
    PENDING_LIFETIME, PENDING_PER_PEER, PROLOGUE_MAX, RESPONSE_LEN, RefusalCode,
};
use crate::dos::{self, Bucket, CookieSecret, Source, SourceKey};
use crate::identity::{Identity, PeerId};
use crate::noise::{self, Completed};
use crate::storage::{Config, Table};
use crate::time::Instant;
use crate::wire::{self, Classified, Mac1Key, Version};

/// How often a responder draws a new index before giving up on a collision.
const INDEX_DRAWS: usize = 8;

/// Why a context could not be served, or changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderError {
    /// A context is longer than allowed.
    ContextTooLong(ContextTooLong),
    /// The storage profile's contexts table is full.
    TooManyContexts {
        /// How many contexts the profile serves, the relay's included.
        capacity: usize,
    },
    /// The context is served already.
    AlreadyServed,
    /// The relay context, which only pinning a relay, or a relay, serves.
    RelayContext,
    /// The context is not one this responder serves.
    NotServed,
}

impl core::fmt::Display for ResponderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ContextTooLong(error) => error.fmt(f),
            Self::TooManyContexts { capacity } => write!(
                f,
                "the contexts table is full: the storage profile serves at most {capacity} \
                 contexts, the relay's included"
            ),
            Self::AlreadyServed => f.write_str("the context is served already"),
            Self::RelayContext => {
                f.write_str("the relay context is served only by pinning a relay, or by a relay")
            }
            Self::NotServed => f.write_str("the context is not served"),
        }
    }
}

/// Who may reach this endpoint in a context it serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Whoever the application's [`Admission`] accepts, asked for each first
    /// contact.
    Policy,
    /// This peer alone: a first contact from any other is met with silence,
    /// and admission is not asked.
    Bound(PeerId),
}

/// A context served: who may reach it, and whether a first contact may carry
/// a payload in it.
#[derive(Debug, Clone, Copy)]
pub struct Served {
    access: Access,
    accepts_payload: bool,
}

impl core::error::Error for ResponderError {}

/// Where this side stands with the initiator of a first contact, in its
/// context, as the endpoint knows it (`PROTOCOL.md §3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// No live keys: a renewal is answered `02 00 00`.
    NoKeys,
    /// Live keys: a renewal renews them.
    LiveKeys,
    /// This side's own opening to the peer crossed this one, and wins: the
    /// first contact is met with silence, and the peer's dial yields.
    Ignore,
}

/// What a responder does with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderOutput {
    /// Nothing: no answer, and no state kept.
    Silent,
    /// Send the first `n` bytes of the output buffer back to the sender.
    Send(usize),
    /// Send the first `len` bytes of the output buffer back to the sender: an
    /// acceptance. The admitted initiator's payload follows it in the buffer,
    /// `payload` bytes from offset `len`. It is authenticated as `peer`'s, but
    /// unconfirmed: a replay of the same first contact delivers it again.
    Payload {
        /// The response's length.
        len: usize,
        /// The payload's length.
        payload: usize,
        /// The initiator.
        peer: PeerId,
        /// The context.
        context: Context,
    },
}

/// An accepted handshake, not yet confirmed.
pub struct Pending {
    peer: PeerId,
    initiator_index: u32,
    responder_index: u32,
    context: Context,
    expires_at: Instant,
    accepted: u64,
    completed: Completed,
    opens: bool,
}

impl Pending {
    /// The initiator's identity.
    #[must_use]
    pub const fn peer(&self) -> &PeerId {
        &self.peer
    }

    /// The initiator's index.
    #[must_use]
    pub const fn initiator_index(&self) -> u32 {
        self.initiator_index
    }

    /// This responder's index for the handshake.
    #[must_use]
    pub const fn responder_index(&self) -> u32 {
        self.responder_index
    }

    /// The context the handshake is bound to.
    #[must_use]
    pub const fn context(&self) -> &Context {
        &self.context
    }

    /// When the handshake is discarded unless confirmed.
    #[must_use]
    pub const fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// The channel binding, equal to the initiator's.
    #[must_use]
    pub const fn channel_binding(&self) -> &ChannelBinding {
        &self.completed.handshake_hash
    }

    /// Whether the handshake opens a session, rather than renew one: as the
    /// initiator said, or as this responder answered a renewal it had no
    /// keys for (`02 00 00`).
    #[must_use]
    pub const fn opens(&self) -> bool {
        self.opens
    }

    #[cfg(test)]
    pub(crate) fn completed_mut(&mut self) -> &mut Completed {
        &mut self.completed
    }

    /// When the handshake completed: its keys expire 180 s after this.
    pub(crate) fn completed_at(&self) -> Instant {
        Instant::from_millis(
            self.expires_at
                .as_millis()
                .saturating_sub(u64::try_from(PENDING_LIFETIME.as_millis()).unwrap_or(0)),
        )
    }

    /// The keys this handshake would give a session: the responder receives
    /// with the first `Split()` output and sends with the second.
    pub(crate) fn keys(&self) -> Option<([u8; 32], [u8; 32])> {
        Some((
            self.completed.transport.send.key()?,
            self.completed.transport.recv.key()?,
        ))
    }
}

/// The responder's side: answers first contacts addressed to this identity.
pub struct Responder<C: Config> {
    identity: Identity,
    mac1_key: Mac1Key,
    contexts: C::Contexts<Context, Served>,
    pending: C::Pending<u32, Pending>,
    accepted: u64,
    load: Option<Bucket>,
    cookie_secret: CookieSecret,
    recent: C::RecentEphemerals<[u8; 32], Instant>,
    rates: C::SourceRates<SourceKey, Bucket>,
    #[cfg(test)]
    pub(crate) diffie_hellmans: usize,
}

impl<C: Config> Responder<C> {
    /// A responder for `identity`, serving `contexts` under [`Access::Policy`].
    /// With none, it answers no first contact until it serves one.
    ///
    /// # Errors
    ///
    /// As [`Self::serve`].
    pub fn new(identity: Identity, contexts: &[&[u8]]) -> Result<Self, ResponderError> {
        let mut responder = Self {
            mac1_key: Mac1Key::for_address(identity.address().as_bytes()),
            identity,
            contexts: Default::default(),
            pending: Default::default(),
            accepted: 0,
            load: None,
            cookie_secret: CookieSecret::default(),
            recent: Default::default(),
            rates: Default::default(),
            #[cfg(test)]
            diffie_hellmans: 0,
        };
        for context in contexts {
            responder.serve(context, Access::Policy)?;
        }
        Ok(responder)
    }

    /// Serves `context`, reached under `access`. A first contact in a context
    /// not served meets silence.
    ///
    /// # Errors
    ///
    /// A [`ResponderError`] when the context is too long, is served already,
    /// or would be one more than the storage profile's contexts table holds.
    pub fn serve(&mut self, context: &[u8], access: Access) -> Result<(), ResponderError> {
        let context = Context::new(context).map_err(ResponderError::ContextTooLong)?;
        if self.contexts.get(&context).is_some() {
            return Err(ResponderError::AlreadyServed);
        }
        let served = Served {
            access,
            accepts_payload: false,
        };
        self.contexts
            .insert(context, served)
            .map(|_| ())
            .map_err(|full| ResponderError::TooManyContexts {
                capacity: full.capacity,
            })
    }

    /// Whether `context` is served.
    #[must_use]
    pub fn serves(&self, context: &Context) -> bool {
        self.contexts.get(context).is_some()
    }

    /// The access of `context`, if it is served.
    #[must_use]
    pub fn access(&self, context: &Context) -> Option<Access> {
        self.contexts.get(context).map(|served| served.access)
    }

    /// Changes the access of a context served. Pending handshakes and sessions
    /// are not judged again here: the endpoint does that.
    ///
    /// # Errors
    ///
    /// [`ResponderError::NotServed`] for a context not served.
    pub fn set_access(&mut self, context: &Context, access: Access) -> Result<(), ResponderError> {
        let served = self
            .contexts
            .get_mut(context)
            .ok_or(ResponderError::NotServed)?;
        served.access = access;
        Ok(())
    }

    /// Stops serving `context`, freeing its entry; returns whether it was
    /// served. Its pending handshakes are not discarded here: the endpoint
    /// does that.
    pub fn stop_serving(&mut self, context: &Context) -> bool {
        self.contexts.remove(context).is_some()
    }

    /// Accepts first contacts with a payload in `context`. None does unless
    /// told so.
    ///
    /// # Errors
    ///
    /// [`ResponderError::NotServed`] for a context not served.
    pub fn accept_payload(&mut self, context: &[u8]) -> Result<(), ResponderError> {
        let context = Context::new(context).map_err(ResponderError::ContextTooLong)?;
        self.set_accepts_payload(&context, true)
    }

    /// Whether `context` is served and accepts first contacts with a payload.
    #[cfg(test)]
    pub(crate) fn accepts_payload(&self, context: &Context) -> bool {
        self.contexts
            .get(context)
            .is_some_and(|served| served.accepts_payload)
    }

    /// Whether first contacts with a payload are accepted in `context`.
    ///
    /// # Errors
    ///
    /// [`ResponderError::NotServed`] for a context not served.
    pub fn set_accepts_payload(
        &mut self,
        context: &Context,
        on: bool,
    ) -> Result<(), ResponderError> {
        let served = self
            .contexts
            .get_mut(context)
            .ok_or(ResponderError::NotServed)?;
        served.accepts_payload = on;
        Ok(())
    }

    /// How many contexts are served, the relay's included.
    #[must_use]
    pub fn contexts_served(&self) -> usize {
        self.contexts.len()
    }

    /// Handles a packet received at `now` from `source`. When it says
    /// [`ResponderOutput::Send`], the answer is in `out`, which must hold at
    /// least [`MAX_RESPONDER_OUTPUT`](super::MAX_RESPONDER_OUTPUT) bytes. A
    /// first contact with a payload of `n` bytes is handled only when `out`
    /// holds at least `RESPONSE_LEN + n`: room for the payload after the
    /// response.
    pub fn handle(
        &mut self,
        packet: &[u8],
        source: Source<'_>,
        now: Instant,
        admission: &mut impl Admission,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> ResponderOutput {
        let standing = |_: &PeerId, _: &Context, _: bool| Standing::NoKeys;
        self.handle_with(packet, source, now, admission, standing, entropy, out)
    }

    /// [`Self::handle`], with `standing` saying where this side stands with
    /// the initiator, in the context, for a renewal (`true`) or an opening: a
    /// renewal of keys it does not hold is answered `02 00 00`, as opening a
    /// session, and a first contact this side's own crossing opening wins
    /// against meets silence (`PROTOCOL.md §3`). [`Self::handle`] stands
    /// with no keys.
    #[allow(
        clippy::too_many_arguments,
        reason = "the sans-IO inputs of a first contact, and the endpoint's keys"
    )]
    pub fn handle_with(
        &mut self,
        packet: &[u8],
        source: Source<'_>,
        now: Instant,
        admission: &mut impl Admission,
        standing: impl FnMut(&PeerId, &Context, bool) -> Standing,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> ResponderOutput {
        match wire::classify(packet) {
            Classified::Version(Version::V1) => {
                self.first_contact(packet, source, now, admission, standing, entropy, out)
            }
            Classified::Version(_) => {
                match wire::answer_unknown_version(packet, &self.mac1_key, &[Version::V1], out) {
                    Some(len) => ResponderOutput::Send(len),
                    None => ResponderOutput::Silent,
                }
            }
            Classified::Drop | Classified::VersionNotSupported => ResponderOutput::Silent,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the sans-IO inputs of a first contact, and the endpoint's keys"
    )]
    fn first_contact(
        &mut self,
        packet: &[u8],
        source: Source<'_>,
        now: Instant,
        admission: &mut impl Admission,
        mut standing: impl FnMut(&PeerId, &Context, bool) -> Standing,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> ResponderOutput {
        use ResponderOutput::Silent;

        let first = if packet.get(1) == Some(&TYPE_INITIATION_PAYLOAD) {
            match messages::parse_payload_first_contact(packet) {
                Ok(first)
                    if self.any_accepts_payload()
                        && out.len() >= RESPONSE_LEN + first.payload_len() =>
                {
                    Initiation {
                        initiator_index: first.initiator_index,
                        noise: first.noise,
                        renewal: false,
                    }
                }
                _ => return Silent,
            }
        } else {
            match messages::parse_first_contact(packet) {
                Ok(first) => Initiation {
                    initiator_index: first.initiator_index,
                    noise: first.noise,
                    renewal: first.renewal,
                },
                Err(_) => return Silent,
            }
        };
        if !self.mac1_key.verify(packet) {
            return Silent;
        }
        let Some(source) = source.key() else {
            return Silent;
        };
        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(first.noise.get(..32).unwrap_or(&[0; 32]));
        if dos::seen_recently(&self.recent, &ephemeral_public, now) {
            return Silent;
        }
        let load = self
            .load
            .get_or_insert_with(|| Bucket::full(C::LOAD_BURST, now));
        if !load.take(C::LOAD_RATE_PER_SECOND, C::LOAD_BURST, now) {
            // Under load: only a sender that received a cookie for its source
            // gets a Diffie-Hellman, and then only within its source's rate.
            let cookie = dos::cookie(self.cookie_secret.at(now, entropy), &source);
            if !dos::verify_mac2(&cookie, packet) {
                return self.cookie_reply(packet, first.initiator_index, &cookie, entropy, out);
            }
            if !dos::take_source_token(&mut self.rates, source, now) {
                return Silent;
            }
        }

        dos::remember(&mut self.recent, ephemeral_public, now);
        #[cfg(test)]
        {
            self.diffie_hellmans += 1;
        }
        let Ok((re, es)) = noise::initiation_es(self.identity.secret(), first.noise) else {
            return Silent;
        };
        let mut initiation = [0u8; INITIATION_NOISE_LEN + MAX_PAYLOAD];
        let Some((read, context, access, payload_len)) =
            self.decrypt_under_a_context(first.noise, &re, &es, &mut initiation)
        else {
            return Silent;
        };
        let Ok(peer) = PeerId::from_static(*read.remote_static()) else {
            return Silent;
        };
        if let Access::Bound(bound) = access
            && bound != peer
        {
            return Silent;
        }
        let stands = standing(&peer, &context, first.renewal);
        if stands == Standing::Ignore {
            return Silent;
        }

        self.expire(now);
        let (mut decision, psk) = match admission.admit(&peer, context.as_bytes()) {
            Decision::Accept { psk } => (WireDecision::Accept, psk),
            Decision::Refuse { code, psk } => (WireDecision::Refuse(code), psk),
        };
        let psk = psk.unwrap_or(NO_PSK);

        let mut responder_index = draw_index(entropy);
        if decision == WireDecision::Accept {
            match self.make_room(&peer, entropy) {
                Some(index) => responder_index = index,
                None => decision = WireDecision::Refuse(RefusalCode::CAPACITY_EXHAUSTED),
            }
        }
        // A renewal of keys this side does not hold opens a session, and the
        // initiator is told so (`PROTOCOL.md §3`).
        if decision == WireDecision::Accept && first.renewal && stands == Standing::NoKeys {
            decision = WireDecision::AcceptAsNew;
        }
        let accepted = matches!(decision, WireDecision::Accept | WireDecision::AcceptAsNew);

        let mut ephemeral = [0u8; 32];
        entropy.fill(&mut ephemeral);
        let e = StaticSecret::from(ephemeral);
        ephemeral.zeroize();

        let plaintext: [u8; DECISION_LEN] = messages::encode_decision(decision);
        let mut noise_out = [0u8; RESPONSE_NOISE_LEN];
        let Ok((completed, RESPONSE_NOISE_LEN)) =
            noise::write_response(read, &e, &psk, &plaintext, &mut noise_out)
        else {
            return Silent;
        };
        let response = messages::write_response(responder_index, first.initiator_index, &noise_out);
        let Some((out, out_payload)) = out.split_at_mut_checked(RESPONSE_LEN) else {
            return Silent;
        };

        if accepted {
            self.accepted = self.accepted.wrapping_add(1);
            let pending = Pending {
                peer,
                initiator_index: first.initiator_index,
                responder_index,
                context,
                expires_at: now.saturating_add(PENDING_LIFETIME),
                accepted: self.accepted,
                completed,
                opens: !first.renewal || decision == WireDecision::AcceptAsNew,
            };
            // Room was made above; an acceptance is never sent without its state.
            if self.pending.insert(responder_index, pending).is_err() {
                return Silent;
            }
        }
        out.copy_from_slice(&response);
        if accepted && payload_len > 0 {
            // The plaintext follows `e` and the encrypted `s`.
            let at = 32 + 48;
            let (Some(field), Some(payload)) = (
                out_payload.get_mut(..payload_len),
                initiation.get(at..at + payload_len),
            ) else {
                return Silent;
            };
            field.copy_from_slice(payload);
            return ResponderOutput::Payload {
                len: RESPONSE_LEN,
                payload: payload_len,
                peer,
                context,
            };
        }
        ResponderOutput::Send(RESPONSE_LEN)
    }

    /// Answers a first contact without a valid `mac2` under load: its cookie,
    /// encrypted to whoever knows this address and bound to that first
    /// contact's `mac1`. 62 bytes, against the first contact's 134.
    fn cookie_reply(
        &self,
        packet: &[u8],
        initiator_index: u32,
        cookie: &dos::Cookie,
        entropy: &mut impl Entropy,
        out: &mut [u8],
    ) -> ResponderOutput {
        let Some(mac1) = wire::carried_mac1(packet) else {
            return ResponderOutput::Silent;
        };
        let mut nonce = [0u8; 24];
        entropy.fill(&mut nonce);
        let (Some(reply), Some(out)) = (
            dos::write_cookie_reply(
                self.identity.address().as_bytes(),
                initiator_index,
                &nonce,
                cookie,
                &mac1,
            ),
            out.get_mut(..dos::COOKIE_REPLY_LEN),
        ) else {
            return ResponderOutput::Silent;
        };
        out.copy_from_slice(&reply);
        ResponderOutput::Send(dos::COOKIE_REPLY_LEN)
    }

    /// Whether some context served accepts a first contact with a payload.
    fn any_accepts_payload(&self) -> bool {
        let mut any = false;
        self.contexts
            .for_each(|_, served| any |= served.accepts_payload);
        any
    }

    /// Tries each served context with the one `es` result; the first that
    /// decrypts wins. A message without a payload must decrypt to an empty
    /// one; a message with a payload is tried only under the contexts that
    /// accept one. Returns the context, its access and the payload's length,
    /// the plaintext left in `buffer`.
    ///
    /// A wrong context fails at the initiator's static key, before `ss`: each
    /// costs a hash and an AEAD, never a Diffie-Hellman.
    fn decrypt_under_a_context(
        &self,
        message: &[u8],
        re: &[u8; 32],
        es: &[u8; 32],
        buffer: &mut [u8; INITIATION_NOISE_LEN + MAX_PAYLOAD],
    ) -> Option<(noise::ResponderRead, Context, Access, usize)> {
        let expected = message.len().checked_sub(INITIATION_NOISE_LEN)?;
        let buffer = buffer.get_mut(..message.len())?;
        let mut found = None;
        let mut done = false;
        self.contexts.for_each(|context, served| {
            if done || (expected > 0 && !served.accepts_payload) {
                return;
            }
            let mut prologue = [0u8; PROLOGUE_MAX];
            let prologue = context.prologue(&mut prologue);
            buffer.copy_from_slice(message);
            match noise::read_initiation(self.identity.secret(), prologue, re, es, buffer) {
                Ok((read, len)) if len == expected => {
                    found = Some((read, *context, served.access, len));
                    done = true;
                }
                // A payload where there must be none: no context will do better.
                Ok(_) => done = true,
                Err(_) => {}
            }
        });
        found
    }

    /// Makes room for one more pending handshake from `peer` and returns a free
    /// responder index, or `None` when the responder is full.
    fn make_room(&mut self, peer: &PeerId, entropy: &mut impl Entropy) -> Option<u32> {
        let mut from_peer = 0;
        let mut oldest: Option<(u64, u32)> = None;
        self.pending.for_each(|index, pending| {
            if pending.peer == *peer {
                from_peer += 1;
                if oldest.is_none_or(|(accepted, _)| pending.accepted < accepted) {
                    oldest = Some((pending.accepted, *index));
                }
            }
        });
        if from_peer >= PENDING_PER_PEER {
            if let Some((_, index)) = oldest {
                self.pending.remove(&index);
            }
        } else if self
            .pending
            .capacity()
            .is_some_and(|capacity| self.pending.len() >= capacity)
        {
            return None;
        }
        (0..INDEX_DRAWS)
            .map(|_| draw_index(entropy))
            .find(|index| self.pending.get(index).is_none())
    }

    /// Discards every pending handshake whose expiry has passed. Sends nothing.
    pub fn expire(&mut self, now: Instant) {
        self.pending.retain(|_, pending| pending.expires_at > now);
    }

    /// The next instant at which a pending handshake expires, if any.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        self.pending.for_each(|_, pending| {
            if next.is_none_or(|n| pending.expires_at < n) {
                next = Some(pending.expires_at);
            }
        });
        next
    }

    /// The pending handshake under a responder index.
    #[must_use]
    pub fn pending(&self, responder_index: u32) -> Option<&Pending> {
        self.pending.get(&responder_index)
    }

    /// How many handshakes are pending.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// How many handshakes are pending for `peer`.
    #[must_use]
    pub fn pending_for(&self, peer: &PeerId) -> usize {
        let mut count = 0;
        self.pending.for_each(|_, pending| {
            if pending.peer == *peer {
                count += 1;
            }
        });
        count
    }

    /// Whether a renewal from `peer` in `context` is pending: a handshake
    /// that, once confirmed, keeps the session it renews.
    pub(crate) fn renewal_pending(&self, peer: &PeerId, context: &Context) -> bool {
        let mut found = false;
        self.pending.for_each(|_, pending| {
            found |= pending.peer == *peer && pending.context == *context && !pending.opens;
        });
        found
    }

    /// Whether a handshake from `peer` in `context` is pending.
    #[must_use]
    pub fn pending_in(&self, peer: &PeerId, context: &Context) -> bool {
        let mut found = false;
        self.pending.for_each(|_, pending| {
            found |= pending.peer == *peer && pending.context == *context;
        });
        found
    }

    #[cfg(test)]
    pub(crate) fn pending_mut(&mut self, responder_index: u32) -> Option<&mut Pending> {
        self.pending.get_mut(&responder_index)
    }

    /// Takes a pending handshake out, to promote it: its first transport packet
    /// opened.
    pub(crate) fn take_pending(&mut self, responder_index: u32) -> Option<Pending> {
        self.pending.remove(&responder_index)
    }

    /// Discards every pending handshake from `peer`: revocation reaches them.
    pub(crate) fn discard_peer(&mut self, peer: &PeerId) {
        self.pending.retain(|_, pending| pending.peer != *peer);
    }

    /// Keeps only the pending handshakes for which `keep` returns `true`.
    pub(crate) fn retain_pending(&mut self, mut keep: impl FnMut(&Pending) -> bool) {
        self.pending.retain(|_, pending| keep(pending));
    }

    /// This responder's identity, which a dial from the same endpoint uses.
    pub(crate) const fn identity(&self) -> &Identity {
        &self.identity
    }
}

/// A first contact's fields the responder works on, of either type.
struct Initiation<'a> {
    initiator_index: u32,
    noise: &'a [u8],
    renewal: bool,
}

fn draw_index(entropy: &mut impl Entropy) -> u32 {
    let mut bytes = [0u8; 4];
    entropy.fill(&mut bytes);
    u32::from_le_bytes(bytes)
}
