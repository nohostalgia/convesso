//! Version 1's handshake (`PROTOCOL.md §3`): two endpoints addressed
//! by Ed25519 keys authenticate each other and derive session keys, with the
//! single Noise instance `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`.
//!
//! ```text
//! initiator                                             responder
//!   Dial::start ---- first contact (134 B) ---------------->  mac1, decrypt, canonical s,
//!                                                              Admission::admit(PeerId)
//!               <--- response (61 B): accept | refuse(code) -- Pending (5 s, no event)
//!   Established                                            confirmed later, by the
//!                                                          first transport packet
//! ```
//!
//! Sans-IO: packets, the current [`Instant`](crate::time::Instant) and
//! randomness ([`Entropy`]) come in; packets and deadlines go out.

mod initiator;
pub mod messages;
mod responder;
#[cfg(test)]
mod tests;

use core::num::NonZeroU16;
use core::time::Duration;

pub use initiator::{Dial, DialError, DialEvent, DialPoll, Established};
pub use responder::{Pending, Responder, ResponderError, ResponderOutput};

use crate::identity::PeerId;

/// Length of version 1's first contact.
pub const FIRST_CONTACT_LEN: usize = 134;

/// The longest payload a first contact carries (type `0x05`).
pub const MAX_PAYLOAD: usize = 1200;

/// The longest first contact: one with a payload of [`MAX_PAYLOAD`] bytes.
pub const MAX_FIRST_CONTACT_LEN: usize = FIRST_CONTACT_LEN + MAX_PAYLOAD;

/// Length of version 1's response.
pub const RESPONSE_LEN: usize = 61;

/// The most a responder writes in answer to a packet: a response (61 bytes), a
/// cookie reply (62) or a "version not supported" (at most 33).
pub const MAX_RESPONDER_OUTPUT: usize = 62;

/// The longest context an application may bind a handshake to.
pub const MAX_CONTEXT_LEN: usize = 32;

/// The most contexts a responder serves.
pub const MAX_CONTEXTS: usize = 4;

/// The most pending handshakes a responder holds for one `PeerId`.
pub const PENDING_PER_PEER: usize = 2;

/// How long a pending handshake waits for confirmation.
///
/// Sends nothing. Without it, slots taken by replays or abandoned dials would
/// never free.
pub const PENDING_LIFETIME: Duration = Duration::from_secs(5);

/// When an initiator sends a first contact, counted from the start of a dial.
///
/// Sends at most 4 × 134 bytes per dial, and nothing on an idle device. Without
/// retries, one lost packet would fail the dial.
pub const ATTEMPT_OFFSETS: [Duration; 4] = [
    Duration::from_secs(0),
    Duration::from_secs(1),
    Duration::from_secs(3),
    Duration::from_secs(7),
];

/// When an unanswered dial is given up, counted from its start.
pub const GIVE_UP_AFTER: Duration = Duration::from_secs(15);

/// A pre-shared key, mixed in by `psk2`.
pub type Psk = [u8; 32];

/// The PSK used when the application has none: 32 zero bytes.
pub const NO_PSK: Psk = [0; 32];

/// The source of randomness the core draws ephemeral keys and indices from.
///
/// The driver implements it over the operating system's generator or the
/// microcontroller's hardware generator. It must be a cryptographically secure
/// generator: an ephemeral key drawn from anything less breaks the handshake.
pub trait Entropy {
    /// Fills `dest` with random bytes.
    fn fill(&mut self, dest: &mut [u8]);
}

/// Why a handshake was refused, carried in the response.
///
/// `0x0001`–`0x00FF` belong to the library, `0x0100`–`0xFFFF` to the
/// application; `0x0000` is not a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RefusalCode(NonZeroU16);

impl RefusalCode {
    /// The responder holds as many pending handshakes as it can.
    pub const CAPACITY_EXHAUSTED: Self = Self(NonZeroU16::MIN);

    /// The responder is shedding load.
    pub const BUSY: Self = match NonZeroU16::new(0x0002) {
        Some(code) => Self(code),
        None => Self(NonZeroU16::MIN),
    };

    /// An application's own code, `0x0100` to `0xFFFF`.
    #[must_use]
    pub const fn application(code: u16) -> Option<Self> {
        if code < 0x0100 {
            return None;
        }
        match NonZeroU16::new(code) {
            Some(code) => Some(Self(code)),
            None => None,
        }
    }

    /// The code a response carries, or `None` for `0x0000`.
    #[must_use]
    pub const fn from_wire(code: u16) -> Option<Self> {
        match NonZeroU16::new(code) {
            Some(code) => Some(Self(code)),
            None => None,
        }
    }

    /// The code as a number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }

    /// Whether the code belongs to the application.
    #[must_use]
    pub const fn is_application(self) -> bool {
        self.0.get() >= 0x0100
    }
}

/// What an application decides about an initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Admit it, optionally under the PSK held for it.
    Accept {
        /// The PSK held for this peer, if any.
        psk: Option<Psk>,
    },
    /// Refuse it with a code, optionally under the PSK held for it, so that an
    /// initiator configured with that PSK can read the refusal.
    Refuse {
        /// Why.
        code: RefusalCode,
        /// The PSK held for this peer, if any.
        psk: Option<Psk>,
    },
}

/// The application's policy towards peers: whom to admit, and under which PSK
/// to dial whom.
pub trait Admission {
    /// Decides about the initiator `peer` asking for `context`.
    fn admit(&mut self, peer: &PeerId, context: &[u8]) -> Decision;

    /// The PSK to dial `peer` in `context` under, if the application holds one.
    /// None by default.
    fn psk(&mut self, _peer: &PeerId, _context: &[u8]) -> Option<Psk> {
        None
    }
}

/// A context longer than [`MAX_CONTEXT_LEN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextTooLong {
    /// The length asked for.
    pub len: usize,
}

impl core::fmt::Display for ContextTooLong {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "context is {} bytes, at most {MAX_CONTEXT_LEN} allowed",
            self.len
        )
    }
}

impl core::error::Error for ContextTooLong {}

/// An application-chosen string a handshake is bound to, through the prologue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Context {
    bytes: [u8; MAX_CONTEXT_LEN],
    len: u8,
}

/// The prologue: `"convesso" || 0x01 || len || context`.
const PROLOGUE_MAX: usize = 8 + 1 + 1 + MAX_CONTEXT_LEN;

impl Context {
    /// A context, at most [`MAX_CONTEXT_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`ContextTooLong`] beyond that.
    pub fn new(context: &[u8]) -> Result<Self, ContextTooLong> {
        let too_long = ContextTooLong { len: context.len() };
        let len = u8::try_from(context.len()).map_err(|_| too_long)?;
        let mut bytes = [0u8; MAX_CONTEXT_LEN];
        bytes
            .get_mut(..context.len())
            .ok_or(too_long)?
            .copy_from_slice(context);
        Ok(Self { bytes, len })
    }

    /// The context's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }

    /// Writes the prologue for this context into `out`, returning it.
    fn prologue<'a>(&self, out: &'a mut [u8; PROLOGUE_MAX]) -> &'a [u8] {
        let context = self.as_bytes();
        out[..8].copy_from_slice(b"convesso");
        out[8] = crate::wire::Version::V1.get();
        out[9] = self.len;
        let end = 10 + context.len();
        if let Some(field) = out.get_mut(10..end) {
            field.copy_from_slice(context);
        }
        out.get(..end).unwrap_or_default()
    }
}

/// The value both sides of a handshake share and neither chooses: the Noise
/// handshake hash.
pub type ChannelBinding = [u8; 32];
