//! Version 1's handshake messages, byte for byte (`PROTOCOL.md §3`).
//!
//! ```text
//! first contact, 134 bytes:
//!   0x01 | 0x01 | initiator index (4, LE) | e (32) | s, encrypted (48)
//!        | empty payload, encrypted (16) | mac1 (16) | mac2 (16)
//! response, 61 bytes:
//!   0x01 | 0x02 | responder index (4, LE) | initiator index (4, LE) | e (32)
//!        | decision, encrypted (3 + 16)
//! decision: 00 00 00 accept | 01 code-lo code-hi refuse
//! first contact with a payload, 134 + n bytes, 1 <= n <= 1200:
//!   0x01 | 0x05 | initiator index (4, LE) | e (32) | s, encrypted (48)
//!        | payload, encrypted (n + 16) | mac1 (16) | mac2 (16)
//! ```
//!
//! Decoders check lengths and header bytes only; authentication is the Noise
//! layer's. None panics or allocates on any input.

use super::{FIRST_CONTACT_LEN, MAX_PAYLOAD, RESPONSE_LEN, RefusalCode};
use crate::wire::{MAC_LEN, Mac1Key};

/// Byte 1 of a first contact.
pub const TYPE_INITIATION: u8 = 0x01;
/// Byte 1 of a response.
pub const TYPE_RESPONSE: u8 = 0x02;
/// Byte 1 of a first contact with a payload.
pub const TYPE_INITIATION_PAYLOAD: u8 = 0x05;
/// Byte 1 of a first contact that renews keys the initiator still holds: the
/// 134 bytes of [`TYPE_INITIATION`], with no payload.
pub const TYPE_RENEWAL: u8 = 0x06;

/// Whether byte 1 of a version 1 packet names a first contact: an opening,
/// one with a payload, or a renewal.
#[must_use]
pub const fn is_first_contact_type(kind: u8) -> bool {
    matches!(
        kind,
        TYPE_INITIATION | TYPE_INITIATION_PAYLOAD | TYPE_RENEWAL
    )
}

/// The Noise part of a first contact: `e`, `s` encrypted, empty payload encrypted.
pub const INITIATION_NOISE_LEN: usize = 32 + 48 + 16;
/// The Noise part of a response: `e`, the decision encrypted.
pub const RESPONSE_NOISE_LEN: usize = 32 + DECISION_LEN + 16;
/// The plaintext decision.
pub const DECISION_LEN: usize = 3;

const VERSION: u8 = 0x01;
const INITIATION_NOISE_AT: usize = 6;
const RESPONSE_NOISE_AT: usize = 10;

/// Why bytes are not a version 1 handshake message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// Byte 0 is not `0x01`.
    WrongVersion,
    /// Byte 1 is not the expected message type.
    WrongType,
    /// The length is not the message's.
    WrongLength {
        /// The message's length.
        expected: usize,
        /// The length received.
        actual: usize,
    },
}

/// Why a decrypted decision is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionError {
    /// Not 3 bytes.
    WrongLength,
    /// The status byte is none of `0x00`, `0x01` and `0x02`.
    UnknownStatus,
    /// Acceptance, or acceptance as a new session, with a non-zero code.
    AcceptWithCode,
    /// Refusal with code `0x0000`.
    RefuseWithoutCode,
}

/// A decision as it travels: acceptance, or refusal with its code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireDecision {
    /// `00 00 00`.
    Accept,
    /// `02 00 00`: a renewal accepted as a new session, since the responder
    /// holds no live keys to renew.
    AcceptAsNew,
    /// `01` and the code, little-endian.
    Refuse(RefusalCode),
}

/// A first contact, its header checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstContact<'a> {
    /// Whether it renews keys the initiator holds ([`TYPE_RENEWAL`]), rather
    /// than open a session ([`TYPE_INITIATION`]).
    pub renewal: bool,
    /// The initiator's index.
    pub initiator_index: u32,
    /// `e`, `s` encrypted and the empty payload encrypted.
    pub noise: &'a [u8; INITIATION_NOISE_LEN],
}

/// A first contact with a payload, its header and length checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadFirstContact<'a> {
    /// The initiator's index.
    pub initiator_index: u32,
    /// `e`, `s` encrypted and the payload encrypted: `INITIATION_NOISE_LEN + n`
    /// bytes, for a payload of `n`.
    pub noise: &'a [u8],
}

impl PayloadFirstContact<'_> {
    /// The payload's plaintext length.
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.noise.len() - INITIATION_NOISE_LEN
    }
}

/// A response, its header checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response<'a> {
    /// The responder's index.
    pub responder_index: u32,
    /// The initiator's index it answers.
    pub initiator_index: u32,
    /// `e` and the decision encrypted.
    pub noise: &'a [u8; RESPONSE_NOISE_LEN],
}

fn check(packet: &[u8], kind: u8, expected: usize) -> Result<(), MessageError> {
    match packet {
        [VERSION, k, ..] if *k == kind => {
            if packet.len() == expected {
                Ok(())
            } else {
                Err(MessageError::WrongLength {
                    expected,
                    actual: packet.len(),
                })
            }
        }
        [VERSION, ..] => Err(MessageError::WrongType),
        _ => Err(MessageError::WrongVersion),
    }
}

fn u32_at(packet: &[u8], at: usize) -> Option<u32> {
    packet
        .get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
}

/// Reads a first contact's header.
///
/// # Errors
///
/// A [`MessageError`] when it is not exactly a version 1 first contact.
pub fn parse_first_contact(packet: &[u8]) -> Result<FirstContact<'_>, MessageError> {
    let renewal = packet.get(1) == Some(&TYPE_RENEWAL);
    check(
        packet,
        if renewal {
            TYPE_RENEWAL
        } else {
            TYPE_INITIATION
        },
        FIRST_CONTACT_LEN,
    )?;
    let length = MessageError::WrongLength {
        expected: FIRST_CONTACT_LEN,
        actual: packet.len(),
    };
    Ok(FirstContact {
        renewal,
        initiator_index: u32_at(packet, 2).ok_or(length)?,
        noise: packet
            .get(INITIATION_NOISE_AT..INITIATION_NOISE_AT + INITIATION_NOISE_LEN)
            .and_then(|n| n.try_into().ok())
            .ok_or(length)?,
    })
}

/// Reads the header of a first contact with a payload, checking its length,
/// `135 ..= 1334` bytes, before anything else.
///
/// # Errors
///
/// A [`MessageError`] when it is not a version 1 first contact with a payload
/// of 1 to [`MAX_PAYLOAD`] bytes; `expected` then names the nearest valid length.
pub fn parse_payload_first_contact(packet: &[u8]) -> Result<PayloadFirstContact<'_>, MessageError> {
    match packet {
        [VERSION, TYPE_INITIATION_PAYLOAD, ..] => {}
        [VERSION, ..] => return Err(MessageError::WrongType),
        _ => return Err(MessageError::WrongVersion),
    }
    let shortest = FIRST_CONTACT_LEN + 1;
    let longest = FIRST_CONTACT_LEN + MAX_PAYLOAD;
    if packet.len() < shortest || packet.len() > longest {
        return Err(MessageError::WrongLength {
            expected: packet.len().clamp(shortest, longest),
            actual: packet.len(),
        });
    }
    let length = MessageError::WrongLength {
        expected: shortest,
        actual: packet.len(),
    };
    let noise_end = packet.len() - 2 * MAC_LEN;
    Ok(PayloadFirstContact {
        initiator_index: u32_at(packet, 2).ok_or(length)?,
        noise: packet.get(INITIATION_NOISE_AT..noise_end).ok_or(length)?,
    })
}

/// Reads a response's header.
///
/// # Errors
///
/// A [`MessageError`] when it is not exactly a version 1 response.
pub fn parse_response(packet: &[u8]) -> Result<Response<'_>, MessageError> {
    check(packet, TYPE_RESPONSE, RESPONSE_LEN)?;
    let length = MessageError::WrongLength {
        expected: RESPONSE_LEN,
        actual: packet.len(),
    };
    Ok(Response {
        responder_index: u32_at(packet, 2).ok_or(length)?,
        initiator_index: u32_at(packet, 6).ok_or(length)?,
        noise: packet
            .get(RESPONSE_NOISE_AT..RESPONSE_NOISE_AT + RESPONSE_NOISE_LEN)
            .and_then(|n| n.try_into().ok())
            .ok_or(length)?,
    })
}

/// Reads a decrypted decision.
///
/// # Errors
///
/// A [`DecisionError`] for anything but `00 00 00` and `01` with a non-zero code.
pub fn decode_decision(plaintext: &[u8]) -> Result<WireDecision, DecisionError> {
    match plaintext {
        [0x00, 0x00, 0x00] => Ok(WireDecision::Accept),
        [0x02, 0x00, 0x00] => Ok(WireDecision::AcceptAsNew),
        [0x00 | 0x02, _, _] => Err(DecisionError::AcceptWithCode),
        [0x01, lo, hi] => RefusalCode::from_wire(u16::from_le_bytes([*lo, *hi]))
            .map(WireDecision::Refuse)
            .ok_or(DecisionError::RefuseWithoutCode),
        [_, _, _] => Err(DecisionError::UnknownStatus),
        _ => Err(DecisionError::WrongLength),
    }
}

/// The 3 bytes of a decision.
#[must_use]
pub fn encode_decision(decision: WireDecision) -> [u8; DECISION_LEN] {
    match decision {
        WireDecision::Accept => [0x00, 0x00, 0x00],
        WireDecision::AcceptAsNew => [0x02, 0x00, 0x00],
        WireDecision::Refuse(code) => {
            let [lo, hi] = code.get().to_le_bytes();
            [0x01, lo, hi]
        }
    }
}

/// Writes into `out` a first contact: header, Noise part, `mac1` under the
/// responder's key, and `mac2` under `cookie` when the initiator holds one,
/// zeros otherwise. The Noise part is
/// `INITIATION_NOISE_LEN + n` bytes: type `0x01` for `n = 0`, type `0x05` for
/// a payload, and type `0x06` for a `renewal`, which carries none. Returns its
/// length, or `None` when `out` is too small, the payload longer than
/// [`MAX_PAYLOAD`], or a renewal given one.
pub(crate) fn write_first_contact_into(
    out: &mut [u8],
    initiator_index: u32,
    noise: &[u8],
    renewal: bool,
    key: &Mac1Key,
    cookie: Option<&crate::dos::Cookie>,
) -> Option<usize> {
    let payload = noise.len().checked_sub(INITIATION_NOISE_LEN)?;
    if payload > MAX_PAYLOAD || (renewal && payload > 0) {
        return None;
    }
    let len = FIRST_CONTACT_LEN + payload;
    let packet = out.get_mut(..len)?;
    let kind = match (renewal, payload) {
        (true, _) => TYPE_RENEWAL,
        (false, 0) => TYPE_INITIATION,
        (false, _) => TYPE_INITIATION_PAYLOAD,
    };
    let mut head = [0u8; INITIATION_NOISE_AT];
    head[0] = VERSION;
    head[1] = kind;
    head[2..].copy_from_slice(&initiator_index.to_le_bytes());
    let (header, rest) = packet.split_at_mut(INITIATION_NOISE_AT);
    header.copy_from_slice(&head);
    rest.get_mut(..noise.len())?.copy_from_slice(noise);
    let (covered, macs) = packet.split_at_mut(len - 2 * MAC_LEN);
    let mac1 = key.compute(covered);
    let (mac1_field, mac2_field) = macs.split_at_mut(MAC_LEN);
    mac1_field.copy_from_slice(&mac1);
    mac2_field.fill(0);
    if let Some(cookie) = cookie {
        let (covered, mac2_field) = packet.split_at_mut(len - MAC_LEN);
        mac2_field.copy_from_slice(&crate::dos::mac2(cookie, covered));
    }
    Some(len)
}

/// Writes a response: header and Noise part.
pub(crate) fn write_response(
    responder_index: u32,
    initiator_index: u32,
    noise: &[u8; RESPONSE_NOISE_LEN],
) -> [u8; RESPONSE_LEN] {
    let mut packet = [0u8; RESPONSE_LEN];
    packet[0] = VERSION;
    packet[1] = TYPE_RESPONSE;
    packet[2..6].copy_from_slice(&responder_index.to_le_bytes());
    packet[6..10].copy_from_slice(&initiator_index.to_le_bytes());
    packet[RESPONSE_NOISE_AT..].copy_from_slice(noise);
    packet
}
