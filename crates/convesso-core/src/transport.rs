//! Transport packets (`PROTOCOL.md §5`).
//!
//! ```text
//! 0x01 | 0x04 | receiver index (4, LE) | counter (8, LE) | AEAD( inner type (1) | data ) | tag (16)
//! ```
//!
//! Datagrams arrive late, lost or twice, so the counter travels with each
//! packet and is the nonce (4 zero bytes, then the counter, little-endian, as
//! Noise lays out ChaChaPoly's nonce), instead of Noise's implicit counter. The
//! 14 header bytes are the associated data, so the version, type, index and
//! counter are all authenticated. A receiver accepts each counter at most once,
//! through a sliding window ([`ReplayWindow`], RFC 6479).
//!
//! Opening happens in place, and nothing here allocates or panics on input.

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

use crate::handshake::messages::MessageError;

/// Byte 1 of a transport packet.
pub const TYPE_TRANSPORT: u8 = 0x04;

/// The header: version, type, index, counter.
pub const HEADER_LEN: usize = 14;

/// The AEAD tag.
pub const TAG_LEN: usize = 16;

/// How much longer a packet is than its data: header, inner type, tag.
pub const OVERHEAD: usize = HEADER_LEN + 1 + TAG_LEN;

/// Counters run from 0 to `MAX_COUNTER - 1` under one key pair; a key pair
/// that reaches it is used for nothing more. Time (180 s) always comes first;
/// this is the backstop.
pub const MAX_COUNTER: u64 = 1 << 60;

/// The inner types (the first decrypted byte).
pub mod inner {
    /// No data: keeps a path or confirms a handshake.
    pub const KEEPALIVE: u8 = 0x00;
    /// The application's data.
    pub const DATAGRAM: u8 = 0x01;
    /// A close, with a refusal code as a little-endian `u16`.
    pub const CLOSE: u8 = 0x02;
    /// This endpoint's candidate addresses (`crate::paths`).
    pub const CANDIDATES: u8 = 0x03;
    /// A probe of a direct path, with its nonce (`crate::paths`).
    pub const PROBE: u8 = 0x04;
    /// A probe's answer: its nonce and the address it came from (`crate::paths`).
    pub const ANSWER: u8 = 0x05;
    /// A stream data frame (`PROTOCOL.md §8`), carried unread.
    pub const STREAM_DATA: u8 = 0x06;
    /// A stream acknowledgement (`PROTOCOL.md §8`), carried unread.
    pub const STREAM_ACK: u8 = 0x07;
}

/// Why a transport packet could not be sealed or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// Not a version 1 transport packet of at least [`OVERHEAD`] bytes.
    Malformed(MessageError),
    /// It did not authenticate under the key.
    Decrypt,
    /// The counter is at or beyond [`MAX_COUNTER`].
    CounterExhausted,
    /// The output buffer is too small for the packet.
    BufferTooSmall {
        /// The length needed.
        needed: usize,
    },
}

/// A transport packet's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The receiver's index for the session.
    pub receiver_index: u32,
    /// The counter, which is the nonce.
    pub counter: u64,
}

/// Reads a transport packet's header without decrypting anything.
///
/// # Errors
///
/// [`MessageError`] when it is not a version 1 transport packet of at least
/// [`OVERHEAD`] bytes.
pub fn parse_header(packet: &[u8]) -> Result<Header, MessageError> {
    match packet {
        [0x01, TYPE_TRANSPORT, ..] if packet.len() >= OVERHEAD => {}
        [0x01, TYPE_TRANSPORT, ..] => {
            return Err(MessageError::WrongLength {
                expected: OVERHEAD,
                actual: packet.len(),
            });
        }
        [0x01, ..] => return Err(MessageError::WrongType),
        _ => return Err(MessageError::WrongVersion),
    }
    let short = MessageError::WrongLength {
        expected: OVERHEAD,
        actual: packet.len(),
    };
    Ok(Header {
        receiver_index: packet
            .get(2..6)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(short)?,
        counter: packet
            .get(6..14)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(short)?,
    })
}

fn nonce(counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(nonce)
}

/// Seals `inner_type || data` into `out` under `key`, returning the packet's
/// length.
///
/// # Errors
///
/// [`TransportError::CounterExhausted`] for a counter at or beyond
/// [`MAX_COUNTER`], [`TransportError::BufferTooSmall`] when `out` cannot hold
/// the packet.
pub fn seal(
    key: &[u8; 32],
    receiver_index: u32,
    counter: u64,
    inner_type: u8,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, TransportError> {
    let len = OVERHEAD + data.len();
    out.get_mut(HEADER_LEN + 1..HEADER_LEN + 1 + data.len())
        .ok_or(TransportError::BufferTooSmall { needed: len })?
        .copy_from_slice(data);
    seal_in_place(key, receiver_index, counter, inner_type, data.len(), out)
}

/// Where [`seal_in_place`] expects the data: after the header and the inner type.
pub const DATA_AT: usize = HEADER_LEN + 1;

/// [`seal`], with the `data_len` bytes of data already in `out` at
/// [`DATA_AT`]: what lets a caller build the data around a packet it already
/// holds, without a second buffer.
///
/// # Errors
///
/// As [`seal`].
pub fn seal_in_place(
    key: &[u8; 32],
    receiver_index: u32,
    counter: u64,
    inner_type: u8,
    data_len: usize,
    out: &mut [u8],
) -> Result<usize, TransportError> {
    if counter >= MAX_COUNTER {
        return Err(TransportError::CounterExhausted);
    }
    let len = OVERHEAD + data_len;
    let out = out
        .get_mut(..len)
        .ok_or(TransportError::BufferTooSmall { needed: len })?;
    let mut fields = [0u8; HEADER_LEN];
    fields[0] = 0x01;
    fields[1] = TYPE_TRANSPORT;
    fields[2..6].copy_from_slice(&receiver_index.to_le_bytes());
    fields[6..].copy_from_slice(&counter.to_le_bytes());
    let (header, rest) = out.split_at_mut(HEADER_LEN);
    header.copy_from_slice(&fields);
    let (body, tag_out) = rest.split_at_mut(1 + data_len);
    let (inner, _) = body.split_at_mut(1);
    inner.copy_from_slice(&[inner_type]);
    let tag = ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt_inout_detached(&nonce(counter), header, body.into())
        .map_err(|_| TransportError::BufferTooSmall { needed: len })?;
    tag_out.copy_from_slice(&tag);
    Ok(len)
}

/// What an opened packet carries.
#[derive(Debug, PartialEq, Eq)]
pub struct Opened<'a> {
    /// The header, authenticated.
    pub header: Header,
    /// The inner type.
    pub inner_type: u8,
    /// The data, decrypted in place in the packet's buffer.
    pub data: &'a [u8],
}

/// Opens a packet in place under `key`. Says nothing about replay: the caller
/// checks the counter against its window before trusting it, and marks it
/// after this succeeds.
///
/// # Errors
///
/// [`TransportError::Malformed`] for a packet that is not a transport packet,
/// [`TransportError::CounterExhausted`] for a counter at or beyond
/// [`MAX_COUNTER`], [`TransportError::Decrypt`] when it does not authenticate.
pub fn open<'a>(key: &[u8; 32], packet: &'a mut [u8]) -> Result<Opened<'a>, TransportError> {
    let header = parse_header(packet).map_err(TransportError::Malformed)?;
    if header.counter >= MAX_COUNTER {
        return Err(TransportError::CounterExhausted);
    }
    let body_len = packet.len() - HEADER_LEN - TAG_LEN;
    let (head, rest) = packet.split_at_mut(HEADER_LEN);
    let (body, tag) = rest.split_at_mut(body_len);
    let tag = Tag::try_from(&*tag).map_err(|_| TransportError::Decrypt)?;
    ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt_inout_detached(&nonce(header.counter), head, body.into(), &tag)
        .map_err(|_| TransportError::Decrypt)?;
    let (inner, data) = body.split_first().ok_or(TransportError::Decrypt)?;
    Ok(Opened {
        header,
        inner_type: *inner,
        data,
    })
}

/// A receiver's memory of the counters it accepted under one key pair.
pub trait ReplayWindow: Default {
    /// How far below the highest accepted counter a packet may still arrive.
    const WINDOW: u64;

    /// Whether `counter` may be accepted: above the highest, or within the
    /// window and not yet accepted.
    fn may_accept(&self, counter: u64) -> bool;

    /// Records `counter` as accepted. Call only after the packet opened.
    fn accept(&mut self, counter: u64);

    /// The highest counter accepted, if any.
    fn highest(&self) -> Option<u64>;
}

/// RFC 6479's window over `WORDS` words of 64 bits, guaranteeing a window of
/// `(WORDS - 1) * 64` counters: the extra word is the one the ring advances
/// into, so that sliding forward never clears a counter still in the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window<const WORDS: usize> {
    bits: [u64; WORDS],
    highest: Option<u64>,
}

impl<const WORDS: usize> Default for Window<WORDS> {
    fn default() -> Self {
        Self {
            bits: [0; WORDS],
            highest: None,
        }
    }
}

impl<const WORDS: usize> Window<WORDS> {
    fn locate(counter: u64) -> (usize, u64) {
        let word = usize::try_from((counter / 64) % (WORDS as u64)).unwrap_or(0);
        (word, 1u64 << (counter % 64))
    }
}

impl<const WORDS: usize> ReplayWindow for Window<WORDS> {
    const WINDOW: u64 = (WORDS as u64 - 1) * 64;

    fn may_accept(&self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if counter > highest {
            return true;
        }
        if highest - counter >= Self::WINDOW {
            return false;
        }
        let (word, bit) = Self::locate(counter);
        self.bits.get(word).is_some_and(|w| w & bit == 0)
    }

    fn accept(&mut self, counter: u64) {
        match self.highest {
            None => {
                self.bits = [0; WORDS];
                self.highest = Some(counter);
            }
            Some(highest) if counter > highest => {
                // Clear every word the window slides into, up to WORDS of them.
                let from = highest / 64;
                let to = counter / 64;
                let steps = (to - from).min(WORDS as u64);
                for step in 1..=steps {
                    let word = usize::try_from((from + step) % (WORDS as u64)).unwrap_or(0);
                    if let Some(w) = self.bits.get_mut(word) {
                        *w = 0;
                    }
                }
                self.highest = Some(counter);
            }
            Some(_) => {}
        }
        let (word, bit) = Self::locate(counter);
        if let Some(w) = self.bits.get_mut(word) {
            *w |= bit;
        }
    }

    fn highest(&self) -> Option<u64> {
        self.highest
    }
}

#[cfg(test)]
mod tests;
