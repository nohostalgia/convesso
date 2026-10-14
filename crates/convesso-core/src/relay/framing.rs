//! A TCP link to a relay: the preamble, then length-prefixed packets.
//!
//! ```text
//! 63 6f 6e 76 65 73 73 6f 01         "convesso", framing version 1; once each way
//! len (2, LE) | packet (len bytes)   len 1..=1500
//! 00 00                              the keep-alive: it carries nothing
//! ```
//!
//! The preamble's first byte is never `0x16`, the first byte of a TLS record,
//! so a relay can serve plain and TLS-wrapped links on one port.
//!
//! [`Deframer`] reads a stream in pieces of any size, with a fixed buffer of
//! one packet and no allocation. Anything but the preamble, or a length above
//! [`MAX_FRAME`], closes the link: a stream that has lost its framing cannot
//! find it again.

/// What every TCP link starts with, in each direction.
pub const PREAMBLE: [u8; 9] = *b"convesso\x01";

/// The longest packet a TCP link carries.
pub const MAX_FRAME: usize = 1500;

/// The keep-alive: a length of 0.
pub const KEEPALIVE: [u8; 2] = [0, 0];

/// Why a link must be closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// The stream did not start with [`PREAMBLE`].
    WrongPreamble,
    /// A length above [`MAX_FRAME`].
    Length(u16),
}

/// What a piece of stream produced.
#[derive(Debug, PartialEq, Eq)]
pub enum Deframed<'a> {
    /// Nothing yet: the input was consumed, and more is needed.
    NeedMore,
    /// A keep-alive.
    KeepAlive,
    /// A packet, valid until the next call.
    Packet(&'a [u8]),
    /// The link must be closed; nothing more will be read from it.
    Closed(CloseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Preamble(usize),
    Length { have: usize, low: u8 },
    Body { len: usize, have: usize },
    Closed(CloseReason),
}

/// Reads the packets of one direction of a TCP link.
#[derive(Debug, Clone)]
pub struct Deframer {
    state: State,
    buffer: [u8; MAX_FRAME],
}

impl Default for Deframer {
    fn default() -> Self {
        Self {
            state: State::Preamble(0),
            buffer: [0; MAX_FRAME],
        }
    }
}

impl Deframer {
    /// Reads from `input`, returning how many bytes it consumed and what they
    /// produced. Call again with the rest of the input while it produces
    /// something other than [`Deframed::NeedMore`] and input remains.
    pub fn feed(&mut self, input: &[u8]) -> (usize, Deframed<'_>) {
        let mut used = 0;
        loop {
            match self.state {
                State::Closed(reason) => return (used, Deframed::Closed(reason)),
                State::Preamble(have) => {
                    let Some(&byte) = input.get(used) else {
                        return (used, Deframed::NeedMore);
                    };
                    used += 1;
                    if PREAMBLE.get(have) != Some(&byte) {
                        self.state = State::Closed(CloseReason::WrongPreamble);
                    } else if have + 1 == PREAMBLE.len() {
                        self.state = State::Length { have: 0, low: 0 };
                    } else {
                        self.state = State::Preamble(have + 1);
                    }
                }
                State::Length { have, low } => {
                    let Some(&byte) = input.get(used) else {
                        return (used, Deframed::NeedMore);
                    };
                    used += 1;
                    if have == 0 {
                        self.state = State::Length { have: 1, low: byte };
                        continue;
                    }
                    let len = u16::from_le_bytes([low, byte]);
                    match usize::from(len) {
                        0 => {
                            self.state = State::Length { have: 0, low: 0 };
                            return (used, Deframed::KeepAlive);
                        }
                        n if n > MAX_FRAME => {
                            self.state = State::Closed(CloseReason::Length(len));
                        }
                        n => self.state = State::Body { len: n, have: 0 },
                    }
                }
                State::Body { len, have } => {
                    let rest = input.get(used..).unwrap_or_default();
                    let take = rest.len().min(len - have);
                    if let (Some(field), Some(bytes)) =
                        (self.buffer.get_mut(have..have + take), rest.get(..take))
                    {
                        field.copy_from_slice(bytes);
                    }
                    used += take;
                    if have + take < len {
                        self.state = State::Body {
                            len,
                            have: have + take,
                        };
                        return (used, Deframed::NeedMore);
                    }
                    self.state = State::Length { have: 0, low: 0 };
                    return (
                        used,
                        Deframed::Packet(self.buffer.get(..len).unwrap_or_default()),
                    );
                }
            }
        }
    }

    /// Whether the link must be closed.
    #[must_use]
    pub const fn closed(&self) -> Option<CloseReason> {
        match self.state {
            State::Closed(reason) => Some(reason),
            _ => None,
        }
    }
}

/// Writes `packet` as a frame into `out`, returning the frame's length, or
/// `None` when the packet is empty, longer than [`MAX_FRAME`], or does not
/// fit.
#[must_use]
pub fn frame(packet: &[u8], out: &mut [u8]) -> Option<usize> {
    if packet.is_empty() || packet.len() > MAX_FRAME {
        return None;
    }
    let len = u16::try_from(packet.len()).ok()?;
    let out = out.get_mut(..2 + packet.len())?;
    let (prefix, body) = out.split_at_mut(2);
    prefix.copy_from_slice(&len.to_le_bytes());
    body.copy_from_slice(packet);
    Some(2 + packet.len())
}
