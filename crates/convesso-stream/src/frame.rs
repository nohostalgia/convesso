//! The two stream frames, byte for byte (`PROTOCOL.md §8`).
//!
//! ```text
//! 0x06 data   incarnation (8) | sequence (4, LE) | flags (1: FIRST, LAST, START)
//!             | [message length (4, LE), with FIRST] | 1 to 1,332 bytes
//! 0x07 ack    incarnation (8) | flags (1: RESET) | cumulative (4, LE) | window (4, LE)
//!             | maximum message (4, LE) | count (1, 0 to 4) | count x (start (4), end (4))
//! ```
//!
//! Decoders refuse a frame that breaks any rule, whole; encoders refuse to
//! write one. Sequences compare in serial-number arithmetic over 32 bits
//! (RFC 1982): see [`after`].

/// The length of an incarnation.
pub const INCARNATION_LEN: usize = 8;

/// A channel's incarnation: 8 random bytes chosen when the channel starts.
pub type Incarnation = [u8; INCARNATION_LEN];

/// The most bytes a data frame carries: so that a FIRST frame's packet is
/// 1,380 bytes, the longest the relay carries.
pub const MAX_FRAGMENT: usize = 1332;

/// The most ranges of selective acknowledgement in one acknowledgement.
pub const MAX_RANGES: usize = 4;

/// A data frame's fixed header: incarnation, sequence, flags.
pub const DATA_HEADER_LEN: usize = INCARNATION_LEN + 4 + 1;

/// The longest data frame: a FIRST frame with its length and a full fragment.
pub const MAX_DATA_LEN: usize = DATA_HEADER_LEN + 4 + MAX_FRAGMENT;

/// An acknowledgement without ranges.
pub const ACK_HEADER_LEN: usize = INCARNATION_LEN + 1 + 4 + 4 + 4 + 1;

/// The longest acknowledgement.
pub const MAX_ACK_LEN: usize = ACK_HEADER_LEN + MAX_RANGES * 8;

const FIRST: u8 = 0x01;
const LAST: u8 = 0x02;
const START: u8 = 0x04;
const RESET: u8 = 0x01;

/// Why a frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// It breaks a rule of the format.
    Malformed,
    /// The output buffer is too small.
    BufferTooSmall,
}

/// Whether sequence `a` comes after `b`, in serial-number arithmetic over 32
/// bits (RFC 1982). Sequences 2^31 apart are not ordered, and come after
/// nothing; no window ever spans that far.
#[must_use]
pub const fn after(a: u32, b: u32) -> bool {
    let distance = a.wrapping_sub(b);
    distance != 0 && distance < 1 << 31
}

/// A data frame (inner type `0x06`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Data<'a> {
    /// The sender's channel incarnation.
    pub incarnation: Incarnation,
    /// The fragment's number.
    pub sequence: u32,
    /// With FIRST: the message's length, at least 1.
    pub length: Option<u32>,
    /// LAST: the message's last fragment.
    pub last: bool,
    /// START: the sender has had no acknowledgement in this incarnation.
    pub start: bool,
    /// The fragment's bytes: 1 to [`MAX_FRAGMENT`].
    pub bytes: &'a [u8],
}

impl<'a> Data<'a> {
    /// Decodes a data frame.
    ///
    /// # Errors
    ///
    /// [`FrameError::Malformed`] for a frame that breaks a rule.
    pub fn decode(frame: &'a [u8]) -> Result<Self, FrameError> {
        let incarnation = take::<INCARNATION_LEN>(frame, 0)?;
        let sequence = u32::from_le_bytes(take(frame, INCARNATION_LEN)?);
        let [flags] = take::<1>(frame, INCARNATION_LEN + 4)?;
        if flags & !(FIRST | LAST | START) != 0 {
            return Err(FrameError::Malformed);
        }
        let (length, at) = if flags & FIRST == 0 {
            (None, DATA_HEADER_LEN)
        } else {
            let length = u32::from_le_bytes(take(frame, DATA_HEADER_LEN)?);
            if length == 0 {
                return Err(FrameError::Malformed);
            }
            (Some(length), DATA_HEADER_LEN + 4)
        };
        let bytes = frame.get(at..).ok_or(FrameError::Malformed)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAGMENT {
            return Err(FrameError::Malformed);
        }
        Ok(Self {
            incarnation,
            sequence,
            length,
            last: flags & LAST != 0,
            start: flags & START != 0,
            bytes,
        })
    }

    /// The frame's length once encoded.
    #[must_use]
    pub const fn len(&self) -> usize {
        DATA_HEADER_LEN + if self.length.is_some() { 4 } else { 0 } + self.bytes.len()
    }

    /// Never: a data frame always carries at least one byte.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Encodes the frame into `out`; returns its length.
    ///
    /// # Errors
    ///
    /// [`FrameError::Malformed`] for a frame that would break a rule,
    /// [`FrameError::BufferTooSmall`] when `out` cannot hold it.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, FrameError> {
        let header = encode_data_header(
            &self.incarnation,
            self.sequence,
            self.length,
            self.last,
            self.start,
            self.bytes.len(),
            out,
        )?;
        let body = out
            .get_mut(header..header + self.bytes.len())
            .ok_or(FrameError::BufferTooSmall)?;
        body.copy_from_slice(self.bytes);
        Ok(header + self.bytes.len())
    }
}

/// Writes the header of a data frame that carries `payload` bytes, and checks
/// that `out` has room for them after it; returns the header's length. The
/// caller writes the bytes after the header.
///
/// # Errors
///
/// [`FrameError::Malformed`] for a frame that would break a rule,
/// [`FrameError::BufferTooSmall`] when `out` cannot hold the whole frame.
pub fn encode_data_header(
    incarnation: &Incarnation,
    sequence: u32,
    length: Option<u32>,
    last: bool,
    start: bool,
    payload: usize,
    out: &mut [u8],
) -> Result<usize, FrameError> {
    if payload == 0 || payload > MAX_FRAGMENT || length == Some(0) {
        return Err(FrameError::Malformed);
    }
    let header = DATA_HEADER_LEN + if length.is_some() { 4 } else { 0 };
    let out = out
        .get_mut(..header + payload)
        .ok_or(FrameError::BufferTooSmall)?;
    let mut flags = 0;
    if length.is_some() {
        flags |= FIRST;
    }
    if last {
        flags |= LAST;
    }
    if start {
        flags |= START;
    }
    let mut writer = Writer { out, at: 0 };
    writer.put(incarnation);
    writer.put(&sequence.to_le_bytes());
    writer.put(&[flags]);
    if let Some(length) = length {
        writer.put(&length.to_le_bytes());
    }
    Ok(header)
}

/// A range of fragments received beyond the cumulative point: from `start`,
/// up to `end` excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Range {
    /// The first fragment of the range.
    pub start: u32,
    /// The fragment after the last.
    pub end: u32,
}

/// An acknowledgement (inner type `0x07`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    /// The incarnation acknowledged: the peer's sending one.
    pub incarnation: Incarnation,
    /// RESET: this channel is reset here.
    pub reset: bool,
    /// The next sequence expected; every one before it was received.
    pub cumulative: u32,
    /// The bytes the receiver can still take beyond the cumulative point.
    pub window: u32,
    /// The largest message the receiver accepts.
    pub max_message: u32,
    ranges: [Range; MAX_RANGES],
    count: u8,
}

impl Ack {
    /// An acknowledgement without ranges.
    #[must_use]
    pub const fn new(
        incarnation: Incarnation,
        reset: bool,
        cumulative: u32,
        window: u32,
        max_message: u32,
    ) -> Self {
        Self {
            incarnation,
            reset,
            cumulative,
            window,
            max_message,
            ranges: [Range { start: 0, end: 0 }; MAX_RANGES],
            count: 0,
        }
    }

    /// Adds a range of selective acknowledgement; returns false when there
    /// are already [`MAX_RANGES`].
    pub fn push_range(&mut self, range: Range) -> bool {
        let Some(slot) = self.ranges.get_mut(usize::from(self.count)) else {
            return false;
        };
        *slot = range;
        self.count += 1;
        true
    }

    /// The ranges of selective acknowledgement.
    #[must_use]
    pub fn ranges(&self) -> &[Range] {
        self.ranges
            .get(..usize::from(self.count))
            .unwrap_or_default()
    }

    /// Whether the ranges keep the rules: each after the cumulative point,
    /// not empty, ascending and not overlapping.
    fn ranges_valid(&self) -> bool {
        let mut floor = self.cumulative;
        for range in self.ranges() {
            let span = range.end.wrapping_sub(range.start);
            if !after(range.start, floor) || span == 0 || span >= 1 << 31 {
                return false;
            }
            floor = range.end.wrapping_sub(1);
        }
        true
    }

    /// Decodes an acknowledgement.
    ///
    /// # Errors
    ///
    /// [`FrameError::Malformed`] for a frame that breaks a rule.
    pub fn decode(frame: &[u8]) -> Result<Self, FrameError> {
        let incarnation = take::<INCARNATION_LEN>(frame, 0)?;
        let [flags] = take::<1>(frame, 8)?;
        if flags & !RESET != 0 {
            return Err(FrameError::Malformed);
        }
        let cumulative = u32::from_le_bytes(take(frame, 9)?);
        let window = u32::from_le_bytes(take(frame, 13)?);
        let max_message = u32::from_le_bytes(take(frame, 17)?);
        let [count] = take::<1>(frame, 21)?;
        if usize::from(count) > MAX_RANGES || frame.len() != ACK_HEADER_LEN + 8 * usize::from(count)
        {
            return Err(FrameError::Malformed);
        }
        let mut ack = Self::new(
            incarnation,
            flags & RESET != 0,
            cumulative,
            window,
            max_message,
        );
        for i in 0..usize::from(count) {
            let at = ACK_HEADER_LEN + 8 * i;
            let range = Range {
                start: u32::from_le_bytes(take(frame, at)?),
                end: u32::from_le_bytes(take(frame, at + 4)?),
            };
            if !ack.push_range(range) {
                return Err(FrameError::Malformed);
            }
        }
        if !ack.ranges_valid() {
            return Err(FrameError::Malformed);
        }
        Ok(ack)
    }

    /// The frame's length once encoded.
    #[must_use]
    pub const fn len(&self) -> usize {
        ACK_HEADER_LEN + 8 * self.count as usize
    }

    /// Never: an acknowledgement has a header.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Encodes the acknowledgement into `out`; returns its length.
    ///
    /// # Errors
    ///
    /// [`FrameError::Malformed`] for ranges that break the rules,
    /// [`FrameError::BufferTooSmall`] when `out` cannot hold it.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, FrameError> {
        if !self.ranges_valid() {
            return Err(FrameError::Malformed);
        }
        let len = self.len();
        let out = out.get_mut(..len).ok_or(FrameError::BufferTooSmall)?;
        let mut writer = Writer { out, at: 0 };
        writer.put(&self.incarnation);
        writer.put(&[if self.reset { RESET } else { 0 }]);
        writer.put(&self.cumulative.to_le_bytes());
        writer.put(&self.window.to_le_bytes());
        writer.put(&self.max_message.to_le_bytes());
        writer.put(&[self.count]);
        for range in self.ranges() {
            writer.put(&range.start.to_le_bytes());
            writer.put(&range.end.to_le_bytes());
        }
        Ok(len)
    }
}

/// `N` bytes of `frame` at `at`.
fn take<const N: usize>(frame: &[u8], at: usize) -> Result<[u8; N], FrameError> {
    frame
        .get(at..at + N)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(FrameError::Malformed)
}

/// Writes into a buffer already checked to be long enough.
struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        if let Some(slot) = self.out.get_mut(self.at..self.at + bytes.len()) {
            slot.copy_from_slice(bytes);
        }
        self.at += bytes.len();
    }
}

#[cfg(test)]
mod tests;
