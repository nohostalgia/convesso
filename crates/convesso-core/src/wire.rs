//! The wire invariants: the bytes every convesso version shares, past and future
//! (`PROTOCOL.md §1`).
//!
//! Three things mean the same in every version, and no version may change them:
//!
//! - **Byte 0 is the version.** `0x00` is the version-independent "version not
//!   supported" message, `0x01`–`0xFE` are protocol versions, `0xFF` is reserved.
//! - **A first contact ends with `mac1 || mac2`**, 16 bytes each. `mac1` is
//!   keyed BLAKE2s over everything before it, under a key derived from the
//!   responder's Ed25519 address, so any version can drop a stranger for the
//!   cost of a hash and before any Diffie-Hellman. `mac2` belongs to each version.
//! - **"Version not supported"** lists the versions a responder speaks and echoes
//!   the `mac1` of the packet it answers, so that nobody who did not see that
//!   packet can forge it. It is never larger than the packet it answers, so it
//!   cannot amplify.
//!
//! Everything here is sans-IO and allocation-free, and no input makes it panic.

use blake2::digest::consts::U16;
use blake2::digest::{Digest, KeyInit, Mac as _};
use blake2::{Blake2s256, Blake2sMac};

/// Length of `mac1` and of `mac2`.
pub const MAC_LEN: usize = 16;

/// Length of `mac1 || mac2`, which ends every first contact.
pub const MACS_LEN: usize = 2 * MAC_LEN;

/// The shortest first contact: a version byte and the two MACs.
pub const MIN_FIRST_CONTACT_LEN: usize = 1 + MACS_LEN;

/// Byte 0 of a "version not supported" message.
pub const VERSION_NOT_SUPPORTED: u8 = 0x00;

/// Byte 0 that no packet may carry.
pub const RESERVED: u8 = 0xFF;

/// The most versions a "version not supported" message lists.
///
/// With 15, the longest message (33 bytes) is no longer than the shortest
/// first contact (33 bytes), so an answer can never amplify.
pub const MAX_LISTED_VERSIONS: usize = 15;

/// The longest "version not supported" message.
pub const MAX_VERSION_NOT_SUPPORTED_LEN: usize = 2 + MAX_LISTED_VERSIONS + MAC_LEN;

/// The label `mac1` keys are derived under: the ASCII bytes
/// `63 6f 6e 76 65 73 73 6f 2d 6d 61 63 31`.
const MAC1_LABEL: &[u8; 13] = b"convesso-mac1";

/// A `mac1` or `mac2` value.
pub type Mac = [u8; MAC_LEN];

/// A protocol version, `0x01` to `0xFE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(u8);

impl Version {
    /// Version 1.
    pub const V1: Self = Self(0x01);

    /// The version a byte names, or `None` for `0x00` and `0xFF`, which are not
    /// versions.
    #[must_use]
    pub const fn new(byte: u8) -> Option<Self> {
        match byte {
            VERSION_NOT_SUPPORTED | RESERVED => None,
            _ => Some(Self(byte)),
        }
    }

    /// The byte this version is written as.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// What byte 0 says a packet is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classified {
    /// Empty, or reserved: drop it, answer nothing, keep nothing.
    Drop,
    /// A "version not supported" message.
    VersionNotSupported,
    /// A packet of this protocol version.
    Version(Version),
}

/// Reads byte 0 of a packet.
#[must_use]
pub fn classify(packet: &[u8]) -> Classified {
    match packet.first() {
        None | Some(&RESERVED) => Classified::Drop,
        Some(&VERSION_NOT_SUPPORTED) => Classified::VersionNotSupported,
        Some(&byte) => Classified::Version(Version(byte)),
    }
}

/// The `mac1` a first contact carries, or `None` when the packet is too short
/// to be one.
#[must_use]
pub fn carried_mac1(packet: &[u8]) -> Option<Mac> {
    let macs = packet
        .len()
        .checked_sub(MACS_LEN)
        .filter(|&prefix| prefix >= 1)
        .and_then(|prefix| packet.get(prefix..prefix + MAC_LEN))?;
    macs.try_into().ok()
}

/// The key `mac1` is computed under, for one responder address.
///
/// Derived once per address: `BLAKE2s-256("convesso-mac1" || address)`.
#[derive(Clone)]
pub struct Mac1Key([u8; 32]);

impl Mac1Key {
    /// The `mac1` key of the responder whose Ed25519 address is `address`.
    #[must_use]
    pub fn for_address(address: &[u8; 32]) -> Self {
        let mut hash = Blake2s256::new();
        hash.update(MAC1_LABEL);
        hash.update(address);
        Self(hash.finalize().into())
    }

    /// `mac1` over `prefix`: keyed BLAKE2s with a 16-byte output.
    #[must_use]
    pub fn compute(&self, prefix: &[u8]) -> Mac {
        let mut mac = self.mac();
        mac.update(prefix);
        mac.finalize().into_bytes().into()
    }

    /// Whether `packet` is a first contact whose `mac1` is valid under this key.
    ///
    /// The comparison takes the same time whatever the bytes, so it does not
    /// reveal how much of a forged `mac1` was right. A packet too short to be a
    /// first contact is not valid.
    #[must_use]
    pub fn verify(&self, packet: &[u8]) -> bool {
        let Some(prefix_len) = packet.len().checked_sub(MACS_LEN).filter(|&p| p >= 1) else {
            return false;
        };
        let (Some(prefix), Some(carried)) = (
            packet.get(..prefix_len),
            packet.get(prefix_len..prefix_len + MAC_LEN),
        ) else {
            return false;
        };
        let mut mac = self.mac();
        mac.update(prefix);
        mac.verify_slice(carried).is_ok()
    }

    fn mac(&self) -> Blake2sMac<U16> {
        // The key is a fixed 32-byte array, BLAKE2s's full key size, so the
        // fixed-size constructor applies and nothing can fail.
        <Blake2sMac<U16> as KeyInit>::new(&self.0.into())
    }
}

/// Why bytes are not a well-formed "version not supported" message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Byte 0 is not `0x00`.
    NotVersionNotSupported,
    /// Too short to hold byte 0 and the count.
    Truncated,
    /// The count is zero.
    EmptyVersionList,
    /// The count is above [`MAX_LISTED_VERSIONS`].
    TooManyVersions {
        /// The count the message declares.
        count: u8,
    },
    /// The length is not `18 + count`.
    WrongLength {
        /// The length the count implies.
        expected: usize,
        /// The length received.
        actual: usize,
    },
    /// A listed version is `0x00` or `0xFF`.
    ReservedVersion {
        /// The byte listed.
        byte: u8,
    },
    /// The versions are not strictly increasing.
    VersionsNotIncreasing,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotVersionNotSupported => f.write_str("not a version-not-supported message"),
            Self::Truncated => f.write_str("version-not-supported message truncated"),
            Self::EmptyVersionList => f.write_str("version-not-supported message lists no version"),
            Self::TooManyVersions { count } => write!(
                f,
                "version-not-supported message lists {count} versions, at most {MAX_LISTED_VERSIONS} allowed"
            ),
            Self::WrongLength { expected, actual } => write!(
                f,
                "version-not-supported message is {actual} bytes, its count implies {expected}"
            ),
            Self::ReservedVersion { byte } => {
                write!(
                    f,
                    "version-not-supported message lists {byte:#04x}, which is not a version"
                )
            }
            Self::VersionsNotIncreasing => {
                f.write_str("version-not-supported message lists versions out of order or twice")
            }
        }
    }
}

impl core::error::Error for DecodeError {}

/// An output buffer too small for what had to be written into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall {
    /// The length that was needed.
    pub needed: usize,
}

/// A "version not supported" message: the versions a responder speaks, and the
/// `mac1` of the first contact it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionNotSupported {
    versions: [Version; MAX_LISTED_VERSIONS],
    count: u8,
    echo: Mac,
}

impl VersionNotSupported {
    /// A message listing `versions` and echoing `echo`.
    ///
    /// # Errors
    ///
    /// The same defects [`Self::decode`] refuses: no version, more than
    /// [`MAX_LISTED_VERSIONS`], or versions not strictly increasing.
    pub fn new(versions: &[Version], echo: Mac) -> Result<Self, DecodeError> {
        let count = check_count(versions.len())?;
        let mut listed = [Version::V1; MAX_LISTED_VERSIONS];
        for (slot, version) in listed.iter_mut().zip(versions) {
            *slot = *version;
        }
        if versions
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if a >= b))
        {
            return Err(DecodeError::VersionsNotIncreasing);
        }
        Ok(Self {
            versions: listed,
            count,
            echo,
        })
    }

    /// Decodes a received message, refusing anything not exactly well formed.
    ///
    /// # Errors
    ///
    /// A [`DecodeError`] naming the first defect found.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (tag, count) = match bytes {
            [tag, count, ..] => (*tag, *count),
            [tag] if *tag != VERSION_NOT_SUPPORTED => {
                return Err(DecodeError::NotVersionNotSupported);
            }
            _ => return Err(DecodeError::Truncated),
        };
        if tag != VERSION_NOT_SUPPORTED {
            return Err(DecodeError::NotVersionNotSupported);
        }
        let count_usize = usize::from(count);
        check_count(count_usize).map_err(|error| match error {
            DecodeError::TooManyVersions { .. } => DecodeError::TooManyVersions { count },
            other => other,
        })?;
        let expected = 2 + count_usize + MAC_LEN;
        if bytes.len() != expected {
            return Err(DecodeError::WrongLength {
                expected,
                actual: bytes.len(),
            });
        }
        let (Some(listed), Some(echo)) = (
            bytes.get(2..2 + count_usize),
            bytes.get(2 + count_usize..expected),
        ) else {
            return Err(DecodeError::Truncated);
        };
        let mut versions = [Version::V1; MAX_LISTED_VERSIONS];
        for (slot, &byte) in versions.iter_mut().zip(listed) {
            *slot = Version::new(byte).ok_or(DecodeError::ReservedVersion { byte })?;
        }
        if listed
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if a >= b))
        {
            return Err(DecodeError::VersionsNotIncreasing);
        }
        Ok(Self {
            versions,
            count,
            echo: echo.try_into().map_err(|_| DecodeError::Truncated)?,
        })
    }

    /// Writes the message into `out`, returning its length.
    ///
    /// # Errors
    ///
    /// [`BufferTooSmall`] when `out` is shorter than [`Self::encoded_len`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, BufferTooSmall> {
        let len = self.encoded_len();
        let out = out.get_mut(..len).ok_or(BufferTooSmall { needed: len })?;
        let (head, rest) = out.split_at_mut(2);
        head.copy_from_slice(&[VERSION_NOT_SUPPORTED, self.count]);
        let (listed, echo) = rest.split_at_mut(usize::from(self.count));
        for (byte, version) in listed.iter_mut().zip(self.versions()) {
            *byte = version.get();
        }
        echo.copy_from_slice(&self.echo);
        Ok(len)
    }

    /// The length of the encoded message: `18 + count`.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        2 + usize::from(self.count) + MAC_LEN
    }

    /// The versions listed, in increasing order.
    #[must_use]
    pub fn versions(&self) -> &[Version] {
        self.versions
            .get(..usize::from(self.count))
            .unwrap_or_default()
    }

    /// The `mac1` of the first contact this message answers.
    #[must_use]
    pub fn echo(&self) -> &Mac {
        &self.echo
    }
}

fn check_count(count: usize) -> Result<u8, DecodeError> {
    match count {
        0 => Err(DecodeError::EmptyVersionList),
        1..=MAX_LISTED_VERSIONS => u8::try_from(count).map_err(|_| DecodeError::EmptyVersionList),
        _ => Err(DecodeError::TooManyVersions {
            count: u8::try_from(count).unwrap_or(u8::MAX),
        }),
    }
}

/// The responder's side: the bytes to answer a packet of a version it does not
/// speak with, or `None` when it must stay silent.
///
/// Answers only a first contact (at least [`MIN_FIRST_CONTACT_LEN`] bytes) of a
/// version not in `spoken`, whose `mac1` is valid under `key`, and only when the
/// answer is no longer than that packet. Keeps no state either way.
#[must_use]
pub fn answer_unknown_version(
    packet: &[u8],
    key: &Mac1Key,
    spoken: &[Version],
    out: &mut [u8],
) -> Option<usize> {
    let Classified::Version(version) = classify(packet) else {
        return None;
    };
    if spoken.contains(&version) || !key.verify(packet) {
        return None;
    }
    let answer = VersionNotSupported::new(spoken, carried_mac1(packet)?).ok()?;
    if answer.encoded_len() > packet.len() {
        return None;
    }
    answer.encode(out).ok()
}

/// A first contact an initiator sent and is still waiting on an answer to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingFirstContact {
    /// The version the first contact was sent in.
    pub version: Version,
    /// Its `mac1`, which a genuine answer echoes.
    pub mac1: Mac,
}

/// A peer does not speak the version an attempt used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedVersion {
    /// The version the attempt used.
    pub attempted: Version,
    /// The peer's answer, listing the versions it speaks.
    pub answer: VersionNotSupported,
}

impl UnsupportedVersion {
    /// The versions the peer speaks.
    #[must_use]
    pub fn peer_versions(&self) -> &[Version] {
        self.answer.versions()
    }
}

impl core::fmt::Display for UnsupportedVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "peer does not speak version {}; it speaks",
            self.attempted.get()
        )?;
        for version in self.peer_versions() {
            write!(f, " {}", version.get())?;
        }
        Ok(())
    }
}

impl core::error::Error for UnsupportedVersion {}

/// The initiator's side: which pending attempt, if any, a "version not
/// supported" answer ends.
///
/// Returns the index of the attempt in `pending` and the error that names the
/// versions the peer speaks. Returns `None`, and the caller ignores the answer,
/// when its echo matches no pending attempt or when it lists the very version
/// the attempt used. Never suggests another version: an initiator does not fall
/// back on its own.
#[must_use]
pub fn match_answer(
    answer: &VersionNotSupported,
    pending: &[PendingFirstContact],
) -> Option<(usize, UnsupportedVersion)> {
    let (index, attempt) = pending
        .iter()
        .enumerate()
        .find(|(_, attempt)| attempt.mac1 == *answer.echo())?;
    if answer.versions().contains(&attempt.version) {
        return None;
    }
    Some((
        index,
        UnsupportedVersion {
            attempted: attempt.version,
            answer: *answer,
        },
    ))
}
