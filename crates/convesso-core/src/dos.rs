//! Keeping a responder reachable under a flood (`PROTOCOL.md §4`).
//!
//! `mac1` stops strangers for the cost of a hash, but an address is public, so
//! anyone may still make a responder run a Diffie-Hellman per packet. This
//! module gives a responder what WireGuard gives one, with convesso's own labels
//! and source binding:
//!
//! - a **load bucket**: until it runs dry, nothing changes;
//! - under load, a **cookie reply** instead of a Diffie-Hellman for a first
//!   contact without a valid `mac2`. The cookie is a MAC of the packet's
//!   [`Source`] under a secret that rotates every 120 s, so a spoofed source
//!   never receives the cookie it would need;
//! - a **rate per source**, 20 a second with a burst of 5, for first contacts
//!   whose `mac2` is valid;
//! - a memory of **recent ephemerals**, so an exact replay costs no
//!   Diffie-Hellman.
//!
//! All of it runs on caller-supplied time and sends nothing on its own.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use blake2::digest::consts::U16;
use blake2::digest::{Digest, KeyInit, Mac as _};
use blake2::{Blake2s256, Blake2sMac};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};

use crate::handshake::Entropy;
use crate::handshake::messages::MessageError;
use crate::identity::PeerId;
use crate::storage::Table;
use crate::time::Instant;
use crate::wire::{MAC_LEN, Mac};

/// A cookie: 16 bytes.
pub type Cookie = [u8; COOKIE_LEN];

/// Length of a cookie.
pub const COOKIE_LEN: usize = 16;

/// Length of version 1's cookie reply.
pub const COOKIE_REPLY_LEN: usize = 62;

/// Byte 1 of a cookie reply.
pub const TYPE_COOKIE_REPLY: u8 = 0x03;

/// How long a responder's cookie secret lives, and so how long an initiator
/// uses a cookie. Sends nothing.
pub const COOKIE_LIFETIME: Duration = Duration::from_secs(120);

/// How long a responder remembers an ephemeral key. Sends nothing.
pub const EPHEMERAL_MEMORY: Duration = Duration::from_secs(5);

/// A source's rate under load: first contacts per second.
pub const SOURCE_RATE_PER_SECOND: u32 = 20;

/// A source's burst under load.
pub const SOURCE_BURST: u32 = 5;

/// The longest direct source a driver may give.
pub const MAX_DIRECT_SOURCE_LEN: usize = 32;

const COOKIE_LABEL: &[u8; 15] = b"convesso-cookie";
const NONCE_LEN: usize = 24;
const TAG_DIRECT: u8 = 0x01;
const TAG_RELAYED: u8 = 0x02;

/// Where a packet came from, as the driver knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source<'a> {
    /// On a direct path: the driver's encoding of the IP address and port, at
    /// most [`MAX_DIRECT_SOURCE_LEN`] bytes.
    Direct(&'a [u8]),
    /// Through a relay: the sender, as the relay authenticated it. Over a relay
    /// the IP address is the relay's, so it would name every relayed peer alike.
    Relayed(PeerId),
}

/// A source as a table key: its tag, its length and its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceKey {
    tag: u8,
    len: u8,
    bytes: [u8; MAX_DIRECT_SOURCE_LEN],
}

impl Source<'_> {
    /// The source as a key, or `None` for a direct source longer than allowed,
    /// which is a driver bug: such a packet is dropped.
    #[must_use]
    pub fn key(&self) -> Option<SourceKey> {
        let (tag, bytes): (u8, &[u8]) = match self {
            Self::Direct(bytes) => (TAG_DIRECT, bytes),
            Self::Relayed(peer) => (TAG_RELAYED, peer.as_bytes()),
        };
        let mut key = SourceKey {
            tag,
            len: u8::try_from(bytes.len()).ok()?,
            bytes: [0; MAX_DIRECT_SOURCE_LEN],
        };
        key.bytes.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(key)
    }
}

/// The longest IP source: an IPv6 address and a port.
pub const IP_SOURCE_LEN: usize = 18;

/// An IP address and port as a direct source, in the encoding every driver
/// uses (`DESIGN.md §5`): the IPv4 address (4 bytes) or the IPv6 address (16
/// bytes), then the port (2 bytes, big-endian). An IPv4-mapped IPv6 address is
/// encoded as IPv4, so that one peer has one source however a dual-stack
/// socket reports it. Returns the bytes and how many are used.
#[must_use]
pub fn encode_ip(address: SocketAddr) -> ([u8; IP_SOURCE_LEN], usize) {
    let mut out = [0u8; IP_SOURCE_LEN];
    let port = address.port().to_be_bytes();
    let ip = match address.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip @ IpAddr::V4(_) => ip,
    };
    let len = match ip {
        IpAddr::V4(ip) => {
            out[..4].copy_from_slice(&ip.octets());
            out[4..6].copy_from_slice(&port);
            6
        }
        IpAddr::V6(ip) => {
            out[..16].copy_from_slice(&ip.octets());
            out[16..18].copy_from_slice(&port);
            18
        }
    };
    (out, len)
}

/// The IP address and port an IP source names, or `None` for bytes of another
/// length.
#[must_use]
pub fn decode_ip(bytes: &[u8]) -> Option<SocketAddr> {
    let (ip, port) = match bytes.len() {
        6 => {
            let ip: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
            (IpAddr::V4(Ipv4Addr::from(ip)), bytes.get(4..6)?)
        }
        18 => {
            let ip: [u8; 16] = bytes.get(..16)?.try_into().ok()?;
            (IpAddr::V6(Ipv6Addr::from(ip)), bytes.get(16..18)?)
        }
        _ => return None,
    };
    let port: [u8; 2] = port.try_into().ok()?;
    Some(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

impl SourceKey {
    /// The source an IP address and port are, in the core's encoding.
    #[must_use]
    pub fn from_ip(address: SocketAddr) -> Self {
        let (bytes, len) = encode_ip(address);
        let mut key = Self {
            tag: TAG_DIRECT,
            len: u8::try_from(len).unwrap_or(0),
            bytes: [0; MAX_DIRECT_SOURCE_LEN],
        };
        if let (Some(field), Some(bytes)) = (key.bytes.get_mut(..len), bytes.get(..len)) {
            field.copy_from_slice(bytes);
        }
        key
    }

    /// The IP address and port a direct source names, if it is an IP source.
    #[must_use]
    pub fn as_ip(&self) -> Option<SocketAddr> {
        self.as_direct().and_then(decode_ip)
    }

    /// A direct source's bytes, in the driver's encoding: where a driver sends
    /// a packet the core addressed to it. `None` for a relayed source.
    #[must_use]
    pub fn as_direct(&self) -> Option<&[u8]> {
        (self.tag == TAG_DIRECT)
            .then(|| self.bytes.get(..usize::from(self.len)))
            .flatten()
    }

    /// The sender a relayed source names, or `None` for a direct source.
    #[must_use]
    pub fn relayed_from(&self) -> Option<PeerId> {
        if self.tag != TAG_RELAYED {
            return None;
        }
        let bytes: [u8; 32] = self.bytes.get(..32)?.try_into().ok()?;
        Some(PeerId::vouched(bytes))
    }

    fn tagged(&self) -> (u8, &[u8]) {
        (
            self.tag,
            self.bytes.get(..usize::from(self.len)).unwrap_or_default(),
        )
    }
}

/// Keyed BLAKE2s with a 16-byte output. Every key passed here is a 32-byte
/// secret or a 16-byte cookie, within BLAKE2s's 32-byte limit, so it cannot
/// fail; callers still treat `None` as a MAC that matches nothing.
fn keyed_blake2s_16(key: &[u8], parts: &[&[u8]]) -> Option<[u8; 16]> {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key).ok()?;
    for part in parts {
        mac.update(part);
    }
    Some(mac.finalize().into_bytes().into())
}

/// The cookie of `source` under `secret`:
/// `BLAKE2s(key = secret, out = 16)(tag || source)`.
#[must_use]
pub fn cookie(secret: &[u8; 32], source: &SourceKey) -> Cookie {
    let (tag, bytes) = source.tagged();
    keyed_blake2s_16(secret, &[&[tag], bytes]).unwrap_or_default()
}

/// `mac2` over `prefix`: `BLAKE2s(key = cookie, out = 16)`.
#[must_use]
pub fn mac2(cookie: &Cookie, prefix: &[u8]) -> Mac {
    keyed_blake2s_16(cookie, &[prefix]).unwrap_or_default()
}

/// Whether a first contact's `mac2` is valid under `cookie`, compared in
/// constant time.
#[must_use]
pub fn verify_mac2(cookie: &Cookie, packet: &[u8]) -> bool {
    let Some(prefix_len) = packet.len().checked_sub(MAC_LEN) else {
        return false;
    };
    let (Some(prefix), Some(carried)) = (packet.get(..prefix_len), packet.get(prefix_len..)) else {
        return false;
    };
    let Ok(mut mac) = <Blake2sMac<U16> as KeyInit>::new_from_slice(cookie) else {
        return false;
    };
    mac.update(prefix);
    mac.verify_slice(carried).is_ok()
}

/// The key a cookie is encrypted under for the responder at `address`:
/// `BLAKE2s-256("convesso-cookie" || address)`.
fn cookie_key(address: &[u8; 32]) -> Key {
    let mut hash = Blake2s256::new();
    hash.update(COOKIE_LABEL);
    hash.update(address);
    let key: [u8; 32] = hash.finalize().into();
    Key::from(key)
}

/// Writes a cookie reply: `0x01 | 0x03 | index | nonce | cookie encrypted`,
/// with the first contact's `mac1` as associated data.
#[must_use]
pub fn write_cookie_reply(
    address: &[u8; 32],
    initiator_index: u32,
    nonce: &[u8; NONCE_LEN],
    cookie: &Cookie,
    mac1: &Mac,
) -> Option<[u8; COOKIE_REPLY_LEN]> {
    let mut sealed = *cookie;
    let tag = XChaCha20Poly1305::new(&cookie_key(address))
        .encrypt_inout_detached(&XNonce::from(*nonce), mac1, sealed.as_mut_slice().into())
        .ok()?;
    let mut packet = [0u8; COOKIE_REPLY_LEN];
    let (header, rest) = packet.split_at_mut(6);
    header.copy_from_slice(&[0x01, TYPE_COOKIE_REPLY, 0, 0, 0, 0]);
    header
        .get_mut(2..6)?
        .copy_from_slice(&initiator_index.to_le_bytes());
    let (nonce_field, rest) = rest.split_at_mut(NONCE_LEN);
    nonce_field.copy_from_slice(nonce);
    let (cookie_field, tag_field) = rest.split_at_mut(COOKIE_LEN);
    cookie_field.copy_from_slice(&sealed);
    tag_field.copy_from_slice(&tag);
    Some(packet)
}

/// A cookie reply, its header checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookieReply<'a> {
    /// The initiator's index it answers.
    pub initiator_index: u32,
    /// The nonce.
    pub nonce: &'a [u8; NONCE_LEN],
    /// The cookie, encrypted, and its tag.
    pub sealed: &'a [u8; COOKIE_LEN + 16],
}

/// Reads a cookie reply's header.
///
/// # Errors
///
/// A [`MessageError`] when it is not exactly a version 1 cookie reply.
pub fn parse_cookie_reply(packet: &[u8]) -> Result<CookieReply<'_>, MessageError> {
    match packet {
        [0x01, TYPE_COOKIE_REPLY, ..] if packet.len() == COOKIE_REPLY_LEN => {}
        [0x01, TYPE_COOKIE_REPLY, ..] => {
            return Err(MessageError::WrongLength {
                expected: COOKIE_REPLY_LEN,
                actual: packet.len(),
            });
        }
        [0x01, ..] => return Err(MessageError::WrongType),
        _ => return Err(MessageError::WrongVersion),
    }
    let length = MessageError::WrongLength {
        expected: COOKIE_REPLY_LEN,
        actual: packet.len(),
    };
    Ok(CookieReply {
        initiator_index: packet
            .get(2..6)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(length)?,
        nonce: packet
            .get(6..30)
            .and_then(|b| b.try_into().ok())
            .ok_or(length)?,
        sealed: packet
            .get(30..62)
            .and_then(|b| b.try_into().ok())
            .ok_or(length)?,
    })
}

/// Opens a cookie reply as the initiator that dialled `address` with a first
/// contact whose `mac1` was `mac1`. `None` when it does not decrypt.
#[must_use]
pub fn open_cookie_reply(
    reply: &CookieReply<'_>,
    address: &[u8; 32],
    mac1: &Mac,
) -> Option<Cookie> {
    let (sealed, tag) = reply.sealed.split_at(COOKIE_LEN);
    let mut cookie: Cookie = sealed.try_into().ok()?;
    XChaCha20Poly1305::new(&cookie_key(address))
        .decrypt_inout_detached(
            &XNonce::from(*reply.nonce),
            mac1,
            cookie.as_mut_slice().into(),
            &Tag::try_from(tag).ok()?,
        )
        .ok()?;
    Some(cookie)
}

/// A responder's cookie secret, drawn when first needed and replaced 120 s
/// after it was drawn.
#[derive(Default)]
pub(crate) struct CookieSecret {
    current: Option<([u8; 32], Instant)>,
}

impl Drop for CookieSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some((secret, _)) = self.current.as_mut() {
            secret.zeroize();
        }
    }
}

impl CookieSecret {
    /// The secret in force at `now`, drawing a fresh one if there is none or it
    /// has lived [`COOKIE_LIFETIME`].
    pub(crate) fn at(&mut self, now: Instant, entropy: &mut impl Entropy) -> &[u8; 32] {
        let expired = self
            .current
            .is_none_or(|(_, drawn)| now >= drawn.saturating_add(COOKIE_LIFETIME));
        if expired {
            let mut secret = [0u8; 32];
            entropy.fill(&mut secret);
            self.current = Some((secret, now));
        }
        match &self.current {
            Some((secret, _)) => secret,
            None => &[0; 32],
        }
    }
}

/// A token bucket in thousandths of a token, refilled from caller time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bucket {
    millitokens: u64,
    at: Instant,
}

impl Bucket {
    pub(crate) fn full(burst: u32, now: Instant) -> Self {
        Self {
            millitokens: u64::from(burst) * 1000,
            at: now,
        }
    }

    /// Takes a token if one is there after refilling to `now`.
    pub(crate) fn take(&mut self, rate_per_second: u32, burst: u32, now: Instant) -> bool {
        let elapsed = now.as_millis().saturating_sub(self.at.as_millis());
        // `rate` tokens a second is `rate` millitokens a millisecond.
        self.millitokens = self
            .millitokens
            .saturating_add(elapsed.saturating_mul(u64::from(rate_per_second)))
            .min(u64::from(burst) * 1000);
        self.at = self.at.max(now);
        if self.millitokens >= 1000 {
            self.millitokens -= 1000;
            true
        } else {
            false
        }
    }
}

/// Takes a token from `source`'s bucket, creating it full if unknown and
/// forgetting the source seen least recently when the table is full.
pub(crate) fn take_source_token<T: Table<SourceKey, Bucket>>(
    table: &mut T,
    source: SourceKey,
    now: Instant,
) -> bool {
    if table.get(&source).is_none() {
        if table.capacity().is_some_and(|c| table.len() >= c) {
            let mut oldest: Option<(Instant, SourceKey)> = None;
            table.for_each(|key, bucket| {
                if oldest.is_none_or(|(at, _)| bucket.at < at) {
                    oldest = Some((bucket.at, *key));
                }
            });
            if let Some((_, key)) = oldest {
                table.remove(&key);
            }
        }
        if table
            .insert(source, Bucket::full(SOURCE_BURST, now))
            .is_err()
        {
            return false;
        }
    }
    table
        .get_mut(&source)
        .is_some_and(|bucket| bucket.take(SOURCE_RATE_PER_SECOND, SOURCE_BURST, now))
}

/// Whether `ephemeral` was seen within [`EPHEMERAL_MEMORY`] of `now`.
pub(crate) fn seen_recently<T: Table<[u8; 32], Instant>>(
    table: &T,
    ephemeral: &[u8; 32],
    now: Instant,
) -> bool {
    table.get(ephemeral).is_some_and(|expires| *expires > now)
}

/// Remembers `ephemeral` until `now + EPHEMERAL_MEMORY`, dropping expired
/// entries and, when still full, the one expiring first.
pub(crate) fn remember<T: Table<[u8; 32], Instant>>(
    table: &mut T,
    ephemeral: [u8; 32],
    now: Instant,
) {
    table.retain(|_, expires| *expires > now);
    if table.capacity().is_some_and(|c| table.len() >= c) {
        let mut first: Option<(Instant, [u8; 32])> = None;
        table.for_each(|key, expires| {
            if first.is_none_or(|(at, _)| *expires < at) {
                first = Some((*expires, *key));
            }
        });
        if let Some((_, key)) = first {
            table.remove(&key);
        }
    }
    let _ = table.insert(ephemeral, now.saturating_add(EPHEMERAL_MEMORY));
}

#[cfg(test)]
mod tests;
