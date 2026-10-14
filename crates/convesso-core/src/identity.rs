//! Who an endpoint is (`PROTOCOL.md §2`).
//!
//! An endpoint is dialled by its [`Address`], an Ed25519 public key. What the
//! handshake authenticates, and what an application admits, refuses and
//! compares, is its [`PeerId`]: the X25519 key converted from the address,
//! `u = (1 + y) / (1 − y)`, accepted only in its one canonical, torsion-free
//! form. That is what makes one private key exactly one identity:
//!
//! - the conversion uses only `y`, so an address and its negation give one
//!   `PeerId`; comparing `PeerId`s, never address bytes, removes that alias;
//! - X25519 ignores bit 255, accepts values at or above `p`, and with a clamped
//!   scalar cannot tell a point from the same point plus one of small order; a
//!   received static key is therefore refused unless bit 255 is clear, it is
//!   below `p`, it is on the curve and its point is torsion-free.
//!
//! The transport key never signs: its Ed25519 form only names an endpoint.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use x25519_dalek::{PublicKey, StaticSecret};

/// `p = 2^255 − 19`, little-endian.
const P_BYTES: [u8; 32] = {
    let mut p = [0xFF; 32];
    p[0] = 0xED;
    p[31] = 0x7F;
    p
};

/// Whether a 255-bit little-endian value (bit 255 already clear) is at least `p`.
fn at_least_p(value: &[u8; 32]) -> bool {
    // Compare from the most significant byte down.
    for (byte, p) in value.iter().rev().zip(P_BYTES.iter().rev()) {
        if byte != p {
            return byte > p;
        }
    }
    true
}

/// Why 32 bytes are not an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// Not the canonical encoding of a point: `y ≥ p`, or a negative zero.
    NotCanonical,
    /// `y` is not the `y` of a point of the curve.
    NotOnCurve,
    /// The point has small order.
    SmallOrder,
    /// The point is not in the prime-order subgroup.
    NotTorsionFree,
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotCanonical => "address is not a canonical point encoding",
            Self::NotOnCurve => "address is not a point of the curve",
            Self::SmallOrder => "address is a point of small order",
            Self::NotTorsionFree => "address is not in the prime-order subgroup",
        })
    }
}

impl core::error::Error for AddressError {}

/// Why 32 bytes received as a static key are not a peer identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticKeyError {
    /// Bit 255 is set: X25519 would ignore it, so it is another encoding.
    Bit255Set,
    /// The value is at least `p`: X25519 would reduce it, so it is another encoding.
    NotCanonical,
    /// The value is not the `u` of a point of the curve (it is on the twist).
    NotOnCurve,
    /// The point has small order.
    SmallOrder,
    /// The point is not in the prime-order subgroup: it is a key plus a point of
    /// small order, which X25519 cannot tell from the key itself.
    NotTorsionFree,
}

impl core::fmt::Display for StaticKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Bit255Set => "static key has bit 255 set",
            Self::NotCanonical => "static key is not reduced modulo p",
            Self::NotOnCurve => "static key is not on the curve",
            Self::SmallOrder => "static key is a point of small order",
            Self::NotTorsionFree => "static key is not in the prime-order subgroup",
        })
    }
}

impl core::error::Error for StaticKeyError {}

/// A peer's identity: its X25519 static key in canonical form.
///
/// Admit, refuse and compare peers by this, never by address bytes: an address
/// and its negation are one `PeerId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// The identity a received static key names, if it is in its one canonical
    /// form.
    ///
    /// # Errors
    ///
    /// A [`StaticKeyError`] naming the first defect found.
    pub fn from_static(bytes: [u8; 32]) -> Result<Self, StaticKeyError> {
        if bytes[31] & 0x80 != 0 {
            return Err(StaticKeyError::Bit255Set);
        }
        if at_least_p(&bytes) {
            return Err(StaticKeyError::NotCanonical);
        }
        // Either sign gives a point of the same order; `None` means `u` is not
        // on the curve (or is `−1`, which is not on it either).
        let point = MontgomeryPoint(bytes)
            .to_edwards(0)
            .ok_or(StaticKeyError::NotOnCurve)?;
        if point.is_small_order() {
            return Err(StaticKeyError::SmallOrder);
        }
        if !point.is_torsion_free() {
            return Err(StaticKeyError::NotTorsionFree);
        }
        Ok(Self(bytes))
    }

    /// A `PeerId` for bytes this endpoint did not check, because a party it
    /// authenticated vouches for them: the sender the pinned relay names, or a
    /// key this endpoint itself made into a `PeerId` earlier. Checking costs
    /// about a Diffie-Hellman, which a relayed packet cannot spend. Such a
    /// `PeerId` only labels where a packet came from: every identity that
    /// admission or a session relies on comes from a handshake, checked.
    pub(crate) const fn vouched(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes of the static key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An endpoint's address: an Ed25519 public key, validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    bytes: [u8; 32],
    peer_id: PeerId,
}

impl Address {
    /// Parses an address, refusing anything but the canonical encoding of a
    /// point of the prime-order subgroup.
    ///
    /// # Errors
    ///
    /// An [`AddressError`] naming the first defect found.
    pub fn parse(bytes: [u8; 32]) -> Result<Self, AddressError> {
        let mut y = bytes;
        y[31] &= 0x7F;
        let negative = bytes[31] & 0x80 != 0;
        if at_least_p(&y) {
            return Err(AddressError::NotCanonical);
        }
        // x = 0 only for y = 1 and y = p − 1; a set sign bit there is a negative zero.
        let mut p_minus_one = P_BYTES;
        p_minus_one[0] -= 1;
        let mut one = [0u8; 32];
        one[0] = 1;
        if negative && (y == one || y == p_minus_one) {
            return Err(AddressError::NotCanonical);
        }
        let point = CompressedEdwardsY(bytes)
            .decompress()
            .ok_or(AddressError::NotOnCurve)?;
        if point.compress().to_bytes() != bytes {
            return Err(AddressError::NotCanonical);
        }
        if point.is_small_order() {
            return Err(AddressError::SmallOrder);
        }
        if !point.is_torsion_free() {
            return Err(AddressError::NotTorsionFree);
        }
        Ok(Self {
            bytes,
            peer_id: PeerId(convert(&point)),
        })
    }

    /// The identity this address converts to.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The 32 bytes of the address.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// The Montgomery `u`-coordinate of a point, as 32 canonical bytes.
fn convert(point: &EdwardsPoint) -> [u8; 32] {
    point.to_montgomery().to_bytes()
}

/// A provisioned scalar whose public key is not its address's `PeerId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityMismatch;

impl core::fmt::Display for IdentityMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the X25519 scalar does not belong to the address")
    }
}

impl core::error::Error for IdentityMismatch {}

/// This endpoint's own identity: its address and the X25519 secret of the same key.
pub struct Identity {
    secret: StaticSecret,
    address: Address,
}

impl Identity {
    /// An identity from the X25519 scalar of an Ed25519 key (the first 32 bytes
    /// of SHA-512 of its seed, unclamped) and that key's address.
    ///
    /// This is how a microcontroller is provisioned: it never needs SHA-512.
    ///
    /// # Errors
    ///
    /// [`IdentityMismatch`] when the scalar's public key is not the address's
    /// `PeerId`.
    pub fn from_parts(scalar: [u8; 32], address: Address) -> Result<Self, IdentityMismatch> {
        let secret = StaticSecret::from(scalar);
        if PublicKey::from(&secret).as_bytes() != address.peer_id().as_bytes() {
            return Err(IdentityMismatch);
        }
        Ok(Self { secret, address })
    }

    /// An identity from an Ed25519 seed, deriving its X25519 scalar as RFC 8032
    /// derives the signing scalar.
    ///
    /// # Errors
    ///
    /// [`IdentityMismatch`] if the derived key fails the checks of
    /// [`Self::from_parts`]. A key derived from a seed always passes them; they
    /// are run rather than assumed.
    #[cfg(feature = "ed25519-seed")]
    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Result<Self, IdentityMismatch> {
        let signing = ed25519_dalek::SigningKey::from_bytes(seed);
        let address =
            Address::parse(signing.verifying_key().to_bytes()).map_err(|_| IdentityMismatch)?;
        Self::from_parts(signing.to_scalar_bytes(), address)
    }

    /// This endpoint's address.
    #[must_use]
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// This endpoint's identity as peers see it.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.address.peer_id
    }

    pub(crate) const fn secret(&self) -> &StaticSecret {
        &self.secret
    }
}
