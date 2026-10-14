//! The provisioning record: an embedded device is given its identity, and
//! never makes one (`DESIGN.md §5`).
//!
//! ```text
//! scalar (32)   the X25519 static scalar
//! address (32)  the Ed25519 public key, which peers know the device by
//! ```
//!
//! Written on the host from a key file (the `provision` example of
//! `convesso-tokio`), stored where the integrator chooses, and read at start.
//! The device neither generates nor derives a key, so it needs neither SHA-512
//! nor Ed25519 code. The record holds a private key: whoever reads it has the
//! device's identity, and protecting it (read-out protection, a secure
//! element) is the integrator's.

use convesso_core::identity::{Address, Identity};

/// The length of a provisioning record.
pub const RECORD_LEN: usize = 64;

/// A record whose two halves do not belong to one key, or whose address is
/// not a valid one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRecord;

impl core::fmt::Display for InvalidRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the provisioning record's scalar and address do not belong to one key")
    }
}

impl core::error::Error for InvalidRecord {}

/// The identity a record gives.
///
/// # Errors
///
/// [`InvalidRecord`] when the address is not a valid one, or the scalar is not
/// that address's.
pub fn identity(record: &[u8; RECORD_LEN]) -> Result<Identity, InvalidRecord> {
    let (scalar, address) = record.split_at(32);
    let scalar: [u8; 32] = scalar.try_into().map_err(|_| InvalidRecord)?;
    let address: [u8; 32] = address.try_into().map_err(|_| InvalidRecord)?;
    let address = Address::parse(address).map_err(|_| InvalidRecord)?;
    Identity::from_parts(scalar, address).map_err(|_| InvalidRecord)
}

/// The record of an identity's parts: what the provisioning tool writes.
#[must_use]
pub fn write(scalar: &[u8; 32], address: &Address) -> [u8; RECORD_LEN] {
    let mut record = [0u8; RECORD_LEN];
    let (first, second) = record.split_at_mut(32);
    first.copy_from_slice(scalar);
    second.copy_from_slice(address.as_bytes());
    record
}

#[cfg(test)]
mod tests;
