//! Entropy from the chip's generator: randomness comes from a secure
//! generator, or nothing starts (`DESIGN.md §5`).
//!
//! A microcontroller has no operating system to ask: the core's entropy comes
//! from the chip's hardware generator, through [`SecureRng`]. The driver reads
//! it once before starting and refuses to start on an error. There is no
//! fallback: a chip without a generator fit for cryptography cannot implement
//! [`SecureRng`] honestly, and must be given a secure element or not use the
//! driver.

use convesso_core::handshake::Entropy;

/// The generator could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngFailed;

impl core::fmt::Display for RngFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the hardware random generator could not be read")
    }
}

impl core::error::Error for RngFailed {}

/// A cryptographically secure generator: the chip's hardware one, or a secure
/// element. Implement it only for a source fit for keys.
pub trait SecureRng {
    /// Fills `dest` with random bytes.
    ///
    /// # Errors
    ///
    /// [`RngFailed`] when the generator cannot be read, for instance when its
    /// health test fails.
    fn try_fill(&mut self, dest: &mut [u8]) -> Result<(), RngFailed>;
}

/// The core's entropy, from a checked [`SecureRng`]. A read that fails after
/// the check stops the device: the core cannot be handed predictable bytes.
pub(crate) struct Checked<R>(pub(crate) R);

impl<R: SecureRng> Checked<R> {
    /// Reads the generator once.
    ///
    /// # Errors
    ///
    /// [`RngFailed`].
    pub(crate) fn new(mut rng: R) -> Result<Self, RngFailed> {
        let mut probe = [0u8; 32];
        rng.try_fill(&mut probe)?;
        Ok(Self(rng))
    }
}

impl<R: SecureRng> Entropy for Checked<R> {
    #[allow(
        clippy::panic,
        reason = "a generator that fails after its check must not give the core predictable bytes"
    )]
    fn fill(&mut self, dest: &mut [u8]) {
        if self.0.try_fill(dest).is_err() {
            panic!("the hardware random generator failed");
        }
    }
}

/// A `rand_core` 0.9 generator marked fit for cryptography, as a
/// [`SecureRng`].
#[cfg(feature = "rand_core")]
pub struct FromRandCore<R>(pub R);

#[cfg(feature = "rand_core")]
impl<R: rand_core::TryCryptoRng> SecureRng for FromRandCore<R> {
    fn try_fill(&mut self, dest: &mut [u8]) -> Result<(), RngFailed> {
        self.0.try_fill_bytes(dest).map_err(|_| RngFailed)
    }
}
