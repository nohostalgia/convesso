//! The core's entropy, from the operating system's generator.
//!
//! The core's [`Entropy`] cannot fail, so the generator is read once when an
//! endpoint starts, and a failure there stops the start. A failure later
//! panics inside the core's call: the call produces nothing, the endpoint's
//! task ends, and no packet built from anything less than the generator's
//! output ever leaves.

use convesso_core::handshake::Entropy;

/// Why the generator could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntropyError(pub String);

impl std::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the operating system's generator failed: {}", self.0)
    }
}

impl std::error::Error for EntropyError {}

/// A source of entropy for an endpoint, checked before the endpoint starts.
pub trait SystemEntropy: Entropy + Send + 'static {
    /// Reads the generator once.
    ///
    /// # Errors
    ///
    /// [`EntropyError`] when it cannot be read.
    fn check(&mut self) -> Result<(), EntropyError>;
}

/// The operating system's cryptographically secure generator.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    #[allow(
        clippy::panic,
        reason = "no packet may be built from less than the generator's output"
    )]
    fn fill(&mut self, dest: &mut [u8]) {
        if let Err(error) = getrandom::fill(dest) {
            panic!("the operating system's generator failed: {error}");
        }
    }
}

impl SystemEntropy for OsEntropy {
    fn check(&mut self) -> Result<(), EntropyError> {
        let mut probe = [0u8; 32];
        getrandom::fill(&mut probe).map_err(|error| EntropyError(error.to_string()))
    }
}
