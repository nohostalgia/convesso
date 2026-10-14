//! Time, as the caller gives it.
//!
//! The core reads no clock (`DESIGN.md §2`). Every
//! state machine takes the current [`Instant`] from its caller and returns the
//! next deadline it cares about, so a test drives it with a virtual clock and a
//! microcontroller with its own timer.

use core::time::Duration;

/// A point in time: milliseconds since an epoch the caller chooses and keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Instant(u64);

impl Instant {
    /// The instant `millis` milliseconds after the caller's epoch.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the caller's epoch.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// `self + duration`, saturating rather than wrapping.
    #[must_use]
    pub fn saturating_add(self, duration: Duration) -> Self {
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(millis))
    }
}
