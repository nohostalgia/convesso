//! An identity kept in a file: a 32-byte Ed25519 seed, created from the
//! operating system's generator on first use, readable only by its owner.
//!
//! On Unix the file is created with mode 0600, and a file that its group or
//! others can read is refused. Elsewhere it is created in the place the caller
//! chooses, usually the user's profile, whose access list admits only the user;
//! the file's own access list is not inspected.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use convesso_core::identity::Identity;

/// Why an identity file could not be used.
#[derive(Debug)]
pub enum IdentityFileError {
    /// Reading or writing it failed.
    Io(io::Error),
    /// It is not 32 bytes.
    WrongLength(usize),
    /// Its group or others can read it (Unix).
    ReadableByOthers,
    /// The generator failed.
    Entropy(String),
    /// The seed gives no usable identity.
    Invalid,
}

impl std::fmt::Display for IdentityFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "the identity file: {error}"),
            Self::WrongLength(len) => {
                write!(f, "the identity file holds {len} bytes, not a 32-byte seed")
            }
            Self::ReadableByOthers => f.write_str(
                "the identity file can be read by others than its owner; make it mode 0600",
            ),
            Self::Entropy(error) => write!(f, "the operating system's generator failed: {error}"),
            Self::Invalid => f.write_str("the identity file's seed gives no usable identity"),
        }
    }
}

impl std::error::Error for IdentityFileError {}

impl From<io::Error> for IdentityFileError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Loads the identity in `path`, or creates it there. Returns the identity and
/// whether it was created.
///
/// # Errors
///
/// An [`IdentityFileError`] when the file cannot be read, written, or trusted.
pub fn load_or_create(path: &Path) -> Result<(Identity, bool), IdentityFileError> {
    match fs::read(path) {
        Ok(seed) => {
            check_permissions(path)?;
            let seed: [u8; 32] = seed
                .as_slice()
                .try_into()
                .map_err(|_| IdentityFileError::WrongLength(seed.len()))?;
            let identity =
                Identity::from_ed25519_seed(&seed).map_err(|_| IdentityFileError::Invalid)?;
            Ok((identity, false))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| IdentityFileError::Entropy(e.to_string()))?;
            write_private(path, &seed)?;
            let identity =
                Identity::from_ed25519_seed(&seed).map_err(|_| IdentityFileError::Invalid)?;
            Ok((identity, true))
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn write_private(path: &Path, seed: &[u8; 32]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(seed)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, seed: &[u8; 32]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(seed)?;
    file.sync_all()
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), IdentityFileError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(IdentityFileError::ReadableByOthers);
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the same signature as on Unix, where it can fail"
)]
fn check_permissions(_path: &Path) -> Result<(), IdentityFileError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("convesso-identity-{}-{name}", std::process::id()));
        let _ = fs::remove_file(&dir);
        dir
    }

    #[test]
    fn a_first_use_creates_and_a_second_loads_the_same() {
        let path = scratch("create");
        let (first, created) = load_or_create(&path).unwrap();
        assert!(created);
        let (second, created) = load_or_create(&path).unwrap();
        assert!(!created);
        assert_eq!(first.address(), second.address());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_file_of_the_wrong_length_is_refused() {
        let path = scratch("length");
        fs::write(&path, [1u8; 31]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            load_or_create(&path),
            Err(IdentityFileError::WrongLength(31))
        ));
        fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = scratch("open");
        load_or_create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_or_create(&path),
            Err(IdentityFileError::ReadableByOthers)
        ));
        fs::remove_file(&path).unwrap();
    }
}
