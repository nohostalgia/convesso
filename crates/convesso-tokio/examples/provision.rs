//! `provision`: writes the 64-byte provisioning record of a key file, for an
//! embedded device, which is given its identity and never makes one
//! (`DESIGN.md §5`).
//!
//! ```text
//! cargo run -p convesso-tokio --example provision -- --key device.key --out device.record
//! ```
//!
//! The key file is the tokio driver's (an Ed25519 seed); it is created if it
//! does not exist. The record is the X25519 scalar, then the address: the
//! scalar is derived here, on the host, so the device needs neither SHA-512
//! nor Ed25519 code. The record holds the private key: whoever reads it has
//! the device's identity. Store it where only the device can read it.

use std::path::{Path, PathBuf};

use convesso_embassy::record;
use convesso_tokio::identity::load_or_create;

/// What the command line gives.
#[derive(Debug, Clone)]
pub struct Args {
    /// The key file.
    pub key: PathBuf,
    /// Where to write the record.
    pub out: PathBuf,
}

/// Parses the command line, without the program's name.
///
/// # Errors
///
/// A message naming what is wrong.
pub fn parse_args(args: &[String]) -> Result<Args, String> {
    let (mut key, mut out) = (None, None);
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--key" => key = Some(PathBuf::from(value)),
            "--out" => out = Some(PathBuf::from(value)),
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(Args {
        key: key.ok_or("--key is needed")?,
        out: out.ok_or("--out is needed")?,
    })
}

/// Writes the record of `args.key` to `args.out`; returns the address, in hex.
///
/// # Errors
///
/// A message when the key file cannot be read or the record written.
pub fn run(args: &Args) -> Result<String, String> {
    let (identity, _) = load_or_create(&args.key).map_err(|e| e.to_string())?;
    let seed: [u8; 32] = std::fs::read(&args.key)
        .map_err(|e| e.to_string())?
        .as_slice()
        .try_into()
        .map_err(|_| "the key file is not a 32-byte seed".to_string())?;
    let scalar = ed25519_dalek::SigningKey::from_bytes(&seed).to_scalar_bytes();
    let bytes = record::write(&scalar, identity.address());
    // The record is checked as the device will read it before it is written.
    let check = record::identity(&bytes).map_err(|e| e.to_string())?;
    if check.address() != identity.address() {
        return Err("the record does not give the key file's address".into());
    }
    write_private(&args.out, &bytes).map_err(|e| e.to_string())?;
    Ok(identity
        .address()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[allow(dead_code, reason = "the tests include this file and call `run`")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = parse_args(&args).and_then(|args| {
        let address = run(&args)?;
        Ok((address, args.out))
    });
    match result {
        Ok((address, out)) => {
            println!("address {address}");
            println!(
                "wrote {}: it holds the private key; store it where only the device can read it",
                out.display()
            );
        }
        Err(error) => {
            eprintln!("provision: {error}");
            std::process::exit(1);
        }
    }
}
