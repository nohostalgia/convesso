//! The `provision` example: an embedded device is given its identity, and
//! never makes one (`DESIGN.md §5`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../examples/provision.rs"]
#[allow(dead_code, unreachable_pub, missing_docs)]
mod provision;

/// Scenario: a provisioned device has the identity it was given. The record
/// the tool writes, read by the driver's reader, gives the key file's address.
#[test]
fn a_record_gives_the_key_files_identity() {
    let dir = std::env::temp_dir().join(format!("convesso-provision-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("device.key");
    let out = dir.join("device.record");
    let _ = std::fs::remove_file(&key);
    let (identity, created) = convesso_tokio::identity::load_or_create(&key).unwrap();
    assert!(created);
    let args = provision::parse_args(&[
        "--key".into(),
        key.display().to_string(),
        "--out".into(),
        out.display().to_string(),
    ])
    .unwrap();
    let hex = provision::run(&args).unwrap();
    let record: [u8; 64] = std::fs::read(&out).unwrap().try_into().unwrap();
    let device = convesso_embassy::record::identity(&record).unwrap();
    assert_eq!(device.address(), identity.address());
    assert_eq!(hex.len(), 64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "readable by its owner only");
    }
    assert!(provision::parse_args(&["--key".into(), "x".into()]).is_err());
}
