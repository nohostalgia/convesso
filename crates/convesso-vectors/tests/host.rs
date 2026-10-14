//! The vectors on the host. The embedded targets run the same function under
//! emulation (`firmware/src/bin/vectors.rs`).

#![allow(missing_docs, clippy::panic)]

#[test]
fn every_official_vector_passes() {
    match convesso_vectors::run_all() {
        Ok(checked) => assert!(checked > 0),
        Err(failure) => panic!("{failure}"),
    }
}
