//! The official test vectors of the primitives convesso is built on, as a
//! function that runs anywhere the core runs.
//!
//! `no_std` and without an allocator, so the same checks run on the host as a
//! test and on each embedded target under emulation. A crate that computes the
//! right answer on x86 and the wrong one on a Cortex-M is exactly what this
//! exists to catch.
//!
//! - X25519: RFC 7748, §5.2 (two single vectors, 1 and 1,000 iterations) and
//!   §6.1 (the Diffie-Hellman exchange).
//! - ChaCha20-Poly1305: RFC 8439, §2.8.2 (encryption) and §A.5 (decryption),
//!   plus a refused forgery.
//! - XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03, §A.3.1, plus a refused
//!   forgery.
//! - BLAKE2s: RFC 7693, Appendix B ("abc") and Appendix E (the self-test's
//!   grand hash over keyed and unkeyed hashes of four output sizes).
//! - HMAC-BLAKE2s, which Noise derives its keys with: no RFC publishes
//!   vectors, so they come from an independent implementation (see
//!   `generate.py`), including a key that the HMAC block-size bug of
//!   RUSTSEC-2019-0019 would have hashed.

#![no_std]
#![forbid(unsafe_code)]

#[rustfmt::skip]
mod generated;

use blake2::digest::consts::{U16, U20, U28, U32};
use blake2::digest::{Digest, Mac};
use blake2::{Blake2s, Blake2s256, Blake2sMac};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag, XChaCha20Poly1305, XNonce};
use generated::*;
use hmac::SimpleHmac;
use x25519_dalek::{PublicKey, StaticSecret, X25519_BASEPOINT_BYTES, x25519};

/// A vector a primitive did not reproduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// The primitive that disagreed.
    pub primitive: &'static str,
    /// The vector it disagreed with.
    pub vector: &'static str,
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}: output differs from vector {}",
            self.primitive, self.vector
        )
    }
}

/// Runs every vector, stopping at the first that fails.
///
/// Returns how many vectors were checked.
///
/// # Errors
///
/// The first vector a primitive did not reproduce.
pub fn run_all() -> Result<usize, Failure> {
    let mut checked = 0;
    checked += x25519_vectors()?;
    checked += aead_vectors()?;
    checked += xchacha_vectors()?;
    checked += blake2s_vectors()?;
    checked += hmac_blake2s_vectors()?;
    Ok(checked)
}

fn check(ok: bool, primitive: &'static str, vector: &'static str) -> Result<usize, Failure> {
    if ok {
        Ok(1)
    } else {
        Err(Failure { primitive, vector })
    }
}

/// A generated constant as a fixed-size array. A wrong length is reported as
/// the vector failing, never as a panic.
fn array<const N: usize>(
    bytes: &[u8],
    primitive: &'static str,
    vector: &'static str,
) -> Result<[u8; N], Failure> {
    bytes.try_into().map_err(|_| Failure { primitive, vector })
}

const X25519: &str = "X25519";

fn x25519_vectors() -> Result<usize, Failure> {
    let mut checked = 0;

    for (vector, scalar, u, out) in [
        (
            "RFC 7748 5.2, vector 1",
            X25519_1_SCALAR,
            X25519_1_U,
            X25519_1_OUT,
        ),
        (
            "RFC 7748 5.2, vector 2",
            X25519_2_SCALAR,
            X25519_2_U,
            X25519_2_OUT,
        ),
    ] {
        let result = x25519(array(scalar, X25519, vector)?, array(u, X25519, vector)?);
        checked += check(result.as_slice() == out, X25519, vector)?;
    }

    // Each iteration sets k to the result and u to the old k.
    let (mut k, mut u) = (X25519_BASEPOINT_BYTES, X25519_BASEPOINT_BYTES);
    for iteration in 1..=1000 {
        (k, u) = (x25519(k, u), k);
        if iteration == 1 {
            checked += check(
                k.as_slice() == X25519_ITERATED_1,
                X25519,
                "RFC 7748 5.2, after one iteration",
            )?;
        }
    }
    checked += check(
        k.as_slice() == X25519_ITERATED_1000,
        X25519,
        "RFC 7748 5.2, after 1,000 iterations",
    )?;

    let vector = "RFC 7748 6.1, Diffie-Hellman";
    let alice = StaticSecret::from(array::<32>(X25519_ALICE_PRIVATE, X25519, vector)?);
    let bob = StaticSecret::from(array::<32>(X25519_BOB_PRIVATE, X25519, vector)?);
    let alice_public = PublicKey::from(&alice);
    let bob_public = PublicKey::from(&bob);
    checked += check(
        alice_public.as_bytes().as_slice() == X25519_ALICE_PUBLIC
            && bob_public.as_bytes().as_slice() == X25519_BOB_PUBLIC,
        X25519,
        vector,
    )?;
    checked += check(
        alice.diffie_hellman(&bob_public).as_bytes().as_slice() == X25519_SHARED
            && bob.diffie_hellman(&alice_public).as_bytes().as_slice() == X25519_SHARED,
        X25519,
        vector,
    )?;

    Ok(checked)
}

const AEAD: &str = "ChaCha20-Poly1305";

fn aead_vectors() -> Result<usize, Failure> {
    let mut checked = 0;

    let vector = "RFC 8439 2.8.2, encryption";
    let cipher = ChaCha20Poly1305::new(&Key::from(array::<32>(AEAD_ENCRYPT_KEY, AEAD, vector)?));
    let nonce = Nonce::from(array::<12>(AEAD_ENCRYPT_NONCE, AEAD, vector)?);
    let mut buffer = array::<114>(AEAD_ENCRYPT_PLAINTEXT, AEAD, vector)?;
    let tag = cipher
        .encrypt_inout_detached(&nonce, AEAD_ENCRYPT_AAD, buffer.as_mut_slice().into())
        .map_err(|_| Failure {
            primitive: AEAD,
            vector,
        })?;
    checked += check(
        buffer.as_slice() == AEAD_ENCRYPT_CIPHERTEXT && tag.as_slice() == AEAD_ENCRYPT_TAG,
        AEAD,
        vector,
    )?;

    let vector = "RFC 8439 A.5, decryption";
    let cipher = ChaCha20Poly1305::new(&Key::from(array::<32>(AEAD_DECRYPT_KEY, AEAD, vector)?));
    let nonce = Nonce::from(array::<12>(AEAD_DECRYPT_NONCE, AEAD, vector)?);
    let tag = Tag::from(array::<16>(AEAD_DECRYPT_TAG, AEAD, vector)?);
    let mut buffer = array::<265>(AEAD_DECRYPT_CIPHERTEXT, AEAD, vector)?;
    let opened =
        cipher.decrypt_inout_detached(&nonce, AEAD_DECRYPT_AAD, buffer.as_mut_slice().into(), &tag);
    checked += check(
        opened.is_ok() && buffer.as_slice() == AEAD_DECRYPT_PLAINTEXT,
        AEAD,
        vector,
    )?;

    // The same ciphertext with one bit of the tag changed must be refused.
    let vector = "RFC 8439 A.5, with a forged tag";
    let mut forged = array::<16>(AEAD_DECRYPT_TAG, AEAD, vector)?;
    forged[0] ^= 1;
    let mut buffer = array::<265>(AEAD_DECRYPT_CIPHERTEXT, AEAD, vector)?;
    let opened = cipher.decrypt_inout_detached(
        &nonce,
        AEAD_DECRYPT_AAD,
        buffer.as_mut_slice().into(),
        &Tag::from(forged),
    );
    checked += check(opened.is_err(), AEAD, vector)?;

    Ok(checked)
}

const XAEAD: &str = "XChaCha20-Poly1305";

fn xchacha_vectors() -> Result<usize, Failure> {
    let vector = "draft-irtf-cfrg-xchacha-03 A.3.1";
    let cipher = XChaCha20Poly1305::new(&Key::from(array::<32>(XAEAD_KEY, XAEAD, vector)?));
    let nonce = XNonce::from(array::<24>(XAEAD_NONCE, XAEAD, vector)?);
    let mut buffer = array::<114>(XAEAD_PLAINTEXT, XAEAD, vector)?;
    let tag = cipher
        .encrypt_inout_detached(&nonce, XAEAD_AAD, buffer.as_mut_slice().into())
        .map_err(|_| Failure {
            primitive: XAEAD,
            vector,
        })?;
    let mut checked = check(
        buffer.as_slice() == XAEAD_CIPHERTEXT && tag.as_slice() == XAEAD_TAG,
        XAEAD,
        vector,
    )?;

    let vector = "draft-irtf-cfrg-xchacha-03 A.3.1, with a forged tag";
    let mut forged = array::<16>(XAEAD_TAG, XAEAD, vector)?;
    forged[0] ^= 1;
    let mut buffer = array::<114>(XAEAD_CIPHERTEXT, XAEAD, vector)?;
    let opened = cipher.decrypt_inout_detached(
        &nonce,
        XAEAD_AAD,
        buffer.as_mut_slice().into(),
        &Tag::from(forged),
    );
    checked += check(opened.is_err(), XAEAD, vector)?;
    Ok(checked)
}

const BLAKE2S: &str = "BLAKE2s";

fn blake2s_vectors() -> Result<usize, Failure> {
    let mut checked = check(
        Blake2s256::digest(b"abc").as_slice() == BLAKE2S_256_ABC,
        BLAKE2S,
        "RFC 7693 Appendix B, \"abc\"",
    )?;

    // RFC 7693 Appendix E, `blake2s_selftest`, step for step.
    let vector = "RFC 7693 Appendix E, self-test grand hash";
    let mut grand = Blake2s256::new();
    let mut input = [0u8; 1024];
    let mut key = [0u8; 32];
    macro_rules! with_output_size {
        ($size:ty, $len:expr) => {
            for inlen in [0usize, 3, 64, 65, 255, 1024] {
                let input = input.get_mut(..inlen).ok_or(Failure {
                    primitive: BLAKE2S,
                    vector,
                })?;
                selftest_seq(input, inlen);
                grand.update(Blake2s::<$size>::digest(&*input));
                let key = key.get_mut(..$len).ok_or(Failure {
                    primitive: BLAKE2S,
                    vector,
                })?;
                selftest_seq(key, $len);
                let mut mac =
                    <Blake2sMac<$size> as KeyInit>::new_from_slice(key).map_err(|_| Failure {
                        primitive: BLAKE2S,
                        vector,
                    })?;
                Mac::update(&mut mac, input);
                grand.update(mac.finalize().into_bytes());
            }
        };
    }
    with_output_size!(U16, 16);
    with_output_size!(U20, 20);
    with_output_size!(U28, 28);
    with_output_size!(U32, 32);
    checked += check(
        grand.finalize().as_slice() == BLAKE2S_SELFTEST_GRAND_HASH,
        BLAKE2S,
        vector,
    )?;

    Ok(checked)
}

/// RFC 7693 Appendix E's deterministic sequence (a Fibonacci generator).
fn selftest_seq(out: &mut [u8], seed: usize) {
    // `seed` is at most 1,024 here; the C reference takes it as a `uint32_t`.
    let mut a = 0xDEAD_4BAD_u32.wrapping_mul(u32::try_from(seed).unwrap_or(u32::MAX));
    let mut b = 1u32;
    for byte in out {
        let t = a.wrapping_add(b);
        a = b;
        b = t;
        *byte = t.to_be_bytes()[0];
    }
}

const HMAC_BLAKE2S_NAME: &str = "HMAC-BLAKE2s";

fn hmac_blake2s_vectors() -> Result<usize, Failure> {
    let mut checked = 0;
    for &(vector, key, data, expected) in HMAC_BLAKE2S {
        let mut mac =
            <SimpleHmac<Blake2s256> as KeyInit>::new_from_slice(key).map_err(|_| Failure {
                primitive: HMAC_BLAKE2S_NAME,
                vector,
            })?;
        Mac::update(&mut mac, data);
        checked += check(
            mac.finalize().into_bytes().as_slice() == expected,
            HMAC_BLAKE2S_NAME,
            vector,
        )?;
    }
    Ok(checked)
}
