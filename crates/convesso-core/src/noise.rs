//! The one Noise instance convesso speaks: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`,
//! as revision 34 of the Noise Protocol Framework specifies it.
//!
//! No pattern table, no resolver, no choice at runtime: every function below
//! is a step of IKpsk2 with X25519, ChaCha20-Poly1305 and BLAKE2s, named as the
//! specification names it, so that it can be read against §5 (processing
//! rules), §7 (IK) and §9 (`psk2`) line by line. It is checked against the
//! official vectors, byte for byte against `snow`, and by interoperating with
//! `snow` in both roles.
//!
//! ```text
//! IKpsk2:
//!   <- s
//!   ...
//!   -> e, es, s, ss
//!   <- e, ee, se, psk
//! ```
//!
//! With a PSK modifier, every `e` token also calls `MixKey(e.public_key)` (§9.2).

use blake2::Blake2s256;
use blake2::digest::{Digest, KeyInit, Mac};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hmac::SimpleHmac;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// `HASHLEN` for BLAKE2s.
pub(crate) const HASHLEN: usize = 32;
/// `DHLEN` for X25519.
pub(crate) const DHLEN: usize = 32;
/// The AEAD tag length.
pub(crate) const TAGLEN: usize = 16;

const PROTOCOL_NAME: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// Why a Noise step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoiseError {
    /// A ciphertext did not authenticate.
    Decrypt,
    /// A Diffie-Hellman result was all zeros: the peer's key has small order.
    ZeroDh,
    /// An output buffer was too small, or an input too short.
    Length,
    /// The nonce reached its reserved maximum.
    NonceExhausted,
}

fn hash(parts: &[&[u8]]) -> [u8; HASHLEN] {
    let mut hasher = Blake2s256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn hmac(key: &[u8; HASHLEN], parts: &[&[u8]]) -> [u8; HASHLEN] {
    // HMAC pads a key shorter than the hash's block (64 bytes for BLAKE2s) with
    // zeros (RFC 2104 §2), so the padded key gives the same MAC through the
    // fixed-size constructor, which cannot fail.
    let mut block = [0u8; 64];
    block[..HASHLEN].copy_from_slice(key);
    let mut mac = <SimpleHmac<Blake2s256> as KeyInit>::new(&block.into());
    block.zeroize();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// `HKDF(chaining_key, input_key_material, 3)` (§4.3); callers take the
/// outputs they need.
fn hkdf3(chaining_key: &[u8; HASHLEN], ikm: &[u8]) -> [[u8; HASHLEN]; 3] {
    let mut temp = hmac(chaining_key, &[ikm]);
    let out1 = hmac(&temp, &[&[0x01]]);
    let out2 = hmac(&temp, &[&out1, &[0x02]]);
    let out3 = hmac(&temp, &[&out2, &[0x03]]);
    temp.zeroize();
    [out1, out2, out3]
}

fn dh(secret: &StaticSecret, public: &[u8; DHLEN]) -> Result<[u8; DHLEN], NoiseError> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(NoiseError::ZeroDh);
    }
    Ok(shared.to_bytes())
}

/// A `CipherState` (§5.1): a key, or none, and a nonce.
pub(crate) struct CipherState {
    k: Option<[u8; 32]>,
    n: u64,
}

impl Drop for CipherState {
    fn drop(&mut self) {
        if let Some(k) = self.k.as_mut() {
            k.zeroize();
        }
    }
}

impl CipherState {
    const fn empty() -> Self {
        Self { k: None, n: 0 }
    }

    /// The raw key, for transport packets that carry their own nonce.
    pub(crate) const fn key(&self) -> Option<[u8; 32]> {
        self.k
    }

    fn with_key(k: [u8; 32]) -> Self {
        Self { k: Some(k), n: 0 }
    }

    /// ChaChaPoly's nonce: 32 bits of zeros, then `n` little-endian (§12.3).
    fn nonce(n: u64) -> Nonce {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&n.to_le_bytes());
        Nonce::from(nonce)
    }

    fn next_nonce(&mut self) -> Result<u64, NoiseError> {
        // 2^64 − 1 is reserved (§5.1).
        if self.n == u64::MAX {
            return Err(NoiseError::NonceExhausted);
        }
        let n = self.n;
        self.n += 1;
        Ok(n)
    }

    /// `EncryptWithAd`: encrypts `buffer[..len]` in place and appends the tag,
    /// returning the ciphertext length. Without a key, the plaintext is the
    /// ciphertext.
    pub(crate) fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        buffer: &mut [u8],
        len: usize,
    ) -> Result<usize, NoiseError> {
        let Some(k) = self.k else {
            return Ok(len);
        };
        let total = len.checked_add(TAGLEN).ok_or(NoiseError::Length)?;
        let buffer = buffer.get_mut(..total).ok_or(NoiseError::Length)?;
        let n = self.next_nonce()?;
        let (text, tag_out) = buffer.split_at_mut(len);
        let tag = ChaCha20Poly1305::new(&Key::from(k))
            .encrypt_inout_detached(&Self::nonce(n), ad, text.into())
            .map_err(|_| NoiseError::Length)?;
        tag_out.copy_from_slice(&tag);
        Ok(total)
    }

    /// `DecryptWithAd`: decrypts `buffer` (ciphertext and tag) in place,
    /// returning the plaintext length. The nonce advances only on success, so
    /// a forged message cannot desynchronise the state.
    pub(crate) fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, NoiseError> {
        let Some(k) = self.k else {
            return Ok(buffer.len());
        };
        let len = buffer
            .len()
            .checked_sub(TAGLEN)
            .ok_or(NoiseError::Decrypt)?;
        if self.n == u64::MAX {
            return Err(NoiseError::NonceExhausted);
        }
        let (text, tag) = buffer.split_at_mut(len);
        let tag = Tag::try_from(&*tag).map_err(|_| NoiseError::Decrypt)?;
        ChaCha20Poly1305::new(&Key::from(k))
            .decrypt_inout_detached(&Self::nonce(self.n), ad, text.into(), &tag)
            .map_err(|_| NoiseError::Decrypt)?;
        self.n += 1;
        Ok(len)
    }
}

/// A `SymmetricState` (§5.2).
struct SymmetricState {
    ck: [u8; HASHLEN],
    h: [u8; HASHLEN],
    cipher: CipherState,
}

impl Drop for SymmetricState {
    fn drop(&mut self) {
        self.ck.zeroize();
    }
}

impl SymmetricState {
    /// `InitializeSymmetric(protocol_name)`: the name is longer than
    /// `HASHLEN`, so `h = HASH(protocol_name)`; then `MixHash(prologue)`.
    fn new(prologue: &[u8]) -> Self {
        let h = hash(&[PROTOCOL_NAME]);
        let mut state = Self {
            ck: h,
            h,
            cipher: CipherState::empty(),
        };
        state.mix_hash(prologue);
        state
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash(&[&self.h, data]);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let [ck, temp_k, _] = hkdf3(&self.ck, ikm);
        self.ck = ck;
        self.cipher = CipherState::with_key(temp_k);
    }

    fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let [ck, temp_h, temp_k] = hkdf3(&self.ck, ikm);
        self.ck = ck;
        self.mix_hash(&temp_h);
        self.cipher = CipherState::with_key(temp_k);
    }

    /// `EncryptAndHash` over `buffer[..len]`, returning the ciphertext length.
    fn encrypt_and_hash(&mut self, buffer: &mut [u8], len: usize) -> Result<usize, NoiseError> {
        let h = self.h;
        let total = self.cipher.encrypt_with_ad(&h, buffer, len)?;
        let ciphertext = buffer.get(..total).ok_or(NoiseError::Length)?;
        self.mix_hash(ciphertext);
        Ok(total)
    }

    /// `DecryptAndHash` over `buffer` in place, returning the plaintext length.
    fn decrypt_and_hash(&mut self, buffer: &mut [u8]) -> Result<usize, NoiseError> {
        let h = self.h;
        let next_h = hash(&[&h, buffer]);
        let len = self.cipher.decrypt_with_ad(&h, buffer)?;
        self.h = next_h;
        Ok(len)
    }

    /// `Split()`: the two transport `CipherState`s, for the initiator's sending
    /// and the responder's sending direction.
    fn split(&self) -> (CipherState, CipherState) {
        let [k1, k2, _] = hkdf3(&self.ck, &[]);
        (CipherState::with_key(k1), CipherState::with_key(k2))
    }

    /// Runs an `e` token received or sent: `MixHash`, then `MixKey` (PSK modifier).
    fn mix_ephemeral(&mut self, e: &[u8; DHLEN]) {
        self.mix_hash(e);
        self.mix_key(e);
    }
}

/// The two transport directions after `Split()`, from one side's point of view.
#[allow(
    dead_code,
    reason = "consumed by the sessions; until then only tests read them"
)]
pub(crate) struct Transport {
    pub(crate) send: CipherState,
    pub(crate) recv: CipherState,
}

/// What a completed handshake leaves: the transport ciphers and the handshake
/// hash, which is the channel binding.
#[allow(
    dead_code,
    reason = "the transport ciphers are consumed by the sessions"
)]
pub(crate) struct Completed {
    pub(crate) transport: Transport,
    pub(crate) handshake_hash: [u8; HASHLEN],
}

/// The initiator after writing `-> e, es, s, ss`, waiting for the response.
pub(crate) struct InitiatorAwaiting {
    state: SymmetricState,
    e: StaticSecret,
}

/// The responder after reading `-> e, es, s, ss`.
pub(crate) struct ResponderRead {
    state: SymmetricState,
    re: [u8; DHLEN],
    rs: [u8; DHLEN],
}

impl ResponderRead {
    /// The initiator's static public key, as decrypted.
    pub(crate) const fn remote_static(&self) -> &[u8; DHLEN] {
        &self.rs
    }
}

/// Initiator: `<- s` known, writes `-> e, es, s, ss` and the payload into `out`
/// (`e || encrypted s || encrypted payload`), returning its length.
pub(crate) fn write_initiation(
    s: &StaticSecret,
    rs: &[u8; DHLEN],
    e: StaticSecret,
    prologue: &[u8],
    payload: &[u8],
    out: &mut [u8],
) -> Result<(InitiatorAwaiting, usize), NoiseError> {
    let presented = PublicKey::from(s).to_bytes();
    write_initiation_presenting(s, &presented, rs, e, prologue, payload, out)
}

/// [`write_initiation`], sending `presented` as the static key while computing
/// `ss` with `s`. Only tests use another key than `s`'s own: it is how a test
/// presents an encoding X25519 treats as equal, which a responder must refuse.
pub(crate) fn write_initiation_presenting(
    s: &StaticSecret,
    presented: &[u8; DHLEN],
    rs: &[u8; DHLEN],
    e: StaticSecret,
    prologue: &[u8],
    payload: &[u8],
    out: &mut [u8],
) -> Result<(InitiatorAwaiting, usize), NoiseError> {
    let mut state = SymmetricState::new(prologue);
    state.mix_hash(rs);

    let e_pub = PublicKey::from(&e).to_bytes();
    let out_e = out.get_mut(..DHLEN).ok_or(NoiseError::Length)?;
    out_e.copy_from_slice(&e_pub);
    state.mix_ephemeral(&e_pub);

    state.mix_key(&dh(&e, rs)?);

    let rest = out.get_mut(DHLEN..).ok_or(NoiseError::Length)?;
    let s_field = rest.get_mut(..DHLEN).ok_or(NoiseError::Length)?;
    s_field.copy_from_slice(presented);
    let s_len = state.encrypt_and_hash(rest, DHLEN)?;

    state.mix_key(&dh(s, rs)?);

    let rest = rest.get_mut(s_len..).ok_or(NoiseError::Length)?;
    let payload_field = rest.get_mut(..payload.len()).ok_or(NoiseError::Length)?;
    payload_field.copy_from_slice(payload);
    let payload_len = state.encrypt_and_hash(rest, payload.len())?;

    Ok((InitiatorAwaiting { state, e }, DHLEN + s_len + payload_len))
}

/// Responder: the `es` Diffie-Hellman of a received first message, which does
/// not depend on the prologue and so is computed once for every context tried.
pub(crate) fn initiation_es(
    s: &StaticSecret,
    message: &[u8],
) -> Result<([u8; DHLEN], [u8; DHLEN]), NoiseError> {
    let re: [u8; DHLEN] = message
        .get(..DHLEN)
        .and_then(|e| e.try_into().ok())
        .ok_or(NoiseError::Length)?;
    Ok((re, dh(s, &re)?))
}

/// Responder: reads `-> e, es, s, ss` and the payload, under one prologue, given
/// the `es` result from [`initiation_es`]. `message` is
/// `e || encrypted s || encrypted payload`; it is decrypted in place, and the
/// payload's plaintext length is returned.
pub(crate) fn read_initiation(
    s: &StaticSecret,
    prologue: &[u8],
    re: &[u8; DHLEN],
    es: &[u8; DHLEN],
    message: &mut [u8],
) -> Result<(ResponderRead, usize), NoiseError> {
    let mut state = SymmetricState::new(prologue);
    state.mix_hash(PublicKey::from(s).as_bytes());
    state.mix_ephemeral(re);
    state.mix_key(es);

    let rest = message.get_mut(DHLEN..).ok_or(NoiseError::Length)?;
    let (s_field, payload) = rest
        .split_at_mut_checked(DHLEN + TAGLEN)
        .ok_or(NoiseError::Length)?;
    state.decrypt_and_hash(s_field)?;
    let rs: [u8; DHLEN] = s_field
        .get(..DHLEN)
        .and_then(|k| k.try_into().ok())
        .ok_or(NoiseError::Length)?;

    state.mix_key(&dh(s, &rs)?);

    let payload_len = state.decrypt_and_hash(payload)?;
    Ok((ResponderRead { state, re: *re, rs }, payload_len))
}

/// Responder: writes `<- e, ee, se, psk` and the payload into `out`
/// (`e || encrypted payload`), returning the completed handshake and the length.
pub(crate) fn write_response(
    read: ResponderRead,
    e: &StaticSecret,
    psk: &[u8; 32],
    payload: &[u8],
    out: &mut [u8],
) -> Result<(Completed, usize), NoiseError> {
    let ResponderRead { mut state, re, rs } = read;

    let e_pub = PublicKey::from(e).to_bytes();
    let out_e = out.get_mut(..DHLEN).ok_or(NoiseError::Length)?;
    out_e.copy_from_slice(&e_pub);
    state.mix_ephemeral(&e_pub);

    state.mix_key(&dh(e, &re)?);
    state.mix_key(&dh(e, &rs)?);
    state.mix_key_and_hash(psk);

    let rest = out.get_mut(DHLEN..).ok_or(NoiseError::Length)?;
    let payload_field = rest.get_mut(..payload.len()).ok_or(NoiseError::Length)?;
    payload_field.copy_from_slice(payload);
    let payload_len = state.encrypt_and_hash(rest, payload.len())?;

    let (initiator_to_responder, responder_to_initiator) = state.split();
    Ok((
        Completed {
            transport: Transport {
                send: responder_to_initiator,
                recv: initiator_to_responder,
            },
            handshake_hash: state.h,
        },
        DHLEN + payload_len,
    ))
}

/// Initiator: reads `<- e, ee, se, psk` and the payload. `message` is
/// `e || encrypted payload`, decrypted in place; the payload's plaintext length
/// is returned. The awaiting state is consumed only on success, so a forged
/// response leaves it intact for the genuine one.
pub(crate) fn read_response(
    awaiting: &InitiatorAwaiting,
    s: &StaticSecret,
    psk: &[u8; 32],
    message: &mut [u8],
) -> Result<(Completed, usize), NoiseError> {
    let InitiatorAwaiting { state, e } = awaiting;
    let mut state = SymmetricState {
        ck: state.ck,
        h: state.h,
        cipher: CipherState {
            k: state.cipher.k,
            n: state.cipher.n,
        },
    };

    let re: [u8; DHLEN] = message
        .get(..DHLEN)
        .and_then(|e| e.try_into().ok())
        .ok_or(NoiseError::Length)?;
    state.mix_ephemeral(&re);
    state.mix_key(&dh(e, &re)?);
    state.mix_key(&dh(s, &re)?);
    state.mix_key_and_hash(psk);

    let payload = message.get_mut(DHLEN..).ok_or(NoiseError::Length)?;
    let payload_len = state.decrypt_and_hash(payload)?;

    let (initiator_to_responder, responder_to_initiator) = state.split();
    Ok((
        Completed {
            transport: Transport {
                send: initiator_to_responder,
                recv: responder_to_initiator,
            },
            handshake_hash: state.h,
        },
        payload_len,
    ))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod tests_support {
    /// BLAKE2s-256, for test fixtures.
    pub(crate) fn hash(data: &[u8]) -> [u8; 32] {
        super::hash(&[data])
    }
}
