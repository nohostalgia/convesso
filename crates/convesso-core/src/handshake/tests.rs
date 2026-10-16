//! The handshake's scenarios (`PROTOCOL.md §3`), driven by a virtual clock and a
//! deterministic entropy source. Inside the crate, because some of them compare
//! the transport keys the two sides derived.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::vec;
use std::vec::Vec;

use serde_json::Value;
use x25519_dalek::StaticSecret;

use super::messages::{
    self, DecisionError, INITIATION_NOISE_LEN, MessageError, RESPONSE_NOISE_LEN, WireDecision,
};
use super::*;
use crate::dos::Source;
use crate::identity::{Address, Identity, PeerId};
use crate::noise::{self, CipherState};
use crate::storage::Mcu;
use crate::time::Instant;
use crate::wire::{Mac1Key, Version, VersionNotSupported};

// --- fixtures ---------------------------------------------------------------

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../vectors/identity.json")).unwrap()
}

fn bytes32(value: &Value) -> [u8; 32] {
    let text = value.as_str().unwrap();
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

/// The identity of the `i`-th key in the vectors.
fn identity(i: usize) -> Identity {
    let key = &vectors()["keys"][i];
    Identity::from_parts(
        bytes32(&key["x25519_scalar"]),
        Address::parse(bytes32(&key["address"])).unwrap(),
    )
    .unwrap()
}

/// Deterministic, never repeating within a test: BLAKE2s of a counter.
struct TestEntropy(u64);

impl Entropy for TestEntropy {
    fn fill(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            self.0 += 1;
            let block = crate::noise::tests_support::hash(&self.0.to_le_bytes());
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

/// Admission that answers with a fixed decision and counts how often it is asked.
struct Fixed {
    decision: Decision,
    asked: usize,
    last: Option<PeerId>,
}

impl Fixed {
    fn accept() -> Self {
        Self::with(Decision::Accept { psk: None })
    }
    fn with(decision: Decision) -> Self {
        Self {
            decision,
            asked: 0,
            last: None,
        }
    }
}

impl Admission for Fixed {
    fn admit(&mut self, peer: &PeerId, _context: &[u8]) -> Decision {
        self.asked += 1;
        self.last = Some(*peer);
        self.decision
    }
}

const CONTEXT: &[u8] = b"session";

/// The source every test packet arrives from, unless a test says otherwise.
const SOURCE: Source<'static> = Source::Direct(&[192, 0, 2, 1, 0xCA, 0x6C]);
const RESPONDER: usize = 0;
const INITIATOR: usize = 1;

fn t(millis: u64) -> Instant {
    Instant::from_millis(millis)
}

fn responder() -> Responder<Mcu> {
    Responder::new(identity(RESPONDER), &[CONTEXT]).unwrap()
}

fn responder_address() -> Address {
    *identity(RESPONDER).address()
}

/// Starts a dial from `INITIATOR` to the responder; returns it and its first contact.
fn dial(entropy: &mut TestEntropy, psk: Option<Psk>) -> (Dial, Vec<u8>) {
    let mut out = [0u8; 256];
    let (dial, len) = Dial::start(
        &identity(INITIATOR),
        &responder_address(),
        CONTEXT,
        psk,
        t(0),
        entropy,
        &mut out,
    )
    .unwrap();
    assert_eq!(len, FIRST_CONTACT_LEN);
    (dial, out[..len].to_vec())
}

fn answer(
    responder: &mut Responder<Mcu>,
    packet: &[u8],
    now: Instant,
    admission: &mut Fixed,
    entropy: &mut TestEntropy,
) -> Option<Vec<u8>> {
    let mut out = [0u8; 256];
    match responder.handle(packet, SOURCE, now, admission, entropy, &mut out) {
        ResponderOutput::Send(len) => Some(out[..len].to_vec()),
        ResponderOutput::Payload { .. } => panic!("no context here accepts a payload"),
        ResponderOutput::Silent => None,
    }
}

fn established(event: DialEvent) -> Established {
    match event {
        DialEvent::Established(established) => established,
        DialEvent::Ignored => panic!("ignored"),
        DialEvent::Failed(error) => panic!("failed: {error}"),
    }
}

fn seal(cipher: &mut CipherState, message: &[u8]) -> Vec<u8> {
    let mut buffer = message.to_vec();
    buffer.resize(message.len() + 16, 0);
    let len = cipher
        .encrypt_with_ad(&[], &mut buffer, message.len())
        .unwrap();
    buffer.truncate(len);
    buffer
}

fn open(cipher: &mut CipherState, message: &[u8]) -> Vec<u8> {
    let mut buffer = message.to_vec();
    let len = cipher.decrypt_with_ad(&[], &mut buffer).unwrap();
    buffer.truncate(len);
    buffer
}

/// Builds a first contact by hand: presenting `presented` as the static key,
/// with `ephemeral_secret`, to `address`, under `context`.
fn crafted_first_contact(
    initiator: &Identity,
    presented: &[u8; 32],
    address: &Address,
    context: &[u8],
    ephemeral_secret: [u8; 32],
) -> Vec<u8> {
    let mut prologue = [0u8; PROLOGUE_MAX];
    let prologue = Context::new(context)
        .unwrap()
        .prologue(&mut prologue)
        .to_vec();
    let mut noise_out = [0u8; INITIATION_NOISE_LEN];
    noise::write_initiation_presenting(
        initiator.secret(),
        presented,
        address.peer_id().as_bytes(),
        StaticSecret::from(ephemeral_secret),
        &prologue,
        &[],
        &mut noise_out,
    )
    .unwrap();
    let mut packet = vec![0u8; FIRST_CONTACT_LEN];
    messages::write_first_contact_into(
        &mut packet,
        7,
        &noise_out,
        &Mac1Key::for_address(address.as_bytes()),
        None,
    )
    .unwrap();
    packet
}

// --- messages ----------------------------------------------------------------

/// Scenario: a first contact of any other length or type is dropped.
#[test]
fn only_exact_messages_parse() {
    let mut entropy = TestEntropy(0);
    let (_, first) = dial(&mut entropy, None);
    assert_eq!(first.len(), 134);
    assert_eq!(&first[..2], &[0x01, 0x01]);
    assert!(messages::parse_first_contact(&first).is_ok());
    assert_eq!(
        messages::parse_first_contact(&first[..133]),
        Err(MessageError::WrongLength {
            expected: 134,
            actual: 133
        })
    );
    let mut longer = first.clone();
    longer.push(0);
    assert!(messages::parse_first_contact(&longer).is_err());
    let mut wrong_type = first.clone();
    wrong_type[1] = 0x03;
    assert_eq!(
        messages::parse_first_contact(&wrong_type),
        Err(MessageError::WrongType)
    );

    let mut responder = responder();
    let mut admission = Fixed::accept();
    for packet in [&first[..133], &longer[..], &wrong_type[..]] {
        assert_eq!(
            answer(&mut responder, packet, t(0), &mut admission, &mut entropy),
            None
        );
    }
    // A response sent to a responder is not a first contact either.
    let response = answer(&mut responder, &first, t(0), &mut admission, &mut entropy).unwrap();
    assert_eq!(response.len(), 61);
    assert_eq!(&response[..2], &[0x01, 0x02]);
    assert!(messages::parse_response(&response).is_ok());
    assert!(messages::parse_response(&response[..60]).is_err());
    assert_eq!(
        answer(
            &mut responder,
            &response,
            t(0),
            &mut admission,
            &mut entropy
        ),
        None
    );
    assert_eq!(admission.asked, 1);
}

#[test]
fn decisions_decode_strictly() {
    use messages::decode_decision;
    assert_eq!(decode_decision(&[0, 0, 0]), Ok(WireDecision::Accept));
    assert_eq!(
        decode_decision(&[1, 0x00, 0x01]),
        Ok(WireDecision::Refuse(
            RefusalCode::application(0x0100).unwrap()
        ))
    );
    assert_eq!(
        decode_decision(&[1, 0x01, 0x00]),
        Ok(WireDecision::Refuse(RefusalCode::CAPACITY_EXHAUSTED))
    );
    assert_eq!(
        decode_decision(&[0, 1, 0]),
        Err(DecisionError::AcceptWithCode)
    );
    assert_eq!(
        decode_decision(&[1, 0, 0]),
        Err(DecisionError::RefuseWithoutCode)
    );
    assert_eq!(
        decode_decision(&[2, 0, 0]),
        Err(DecisionError::UnknownStatus)
    );
    assert_eq!(decode_decision(&[0, 0]), Err(DecisionError::WrongLength));
    assert_eq!(
        messages::encode_decision(WireDecision::Refuse(RefusalCode::BUSY)),
        [1, 2, 0]
    );
}

/// Scenario: a malformed decision is not acted on.
#[test]
fn a_malformed_decision_is_ignored() {
    let mut entropy = TestEntropy(100);
    let (mut dial, first) = dial(&mut entropy, None);

    // Answer as the responder would, but with a malformed decision.
    let responder_identity = identity(RESPONDER);
    let parsed = messages::parse_first_contact(&first).unwrap();
    let (re, es) = noise::initiation_es(responder_identity.secret(), parsed.noise).unwrap();
    let mut prologue = [0u8; PROLOGUE_MAX];
    let prologue = Context::new(CONTEXT)
        .unwrap()
        .prologue(&mut prologue)
        .to_vec();
    let mut buffer = *parsed.noise;
    let (read, _) = noise::read_initiation(
        responder_identity.secret(),
        &prologue,
        &re,
        &es,
        &mut buffer,
    )
    .unwrap();
    let mut noise_out = [0u8; RESPONSE_NOISE_LEN];
    noise::write_response(
        read,
        &StaticSecret::from([42; 32]),
        &NO_PSK,
        &[0x00, 0x01, 0x00],
        &mut noise_out,
    )
    .unwrap();
    let response = messages::write_response(9, parsed.initiator_index, &noise_out);

    assert!(matches!(
        dial.handle(&identity(INITIATOR), &response, t(10)),
        DialEvent::Ignored
    ));
    // The attempt continues: the genuine answer still completes it.
    let mut responder = responder();
    let genuine = answer(
        &mut responder,
        &first,
        t(20),
        &mut Fixed::accept(),
        &mut entropy,
    )
    .unwrap();
    established(dial.handle(&identity(INITIATOR), &genuine, t(30)));
}

// --- the responder ------------------------------------------------------------

/// Scenarios: an admitted initiator is accepted; acceptance establishes the
/// session keys on both sides; the bindings agree.
#[test]
fn a_handshake_completes_with_matching_keys() {
    let mut entropy = TestEntropy(200);
    let (mut dial, first) = dial(&mut entropy, None);
    let mut responder = responder();
    let mut admission = Fixed::accept();

    let response = answer(&mut responder, &first, t(5), &mut admission, &mut entropy).unwrap();
    assert_eq!(admission.asked, 1);
    assert_eq!(admission.last, Some(identity(INITIATOR).peer_id()));

    let mut established = established(dial.handle(&identity(INITIATOR), &response, t(10)));
    assert_eq!(established.peer(), &identity(RESPONDER).peer_id());

    let index = established.remote_index();
    assert_eq!(responder.pending_count(), 1);
    let pending = responder.pending_mut(index).unwrap();
    assert_eq!(pending.peer(), &identity(INITIATOR).peer_id());
    assert_eq!(pending.initiator_index(), established.local_index());
    assert_eq!(pending.expires_at(), t(5 + 5000));
    assert_eq!(pending.channel_binding(), established.channel_binding());

    let ours = established.completed_mut();
    let theirs = pending.completed_mut();
    let sealed = seal(&mut ours.transport.send, b"from the initiator");
    assert_eq!(
        open(&mut theirs.transport.recv, &sealed),
        b"from the initiator"
    );
    let sealed = seal(&mut theirs.transport.send, b"from the responder");
    assert_eq!(
        open(&mut ours.transport.recv, &sealed),
        b"from the responder"
    );
}

/// Scenario: a wrong mac1 costs no Diffie-Hellman — including one computed for
/// the negation of the responder's address, which is how a dial to that
/// address arrives.
#[test]
fn a_dial_to_the_negated_address_meets_silence() {
    let mut entropy = TestEntropy(300);
    let negated =
        Address::parse(bytes32(&vectors()["keys"][RESPONDER]["negated_address"])).unwrap();
    assert_eq!(negated.peer_id(), responder_address().peer_id());
    let mut out = [0u8; 256];
    let (_, len) = Dial::start(
        &identity(INITIATOR),
        &negated,
        CONTEXT,
        None,
        t(0),
        &mut entropy,
        &mut out,
    )
    .unwrap();

    let mut responder = responder();
    let mut admission = Fixed::accept();
    assert_eq!(
        answer(
            &mut responder,
            &out[..len],
            t(0),
            &mut admission,
            &mut entropy
        ),
        None
    );
    assert_eq!(admission.asked, 0);
    assert_eq!(responder.pending_count(), 0);

    // Any other wrong mac1 too.
    let (_, mut first) = dial(&mut entropy, None);
    first[110] ^= 1;
    assert_eq!(
        answer(&mut responder, &first, t(0), &mut admission, &mut entropy),
        None
    );
    assert_eq!(admission.asked, 0);
}

/// Scenario: different contexts never complete a handshake.
#[test]
fn an_unserved_context_meets_silence() {
    let mut entropy = TestEntropy(400);
    let mut out = [0u8; 256];
    let (_, len) = Dial::start(
        &identity(INITIATOR),
        &responder_address(),
        b"pairing",
        None,
        t(0),
        &mut entropy,
        &mut out,
    )
    .unwrap();
    let mut responder = responder();
    let mut admission = Fixed::accept();
    assert_eq!(
        answer(
            &mut responder,
            &out[..len],
            t(0),
            &mut admission,
            &mut entropy
        ),
        None
    );
    assert_eq!(admission.asked, 0);

    // A responder serving both contexts answers it.
    let mut both: Responder<Mcu> =
        Responder::new(identity(RESPONDER), &[CONTEXT, b"pairing"]).unwrap();
    assert!(answer(&mut both, &out[..len], t(0), &mut admission, &mut entropy).is_some());
}

/// Scenario: a context longer than 32 bytes is refused.
#[test]
fn contexts_are_bounded() {
    let mut entropy = TestEntropy(500);
    let mut out = [0u8; 256];
    assert!(matches!(
        Dial::start(
            &identity(INITIATOR),
            &responder_address(),
            &[0; 33],
            None,
            t(0),
            &mut entropy,
            &mut out
        ),
        Err(DialError::ContextTooLong(ContextTooLong { len: 33 }))
    ));
    assert_eq!(out, [0u8; 256]);
    assert!(matches!(
        Responder::<Mcu>::new(identity(RESPONDER), &[&[0; 33]]),
        Err(ResponderError::ContextTooLong(_))
    ));
    assert_eq!(
        Responder::<Mcu>::new(identity(RESPONDER), &[])
            .unwrap()
            .contexts_served(),
        0
    );
    assert!(matches!(
        Responder::<Mcu>::new(identity(RESPONDER), &[b"a", b"b", b"c", b"d", b"e"]),
        Err(ResponderError::TooManyContexts { capacity: 4 })
    ));
    assert!(matches!(
        Responder::<Mcu>::new(identity(RESPONDER), &[b"a", b"a"]),
        Err(ResponderError::AlreadyServed)
    ));
    assert!(Responder::<Mcu>::new(identity(RESPONDER), &[&[0; 32]]).is_ok());
}

/// Scenario: equivalent encodings of a valid key are refused, without asking
/// admission, while the canonical key of the same initiator is accepted.
#[test]
fn equivalent_static_keys_are_refused_without_admission() {
    let vectors = vectors();
    let owner = identity(0);
    let responder_identity = identity(2);
    let address = *responder_identity.address();
    let mut responder: Responder<Mcu> = Responder::new(responder_identity, &[CONTEXT]).unwrap();
    let mut admission = Fixed::accept();
    let mut entropy = TestEntropy(600);

    let equivalents: Vec<[u8; 32]> = vectors["invalid_statics"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["equivalent"] == true && s["of_key"] == vectors["keys"][0]["name"])
        .map(|s| bytes32(&s["static"]))
        .collect();
    assert!(equivalents.len() >= 8);
    let mut prologue = [0u8; PROLOGUE_MAX];
    let prologue = Context::new(CONTEXT)
        .unwrap()
        .prologue(&mut prologue)
        .to_vec();
    let responder_secret = identity(2);
    for (i, presented) in equivalents.iter().enumerate() {
        let packet = crafted_first_contact(&owner, presented, &address, CONTEXT, [i as u8 + 1; 32]);
        // It really is an equivalent key: the first contact decrypts, and only
        // the canonical-key check stands between it and admission.
        let parsed = messages::parse_first_contact(&packet).unwrap();
        let (re, es) = noise::initiation_es(responder_secret.secret(), parsed.noise).unwrap();
        let mut buffer = *parsed.noise;
        let (read, _) =
            noise::read_initiation(responder_secret.secret(), &prologue, &re, &es, &mut buffer)
                .expect("an equivalent key decrypts");
        assert_eq!(read.remote_static(), presented);
        assert!(PeerId::from_static(*presented).is_err());
        // A second apart, so that the responder never comes under load and its
        // silence is the canonical-key check's, not the load bucket's.
        let now = t(1000 * i as u64);
        assert_eq!(
            answer(&mut responder, &packet, now, &mut admission, &mut entropy),
            None,
            "equivalent {i}"
        );
    }
    assert_eq!(admission.asked, 0);

    let canonical = *owner.peer_id().as_bytes();
    let packet = crafted_first_contact(&owner, &canonical, &address, CONTEXT, [99; 32]);
    assert!(
        answer(
            &mut responder,
            &packet,
            t(60_000),
            &mut admission,
            &mut entropy
        )
        .is_some()
    );
    assert_eq!(admission.last, Some(owner.peer_id()));
}

/// Scenario: a small-order key is refused silently.
#[test]
fn a_small_order_ephemeral_meets_silence() {
    let mut entropy = TestEntropy(700);
    let (_, mut first) = dial(&mut entropy, None);
    // Replace `e` with the u-coordinate 0, a point of small order, and re-MAC.
    first[6..38].copy_from_slice(&[0; 32]);
    let mac1 = Mac1Key::for_address(responder_address().as_bytes()).compute(&first[..102]);
    first[102..118].copy_from_slice(&mac1);
    let mut admission = Fixed::accept();
    assert_eq!(
        answer(&mut responder(), &first, t(0), &mut admission, &mut entropy),
        None
    );
    assert_eq!(admission.asked, 0);
}

/// Scenario: a refused initiator learns why, from the responder only.
#[test]
fn a_refusal_names_its_code() {
    for code in [
        RefusalCode::application(0x0101).unwrap(),
        RefusalCode::application(0xFFFF).unwrap(),
    ] {
        let mut entropy = TestEntropy(800);
        let (mut dial, first) = dial(&mut entropy, None);
        let mut responder = responder();
        let mut admission = Fixed::with(Decision::Refuse { code, psk: None });
        let response = answer(&mut responder, &first, t(0), &mut admission, &mut entropy).unwrap();
        assert_eq!(response.len(), 61);
        assert_eq!(responder.pending_count(), 0);
        assert!(matches!(
            dial.handle(&identity(INITIATOR), &response, t(1)),
            DialEvent::Failed(DialError::Refused(c)) if c == code
        ));
        // The dial is over.
        assert!(matches!(
            dial.poll(&identity(INITIATOR), t(2000), &mut entropy, &mut [0; 256]),
            DialPoll::Failed(_)
        ));
    }
}

/// Refusals and acceptances under a PSK are read by an initiator holding it;
/// one without it sees nothing.
#[test]
fn a_psk_covers_acceptance_and_refusal() {
    let psk = [7; 32];
    let code = RefusalCode::application(0x0200).unwrap();
    for decision in [
        Decision::Accept { psk: Some(psk) },
        Decision::Refuse {
            code,
            psk: Some(psk),
        },
    ] {
        let mut entropy = TestEntropy(900);
        let (mut with, first) = dial(&mut entropy, Some(psk));
        let response = answer(
            &mut responder(),
            &first,
            t(0),
            &mut Fixed::with(decision),
            &mut entropy,
        )
        .unwrap();
        match (decision, with.handle(&identity(INITIATOR), &response, t(1))) {
            (Decision::Accept { .. }, DialEvent::Established(_)) => {}
            (Decision::Refuse { .. }, DialEvent::Failed(DialError::Refused(c))) => {
                assert_eq!(c, code);
            }
            _ => panic!("unexpected outcome"),
        }

        let mut entropy = TestEntropy(900);
        let (mut without, first) = dial(&mut entropy, None);
        let response = answer(
            &mut responder(),
            &first,
            t(0),
            &mut Fixed::with(decision),
            &mut entropy,
        )
        .unwrap();
        assert!(matches!(
            without.handle(&identity(INITIATOR), &response, t(1)),
            DialEvent::Ignored
        ));
    }
}

/// Scenario: a forged refusal is not believed.
#[test]
fn a_forged_response_is_ignored() {
    let mut entropy = TestEntropy(1000);
    let (mut dial, first) = dial(&mut entropy, None);
    let index = messages::parse_first_contact(&first)
        .unwrap()
        .initiator_index;
    let forged = messages::write_response(1, index, &[0x55; RESPONSE_NOISE_LEN]);
    assert!(matches!(
        dial.handle(&identity(INITIATOR), &forged, t(1)),
        DialEvent::Ignored
    ));
    let genuine = answer(
        &mut responder(),
        &first,
        t(2),
        &mut Fixed::accept(),
        &mut entropy,
    )
    .unwrap();
    established(dial.handle(&identity(INITIATOR), &genuine, t(3)));
}

/// Scenario: a response to no attempt is ignored.
#[test]
fn a_response_to_no_attempt_is_ignored() {
    let mut entropy = TestEntropy(1100);
    let (mut a, first_a) = dial(&mut entropy, None);
    let (mut b, _) = dial(&mut entropy, None);
    let response_a = answer(
        &mut responder(),
        &first_a,
        t(0),
        &mut Fixed::accept(),
        &mut entropy,
    )
    .unwrap();
    assert!(matches!(
        b.handle(&identity(INITIATOR), &response_a, t(1)),
        DialEvent::Ignored
    ));
    established(a.handle(&identity(INITIATOR), &response_a, t(1)));
}

/// Scenario: a replayed first contact never becomes a connection.
#[test]
fn a_replay_only_ever_pends_and_expires() {
    let mut entropy = TestEntropy(1200);
    let (_, first) = dial(&mut entropy, None);
    let mut responder = responder();
    let mut admission = Fixed::accept();
    answer(&mut responder, &first, t(0), &mut admission, &mut entropy).unwrap();
    assert_eq!(responder.diffie_hellmans, 1);

    // The same bytes within 5 seconds: dropped before any Diffie-Hellman
    // (PROTOCOL.md §4, recent ephemerals).
    assert_eq!(
        answer(
            &mut responder,
            &first,
            t(1000),
            &mut admission,
            &mut entropy
        ),
        None
    );
    assert_eq!(responder.diffie_hellmans, 1);
    assert_eq!(admission.asked, 1);

    // The same bytes later: processed again, and still only pending.
    answer(
        &mut responder,
        &first,
        t(6000),
        &mut admission,
        &mut entropy,
    )
    .unwrap();
    assert_eq!(responder.pending_count(), 1);
    assert_eq!(responder.next_deadline(), Some(t(11_000)));
    responder.expire(t(11_000));
    assert_eq!(responder.pending_count(), 0);
    assert_eq!(responder.next_deadline(), None);
}

/// Scenario: pending handshakes per peer are bounded.
#[test]
fn at_most_two_pend_per_peer() {
    let mut entropy = TestEntropy(1300);
    let mut responder = responder();
    let mut admission = Fixed::accept();
    let mut indices = Vec::new();
    for i in 0..3 {
        let (_, first) = dial(&mut entropy, None);
        let response = answer(&mut responder, &first, t(i), &mut admission, &mut entropy).unwrap();
        indices.push(messages::parse_response(&response).unwrap().responder_index);
    }
    assert_eq!(responder.pending_for(&identity(INITIATOR).peer_id()), 2);
    assert!(responder.pending(indices[0]).is_none());
    assert!(responder.pending(indices[1]).is_some());
    assert!(responder.pending(indices[2]).is_some());
}

/// Scenario: a full responder refuses with capacity exhausted.
#[test]
fn a_full_responder_refuses_with_capacity_exhausted() {
    let mut entropy = TestEntropy(1400);
    let mut responder = responder();
    let mut admission = Fixed::accept();
    // Four initiators fill the microcontroller configuration's four slots.
    for key in 1..=4 {
        let initiator = identity(key);
        let mut out = [0u8; 256];
        let (_, len) = Dial::start(
            &initiator,
            &responder_address(),
            CONTEXT,
            None,
            t(0),
            &mut entropy,
            &mut out,
        )
        .unwrap();
        answer(
            &mut responder,
            &out[..len],
            t(0),
            &mut admission,
            &mut entropy,
        )
        .unwrap();
    }
    assert_eq!(responder.pending_count(), 4);

    // A fifth initiator with none pending is refused, and leaves no state. The
    // vectors hold five keys; the fifth initiator is the responder's own key,
    // which is a different PeerId from the four pending.
    let fifth = identity(RESPONDER);
    let mut out = [0u8; 256];
    let (mut dial, len) = Dial::start(
        &fifth,
        &responder_address(),
        CONTEXT,
        None,
        t(0),
        &mut entropy,
        &mut out,
    )
    .unwrap();
    let response = answer(
        &mut responder,
        &out[..len],
        t(1),
        &mut admission,
        &mut entropy,
    )
    .unwrap();
    assert_eq!(responder.pending_count(), 4);
    assert!(matches!(
        dial.handle(&fifth, &response, t(2)),
        DialEvent::Failed(DialError::Refused(RefusalCode::CAPACITY_EXHAUSTED))
    ));
}

/// An unknown version from a sender that knows the address is answered, and the
/// initiator that receives the answer reports the versions the peer speaks.
#[test]
fn an_unknown_version_is_answered_and_reported() {
    let mut entropy = TestEntropy(1500);
    let (mut dial, first) = dial(&mut entropy, None);
    let mut responder = responder();
    let mut admission = Fixed::accept();

    let mut v2 = first.clone();
    v2[0] = 0x02;
    let mac1 = Mac1Key::for_address(responder_address().as_bytes()).compute(&v2[..102]);
    v2[102..118].copy_from_slice(&mac1);
    let answer_bytes = answer(&mut responder, &v2, t(0), &mut admission, &mut entropy).unwrap();
    let decoded = VersionNotSupported::decode(&answer_bytes).unwrap();
    assert_eq!(decoded.versions(), &[Version::V1]);
    assert_eq!(admission.asked, 0);

    // Our own dial's first contact echoed back as "version not supported".
    let echo = crate::wire::carried_mac1(&first).unwrap();
    let mut out = [0u8; 64];
    let len = VersionNotSupported::new(&[Version::new(9).unwrap()], echo)
        .unwrap()
        .encode(&mut out)
        .unwrap();
    match dial.handle(&identity(INITIATOR), &out[..len], t(1)) {
        DialEvent::Failed(DialError::UnsupportedVersion(error)) => {
            assert_eq!(error.peer_versions(), &[Version::new(9).unwrap()]);
        }
        _ => panic!("expected an unsupported-version error"),
    }
}

// --- the initiator ------------------------------------------------------------

/// Scenario: retries follow the schedule; a dial gives up after 15 seconds,
/// and a response arriving later is ignored.
#[test]
fn retries_follow_the_schedule_then_give_up() {
    let mut entropy = TestEntropy(1600);
    let (mut dial, first) = dial(&mut entropy, None);
    let initiator = identity(INITIATOR);
    let mut sent = vec![(0u64, first)];
    let mut failed_at = None;
    let mut out = [0u8; 256];
    for now in (0..20_000).step_by(100) {
        match dial.poll(&initiator, t(now), &mut entropy, &mut out) {
            DialPoll::Send(len) => sent.push((now, out[..len].to_vec())),
            DialPoll::Wait(deadline) => assert!(deadline > t(now)),
            DialPoll::Failed(DialError::NoResponse) => {
                failed_at.get_or_insert(now);
            }
            DialPoll::Failed(error) => panic!("{error}"),
        }
    }
    let times: Vec<u64> = sent.iter().map(|(at, _)| *at).collect();
    assert_eq!(times, vec![0, 1000, 3000, 7000]);
    assert_eq!(failed_at, Some(15_000));

    // Each attempt has its own index and ephemeral key.
    for (i, (_, a)) in sent.iter().enumerate() {
        for (_, b) in &sent[i + 1..] {
            assert_ne!(a[2..6], b[2..6]);
            assert_ne!(a[6..38], b[6..38]);
        }
    }

    // A response to the first attempt, arriving after the give-up, is ignored.
    let late = answer(
        &mut responder(),
        &sent[0].1,
        t(16_000),
        &mut Fixed::accept(),
        &mut entropy,
    )
    .unwrap();
    assert!(matches!(
        dial.handle(&initiator, &late, t(16_000)),
        DialEvent::Ignored
    ));
}

/// Scenario: a late response to an earlier attempt completes the dial.
#[test]
fn a_late_response_to_an_earlier_attempt_completes() {
    let mut entropy = TestEntropy(1700);
    let (mut dial, first) = dial(&mut entropy, None);
    let initiator = identity(INITIATOR);
    let mut out = [0u8; 256];
    assert!(matches!(
        dial.poll(&initiator, t(1000), &mut entropy, &mut out),
        DialPoll::Send(134)
    ));
    let first_index = messages::parse_first_contact(&first)
        .unwrap()
        .initiator_index;
    let response = answer(
        &mut responder(),
        &first,
        t(1100),
        &mut Fixed::accept(),
        &mut entropy,
    )
    .unwrap();
    let established = established(dial.handle(&initiator, &response, t(1200)));
    assert_eq!(established.local_index(), first_index);
    // Nothing more is sent.
    assert!(matches!(
        dial.poll(&initiator, t(3000), &mut entropy, &mut out),
        DialPoll::Failed(_)
    ));
}

/// Scenario: two handshakes never share a binding.
#[test]
fn two_handshakes_never_share_a_binding() {
    let mut entropy = TestEntropy(1800);
    let mut bindings = Vec::new();
    for _ in 0..2 {
        let (mut dial, first) = dial(&mut entropy, None);
        let response = answer(
            &mut responder(),
            &first,
            t(0),
            &mut Fixed::accept(),
            &mut entropy,
        )
        .unwrap();
        bindings.push(
            *established(dial.handle(&identity(INITIATOR), &response, t(1))).channel_binding(),
        );
    }
    assert_ne!(bindings[0], bindings[1]);
}

// --- committed transcripts ------------------------------------------------------

/// Entropy that hands out a fixed script of bytes, so a transcript's indices
/// and ephemeral keys are exactly the ones it records.
struct Scripted(Vec<u8>);

impl Entropy for Scripted {
    fn fill(&mut self, dest: &mut [u8]) {
        assert!(self.0.len() >= dest.len(), "script exhausted");
        let rest = self.0.split_off(dest.len());
        dest.copy_from_slice(&self.0);
        self.0 = rest;
    }
}

struct Transcript {
    name: &'static str,
    initiator: usize,
    responder: usize,
    context: &'static [u8],
    psk: Option<Psk>,
    initiator_index: u32,
    initiator_ephemeral: [u8; 32],
    responder_index: u32,
    responder_ephemeral: [u8; 32],
    decision: Decision,
    /// The length of the first contact's payload (`a_payload`), 0 for none.
    payload: usize,
}

fn transcripts() -> Vec<Transcript> {
    vec![
        Transcript {
            name: "acceptance, no PSK",
            initiator: 1,
            responder: 0,
            context: b"session",
            psk: None,
            initiator_index: 0x0102_0304,
            initiator_ephemeral: [0x11; 32],
            responder_index: 0x0a0b_0c0d,
            responder_ephemeral: [0x22; 32],
            decision: Decision::Accept { psk: None },
            payload: 0,
        },
        Transcript {
            name: "acceptance under a PSK, empty context",
            initiator: 2,
            responder: 3,
            context: b"",
            psk: Some([0x5a; 32]),
            initiator_index: 0xffff_fffe,
            initiator_ephemeral: [0x33; 32],
            responder_index: 7,
            responder_ephemeral: [0x44; 32],
            decision: Decision::Accept {
                psk: Some([0x5a; 32]),
            },
            payload: 0,
        },
        Transcript {
            name: "refusal with a library code",
            initiator: 4,
            responder: 0,
            context: b"session",
            psk: None,
            initiator_index: 1,
            initiator_ephemeral: [0x55; 32],
            responder_index: 2,
            responder_ephemeral: [0x66; 32],
            decision: Decision::Refuse {
                code: RefusalCode::CAPACITY_EXHAUSTED,
                psk: None,
            },
            payload: 0,
        },
        Transcript {
            name: "refusal with an application code, 32-byte context",
            initiator: 1,
            responder: 2,
            context: b"0123456789abcdef0123456789abcdef",
            psk: None,
            initiator_index: 0xdead_beef,
            initiator_ephemeral: [0x77; 32],
            responder_index: 0xcafe_babe,
            responder_ephemeral: [0x88; 32],
            decision: Decision::Refuse {
                code: RefusalCode::application(0x1234).unwrap(),
                psk: None,
            },
            payload: 0,
        },
        Transcript {
            name: "a payload of 1 byte, relay context",
            initiator: 1,
            responder: 0,
            context: b"convesso-relay",
            psk: None,
            initiator_index: 0x0506_0708,
            initiator_ephemeral: [0x99; 32],
            responder_index: 0x1112_1314,
            responder_ephemeral: [0xaa; 32],
            decision: Decision::Accept { psk: None },
            payload: 1,
        },
        Transcript {
            name: "a payload of 168 bytes under a PSK",
            initiator: 2,
            responder: 3,
            context: b"convesso-relay",
            psk: Some([0xa5; 32]),
            initiator_index: 3,
            initiator_ephemeral: [0xbb; 32],
            responder_index: 4,
            responder_ephemeral: [0xcc; 32],
            decision: Decision::Accept {
                psk: Some([0xa5; 32]),
            },
            payload: 168,
        },
        Transcript {
            name: "a payload of 1,200 bytes",
            initiator: 4,
            responder: 2,
            context: b"convesso-relay",
            psk: None,
            initiator_index: 0x7fff_ffff,
            initiator_ephemeral: [0xdd; 32],
            responder_index: 0x8000_0000,
            responder_ephemeral: [0xee; 32],
            decision: Decision::Accept { psk: None },
            payload: 1200,
        },
        Transcript {
            name: "a payload of 168 bytes, refused",
            initiator: 3,
            responder: 1,
            context: b"convesso-relay",
            psk: None,
            initiator_index: 9,
            initiator_ephemeral: [0x12; 32],
            responder_index: 10,
            responder_ephemeral: [0x34; 32],
            decision: Decision::Refuse {
                code: RefusalCode::application(0x0100).unwrap(),
                psk: None,
            },
            payload: 168,
        },
    ]
}

fn to_hex(bytes: &[u8]) -> std::string::String {
    bytes.iter().map(|b| std::format!("{b:02x}")).collect()
}

/// Runs one transcript through the real `Dial` and `Responder`, checks the Noise
/// part of each message against `snow`, and returns its JSON form.
fn run_transcript(transcript: &Transcript) -> Value {
    let initiator = identity(transcript.initiator);
    let responder_identity = identity(transcript.responder);
    let address = *responder_identity.address();

    let mut script = transcript.initiator_index.to_le_bytes().to_vec();
    script.extend_from_slice(&transcript.initiator_ephemeral);
    let payload = a_payload(transcript.payload);
    let mut out = [0u8; MAX_FIRST_CONTACT_LEN];
    let (mut dial, len) = Dial::start_with_payload(
        &initiator,
        &address,
        transcript.context,
        transcript.psk,
        &payload,
        t(0),
        &mut Scripted(script),
        &mut out,
    )
    .unwrap();
    let first = out[..len].to_vec();
    assert_eq!(first.len(), FIRST_CONTACT_LEN + payload.len());

    let accept = matches!(transcript.decision, Decision::Accept { .. });
    // The responder draws an index, a second one when it accepts, then its ephemeral.
    let mut script = transcript.responder_index.to_le_bytes().to_vec();
    if accept {
        script.extend_from_slice(&transcript.responder_index.to_le_bytes());
    }
    script.extend_from_slice(&transcript.responder_ephemeral);
    let mut responder: Responder<Mcu> =
        Responder::new(responder_identity, &[transcript.context]).unwrap();
    if !payload.is_empty() {
        responder.accept_payload(transcript.context).unwrap();
    }
    let mut response_out = [0u8; RESPONSE_LEN + MAX_PAYLOAD];
    let len = match responder.handle(
        &first,
        SOURCE,
        t(1),
        &mut Fixed::with(transcript.decision),
        &mut Scripted(script),
        &mut response_out,
    ) {
        ResponderOutput::Send(len) => {
            assert!(
                !accept || payload.is_empty(),
                "{}: payload not handed over",
                transcript.name
            );
            len
        }
        ResponderOutput::Payload {
            len, payload: n, ..
        } => {
            assert!(
                accept,
                "{}: a refused payload was handed over",
                transcript.name
            );
            assert_eq!(
                response_out[len..len + n],
                payload[..],
                "{}",
                transcript.name
            );
            len
        }
        ResponderOutput::Silent => panic!("{}: the responder stayed silent", transcript.name),
    };
    let response = response_out[..len].to_vec();

    let (binding, decision_bytes) = match dial.handle(&initiator, &response, t(2)) {
        DialEvent::Established(e) => (Some(*e.channel_binding()), [0u8, 0, 0]),
        DialEvent::Failed(DialError::Refused(code)) => {
            let [lo, hi] = code.get().to_le_bytes();
            (None, [1, lo, hi])
        }
        _ => panic!("{}: unexpected outcome", transcript.name),
    };

    // The same handshake through `snow`, with the same keys and ephemerals.
    let params: snow::params::NoiseParams =
        "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let mut prologue = [0u8; PROLOGUE_MAX];
    let prologue = Context::new(transcript.context)
        .unwrap()
        .prologue(&mut prologue)
        .to_vec();
    let psk = transcript.psk.unwrap_or(NO_PSK);
    let keys = vectors();
    let initiator_scalar = bytes32(&keys["keys"][transcript.initiator]["x25519_scalar"]);
    let responder_scalar = bytes32(&keys["keys"][transcript.responder]["x25519_scalar"]);
    let mut snow_init = snow::Builder::new(params.clone())
        .local_private_key(&initiator_scalar)
        .unwrap()
        .remote_public_key(address.peer_id().as_bytes())
        .unwrap()
        .prologue(&prologue)
        .unwrap()
        .psk(2, &psk)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&transcript.initiator_ephemeral)
        .build_initiator()
        .unwrap();
    let mut snow_resp = snow::Builder::new(params)
        .local_private_key(&responder_scalar)
        .unwrap()
        .prologue(&prologue)
        .unwrap()
        .psk(2, &psk)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&transcript.responder_ephemeral)
        .build_responder()
        .unwrap();
    let mut buffer = [0u8; 2048];
    let mut read = [0u8; 2048];
    let n = snow_init.write_message(&payload, &mut buffer).unwrap();
    assert_eq!(
        &buffer[..n],
        &first[6..first.len() - 32],
        "{}: snow disagrees on the first contact",
        transcript.name
    );
    let read_len = snow_resp.read_message(&buffer[..n], &mut read).unwrap();
    assert_eq!(
        read[..read_len],
        payload[..],
        "{}: snow reads another payload",
        transcript.name
    );
    let n = snow_resp
        .write_message(&decision_bytes, &mut buffer)
        .unwrap();
    assert_eq!(
        &buffer[..n],
        &response[10..61],
        "{}: snow disagrees on the response",
        transcript.name
    );
    if let Some(binding) = binding {
        assert_eq!(snow_resp.get_handshake_hash(), binding);
    }

    let mut record = serde_json::json!({
        "name": transcript.name,
        "initiator_key": transcript.initiator,
        "responder_key": transcript.responder,
        "context": to_hex(transcript.context),
        "psk": transcript.psk.map(|p| to_hex(&p)),
        "initiator_index": transcript.initiator_index,
        "initiator_ephemeral": to_hex(&transcript.initiator_ephemeral),
        "responder_index": transcript.responder_index,
        "responder_ephemeral": to_hex(&transcript.responder_ephemeral),
        "decision": to_hex(&decision_bytes),
        "first_contact": to_hex(&first),
        "response": to_hex(&response),
        "channel_binding": binding.map(|b| to_hex(&b)),
    });
    if !payload.is_empty() {
        record["payload"] = Value::from(to_hex(&payload));
    }
    record
}

/// Every committed transcript is rebuilt byte for byte, and `snow` agrees with
/// each message. With `CONVESSO_REGENERATE=1`, the file is rewritten instead, and
/// only once `snow` has agreed with every transcript.
#[test]
fn the_committed_transcripts_rebuild_byte_for_byte() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/handshake-v1.json");
    let rebuilt = serde_json::json!({
        "description": "Version 1 handshake transcripts (PROTOCOL.md, section 3). Keys are \
            indices into identity.json. Each first contact and response was checked against \
            snow's bytes for the same inputs when generated; do not edit.",
        "transcripts": transcripts().iter().map(run_transcript).collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&rebuilt).unwrap() + "\n";
    if std::env::var_os("CONVESSO_REGENERATE").is_some() {
        std::fs::write(&path, &text).unwrap();
    }
    let committed = std::fs::read_to_string(&path).expect("vectors/handshake-v1.json is committed");
    assert_eq!(committed.replace("\r\n", "\n"), text);
}

/// The time of a complete handshake on the host, both sides: dial, response,
/// established. Ignored by default because only a release build measures
/// anything; run it with
/// `cargo test -p convesso-core --release --lib handshake_time -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, meaningful only in release"]
fn handshake_time() {
    let initiator = identity(INITIATOR);
    let address = responder_address();
    let mut entropy = TestEntropy(9000);
    let mut samples = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let mut responder = responder();
        let started = std::time::Instant::now();
        let mut out = [0u8; 256];
        let (mut dial, len) = Dial::start(
            &initiator,
            &address,
            CONTEXT,
            None,
            t(0),
            &mut entropy,
            &mut out,
        )
        .unwrap();
        let mut response = [0u8; 256];
        let ResponderOutput::Send(n) = responder.handle(
            &out[..len],
            SOURCE,
            t(0),
            &mut Fixed::accept(),
            &mut entropy,
            &mut response,
        ) else {
            panic!("silent");
        };
        established(dial.handle(&initiator, &response[..n], t(0)));
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    std::println!(
        "complete handshake, both sides, median of 1000: {:?} (min {:?}, max {:?})",
        samples[500],
        samples[0],
        samples[999]
    );
}

// --- under load: the responder --------------------------------------------------------

const OTHER_SOURCE: Source<'static> = Source::Direct(&[198, 51, 100, 7, 0xCA, 0x6C]);

fn answer_from(
    responder: &mut Responder<Mcu>,
    packet: &[u8],
    source: Source<'_>,
    now: Instant,
    admission: &mut Fixed,
    entropy: &mut TestEntropy,
) -> Option<Vec<u8>> {
    let mut out = [0u8; MAX_RESPONDER_OUTPUT];
    match responder.handle(packet, source, now, admission, entropy, &mut out) {
        ResponderOutput::Send(len) => Some(out[..len].to_vec()),
        ResponderOutput::Payload { .. } => panic!("no context here accepts a payload"),
        ResponderOutput::Silent => None,
    }
}

/// Fills the responder's load bucket (burst 5 for `Mcu`) at `now`.
fn exhaust(responder: &mut Responder<Mcu>, now: Instant, entropy: &mut TestEntropy) {
    for _ in 0..5 {
        let (_, first) = dial(entropy, None);
        let reply = answer(responder, &first, now, &mut Fixed::accept(), entropy).unwrap();
        assert_eq!(reply.len(), RESPONSE_LEN);
    }
}

/// The cookie a responder would give `source`, obtained the honest way: a
/// first contact without mac2 under load, and its cookie reply opened.
fn cookie_for(
    responder: &mut Responder<Mcu>,
    source: Source<'_>,
    now: Instant,
    entropy: &mut TestEntropy,
) -> crate::dos::Cookie {
    let (_, first) = dial(entropy, None);
    let reply = answer_from(
        responder,
        &first,
        source,
        now,
        &mut Fixed::accept(),
        entropy,
    )
    .unwrap();
    assert_eq!(reply.len(), crate::dos::COOKIE_REPLY_LEN);
    let parsed = crate::dos::parse_cookie_reply(&reply).unwrap();
    let mac1 = crate::wire::carried_mac1(&first).unwrap();
    crate::dos::open_cookie_reply(&parsed, responder_address().as_bytes(), &mac1).unwrap()
}

/// A fresh first contact with its mac2 computed under `cookie`.
fn with_mac2(entropy: &mut TestEntropy, cookie: &crate::dos::Cookie) -> Vec<u8> {
    let (_, mut first) = dial(entropy, None);
    let mac2 = crate::dos::mac2(cookie, &first[..118]);
    first[118..].copy_from_slice(&mac2);
    first
}

/// Scenario: within the rate, mac2 is not needed.
#[test]
fn within_the_rate_mac2_is_not_needed() {
    let mut entropy = TestEntropy(2000);
    let mut responder = responder();
    exhaust(&mut responder, t(0), &mut entropy);
    assert_eq!(responder.diffie_hellmans, 5);
}

/// Scenarios: beyond the rate, the responder is under load; a wrong mac2 under
/// load costs no Diffie-Hellman.
#[test]
fn beyond_the_rate_a_cookie_reply_and_no_diffie_hellman() {
    let mut entropy = TestEntropy(2100);
    let mut responder = responder();
    exhaust(&mut responder, t(0), &mut entropy);
    let mut admission = Fixed::accept();

    let (_, zeros) = dial(&mut entropy, None);
    let mut wrong = with_mac2(&mut entropy, &[0x42; 16]);
    wrong[133] ^= 1;
    for packet in [zeros, wrong] {
        let reply = answer(&mut responder, &packet, t(0), &mut admission, &mut entropy).unwrap();
        assert_eq!(reply.len(), 62);
        assert_eq!(&reply[..2], &[0x01, 0x03]);
        assert_eq!(
            &reply[2..6],
            &packet[2..6],
            "the reply names the initiator's index"
        );
    }
    assert_eq!(responder.diffie_hellmans, 5);
    assert_eq!(admission.asked, 0);
    assert!(responder.pending_count() <= 4);
}

/// Scenario: a valid mac2 is processed under load.
#[test]
fn a_valid_mac2_is_processed_under_load() {
    let mut entropy = TestEntropy(2200);
    let mut responder = responder();
    exhaust(&mut responder, t(0), &mut entropy);
    let cookie = cookie_for(&mut responder, SOURCE, t(0), &mut entropy);
    let packet = with_mac2(&mut entropy, &cookie);
    let reply = answer(
        &mut responder,
        &packet,
        t(0),
        &mut Fixed::accept(),
        &mut entropy,
    )
    .unwrap();
    assert_eq!(reply.len(), RESPONSE_LEN);
    assert_eq!(responder.diffie_hellmans, 6);
}

/// Scenario: a cookie for one source is worth nothing from another.
#[test]
fn a_cookie_from_another_source_is_refused() {
    let mut entropy = TestEntropy(2300);
    let mut responder = responder();
    exhaust(&mut responder, t(0), &mut entropy);
    let cookie = cookie_for(&mut responder, SOURCE, t(0), &mut entropy);
    let packet = with_mac2(&mut entropy, &cookie);
    let reply = answer_from(
        &mut responder,
        &packet,
        OTHER_SOURCE,
        t(0),
        &mut Fixed::accept(),
        &mut entropy,
    )
    .unwrap();
    assert_eq!(reply.len(), 62);
    assert_eq!(responder.diffie_hellmans, 5);
}

/// Scenarios: a burst beyond the rate is dropped; other sources are unaffected.
#[test]
fn under_load_each_source_has_its_rate() {
    let mut entropy = TestEntropy(2400);
    let mut responder = responder();
    exhaust(&mut responder, t(0), &mut entropy);
    let cookie = cookie_for(&mut responder, SOURCE, t(0), &mut entropy);
    let other_cookie = cookie_for(&mut responder, OTHER_SOURCE, t(0), &mut entropy);

    let mut outcomes = Vec::new();
    for _ in 0..6 {
        let packet = with_mac2(&mut entropy, &cookie);
        outcomes.push(
            answer(
                &mut responder,
                &packet,
                t(0),
                &mut Fixed::accept(),
                &mut entropy,
            )
            .is_some(),
        );
    }
    assert_eq!(outcomes, [true, true, true, true, true, false]);
    assert_eq!(responder.diffie_hellmans, 5 + 5);

    let packet = with_mac2(&mut entropy, &other_cookie);
    assert!(
        answer_from(
            &mut responder,
            &packet,
            OTHER_SOURCE,
            t(0),
            &mut Fixed::accept(),
            &mut entropy
        )
        .is_some()
    );
    assert_eq!(responder.diffie_hellmans, 5 + 5 + 1);
}

/// A direct source longer than 32 bytes is a driver bug: the packet is dropped.
#[test]
fn an_oversized_source_is_dropped() {
    let mut entropy = TestEntropy(2500);
    let (_, first) = dial(&mut entropy, None);
    let mut admission = Fixed::accept();
    assert_eq!(
        answer_from(
            &mut responder(),
            &first,
            Source::Direct(&[0; 33]),
            t(0),
            &mut admission,
            &mut entropy
        ),
        None
    );
    assert_eq!(admission.asked, 0);
}

// --- under load: the initiator ----------------------------------------------------------

/// Scenario: the next attempt carries mac2, and nothing was sent in between.
#[test]
fn the_next_attempt_carries_mac2() {
    let mut entropy = TestEntropy(2600);
    let mut responder = responder();
    exhaust(&mut responder, t(0), &mut entropy);
    let initiator = identity(INITIATOR);

    let (mut dial, first) = dial(&mut entropy, None);
    assert_eq!(&first[118..], &[0; 16], "no cookie yet: mac2 is zeros");
    let reply = answer(
        &mut responder,
        &first,
        t(0),
        &mut Fixed::accept(),
        &mut entropy,
    )
    .unwrap();
    assert!(matches!(
        dial.handle(&initiator, &reply, t(10)),
        DialEvent::Ignored
    ));
    let cookie = *dial.cookie_at(t(10)).expect("the cookie was kept");

    let mut out = [0u8; 256];
    for now in (20..1000).step_by(10) {
        assert!(
            matches!(
                dial.poll(&initiator, t(now), &mut entropy, &mut out),
                DialPoll::Wait(_)
            ),
            "nothing is sent before the schedule"
        );
    }
    let DialPoll::Send(len) = dial.poll(&initiator, t(1000), &mut entropy, &mut out) else {
        panic!("the retry is due at 1 s");
    };
    let retry = &out[..len];
    assert_eq!(&retry[118..], &crate::dos::mac2(&cookie, &retry[..118]));

    // Still under load at that instant, the retry goes through on its mac2.
    exhaust(&mut responder, t(1000), &mut entropy);
    let response = answer(
        &mut responder,
        retry,
        t(1000),
        &mut Fixed::accept(),
        &mut entropy,
    )
    .unwrap();
    established(dial.handle(&initiator, &response, t(1001)));
}

/// Scenario: a forged cookie reply is ignored.
#[test]
fn a_forged_cookie_reply_is_ignored() {
    let mut entropy = TestEntropy(2700);
    let initiator = identity(INITIATOR);
    let (mut dial, first) = dial(&mut entropy, None);
    let index = u32::from_le_bytes(first[2..6].try_into().unwrap());
    let mac1 = crate::wire::carried_mac1(&first).unwrap();

    let other_address = *identity(2).address().as_bytes();
    let forgeries = [
        // Another index.
        crate::dos::write_cookie_reply(
            responder_address().as_bytes(),
            index ^ 1,
            &[1; 24],
            &[2; 16],
            &mac1,
        )
        .unwrap(),
        // Encrypted for another address.
        crate::dos::write_cookie_reply(&other_address, index, &[1; 24], &[2; 16], &mac1).unwrap(),
        // Bound to another mac1.
        crate::dos::write_cookie_reply(
            responder_address().as_bytes(),
            index,
            &[1; 24],
            &[2; 16],
            &[0; 16],
        )
        .unwrap(),
    ];
    for forged in forgeries {
        assert!(matches!(
            dial.handle(&initiator, &forged, t(1)),
            DialEvent::Ignored
        ));
        assert!(dial.cookie_at(t(1)).is_none());
    }
    let mut out = [0u8; 256];
    let DialPoll::Send(len) = dial.poll(&initiator, t(1000), &mut entropy, &mut out) else {
        panic!("the retry is due at 1 s");
    };
    assert_eq!(&out[118..len], &[0; 16]);
}

/// Scenario: a cookie older than 120 seconds is no longer used.
#[test]
fn a_cookie_lives_120_seconds() {
    let mut entropy = TestEntropy(2800);
    let mut responder = responder();
    exhaust(&mut responder, t(0), &mut entropy);
    let initiator = identity(INITIATOR);
    let (mut dial, first) = dial(&mut entropy, None);
    let reply = answer(
        &mut responder,
        &first,
        t(0),
        &mut Fixed::accept(),
        &mut entropy,
    )
    .unwrap();
    dial.handle(&initiator, &reply, t(5));
    assert!(dial.cookie_at(t(5 + 119_999)).is_some());
    assert!(dial.cookie_at(t(5 + 120_000)).is_none());
}

// --- under load: end to end -------------------------------------------------------------

/// A responder flooded by first contacts from spoofed sources, and an honest
/// initiator dialling it at the same time.
#[test]
fn an_honest_dial_completes_through_a_spoofed_flood() {
    let mut entropy = TestEntropy(2900);
    let mut responder = responder();
    let attacker = identity(3);
    let honest = identity(INITIATOR);
    let mut cookie_replies = 0;
    let mut answered = 0;

    let mut flood = |responder: &mut Responder<Mcu>, now: u64, entropy: &mut TestEntropy| {
        // A spoofed source: a different address for every packet.
        let spoofed = [10, (now >> 8) as u8, now as u8, 1, 0, 1];
        let mut out = [0u8; 256];
        let (_, len) = Dial::start(
            &attacker,
            &responder_address(),
            CONTEXT,
            None,
            t(now),
            entropy,
            &mut out,
        )
        .unwrap();
        match answer_from(
            responder,
            &out[..len],
            Source::Direct(&spoofed),
            t(now),
            &mut Fixed::accept(),
            entropy,
        ) {
            Some(reply) if reply.len() == 62 => cookie_replies += 1,
            Some(_) => answered += 1,
            None => {}
        }
    };

    // The flood starts first and fills the bucket.
    for now in (0..50).step_by(5) {
        flood(&mut responder, now, &mut entropy);
    }
    let (mut dial, first) = dial(&mut entropy, None);
    let reply = answer(
        &mut responder,
        &first,
        t(50),
        &mut Fixed::accept(),
        &mut entropy,
    )
    .unwrap();
    assert_eq!(
        reply.len(),
        62,
        "the honest first contact meets a cookie reply"
    );
    dial.handle(&honest, &reply, t(51));

    let mut established_at = None;
    let mut out = [0u8; 256];
    for now in (55..=1500).step_by(5) {
        flood(&mut responder, now, &mut entropy);
        if established_at.is_none()
            && let DialPoll::Send(len) = dial.poll(&honest, t(now), &mut entropy, &mut out)
        {
            let response = answer(
                &mut responder,
                &out[..len],
                t(now),
                &mut Fixed::accept(),
                &mut entropy,
            )
            .expect("the retry with mac2 is answered");
            established(dial.handle(&honest, &response, t(now)));
            established_at = Some(now);
        }
    }
    // The dial started at 0 (its first contact reached the responder at 50 ms,
    // behind the flood); its retry falls due at 1 s and carries mac2.
    assert_eq!(
        established_at,
        Some(1000),
        "the honest dial completes on its retry at 1 s"
    );

    // The bucket's allowance over 1.5 s: a burst of 5 plus 5 a second.
    let allowance = 5 + 1500 * 5 / 1000;
    let honest_diffie_hellmans = 1;
    assert!(
        responder.diffie_hellmans <= allowance + honest_diffie_hellmans,
        "{} Diffie-Hellmans",
        responder.diffie_hellmans
    );
    assert_eq!(answered, responder.diffie_hellmans - honest_diffie_hellmans);
    assert!(
        cookie_replies > 250,
        "every other spoofed first contact got a cookie reply"
    );
}

/// The time a responder under load spends on a first contact without a valid
/// mac2 (a cookie reply, no Diffie-Hellman) and on one with a valid mac2 (the
/// full handshake). Ignored by default; run it with
/// `cargo test -p convesso-core --release --lib under_load_time -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, meaningful only in release"]
fn under_load_time() {
    let mut entropy = TestEntropy(9500);
    let mut cookie_path = Vec::with_capacity(1000);
    let mut full_path = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let mut responder = responder();
        exhaust(&mut responder, t(0), &mut entropy);
        let (_, without) = dial(&mut entropy, None);
        let started = std::time::Instant::now();
        let reply = answer(
            &mut responder,
            &without,
            t(0),
            &mut Fixed::accept(),
            &mut entropy,
        );
        cookie_path.push(started.elapsed());
        let reply = reply.unwrap();
        assert_eq!(reply.len(), 62);

        let parsed = crate::dos::parse_cookie_reply(&reply).unwrap();
        let mac1 = crate::wire::carried_mac1(&without).unwrap();
        let cookie =
            crate::dos::open_cookie_reply(&parsed, responder_address().as_bytes(), &mac1).unwrap();
        let with = with_mac2(&mut entropy, &cookie);
        let started = std::time::Instant::now();
        let reply = answer(
            &mut responder,
            &with,
            t(0),
            &mut Fixed::accept(),
            &mut entropy,
        );
        full_path.push(started.elapsed());
        assert_eq!(reply.unwrap().len(), RESPONSE_LEN);
    }
    cookie_path.sort_unstable();
    full_path.sort_unstable();
    std::println!(
        "under load, median of 1000: without a valid mac2 (cookie reply) {:?}; with a valid mac2 (full handshake) {:?}",
        cookie_path[500],
        full_path[500]
    );
}

// --- first contacts with a payload -----------------------------------------------------

const RELAY_CONTEXT: &[u8] = b"convesso-relay";

/// A responder serving `CONTEXT`, and `RELAY_CONTEXT` with payloads.
fn payload_responder() -> Responder<Mcu> {
    let mut responder: Responder<Mcu> =
        Responder::new(identity(RESPONDER), &[CONTEXT, RELAY_CONTEXT]).unwrap();
    responder.accept_payload(RELAY_CONTEXT).unwrap();
    responder
}

fn a_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 13 + 5) as u8).collect()
}

/// Starts a dial carrying `payload` in `context`; returns it and its first contact.
fn dial_with(entropy: &mut TestEntropy, context: &[u8], payload: &[u8]) -> (Dial, Vec<u8>) {
    let mut out = [0u8; MAX_FIRST_CONTACT_LEN];
    let (dial, len) = Dial::start_with_payload(
        &identity(INITIATOR),
        &responder_address(),
        context,
        None,
        payload,
        t(0),
        entropy,
        &mut out,
    )
    .unwrap();
    (dial, out[..len].to_vec())
}

/// A payload handed over, with its peer and context.
type Handed = (Vec<u8>, PeerId, Context);

/// What a responder answers, with the payload it hands over, if any.
fn answer_payload(
    responder: &mut Responder<Mcu>,
    packet: &[u8],
    now: Instant,
    admission: &mut Fixed,
    entropy: &mut TestEntropy,
) -> (Option<Vec<u8>>, Option<Handed>) {
    let mut out = [0u8; RESPONSE_LEN + MAX_PAYLOAD];
    match responder.handle(packet, SOURCE, now, admission, entropy, &mut out) {
        ResponderOutput::Send(len) => (Some(out[..len].to_vec()), None),
        ResponderOutput::Payload {
            len,
            payload,
            peer,
            context,
        } => {
            assert!(len + payload <= out.len());
            (
                Some(out[..len].to_vec()),
                Some((out[len..len + payload].to_vec(), peer, context)),
            )
        }
        ResponderOutput::Silent => (None, None),
    }
}

/// Scenario: an admitted payload is handed over, marked unconfirmed — and the
/// handshake completes as any other.
#[test]
fn an_admitted_payload_is_handed_over() {
    let mut entropy = TestEntropy(5000);
    let payload = a_payload(168);
    let (mut dial, first) = dial_with(&mut entropy, RELAY_CONTEXT, &payload);
    assert_eq!(first.len(), FIRST_CONTACT_LEN + 168);
    assert_eq!(&first[..2], &[0x01, 0x05]);
    let parsed = messages::parse_payload_first_contact(&first).unwrap();
    assert_eq!(parsed.payload_len(), 168);

    let mut responder = payload_responder();
    let mut admission = Fixed::accept();
    let (response, handed) =
        answer_payload(&mut responder, &first, t(5), &mut admission, &mut entropy);
    let response = response.unwrap();
    assert_eq!(response.len(), RESPONSE_LEN);
    let (data, peer, context) = handed.unwrap();
    assert_eq!(data, payload);
    assert_eq!(peer, identity(INITIATOR).peer_id());
    assert_eq!(context.as_bytes(), RELAY_CONTEXT);
    assert_eq!(admission.asked, 1);
    assert_eq!(responder.pending_count(), 1);

    let established = established(dial.handle(&identity(INITIATOR), &response, t(10)));
    assert_eq!(established.context().as_bytes(), RELAY_CONTEXT);
}

/// The payload limits: 1 and 1,200 bytes travel; 1,201 cannot be dialled.
#[test]
fn payloads_of_1_to_1200_bytes_travel() {
    let mut entropy = TestEntropy(5100);
    let mut responder = payload_responder();
    for len in [1, MAX_PAYLOAD] {
        let payload = a_payload(len);
        let (_, first) = dial_with(&mut entropy, RELAY_CONTEXT, &payload);
        assert_eq!(first.len(), FIRST_CONTACT_LEN + len);
        let (_, handed) = answer_payload(
            &mut responder,
            &first,
            t(0),
            &mut Fixed::accept(),
            &mut entropy,
        );
        assert_eq!(handed.unwrap().0, payload);
    }
    let mut out = [0u8; MAX_FIRST_CONTACT_LEN + 1];
    assert!(matches!(
        Dial::start_with_payload(
            &identity(INITIATOR),
            &responder_address(),
            RELAY_CONTEXT,
            None,
            &a_payload(MAX_PAYLOAD + 1),
            t(0),
            &mut entropy,
            &mut out,
        ),
        Err(DialError::PayloadTooLong)
    ));
}

/// Scenario: a context that does not accept a payload is silent — even when the
/// responder accepts payloads in another context. A responder accepting none
/// drops the packet on its type, before any Diffie-Hellman.
#[test]
fn a_context_that_does_not_accept_a_payload_is_silent() {
    let mut entropy = TestEntropy(5200);
    let (_, first) = dial_with(&mut entropy, CONTEXT, &a_payload(40));
    let mut accepting = payload_responder();
    let mut admission = Fixed::accept();
    assert_eq!(
        answer_payload(&mut accepting, &first, t(0), &mut admission, &mut entropy),
        (None, None)
    );
    assert_eq!(admission.asked, 0);
    assert_eq!(accepting.pending_count(), 0);

    let (_, first) = dial_with(&mut entropy, CONTEXT, &a_payload(40));
    let mut plain = responder();
    assert_eq!(
        answer_payload(&mut plain, &first, t(0), &mut admission, &mut entropy),
        (None, None)
    );
    assert_eq!(plain.diffie_hellmans, 0);
    assert_eq!(admission.asked, 0);
}

/// Scenario: a refused payload is never handed over.
#[test]
fn a_refused_payload_is_never_handed_over() {
    let mut entropy = TestEntropy(5300);
    let (mut dial, first) = dial_with(&mut entropy, RELAY_CONTEXT, &a_payload(50));
    let mut responder = payload_responder();
    let code = RefusalCode::application(0x0100).unwrap();
    let mut admission = Fixed::with(Decision::Refuse { code, psk: None });
    let (response, handed) =
        answer_payload(&mut responder, &first, t(0), &mut admission, &mut entropy);
    assert!(handed.is_none());
    assert_eq!(responder.pending_count(), 0);
    assert!(matches!(
        dial.handle(&identity(INITIATOR), &response.unwrap(), t(1)),
        DialEvent::Failed(DialError::Refused(c)) if c == code
    ));
}

/// Scenario: an empty or oversized payload is dropped, with no Diffie-Hellman;
/// and a first contact of type 0x01 with a payload is dropped.
#[test]
fn an_empty_or_oversized_payload_is_dropped() {
    let mut entropy = TestEntropy(5400);
    let mut responder = payload_responder();
    let mut admission = Fixed::accept();

    // Type 0x05, 134 bytes: a valid 0x01 first contact relabelled.
    let (_, mut first) = dial_with(&mut entropy, RELAY_CONTEXT, &[]);
    assert_eq!(first[1], 0x01);
    first[1] = 0x05;
    assert!(matches!(
        messages::parse_payload_first_contact(&first),
        Err(MessageError::WrongLength { actual: 134, .. })
    ));
    assert_eq!(
        answer_payload(&mut responder, &first, t(0), &mut admission, &mut entropy),
        (None, None)
    );

    // Type 0x05, 1,335 bytes.
    let (_, mut first) = dial_with(&mut entropy, RELAY_CONTEXT, &a_payload(MAX_PAYLOAD));
    first.push(0);
    assert!(messages::parse_payload_first_contact(&first).is_err());
    assert_eq!(
        answer_payload(&mut responder, &first, t(0), &mut admission, &mut entropy),
        (None, None)
    );

    // A payload first contact relabelled 0x01: not 134 bytes, dropped.
    let (_, mut first) = dial_with(&mut entropy, RELAY_CONTEXT, &a_payload(10));
    first[1] = 0x01;
    assert_eq!(
        answer_payload(&mut responder, &first, t(0), &mut admission, &mut entropy),
        (None, None)
    );
    assert_eq!(responder.diffie_hellmans, 0);
    assert_eq!(admission.asked, 0);
}

/// Scenario: a replayed payload is delivered again, and never becomes a
/// connection; within 5 seconds the replay is dropped before any
/// Diffie-Hellman.
#[test]
fn a_replayed_payload_is_delivered_again() {
    let mut entropy = TestEntropy(5500);
    let payload = a_payload(100);
    let (_, first) = dial_with(&mut entropy, RELAY_CONTEXT, &payload);
    let mut responder = payload_responder();
    let mut admission = Fixed::accept();
    assert!(
        answer_payload(&mut responder, &first, t(0), &mut admission, &mut entropy)
            .1
            .is_some()
    );
    assert_eq!(
        answer_payload(
            &mut responder,
            &first,
            t(1000),
            &mut admission,
            &mut entropy
        ),
        (None, None)
    );
    let (_, again) = answer_payload(
        &mut responder,
        &first,
        t(6000),
        &mut admission,
        &mut entropy,
    );
    assert_eq!(again.unwrap().0, payload);
    assert_eq!(responder.diffie_hellmans, 2);
    responder.expire(t(11_000));
    assert_eq!(responder.pending_count(), 0);
}

/// Every retry carries the same payload, under a fresh ephemeral key and index.
#[test]
fn retries_carry_the_same_payload() {
    let mut entropy = TestEntropy(5600);
    let payload = a_payload(168);
    let (mut dial, first) = dial_with(&mut entropy, RELAY_CONTEXT, &payload);
    let mut out = [0u8; MAX_FIRST_CONTACT_LEN];
    let DialPoll::Send(len) = dial.poll_with_payload(
        &identity(INITIATOR),
        &payload,
        t(1000),
        &mut entropy,
        &mut out,
    ) else {
        panic!("a retry is due at 1 s");
    };
    let retry = out[..len].to_vec();
    assert_eq!(retry.len(), first.len());
    assert_ne!(
        retry[2..38],
        first[2..38],
        "a fresh index and ephemeral key"
    );
    let mut responder = payload_responder();
    for packet in [&first, &retry] {
        let (_, handed) = answer_payload(
            &mut responder,
            packet,
            t(1000),
            &mut Fixed::accept(),
            &mut entropy,
        );
        assert_eq!(handed.unwrap().0, payload);
    }
}

/// mac2 and the cookie apply to a first contact with a payload as to any: under
/// load, one without a valid mac2 gets a cookie reply and no Diffie-Hellman.
#[test]
fn under_load_a_payload_first_contact_gets_a_cookie() {
    let mut entropy = TestEntropy(5700);
    let mut responder = payload_responder();
    exhaust(&mut responder, t(0), &mut entropy);
    let before = responder.diffie_hellmans;
    let (_, first) = dial_with(&mut entropy, RELAY_CONTEXT, &a_payload(168));
    let (reply, handed) = answer_payload(
        &mut responder,
        &first,
        t(0),
        &mut Fixed::accept(),
        &mut entropy,
    );
    assert!(handed.is_none());
    assert_eq!(reply.unwrap().len(), crate::dos::COOKIE_REPLY_LEN);
    assert_eq!(responder.diffie_hellmans, before);
}

/// A first contact with a payload is handled only with room for the payload
/// after the response; with less, it is dropped before any Diffie-Hellman.
#[test]
fn a_payload_needs_room_in_the_output() {
    let mut entropy = TestEntropy(5800);
    let (_, first) = dial_with(&mut entropy, RELAY_CONTEXT, &a_payload(168));
    let mut responder = payload_responder();
    let mut out = [0u8; RESPONSE_LEN + 167];
    assert_eq!(
        responder.handle(
            &first,
            SOURCE,
            t(0),
            &mut Fixed::accept(),
            &mut entropy,
            &mut out
        ),
        ResponderOutput::Silent
    );
    assert_eq!(responder.diffie_hellmans, 0);
}

// --- contexts bound to one peer --------------------------------------------------------

/// Scenario: the bound peer is admitted.
#[test]
fn the_bound_peer_is_admitted() {
    let mut entropy = TestEntropy(5900);
    let mut responder = payload_responder();
    responder
        .set_access(
            &Context::new(RELAY_CONTEXT).unwrap(),
            Access::Bound(identity(INITIATOR).peer_id()),
        )
        .unwrap();
    let (_, first) = dial_with(&mut entropy, RELAY_CONTEXT, &a_payload(20));
    let mut admission = Fixed::accept();
    let (_, handed) = answer_payload(&mut responder, &first, t(0), &mut admission, &mut entropy);
    assert_eq!(handed.unwrap().0, a_payload(20));
    assert_eq!(admission.asked, 1);
}

/// Scenario: any other peer meets silence — with or without a payload, whatever
/// admission would say, and never with a refusal. The other contexts are not
/// affected.
#[test]
fn any_other_peer_meets_silence_in_a_bound_context() {
    let mut entropy = TestEntropy(6000);
    let mut responder = payload_responder();
    responder
        .set_access(
            &Context::new(RELAY_CONTEXT).unwrap(),
            Access::Bound(identity(2).peer_id()),
        )
        .unwrap();
    let code = RefusalCode::application(0x0100).unwrap();
    for decision in [
        Decision::Accept { psk: None },
        Decision::Refuse { code, psk: None },
    ] {
        let mut admission = Fixed::with(decision);
        for payload in [&[][..], &a_payload(30)[..]] {
            let (_, first) = dial_with(&mut entropy, RELAY_CONTEXT, payload);
            assert_eq!(
                answer_payload(&mut responder, &first, t(0), &mut admission, &mut entropy),
                (None, None)
            );
        }
        assert_eq!(admission.asked, 0);
        assert_eq!(responder.pending_count(), 0);
    }
    let (_, first) = dial(&mut entropy, None);
    assert!(
        answer(
            &mut responder,
            &first,
            t(0),
            &mut Fixed::accept(),
            &mut entropy
        )
        .is_some()
    );
}

/// Binding or accepting payloads in a context not served is an error; serving
/// one twice, or one more than the profile holds, is refused.
#[test]
fn only_served_contexts_can_be_bound() {
    let mut served = responder();
    let relay = Context::new(RELAY_CONTEXT).unwrap();
    assert_eq!(
        served.set_access(&relay, Access::Bound(identity(2).peer_id())),
        Err(ResponderError::NotServed)
    );
    assert_eq!(
        served.accept_payload(RELAY_CONTEXT),
        Err(ResponderError::NotServed)
    );
    served.serve(RELAY_CONTEXT, Access::Policy).unwrap();
    assert_eq!(
        served.serve(RELAY_CONTEXT, Access::Policy),
        Err(ResponderError::AlreadyServed)
    );
    assert!(served.accept_payload(RELAY_CONTEXT).is_ok());
    for extra in [&b"a"[..], b"b"] {
        served.serve(extra, Access::Policy).unwrap();
    }
    assert_eq!(
        served.serve(b"c", Access::Policy),
        Err(ResponderError::TooManyContexts { capacity: 4 })
    );
    assert!(served.stop_serving(&relay));
    assert!(!served.serves(&relay));
    served.serve(b"c", Access::Policy).unwrap();
}
