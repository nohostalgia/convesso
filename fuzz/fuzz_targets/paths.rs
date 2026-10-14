//! The path message decoders never panic, and every message they accept
//! encodes to bytes that decode to the same message (byte for byte, except an
//! IPv4-mapped address, which is written back as IPv4).

#![no_main]

use convesso_core::paths;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut out = [0u8; paths::MAX_CANDIDATES_LEN];
    if let Ok(list) = paths::decode_candidates(data) {
        let len = paths::encode_candidates(list.generation, list.as_slice(), &mut out)
            .expect("a decoded list encodes");
        assert_eq!(paths::decode_candidates(&out[..len]), Ok(list));
    }
    if let Ok((nonce, seen)) = paths::decode_answer(data) {
        let len = paths::encode_answer(&nonce, seen, &mut out).expect("a decoded answer encodes");
        assert_eq!(paths::decode_answer(&out[..len]), Ok((nonce, seen)));
    }
    let _ = paths::decode_probe(data);
});
