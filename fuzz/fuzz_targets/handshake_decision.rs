//! Decoding a decision: never panics, and whatever it accepts encodes back to
//! exactly the bytes it was given.

#![no_main]

use convesso_core::handshake::messages;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(decision) = messages::decode_decision(data) {
        assert_eq!(&messages::encode_decision(decision)[..], data);
    }
});
