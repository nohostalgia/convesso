//! Decoding "version not supported" on arbitrary input: it never panics, and
//! whatever it accepts encodes back to exactly the bytes it was given.

#![no_main]

use convesso_core::wire::VersionNotSupported;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = VersionNotSupported::decode(data) {
        let mut out = [0u8; 64];
        let len = message
            .encode(&mut out)
            .expect("a decoded message fits 64 bytes");
        assert_eq!(&out[..len], data, "decode and encode disagree");
    }
});
