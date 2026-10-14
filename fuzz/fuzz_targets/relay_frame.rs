//! The relay frame decoder never panics, and every frame it accepts encodes
//! back to exactly the bytes it came from.

#![no_main]

use convesso_core::relay;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = relay::decode(data) {
        let mut out = [0u8; 2048];
        let len = relay::encode(&frame, &mut out).expect("a decoded frame encodes");
        assert_eq!(&out[..len], data);
    }
});
