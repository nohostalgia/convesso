//! The stream frame decoders never panic, and every frame they accept encodes
//! back to exactly the bytes it came from.

#![no_main]

use convesso_stream::frame::{Ack, Data, MAX_DATA_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut out = [0u8; MAX_DATA_LEN];
    if let Ok(frame) = Data::decode(data) {
        let len = frame
            .encode(&mut out)
            .expect("a decoded data frame encodes");
        assert_eq!(&out[..len], data);
    }
    if let Ok(frame) = Ack::decode(data) {
        let len = frame
            .encode(&mut out)
            .expect("a decoded acknowledgement encodes");
        assert_eq!(&out[..len], data);
    }
});
