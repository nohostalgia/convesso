//! Parsing a version 1 response: never panics, and accepts exactly the 61-byte
//! packets with the right header.

#![no_main]

use convesso_core::handshake::{RESPONSE_LEN, messages};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = messages::parse_response(data);
    let well_formed = data.len() == RESPONSE_LEN && data[0] == 0x01 && data[1] == 0x02;
    assert_eq!(parsed.is_ok(), well_formed);
});
