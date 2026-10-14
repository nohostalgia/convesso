//! Parsing a cookie reply: never panics, and accepts exactly the 62-byte
//! packets with the right header. Opening one with any address and mac1 never
//! panics either.

#![no_main]

use convesso_core::dos::{self, COOKIE_REPLY_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = dos::parse_cookie_reply(data);
    let well_formed = data.len() == COOKIE_REPLY_LEN && data[0] == 0x01 && data[1] == 0x03;
    assert_eq!(parsed.is_ok(), well_formed);
    if let Ok(reply) = parsed {
        let _ = dos::open_cookie_reply(&reply, &[7; 32], &[9; 16]);
    }
});
