//! Parsing a version 1 first contact: never panics, accepts exactly the
//! 134-byte packets with the right header (an opening, `0x01`, or a renewal,
//! `0x06`), and says which.

#![no_main]

use convesso_core::handshake::{FIRST_CONTACT_LEN, messages};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = messages::parse_first_contact(data);
    let well_formed = data.len() == FIRST_CONTACT_LEN
        && data[0] == 0x01
        && (data[1] == messages::TYPE_INITIATION || data[1] == messages::TYPE_RENEWAL);
    assert_eq!(parsed.is_ok(), well_formed);
    if let Ok(first) = parsed {
        assert_eq!(first.renewal, data[1] == messages::TYPE_RENEWAL);
    }
});
