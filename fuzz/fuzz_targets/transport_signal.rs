//! Parsing an unknown-index signal: never panics, accepts exactly the 10-byte
//! packets with the right header, and reads back the index it was written
//! with.

#![no_main]

use convesso_core::transport::{self, UNKNOWN_INDEX_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = transport::parse_unknown_index(data);
    let well_formed = data.len() == UNKNOWN_INDEX_LEN && data[0] == 0x01 && data[1] == 0x07;
    assert_eq!(parsed.is_ok(), well_formed);
    if let Ok(index) = parsed {
        assert_eq!(transport::write_unknown_index(index).as_slice(), data);
    }
});
