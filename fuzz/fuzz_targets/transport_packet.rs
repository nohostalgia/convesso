//! Parsing and opening a transport packet on arbitrary input never panics, and
//! whatever is sealed opens back to the same inner type and data.

#![no_main]

use convesso_core::transport::{self, OVERHEAD};
use libfuzzer_sys::fuzz_target;

const KEY: [u8; 32] = [0x42; 32];

fuzz_target!(|data: &[u8]| {
    let mut packet = data.to_vec();
    let _ = transport::parse_header(&packet);
    let _ = transport::open(&KEY, &mut packet);

    // Round trip: the input as inner type and data.
    if let Some((&inner_type, body)) = data.split_first() {
        let counter = u64::from(data.len() as u32);
        let mut out = vec![0u8; OVERHEAD + body.len()];
        let len = transport::seal(&KEY, 7, counter, inner_type, body, &mut out).expect("sealed");
        let opened = transport::open(&KEY, &mut out[..len]).expect("opens");
        assert_eq!(opened.inner_type, inner_type);
        assert_eq!(opened.data, body);
        assert_eq!(opened.header.counter, counter);
    }
});
