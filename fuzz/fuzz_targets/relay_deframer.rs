//! The TCP de-framer never panics on any stream cut anywhere, never hands out
//! a packet longer than the framing allows, and once closed stays closed.
//!
//! The first input byte sets the size of the pieces the rest is fed in; half
//! the time the preamble is put in front, so that the fuzzer reaches the
//! frames behind it.

#![no_main]

use convesso_core::relay::framing::{Deframed, Deframer, MAX_FRAME, PREAMBLE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let mut stream = Vec::new();
    if mode & 0x80 == 0 {
        stream.extend_from_slice(&PREAMBLE);
    }
    stream.extend_from_slice(rest);
    let piece = usize::from(mode & 0x7f).max(1);
    let mut deframer = Deframer::default();
    let mut closed = false;
    for chunk in stream.chunks(piece) {
        let mut at = 0;
        loop {
            let (used, result) = deframer.feed(&chunk[at..]);
            at += used;
            assert!(at <= chunk.len());
            match result {
                Deframed::NeedMore => {
                    assert_eq!(at, chunk.len());
                    break;
                }
                Deframed::KeepAlive => assert!(!closed),
                Deframed::Packet(packet) => {
                    assert!(!closed);
                    assert!(!packet.is_empty() && packet.len() <= MAX_FRAME);
                }
                Deframed::Closed(_) => {
                    if closed {
                        assert_eq!(used, 0, "a closed link reads nothing more");
                    }
                    closed = true;
                    break;
                }
            }
        }
    }
});
