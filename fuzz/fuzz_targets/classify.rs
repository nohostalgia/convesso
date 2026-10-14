//! Byte 0 classification and the responder's answer to an unknown version, on
//! arbitrary input. Beyond not panicking, an answer must hold the invariants of
//! PROTOCOL.md §1: never larger than the packet, well formed, echoing the
//! packet's mac1, and only for a packet whose mac1 is valid.

#![no_main]

use convesso_core::wire::{
    Mac1Key, Version, VersionNotSupported, answer_unknown_version, carried_mac1, classify,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = classify(data);
    let Some((address, packet)) = data.split_first_chunk::<32>() else {
        return;
    };
    let key = Mac1Key::for_address(address);
    let mut out = [0u8; 64];
    if let Some(len) = answer_unknown_version(packet, &key, &[Version::V1], &mut out) {
        assert!(len <= packet.len(), "the answer is larger than the packet");
        assert!(
            key.verify(packet),
            "an answer to a packet without a valid mac1"
        );
        let answer = VersionNotSupported::decode(&out[..len]).expect("the answer is well formed");
        assert_eq!(Some(*answer.echo()), carried_mac1(packet));
    }
});
