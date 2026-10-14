//! The reference firmware: convesso-core linked into a bare-metal binary with no
//! global allocator. Its flash and static RAM are what the footprint budget
//! measures, so it calls what a microcontroller would call, on inputs the
//! optimiser cannot see through, and nothing else.

#![no_std]
#![no_main]

use core::hint::black_box;

use convesso_core::wire::{
    MAX_VERSION_NOT_SUPPORTED_LEN, Mac1Key, Version, VersionNotSupported, answer_unknown_version,
    classify,
};
use panic_halt as _;

#[path = "../handshake.rs"]
mod handshake;
#[path = "../relay.rs"]
mod relay;

#[cfg(target_arch = "arm")]
use cortex_m_rt::entry;
#[cfg(target_arch = "riscv32")]
use riscv_rt::entry;

#[entry]
// The firmware exists to be measured, not run: idling without a wait-for-interrupt
// instruction keeps it free of anything but the core and the runtime.
#[allow(clippy::empty_loop)]
fn main() -> ! {
    // The wire invariants a responder runs on every packet it receives.
    let address = black_box([0u8; 32]);
    let packet = black_box([0u8; 64]);
    let key = Mac1Key::for_address(&address);
    let mut out = [0u8; MAX_VERSION_NOT_SUPPORTED_LEN];
    black_box(classify(&packet));
    black_box(key.verify(&packet));
    black_box(answer_unknown_version(
        &packet,
        &key,
        &[Version::V1],
        &mut out,
    ));
    let _ = black_box(VersionNotSupported::decode(&packet));

    // A complete version 1 handshake, initiator and responder both.
    black_box(handshake::run());
    // The same responder under load: cookie reply and cookie (PROTOCOL.md §4).
    black_box(handshake::under_load());
    // Two endpoints: handshake, datagrams both ways, close (PROTOCOL.md §5).
    black_box(handshake::endpoints());
    // A client with a pinned relay: a wake, a forward and a deliver each way
    // (PROTOCOL.md §6).
    black_box(relay::client());

    loop {}
}
