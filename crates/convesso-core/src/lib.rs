//! The convesso protocol core.
//!
//! `no_std`, without an allocator, and sans-IO: bytes and the current time go
//! in, bytes and deadlines come out. No sockets, no clock, no threads, no heap.
//! The same code runs on a server and on a 32-bit microcontroller, which is why
//! none of those may appear here (`DESIGN.md §2`).
//!
//! The `alloc` feature adds a growable [`storage::GrowableTable`] for servers.
//! It does not let the protocol logic allocate: that logic asks a
//! [`storage::Table`] for room and never learns where the room comes from.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod dos;
pub mod endpoint;
pub mod handshake;
pub mod identity;
mod noise;
pub mod paths;
pub mod relay;
pub mod session;
pub mod storage;
pub mod time;
pub mod transport;
pub mod wire;

// The cryptographic crates are loaded even before the handshake uses them, so
// that the no-allocator check on the reference firmware covers them too.
use blake2 as _;
use chacha20poly1305 as _;
use curve25519_dalek as _;
use hmac as _;
use x25519_dalek as _;
