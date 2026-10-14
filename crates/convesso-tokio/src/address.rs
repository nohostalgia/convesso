//! The encoding of IP sources: the core's (`convesso_core::dos::encode_ip`),
//! which every driver uses, re-exported for the driver's callers.

pub use convesso_core::dos::{IP_SOURCE_LEN as MAX_LEN, decode_ip as decode, encode_ip as encode};
