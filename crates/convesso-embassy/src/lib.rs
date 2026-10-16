//! The convesso driver for microcontrollers, on Embassy.
//!
//! A driver does only input and output (`DESIGN.md §5`): it hands
//! the no_std core what its sockets receive, sends what the core outputs on
//! the path the core names, opens and closes the relay link when the core says
//! so, and wakes the core at its deadlines. Every protocol decision is the
//! core's, so this driver and the tokio one behave alike.
//!
//! It allocates nothing: every buffer is the integrator's. It reaches the
//! network through the [`socket`] interface, implemented over `embassy-net`
//! (feature `embassy-net`, on by default), so that a network with its own
//! TCP/IP stack can be plugged in later. The device is given its identity, as
//! a [`record`]; its entropy is the chip's generator, as a [`rng::SecureRng`].

#![no_std]
#![forbid(unsafe_code)]

mod events;
#[cfg(feature = "embassy-net")]
pub mod net;
mod node;
pub mod record;
pub mod rng;
pub mod socket;

pub use events::{ContextEvent, ENTRIES, HELD, NODE_ENTRIES, NODE_HELD, NodeError, NodeEvent};
pub use node::{
    Access, Config, Context, ContextEvents, ContextOptions, ContextSlot, DIRECT_PATH_MAX, DROPPED,
    EVENTS_LEN, Events, Node, RelayLocation, Runner, Shared, StartError, Stats, start,
};
