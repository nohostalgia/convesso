//! The convesso driver for tokio: desktop, server and Android.
//!
//! A driver does only input and output (`DESIGN.md §5`): it hands
//! the no_std core what its sockets receive, sends what the core outputs on
//! the path the core names, opens and closes the relay link when the core
//! says so, and wakes the core at its deadlines. Every protocol decision is the
//! core's, so this driver and the embedded one behave alike.
//!
//! - [`start`] runs an endpoint and returns a [`Node`] handle and its
//!   [`Events`].
//! - [`relay_server::serve`] runs a relay; the `convesso-relay` binary
//!   (feature `relay-bin`) wraps it with a configuration file.
//! - [`identity::load_or_create`] keeps an identity in a private file.

pub mod address;
pub mod entropy;
pub mod identity;
mod node;
mod receiver;
pub mod relay_server;

#[cfg(feature = "relay-bin")]
pub mod relay_config;

pub use node::{
    Config, DIRECT_PATH_MAX, Delivery, Events, Node, NodeError, NodeEvent, RelayLocation,
    SocketHandle, SocketHook, StartError, Stats, start, start_with,
};
pub use receiver::{ELEMENT_COST, Received, Receiver, SessionClosed};
