//! The convesso driver for tokio: desktop, server and Android.
//!
//! A driver does only input and output (`DESIGN.md §5`): it hands
//! the no_std core what its sockets receive, sends what the core outputs on
//! the path the core names, opens and closes the relay link when the core
//! says so, and wakes the core at its deadlines. Every protocol decision is the
//! core's, so this driver and the embedded one behave alike.
//!
//! - [`start`] runs an endpoint and returns a [`Node`] handle and its
//!   [`Events`]; [`Node::context`] opens a context, returning its [`Context`]
//!   handle and its [`ContextEvents`].
//! - [`relay_server::serve`] runs a relay; the `convesso-relay` binary
//!   (feature `relay-bin`) wraps it with a configuration file.
//! - [`identity::load_or_create`] keeps an identity in a private file.
//! - With the feature `tls`, the relay link may be wrapped in TLS 1.3, which
//!   authenticates nothing ([`RelayLocation::tls`], `tls::TlsAcceptor`).

pub mod address;
pub mod entropy;
pub mod identity;
mod node;
mod receiver;
pub mod relay_server;

#[cfg(feature = "relay-bin")]
pub mod relay_config;
#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "stream")]
pub use node::start_with_stream;
pub use node::{
    Access, Config, Context, ContextEvent, ContextEvents, ContextOptions, DIRECT_PATH_MAX, DROPPED,
    Delivery, Events, Node, NodeError, NodeEvent, RelayLocation, SocketHandle, SocketHook,
    StartError, Stats, start, start_with,
};
pub use receiver::{ELEMENT_COST, Received, Receiver, SessionClosed};
