//! The socket interface (`DESIGN.md §5`): what the driver needs from a network,
//! and nothing of how a stack provides it.
//!
//! ```text
//! Datagrams    one socket, one port, both families: everything but the relay link
//! Streams      the stream connection to the relay: connect, read, write, close
//! Interfaces   the addresses this device is reachable at
//! ```
//!
//! A datagram socket is used through `&self`, so that the application's sends
//! and the driver's receives share it without copying a packet between tasks.
//! The stream is `embedded-io-async`'s, which network stacks and modem crates
//! implement.

use core::net::SocketAddr;

/// Why a socket operation failed. The driver turns each into the core's input
/// for it, never into a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    /// The datagram could not be sent.
    SendFailed,
    /// No datagram could be received.
    RecvFailed,
    /// The stream connection could not be opened.
    ConnectFailed,
    /// The stream connection failed or closed.
    StreamFailed,
}

impl core::fmt::Display for SocketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::SendFailed => "a datagram could not be sent",
            Self::RecvFailed => "no datagram could be received",
            Self::ConnectFailed => "the stream connection could not be opened",
            Self::StreamFailed => "the stream connection failed",
        })
    }
}

impl core::error::Error for SocketError {}

/// One datagram socket on one port, carrying both address families.
#[allow(
    async_fn_in_trait,
    reason = "the driver awaits these on one executor; no Send bound is wanted"
)]
pub trait Datagrams {
    /// Sends `packet` to `to`.
    ///
    /// # Errors
    ///
    /// [`SocketError::SendFailed`].
    async fn send_to(&self, packet: &[u8], to: SocketAddr) -> Result<(), SocketError>;

    /// Waits for a datagram, and writes it into `buf`: returns its length and
    /// its source, an IPv4-mapped address given as IPv4.
    ///
    /// # Errors
    ///
    /// [`SocketError::RecvFailed`].
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), SocketError>;

    /// The socket's local port.
    fn local_port(&self) -> u16;
}

/// The stream connection to the relay: one at a time.
#[allow(
    async_fn_in_trait,
    reason = "the driver awaits these on one executor; no Send bound is wanted"
)]
pub trait Streams: embedded_io_async::Read + embedded_io_async::Write {
    /// Opens the connection to `to`, closing one that was open.
    ///
    /// # Errors
    ///
    /// [`SocketError::ConnectFailed`].
    async fn connect(&mut self, to: SocketAddr) -> Result<(), SocketError>;

    /// Closes the connection, if open. Nothing is reported back.
    fn close(&mut self);
}

/// Where this device can be reached.
pub trait Interfaces {
    /// Writes the addresses of the device's interfaces into `out`, without
    /// ports, and returns how many. The driver adds its socket's port; the
    /// core decides which become candidates.
    fn local_addresses(&self, out: &mut [core::net::IpAddr]) -> usize;
}

/// An IPv4-mapped IPv6 address as the IPv4 address it is.
#[must_use]
pub fn canonical(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        core::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(address, |v4| {
            SocketAddr::new(core::net::IpAddr::V4(v4), address.port())
        }),
        core::net::IpAddr::V4(_) => address,
    }
}
