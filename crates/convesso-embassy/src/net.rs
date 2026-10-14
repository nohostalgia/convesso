//! The socket interface over `embassy-net` (feature `embassy-net`).
//!
//! ```text
//! NetDatagrams    one UdpSocket, bound to a port with no address: both families;
//!                 a datagram whose next hop never answers is dropped, not left
//!                 to block the socket
//! NetStream       one TcpSocket, the relay link; TCP keep-alive off (the core
//!                 sends the link's keep-alives)
//! NetInterfaces   the stack's configured addresses, IPv4 and IPv6
//! ```
//!
//! The integrator creates the sockets with its stack and its buffers; these
//! wrap them. The default sizes of those buffers are below: [`UDP_RX_LEN`]
//! and the others, which the NAT tests run with.
//!
//! smoltcp, under `embassy-net`, keeps a datagram whose next hop has no
//! link-layer address yet at the head of the socket's queue, asks for that
//! address at most once a second, and never gives up: one destination on the
//! local subnet that nobody answers (a peer's private address on a network
//! that only numbers like this one) would stop every datagram after it, and
//! the device would send ARP or neighbour requests for as long as it runs.
//! So `NetDatagrams` hands smoltcp one datagram at a time, the driver's sends
//! being one at a time already, and waits for it to leave. A datagram still
//! there after [`STALL`] is dropped by closing and binding the socket again,
//! on the same port, and the destination is refused for [`HOLD`], so that the
//! core's next probes to it do not stall the socket again.

use core::cell::{Cell, RefCell};
use core::future::{Future, poll_fn};
use core::net::{IpAddr, SocketAddr};
use core::pin::pin;

use embassy_futures::select::{Either, select};
use embassy_net::tcp::TcpSocket;
use embassy_net::udp::UdpSocket;
use embassy_net::{IpListenEndpoint, Stack};
use embassy_time::{Duration, Instant, Timer};

use crate::node::OUT_LEN;
use crate::socket::{Datagrams, Interfaces, SocketError, Streams, canonical};

/// The default UDP receive buffer: two datagrams of the largest size, or
/// [`UDP_RX_PACKETS`] of any size, wait while the runner is busy.
pub const UDP_RX_LEN: usize = 2 * OUT_LEN;

/// The default number of UDP datagrams the receive buffer holds.
pub const UDP_RX_PACKETS: usize = 4;

/// The default UDP send buffer: one datagram of the largest size, since
/// `NetDatagrams` hands smoltcp one at a time.
pub const UDP_TX_LEN: usize = OUT_LEN;

/// The default number of UDP datagrams the send buffer holds.
pub const UDP_TX_PACKETS: usize = 1;

/// The default TCP buffers of the relay link, each way: a frame of the
/// largest size and its length, and the keep-alives.
pub const TCP_LEN: usize = 2048;

const _: () = assert!(TCP_LEN >= convesso_core::relay::framing::MAX_FRAME + 2);

/// How long a datagram may wait in the socket for its next hop's link-layer
/// address. smoltcp sends one such request a second, for any neighbour: this
/// is a wait behind another neighbour's request, then two of its own, so that
/// one lost request or answer does not lose the neighbour.
pub const STALL: Duration = Duration::from_secs(3);

/// How long a destination whose datagram stalled is refused. Every datagram
/// waits while one stalls, so this is ten of the core's attempts of a busy
/// session (`ATTEMPT_EVERY`, 30 s): a destination nobody answers stalls the
/// socket once in five minutes. A neighbour refused by mistake, both its
/// answers lost, costs the direct path that long, not the session.
pub const HOLD: Duration = Duration::from_secs(300);

/// The destinations refused at once; the oldest makes room.
const REFUSED: usize = 4;

/// A UDP socket of `embassy-net` as the driver's datagram socket. Bind it to a
/// port with no address before, so that it serves both families.
pub struct NetDatagrams<'a> {
    // Borrowed only inside a poll, never across an await.
    socket: RefCell<UdpSocket<'a>>,
    endpoint: IpListenEndpoint,
    refused: Cell<[Option<(IpAddr, Instant)>; REFUSED]>,
}

impl<'a> NetDatagrams<'a> {
    /// Wraps a bound socket.
    #[must_use]
    pub fn new(socket: UdpSocket<'a>) -> Self {
        let endpoint = socket.endpoint();
        Self {
            socket: RefCell::new(socket),
            endpoint,
            refused: Cell::new([None; REFUSED]),
        }
    }

    fn is_refused(&self, ip: IpAddr, now: Instant) -> bool {
        self.refused
            .get()
            .iter()
            .flatten()
            .any(|&(at, until)| at == ip && now < until)
    }

    fn refuse(&self, ip: IpAddr, now: Instant) {
        let mut refused = self.refused.get();
        let slot = refused
            .iter_mut()
            .min_by_key(|entry| entry.map_or(Instant::MIN, |(_, until)| until));
        if let Some(slot) = slot {
            *slot = Some((ip, now + HOLD));
        }
        self.refused.set(refused);
    }

    /// Drops what the socket holds, the stalled datagram with it.
    fn reset(&self) {
        let mut socket = self.socket.borrow_mut();
        socket.close();
        // The endpoint it was bound to a moment ago, so this cannot fail.
        let _ = socket.bind(self.endpoint);
    }
}

impl Datagrams for NetDatagrams<'_> {
    async fn send_to(&self, packet: &[u8], to: SocketAddr) -> Result<(), SocketError> {
        let to = canonical(to);
        let now = Instant::now();
        if self.is_refused(to.ip(), now) {
            return Err(SocketError::SendFailed);
        }
        poll_fn(|cx| self.socket.borrow().poll_send_to(packet, to, cx))
            .await
            .map_err(|_| SocketError::SendFailed)?;
        let left = poll_fn(|cx| {
            let mut socket = self.socket.borrow_mut();
            let flushed = pin!(socket.flush());
            flushed.poll(cx)
        });
        match select(left, Timer::after(STALL)).await {
            Either::First(()) => Ok(()),
            Either::Second(()) => {
                self.reset();
                self.refuse(to.ip(), now);
                Err(SocketError::SendFailed)
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), SocketError> {
        let (len, meta) = poll_fn(|cx| self.socket.borrow().poll_recv_from(buf, cx))
            .await
            .map_err(|_| SocketError::RecvFailed)?;
        Ok((len, canonical(meta.endpoint.into())))
    }

    fn local_port(&self) -> u16 {
        self.endpoint.port
    }
}

/// A TCP socket of `embassy-net` as the relay link.
pub struct NetStream<'a> {
    socket: TcpSocket<'a>,
}

impl<'a> NetStream<'a> {
    /// Wraps a socket; its TCP keep-alive and timeout are turned off, since
    /// the core decides when the link is dead.
    #[must_use]
    pub fn new(mut socket: TcpSocket<'a>) -> Self {
        socket.set_keep_alive(None);
        socket.set_timeout(None);
        Self { socket }
    }
}

impl embedded_io_async::ErrorType for NetStream<'_> {
    type Error = embassy_net::tcp::Error;
}

impl embedded_io_async::Read for NetStream<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.socket.read(buf).await
    }
}

impl embedded_io_async::Write for NetStream<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.socket.write(buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.socket.flush().await
    }
}

impl Streams for NetStream<'_> {
    async fn connect(&mut self, to: SocketAddr) -> Result<(), SocketError> {
        if self.socket.state() != embassy_net::tcp::State::Closed {
            self.socket.abort();
        }
        self.socket
            .connect(canonical(to))
            .await
            .map_err(|_| SocketError::ConnectFailed)
    }

    fn close(&mut self) {
        self.socket.abort();
    }
}

/// The addresses `embassy-net`'s stack is configured with.
pub struct NetInterfaces<'a> {
    stack: Stack<'a>,
}

impl<'a> NetInterfaces<'a> {
    /// The interfaces of `stack`.
    #[must_use]
    pub const fn new(stack: Stack<'a>) -> Self {
        Self { stack }
    }
}

impl Interfaces for NetInterfaces<'_> {
    fn local_addresses(&self, out: &mut [IpAddr]) -> usize {
        let v4 = self
            .stack
            .config_v4()
            .map(|config| IpAddr::V4(config.address.address()));
        let v6 = self
            .stack
            .config_v6()
            .map(|config| IpAddr::V6(config.address.address()));
        let mut count = 0;
        for (slot, ip) in out.iter_mut().zip([v4, v6].into_iter().flatten()) {
            *slot = ip;
            count += 1;
        }
        count
    }
}
