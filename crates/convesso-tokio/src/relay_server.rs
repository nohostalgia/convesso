//! The relay server on tokio: one UDP socket and one TCP listener around the
//! sans-IO [`Relay`].
//!
//! One task owns the relay and does what it says. Each link has a reader task,
//! which hands the relay what it reads, and a writer task, which writes what the
//! relay outputs and reports how much is still waiting, so that the relay can
//! drop packets for a slow recipient instead of waiting for it.
//!
//! A link is told apart by its first byte (`PROTOCOL.md §6`): a preamble's is
//! served plain, a TLS handshake's inside TLS when the relay has a certificate
//! (feature `tls`), and anything else is closed without a word.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant as Clock};

use convesso_core::handshake::Entropy;
use convesso_core::relay::framing::PREAMBLE;
use convesso_core::time::Instant;
use convesso_relay::{Action, LinkId, Policy, Relay};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

enum LinkNews {
    Read(LinkId, Vec<u8>),
    Closed(LinkId),
    Written(LinkId, usize),
}

struct LinkTasks {
    writer: mpsc::UnboundedSender<Vec<u8>>,
    reader: JoinHandle<()>,
    backlog: usize,
}

/// The first byte of a TLS handshake record.
const TLS_HANDSHAKE: u8 = 0x16;

/// How long a new connection has for its first byte, and then for its TLS
/// handshake: a connection that never starts holds its slot no longer.
const OPENING_WITHIN: Duration = Duration::from_secs(10);

/// What serves TLS: the acceptor with the feature, nothing without it.
#[cfg(feature = "tls")]
type Acceptor = crate::tls::TlsAcceptor;
#[cfg(not(feature = "tls"))]
#[derive(Clone)]
enum Acceptor {}

/// Serves `relay` on `udp` and `listener` until an I/O error ends it, plain
/// links only: a connection that starts a TLS handshake is closed.
///
/// # Errors
///
/// The UDP socket or the listener failing.
pub async fn serve<P, E>(
    relay: Relay<P, E>,
    udp: UdpSocket,
    listener: TcpListener,
) -> std::io::Result<()>
where
    P: Policy + Send + 'static,
    E: Entropy + Send + 'static,
{
    run(relay, udp, listener, None).await
}

/// As [`serve`], and with `tls` serves TLS-wrapped links too, on the same
/// port.
///
/// # Errors
///
/// The UDP socket or the listener failing.
#[cfg(feature = "tls")]
pub async fn serve_with<P, E>(
    relay: Relay<P, E>,
    udp: UdpSocket,
    listener: TcpListener,
    tls: Option<crate::tls::TlsAcceptor>,
) -> std::io::Result<()>
where
    P: Policy + Send + 'static,
    E: Entropy + Send + 'static,
{
    run(relay, udp, listener, tls).await
}

async fn run<P, E>(
    mut relay: Relay<P, E>,
    udp: UdpSocket,
    listener: TcpListener,
    tls: Option<Acceptor>,
) -> std::io::Result<()>
where
    P: Policy + Send + 'static,
    E: Entropy + Send + 'static,
{
    let clock = Clock::now();
    let now = |clock: &Clock| {
        Instant::from_millis(u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX))
    };
    let (news_tx, mut news) = mpsc::unbounded_channel();
    let mut links: HashMap<LinkId, LinkTasks> = HashMap::new();
    let mut next_link: LinkId = 1;
    let mut buffer = vec![0u8; 2048];
    let mut deadline: Option<Instant> = None;
    // An IPv6 socket may carry IPv4 too (`[::]` on Linux): the relay names
    // IPv4 clients as IPv4, and the socket takes them IPv4-mapped.
    let v6 = udp.local_addr()?.is_ipv6();
    loop {
        let sleep = deadline.map(|at| {
            tokio::time::sleep_until(
                (clock + std::time::Duration::from_millis(at.as_millis())).into(),
            )
        });
        tokio::select! {
            received = udp.recv_from(&mut buffer) => {
                let (len, from) = received?;
                relay.udp(buffer.get(..len).unwrap_or_default(), from, now(&clock));
            }
            accepted = listener.accept() => {
                let (stream, from) = accepted?;
                let id = next_link;
                next_link += 1;
                // The relay counts the link from here, before its first byte.
                if relay.link_opened(id, from, now(&clock)) {
                    let _ = stream.set_nodelay(true);
                    links.insert(id, spawn_link(id, stream, tls.clone(), news_tx.clone()));
                }
            }
            Some(item) = news.recv() => match item {
                LinkNews::Read(id, bytes) => relay.link_bytes(id, &bytes, now(&clock)),
                LinkNews::Closed(id) => {
                    relay.link_closed(id);
                    if let Some(tasks) = links.remove(&id) {
                        tasks.reader.abort();
                    }
                }
                LinkNews::Written(id, len) => {
                    if let Some(tasks) = links.get_mut(&id) {
                        tasks.backlog = tasks.backlog.saturating_sub(len);
                        relay.set_link_backlog(id, tasks.backlog);
                    }
                }
            },
            () = async { if let Some(sleep) = sleep { sleep.await } else { std::future::pending().await } } => {}
        }
        deadline = relay.poll(now(&clock));
        while let Some(action) = relay.next_action() {
            match action {
                Action::Udp { to, packet } => {
                    let to = match to.ip() {
                        std::net::IpAddr::V4(v4) if v6 => {
                            SocketAddr::new(v4.to_ipv6_mapped().into(), to.port())
                        }
                        _ => to,
                    };
                    let _ = udp.send_to(&packet, to).await;
                }
                Action::Link { id, bytes } => {
                    if let Some(tasks) = links.get_mut(&id) {
                        tasks.backlog += bytes.len();
                        let _ = tasks.writer.send(bytes);
                    }
                }
                Action::Close { id } => {
                    if let Some(tasks) = links.remove(&id) {
                        tasks.reader.abort();
                    }
                }
            }
        }
    }
}

fn spawn_link(
    id: LinkId,
    stream: TcpStream,
    tls: Option<Acceptor>,
    news: mpsc::UnboundedSender<LinkNews>,
) -> LinkTasks {
    let (writer, to_write) = mpsc::unbounded_channel::<Vec<u8>>();
    let reader = tokio::spawn(async move {
        match opening(stream, tls).await {
            Some(Opened::Plain(stream)) => carry(id, stream, to_write, news).await,
            #[cfg(feature = "tls")]
            Some(Opened::Tls(stream)) => carry(id, *stream, to_write, news).await,
            None => {
                let _ = news.send(LinkNews::Closed(id));
            }
        }
    });
    LinkTasks {
        writer,
        reader,
        backlog: 0,
    }
}

/// A connection that started as a link does.
enum Opened {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

/// Tells a new connection apart by its first byte, within
/// [`OPENING_WITHIN`], and runs its TLS handshake, within as long again;
/// `None` for one to close, having sent nothing.
async fn opening(stream: TcpStream, tls: Option<Acceptor>) -> Option<Opened> {
    let mut first = [0u8; 1];
    let peeked = tokio::time::timeout(OPENING_WITHIN, stream.peek(&mut first)).await;
    if !matches!(peeked, Ok(Ok(1..))) {
        return None;
    }
    match first[0] {
        byte if byte == PREAMBLE[0] => Some(Opened::Plain(stream)),
        #[cfg(feature = "tls")]
        TLS_HANDSHAKE => {
            let acceptor = tls?.0;
            let accepted = tokio::time::timeout(OPENING_WITHIN, acceptor.accept(stream)).await;
            accepted
                .ok()?
                .ok()
                .map(|stream| Opened::Tls(Box::new(stream)))
        }
        // Without the feature, a TLS handshake is a byte like any other.
        _ => {
            let _ = (tls, TLS_HANDSHAKE);
            None
        }
    }
}

/// Carries a link: what it reads to the relay, and what the relay outputs to
/// it, until either side ends it.
async fn carry<S>(
    id: LinkId,
    stream: S,
    mut to_write: mpsc::UnboundedReceiver<Vec<u8>>,
    news: mpsc::UnboundedSender<LinkNews>,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut read, mut write) = tokio::io::split(stream);
    let written = news.clone();
    tokio::spawn(async move {
        while let Some(bytes) = to_write.recv().await {
            if write.write_all(&bytes).await.is_err() {
                break;
            }
            let _ = written.send(LinkNews::Written(id, bytes.len()));
        }
        // The relay dropped the link: the writer half closes with it.
        let _ = write.shutdown().await;
    });
    let mut buffer = vec![0u8; 4096];
    loop {
        match read.read(&mut buffer).await {
            Ok(0) | Err(_) => {
                let _ = news.send(LinkNews::Closed(id));
                return;
            }
            Ok(len) => {
                let bytes = buffer.get(..len).unwrap_or_default().to_vec();
                if news.send(LinkNews::Read(id, bytes)).is_err() {
                    return;
                }
            }
        }
    }
}
