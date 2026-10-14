//! The relay server on tokio: one UDP socket and one TCP listener around the
//! sans-IO [`Relay`].
//!
//! One task owns the relay and does what it says. Each link has a reader task,
//! which hands the relay what it reads, and a writer task, which writes what the
//! relay outputs and reports how much is still waiting, so that the relay can
//! drop packets for a slow recipient instead of waiting for it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant as Clock;

use convesso_core::handshake::Entropy;
use convesso_core::time::Instant;
use convesso_relay::{Action, LinkId, Policy, Relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
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

/// Serves `relay` on `udp` and `listener` until an I/O error ends it.
///
/// # Errors
///
/// The UDP socket or the listener failing.
pub async fn serve<P, E>(
    mut relay: Relay<P, E>,
    udp: UdpSocket,
    listener: TcpListener,
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
                if relay.link_opened(id, from, now(&clock)) {
                    let _ = stream.set_nodelay(true);
                    links.insert(id, spawn_link(id, stream, from, news_tx.clone()));
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
    stream: tokio::net::TcpStream,
    _from: SocketAddr,
    news: mpsc::UnboundedSender<LinkNews>,
) -> LinkTasks {
    let (mut read, mut write) = stream.into_split();
    let (writer, mut to_write) = mpsc::unbounded_channel::<Vec<u8>>();
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
    let reader = tokio::spawn(async move {
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
    });
    LinkTasks {
        writer,
        reader,
        backlog: 0,
    }
}
