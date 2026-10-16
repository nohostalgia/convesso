//! The goodput of reliable messages on real sockets: 10 MiB in 256 KiB
//! messages over the loopback, through a UDP proxy
//! that loses 0% and 1% of the packets. Ignored by default; run in release:
//! `cargo test -p convesso-tokio --release --features stream --test measure_messages -- --ignored --nocapture`.

#![cfg(feature = "stream")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_precision_loss
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use convesso_core::identity::Identity;
use convesso_tokio::{Config, Context, ContextEvent, ContextEvents, ContextOptions, Node};
use tokio::net::UdpSocket;
use tokio::time::timeout;

async fn node(seed: u8) -> (Node, Context, ContextEvents) {
    let (node, _events) = convesso_tokio::start(
        Identity::from_ed25519_seed(&[seed; 32]).unwrap(),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let (app, app_events) = node
        .context(
            b"app",
            ContextOptions {
                events: 64,
                ..ContextOptions::default()
            },
        )
        .await
        .unwrap();
    (node, app, app_events)
}

/// A proxy between two nodes that drops `percent` of the datagrams each way:
/// A talks to `facing_a`, B to `facing_b`. Returns both addresses.
async fn lossy_proxy(a: SocketAddr, b: SocketAddr, percent: u64) -> (SocketAddr, SocketAddr) {
    let facing_a = Arc::new(big_buffers());
    let facing_b = Arc::new(big_buffers());
    let addresses = (
        facing_a.local_addr().unwrap(),
        facing_b.local_addr().unwrap(),
    );
    for (from, to, target, seed) in [
        (facing_a.clone(), facing_b.clone(), b, 0x9e37_79b9_u64),
        (facing_b, facing_a, a, 0x7f4a_7c15_u64),
    ] {
        tokio::spawn(async move {
            let mut state = seed;
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((len, _)) = from.recv_from(&mut buf).await else {
                    return;
                };
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                if state % 100 >= percent {
                    let _ = to.send_to(&buf[..len], target).await;
                }
            }
        });
    }
    addresses
}

/// A loopback UDP socket with 4 MiB buffers: the proxy itself must not be
/// where packets are lost.
fn big_buffers() -> UdpSocket {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    socket.set_recv_buffer_size(4 << 20).unwrap();
    socket.set_send_buffer_size(4 << 20).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
        .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    UdpSocket::from_std(socket.into()).unwrap()
}

async fn goodput(percent: u64) -> (f64, Duration) {
    let (a, a_app, _a_events) = node(31).await;
    let (b, _b_app, mut b_events) = node(32).await;
    let (facing_a, facing_b) = lossy_proxy(a.local_addr(), b.local_addr(), percent).await;
    a.set_hint(b.address().peer_id(), facing_a).await.unwrap();
    b.set_hint(a.address().peer_id(), facing_b).await.unwrap();
    let total = 10 * 1024 * 1024;
    let size = 256 * 1024;
    let count = total / size;
    let start = Instant::now();
    let (a2, to) = (a_app.clone(), b.address());
    tokio::spawn(async move {
        for i in 0..count {
            a2.send_message(to, vec![i as u8; size]).await.unwrap();
        }
    });
    let mut got = 0;
    timeout(Duration::from_secs(600), async {
        while got < count {
            match b_events.next().await {
                Some(ContextEvent::Message { data, .. }) => {
                    assert_eq!(data, vec![got as u8; size], "in order, whole");
                    got += 1;
                }
                Some(ContextEvent::ChannelReset { reason, .. }) => panic!("a reset: {reason:?}"),
                Some(_) => {}
                None => panic!("stopped"),
            }
        }
    })
    .await
    .expect("every message within ten minutes");
    let elapsed = start.elapsed();
    (total as f64 / elapsed.as_secs_f64() / 1024.0, elapsed)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, run on demand in release"]
async fn goodput_on_the_loopback() {
    for percent in [0, 1] {
        let (kib_per_s, elapsed) = goodput(percent).await;
        std::println!(
            "10 MiB in 256 KiB messages, {percent}% loss: {kib_per_s:.0} KiB/s, {elapsed:.2?}"
        );
    }
}
