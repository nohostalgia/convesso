//! The throughput of datagrams on real sockets: two nodes on the loopback, a
//! direct path, 1,400-byte datagrams (a tunnel packet) sent as fast as the
//! node takes them for three seconds. Ignored by default; run in release:
//! `cargo test -p convesso-tokio --release --test measure_datagrams -- --ignored --nocapture`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use convesso_core::identity::Identity;
use convesso_tokio::{Config, Context, ContextEvent, ContextEvents, ContextOptions, Node};

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
                events: 1024,
                ..ContextOptions::default()
            },
        )
        .await
        .unwrap();
    (node, app, app_events)
}

/// Sends for `seconds` from `senders` concurrent tasks; returns datagrams
/// sent and received, per second.
async fn throughput(senders: usize, seconds: u64) -> (f64, f64) {
    let (a, a_app, _a_events) = node(41).await;
    let (b, _b_app, mut b_events) = node(42).await;
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    b.set_hint(a.address().peer_id(), a.local_addr())
        .await
        .unwrap();
    // The session first.
    a_app.send(b.address(), vec![0; 10]).await.unwrap();
    while !matches!(b_events.next().await, Some(ContextEvent::Datagram { .. })) {}

    let received = Arc::new(AtomicU64::new(0));
    let counter = received.clone();
    tokio::spawn(async move {
        while let Some(event) = b_events.next().await {
            if matches!(event, ContextEvent::Datagram { .. }) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    let sent = Arc::new(AtomicU64::new(0));
    let end = Instant::now() + Duration::from_secs(seconds);
    let mut tasks = Vec::new();
    for _ in 0..senders {
        let (a, to, sent) = (a_app.clone(), b.address(), sent.clone());
        tasks.push(tokio::spawn(async move {
            while Instant::now() < end {
                if a.send(to, vec![7; 1400]).await.is_ok() {
                    sent.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let s = seconds as f64;
    (
        sent.load(Ordering::Relaxed) as f64 / s,
        received.load(Ordering::Relaxed) as f64 / s,
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, run on demand in release"]
async fn datagram_throughput_on_the_loopback() {
    for senders in [1, 4] {
        let (sent, received) = throughput(senders, 3).await;
        std::println!(
            "{senders} sender(s): {sent:.0} datagrams/s sent ({:.0} Mbit/s), {received:.0} received ({:.0} Mbit/s), {:.1}% lost",
            sent * 1400.0 * 8.0 / 1e6,
            received * 1400.0 * 8.0 / 1e6,
            100.0 * (1.0 - received / sent)
        );
    }
}
