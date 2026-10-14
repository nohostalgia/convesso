//! Reliable messages on the embedded driver, feature `stream`, over the
//! in-memory sockets (`DESIGN.md §5`).

#![cfg(feature = "stream")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use convesso_core::storage::Mcu;
use convesso_embassy::rng::{RngFailed, SecureRng};
use convesso_embassy::{Config, Events, Node, NodeEvent, RelayLocation, Shared};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use support::{MemDatagrams, MemInterfaces, Net, RelayHost};
use tokio::time::timeout;

type TestNode = Node<'static, NoopRawMutex, Mcu, MemDatagrams>;
type TestEvents = Events<'static, NoopRawMutex, Mcu, MemDatagrams>;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

struct TestRng(u64);

impl SecureRng for TestRng {
    fn try_fill(&mut self, dest: &mut [u8]) -> Result<(), RngFailed> {
        for byte in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (self.0 >> 33) as u8;
        }
        Ok(())
    }
}

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

fn node(
    net: &Net,
    key: usize,
    ip_text: &str,
    relay: &RelayHost,
    events: usize,
) -> (TestNode, TestEvents) {
    let ips = [ip(ip_text)];
    let datagrams: &'static MemDatagrams = leak(net.bind(&ips, 7500));
    let slot: &'static mut Option<Shared<'static, NoopRawMutex, Mcu, MemDatagrams>> = leak(None);
    let (node, runner, events) = convesso_embassy::start(
        support::identity(key),
        Config {
            context: b"app",
            relay: Some(RelayLocation {
                address: relay.address,
                primary: relay.udp[0],
                other: relay.udp.get(1).copied(),
            }),
        },
        datagrams,
        net.stream(ips[0]),
        MemInterfaces::new(&ips),
        leak(TestRng(key as u64 * 977)),
        None,
        leak(vec![0u8; events]).as_mut_slice(),
        slot,
    )
    .unwrap_or_else(|_| panic!("node {key} starts"));
    tokio::task::spawn_local(async move {
        let _: () = runner.run().await;
    });
    (node, events)
}

async fn local<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::LocalSet::new().run_until(f).await
}

fn world() -> (Net, RelayHost) {
    let net = Net::new();
    let relay = support::spawn_relay(&net, &[ip("192.0.2.1"), ip("2001:db8::1")], 7400);
    (net, relay)
}

/// The next `count` messages, skipping other events, within `secs`.
async fn messages(events: &mut TestEvents, count: usize, secs: u64) -> Vec<Vec<u8>> {
    timeout(Duration::from_secs(secs), async {
        let mut buf = [0u8; 2048];
        let mut got = Vec::new();
        while got.len() < count {
            match events.next(&mut buf).await {
                NodeEvent::Message { data, .. } => got.push(data.to_vec()),
                NodeEvent::ChannelReset { reason, .. } => panic!("a reset: {reason:?}"),
                _ => {}
            }
        }
        got
    })
    .await
    .expect("the messages in time")
}

fn message(i: usize) -> Vec<u8> {
    (0..(i * 131) % 2048 + 1).map(|j| (i + j) as u8).collect()
}

/// Two embedded nodes exchange messages of up to 2,048 bytes through a relay,
/// each knowing only the other's key and the relay's address.
#[tokio::test(flavor = "current_thread")]
async fn two_embedded_nodes_exchange_messages_through_a_relay() {
    local(async {
        let (net, relay) = world();
        net.no_direct(true);
        let (a, mut a_events) = node(&net, 1, "10.0.0.1", &relay, 8192);
        let (b, mut b_events) = node(&net, 2, "10.0.1.1", &relay, 8192);
        b.set_reachable(true).await;
        a.set_reachable(true).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let sent: Vec<_> = (0..30).map(message).collect();
        let (b_address, a_address) = (b.address().await, a.address().await);
        let to_b = sent.clone();
        tokio::task::spawn_local(async move {
            for m in &to_b {
                a.send_message(&b_address, m).await.unwrap();
            }
        });
        assert_eq!(messages(&mut b_events, 30, 20).await, sent);
        let to_a = sent.clone();
        tokio::task::spawn_local(async move {
            for m in &to_a {
                b.send_message_to_peer(a_address.peer_id(), m)
                    .await
                    .unwrap();
            }
        });
        assert_eq!(messages(&mut a_events, 30, 20).await, sent);
    })
    .await;
}

/// Scenario: a slow reader holds the sender back without losing messages:
/// the receiver's event buffer holds one message, the application does not
/// read for a second, the sender's sends wait, and every message arrives in
/// order once it reads.
#[tokio::test(flavor = "current_thread")]
async fn a_slow_reader_holds_the_sender_back() {
    local(async {
        let (net, relay) = world();
        let (a, _a_events) = node(&net, 1, "10.0.0.1", &relay, 8192);
        let (b, mut b_events) = node(&net, 2, "10.0.1.1", &relay, 2048 + 400);
        let b_address = b.address().await;
        let b_hint = SocketAddr::new(ip("10.0.1.1"), 7500);
        a.set_hint(b_address.peer_id(), b_hint).await.unwrap();
        let sent: Vec<_> = (0..20).map(|i| vec![i as u8; 1500]).collect();
        let to_b = sent.clone();
        let sender = tokio::task::spawn_local(async move {
            for m in &to_b {
                a.send_message(&b_address, m).await.unwrap();
            }
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!sender.is_finished(), "the sender waits for the reader");
        assert_eq!(messages(&mut b_events, 20, 30).await, sent);
        sender.await.unwrap();
    })
    .await;
}
