//! The tokio driver with a stream configuration the application chooses
//! (feature `stream`).

#![cfg(feature = "stream")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::Duration;

use convesso_core::identity::Identity;
use convesso_core::storage::GrowableTable;
use convesso_stream::config::{GrowableArena, GrowableQueue, GrowableSlots, Key, StreamConfig};
use convesso_stream::{SendError, Sent, Stored};
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::{Config, Delivery, Events, Node, NodeError, NodeEvent, StartError};
use tokio::time::timeout;

/// A server configuration whose largest message makes room for a 64-byte
/// header beside a 262,144-byte payload.
struct Wide;

impl StreamConfig for Wide {
    const MAX_MESSAGE: usize = 262_208;
    type SendQueue = GrowableQueue<{ 2 * 262_208 }>;
    type Lengths = GrowableSlots<u32, 4096>;
    type InFlight = GrowableSlots<Sent, 1024>;
    type ReceiveArena = GrowableArena<{ 2 * 262_208 }>;
    type Stored = GrowableSlots<Stored, 1024>;
    type Channels<V> = GrowableTable<Key, V>;
}

fn config(delivery: Delivery) -> Config {
    Config {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        delivery,
        ..Config::default()
    }
}

async fn node(seed: u8) -> (Node, Events) {
    convesso_tokio::start_with_stream::<Wide, _>(
        Identity::from_ed25519_seed(&[seed; 32]).unwrap(),
        config(Delivery::Events),
        OsEntropy,
    )
    .await
    .unwrap()
}

/// Scenario: the tokio driver uses the configuration the application
/// chooses: a message of its largest size arrives whole, one byte more is
/// refused at once naming both sizes, and a per-peer budget below that
/// message's cost is refused at start.
#[tokio::test]
async fn the_tokio_driver_uses_the_configuration_the_application_chooses() {
    let (a, _a_events) = node(1).await;
    let (b, mut b_events) = node(2).await;
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    b.set_hint(a.address().peer_id(), a.local_addr())
        .await
        .unwrap();
    let largest: Vec<u8> = (0..262_208u32).map(|i| i as u8).collect();
    a.send_message(b.address(), largest.clone()).await.unwrap();
    let got = timeout(Duration::from_secs(20), async {
        loop {
            if let Some(NodeEvent::Message { data, .. }) = b_events.next().await {
                return data;
            }
        }
    })
    .await
    .expect("the largest message");
    assert_eq!(got, largest);

    assert_eq!(
        a.send_message(b.address(), vec![0; 262_209]).await,
        Err(NodeError::Message(SendError::TooLarge {
            size: 262_209,
            max: 262_208,
        }))
    );

    let refused = convesso_tokio::start_with_stream::<Wide, _>(
        Identity::from_ed25519_seed(&[3; 32]).unwrap(),
        config(Delivery::PerPeer {
            messages: 262_271,
            datagrams: 64_000,
        }),
        OsEntropy,
    )
    .await;
    assert!(matches!(
        refused,
        Err(StartError::Budget {
            budget: 262_271,
            needed: 262_272,
        })
    ));
}
