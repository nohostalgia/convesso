//! The tokio driver with a stream configuration the application chooses
//! (feature `stream`).

#![cfg(feature = "stream")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::Duration;

use convesso_core::identity::Identity;
use convesso_stream::SendError;
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::{
    Config, Context, ContextEvent, ContextEvents, ContextOptions, Delivery, Node, NodeError,
};
use tokio::time::timeout;

convesso_stream::config! {
    /// A server configuration whose largest message makes room for a 64-byte
    /// header beside a 262,144-byte payload.
    Wide: Server {
        max_message: 262_208,
        send_bytes: 2 * 262_208,
        receive_bytes: 2 * 262_208,
    }
}

async fn node(seed: u8) -> (Node, Context, ContextEvents) {
    let (node, _events) = convesso_tokio::start_with_stream::<Wide, _>(
        Identity::from_ed25519_seed(&[seed; 32]).unwrap(),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..Config::default()
        },
        OsEntropy,
    )
    .await
    .unwrap();
    let (app, app_events) = node
        .context(b"app", ContextOptions::default())
        .await
        .unwrap();
    (node, app, app_events)
}

/// Scenario: the tokio driver uses the configuration the application
/// chooses: a message of its largest size arrives whole, one byte more is
/// refused at once naming both sizes, and a per-peer budget below that
/// message's cost is refused when a context opens.
#[tokio::test]
async fn the_tokio_driver_uses_the_configuration_the_application_chooses() {
    let (a, a_app, _a_events) = node(1).await;
    let (b, _b_app, mut b_events) = node(2).await;
    a.set_hint(b.address().peer_id(), b.local_addr())
        .await
        .unwrap();
    b.set_hint(a.address().peer_id(), a.local_addr())
        .await
        .unwrap();
    let largest: Vec<u8> = (0..262_208u32).map(|i| i as u8).collect();
    a_app
        .send_message(b.address(), largest.clone())
        .await
        .unwrap();
    let got = timeout(Duration::from_secs(20), async {
        loop {
            if let Some(ContextEvent::Message { data, .. }) = b_events.next().await {
                return data;
            }
        }
    })
    .await
    .expect("the largest message");
    assert_eq!(got, largest);

    assert_eq!(
        a_app.send_message(b.address(), vec![0; 262_209]).await,
        Err(NodeError::Message(SendError::TooLarge {
            size: 262_209,
            max: 262_208,
        }))
    );

    let refused = a
        .context(
            b"per peer",
            ContextOptions {
                delivery: Delivery::PerPeer {
                    messages: 262_271,
                    datagrams: 64_000,
                },
                ..ContextOptions::default()
            },
        )
        .await;
    assert!(matches!(
        refused,
        Err(NodeError::Budget {
            budget: 262_271,
            needed: 262_272,
        })
    ));
}
