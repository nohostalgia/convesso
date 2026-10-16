//! One dual-stack socket on the loopback: an endpoint uses one UDP socket for
//! everything (`DESIGN.md §5`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use convesso_core::identity::Identity;
use convesso_core::paths::PathKind;
use convesso_tokio::{Config, Context, ContextEvent, ContextEvents, ContextOptions, Node};
use tokio::time::timeout;

fn identity(seed: u8) -> Identity {
    Identity::from_ed25519_seed(&[seed; 32]).unwrap()
}

/// A node on the default socket, `[::]`, both families; and its context.
async fn node(seed: u8) -> (Node, Context, ContextEvents) {
    let (node, _events) = convesso_tokio::start(identity(seed), Config::default())
        .await
        .unwrap();
    let (app, app_events) = node
        .context(b"app", ContextOptions::default())
        .await
        .unwrap();
    (node, app, app_events)
}

async fn datagram(events: &mut ContextEvents) -> Vec<u8> {
    timeout(Duration::from_secs(2), async {
        loop {
            match events.next().await {
                Some(ContextEvent::Datagram { data, .. }) => return data,
                Some(_) => {}
                None => panic!("the node stopped"),
            }
        }
    })
    .await
    .expect("a datagram within two seconds")
}

/// Scenario: one socket carries both families. A dual-stack node reaches one
/// peer over IPv4 and another over IPv6; each sees it at the same port, and
/// the IPv4 one at a plain IPv4 address.
#[tokio::test]
async fn one_socket_carries_both_families() {
    let (a, a_app, _a_events) = node(1).await;
    let (b, b_app, mut b_events) = node(2).await;
    let (c, c_app, mut c_events) = node(3).await;
    assert!(a.dual_stack(), "this system offers a dual-stack socket");
    let port = a.local_addr().port();

    let b_at = SocketAddr::from(([127, 0, 0, 1], b.local_addr().port()));
    let c_at = SocketAddr::from((Ipv6Addr::LOCALHOST, c.local_addr().port()));
    a.set_hint(b.address().peer_id(), b_at).await.unwrap();
    a.set_hint(c.address().peer_id(), c_at).await.unwrap();
    a_app
        .send(b.address(), b"over IPv4".to_vec())
        .await
        .unwrap();
    a_app
        .send(c.address(), b"over IPv6".to_vec())
        .await
        .unwrap();
    assert_eq!(datagram(&mut b_events).await, b"over IPv4");
    assert_eq!(datagram(&mut c_events).await, b"over IPv6");

    let a_peer = a.address().peer_id();
    let seen_by_b = b_app.path(a_peer).await.unwrap().unwrap().path;
    let seen_by_c = c_app.path(a_peer).await.unwrap().unwrap().path;
    assert_eq!(
        seen_by_b,
        PathKind::Direct(SocketAddr::from(([127, 0, 0, 1], port)))
    );
    assert_eq!(
        seen_by_c,
        PathKind::Direct(SocketAddr::from((Ipv6Addr::LOCALHOST, port)))
    );
}

/// A node bound to an IPv4 address keeps to IPv4, and says so.
#[tokio::test]
async fn an_ipv4_bind_is_not_dual_stack() {
    let (node, _events) = convesso_tokio::start(
        identity(4),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..Config::default()
        },
    )
    .await
    .unwrap();
    assert!(!node.dual_stack());
    assert!(node.local_addr().is_ipv4());
}
