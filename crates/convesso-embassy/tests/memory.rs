//! The in-memory implementation of the socket interface.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use std::net::{IpAddr, SocketAddr};

use convesso_embassy::socket::{Datagrams, SocketError, Streams};
use embedded_io_async::{Read, Write};
use support::Net;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// Datagrams cross between two nodes in both families, from the one port of
/// each node's socket.
#[tokio::test(flavor = "current_thread")]
async fn datagrams_cross_in_both_families() {
    let net = Net::new();
    let a = net.bind(&[ip("10.0.0.1"), ip("2001:db8::1")], 7500);
    let b = net.bind(&[ip("10.0.0.2"), ip("2001:db8::2")], 7600);
    let mut buf = [0u8; 64];
    for (to, from) in [
        ("10.0.0.2:7600", "10.0.0.1:7500"),
        ("[2001:db8::2]:7600", "[2001:db8::1]:7500"),
        ("[::ffff:10.0.0.2]:7600", "10.0.0.1:7500"),
    ] {
        a.send_to(b"ping", to.parse().unwrap()).await.unwrap();
        let (len, source) = b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"ping");
        assert_eq!(source, from.parse::<SocketAddr>().unwrap());
    }
    assert_eq!(a.local_port(), 7500);
}

/// A stream carries bytes both ways, and a close is seen as the end.
#[tokio::test(flavor = "current_thread")]
async fn a_stream_carries_bytes_both_ways() {
    let net = Net::new();
    let at: SocketAddr = "10.0.0.9:7400".parse().unwrap();
    let listener = net.listen(at);
    let mut client = net.stream(ip("10.0.0.1"));
    client.connect(at).await.unwrap();
    let server = listener.accept().await;
    client.write_all(b"preamble").await.unwrap();
    assert_eq!(server.take(None), (b"preamble".to_vec(), false));
    server.write(b"answer");
    let mut buf = [0u8; 16];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"answer");
    server.close();
    assert_eq!(client.read(&mut buf).await.unwrap(), 0);
}

/// A connection nobody listens for is refused, and a send from a failing
/// interface fails: both come back as errors.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_connection_and_a_failed_send_are_errors() {
    let net = Net::new();
    let mut client = net.stream(ip("10.0.0.1"));
    assert_eq!(
        client.connect("10.0.0.9:7400".parse().unwrap()).await,
        Err(SocketError::ConnectFailed)
    );
    let a = net.bind(&[ip("10.0.0.1")], 7500);
    net.fail_sends_from(ip("10.0.0.1"), true);
    assert_eq!(
        a.send_to(b"x", "10.0.0.2:1".parse().unwrap()).await,
        Err(SocketError::SendFailed)
    );
    assert_eq!(
        a.send_to(b"x", "[2001:db8::2]:1".parse().unwrap()).await,
        Err(SocketError::SendFailed),
        "no IPv6 address to send from"
    );
}

/// A stream to the relay host carries bytes both ways: the relay answers the
/// preamble with its own, and a keep-alive with a keep-alive.
#[tokio::test(flavor = "current_thread")]
async fn a_stream_to_the_relay_host_is_answered() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let net = Net::new();
            let relay = support::spawn_relay(&net, &[ip("10.0.0.9"), ip("2001:db8::9")], 7400);
            let mut link = net.stream(ip("10.0.0.1"));
            link.connect(relay.udp[0]).await.unwrap();
            link.write_all(&convesso_core::relay::framing::PREAMBLE)
                .await
                .unwrap();
            link.write_all(&convesso_core::relay::framing::KEEPALIVE)
                .await
                .unwrap();
            let mut buf = [0u8; 11];
            link.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[..9], convesso_core::relay::framing::PREAMBLE);
            assert_eq!(buf[9..], convesso_core::relay::framing::KEEPALIVE);
        })
        .await;
}
