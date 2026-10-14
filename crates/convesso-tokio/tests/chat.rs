//! The `chat` example, run twice against a relay on the loopback.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[path = "../examples/chat.rs"]
#[allow(dead_code, unreachable_pub, missing_docs)]
mod chat;

use std::time::Duration;

use convesso_core::identity::Identity;
use convesso_relay::{Config as RelayConfig, Open, Relay};
use convesso_tokio::RelayLocation;
use convesso_tokio::entropy::OsEntropy;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;

async fn relay() -> RelayLocation {
    let identity = Identity::from_ed25519_seed(&[200; 32]).unwrap();
    let address = *identity.address();
    let (udp, listener, port) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
            break (udp, listener, port);
        }
    };
    let relay = Relay::new(
        identity,
        Open,
        OsEntropy,
        RelayConfig::default(),
        convesso_core::time::Instant::from_millis(0),
    )
    .unwrap();
    tokio::spawn(convesso_tokio::relay_server::serve(relay, udp, listener));
    RelayLocation {
        address,
        host: format!("127.0.0.1:{port}"),
    }
}

fn key(name: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("convesso-chat-{}-{name}.key", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

/// A chat running in the background: its input, and what it printed.
struct Running {
    input: mpsc::Sender<String>,
    printed: mpsc::UnboundedReceiver<String>,
}

fn spawn(args: chat::Args) -> Running {
    let (input, lines) = mpsc::channel(16);
    let (out, printed) = mpsc::unbounded_channel();
    tokio::spawn(chat::run(args, lines, move |line| {
        let _ = out.send(line);
    }));
    Running { input, printed }
}

async fn wait_for(running: &mut Running, prefix: &str) -> String {
    timeout(Duration::from_secs(3), async {
        loop {
            let line = running.printed.recv().await.expect("the chat ended");
            if line.starts_with(prefix) {
                return line;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no line starting with {prefix:?}"))
}

/// The keys the chats will use: created first, so that each can be given the
/// other's address.
fn identities(
    a: &std::path::Path,
    b: &std::path::Path,
) -> (
    convesso_core::identity::Address,
    convesso_core::identity::Address,
) {
    let (ia, _) = convesso_tokio::identity::load_or_create(a).unwrap();
    let (ib, _) = convesso_tokio::identity::load_or_create(b).unwrap();
    (*ia.address(), *ib.address())
}

/// Scenario: two chats talk through a relay knowing only keys.
#[tokio::test]
async fn two_chats_talk_through_a_relay() {
    let relay = relay().await;
    let (ka, kb) = (key("relay-a"), key("relay-b"));
    let (a_address, b_address) = identities(&ka, &kb);
    let mut a = spawn(chat::Args {
        key: ka.clone(),
        relay: Some(relay.clone()),
        peer: Some(b_address),
        bind: Some("127.0.0.1:0".parse().unwrap()),
        ..chat::Args::default()
    });
    let mut b = spawn(chat::Args {
        key: kb.clone(),
        relay: Some(relay),
        peer: Some(a_address),
        bind: Some("127.0.0.1:0".parse().unwrap()),
        ..chat::Args::default()
    });
    wait_for(&mut a, "address").await;
    wait_for(&mut b, "address").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    a.input.send("hello bob".into()).await.unwrap();
    assert_eq!(wait_for(&mut b, "[").await, "[relayed] hello bob");
    b.input.send("hello alice".into()).await.unwrap();
    assert_eq!(wait_for(&mut a, "[").await, "[relayed] hello alice");
    let _ = std::fs::remove_file(ka);
    let _ = std::fs::remove_file(kb);
}

/// Scenario: two chats on a LAN talk directly with a hint: one is given the
/// other's address, and both print the lines marked direct.
#[tokio::test]
async fn two_chats_talk_directly_with_a_hint() {
    let relay = relay().await;
    let (ka, kb) = (key("direct-a"), key("direct-b"));
    let (a_address, b_address) = identities(&ka, &kb);
    let b_bind: std::net::SocketAddr = {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap()
    };
    let mut b = spawn(chat::Args {
        key: kb.clone(),
        relay: Some(relay.clone()),
        peer: Some(a_address),
        bind: Some(b_bind),
        ..chat::Args::default()
    });
    wait_for(&mut b, "address").await;
    let mut a = spawn(chat::Args {
        key: ka.clone(),
        relay: Some(relay),
        peer: Some(b_address),
        direct: Some(b_bind),
        bind: Some("127.0.0.1:0".parse().unwrap()),
    });
    wait_for(&mut a, "address").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    a.input.send("on the lan".into()).await.unwrap();
    assert_eq!(wait_for(&mut b, "[").await, "[direct] on the lan");
    b.input.send("and back".into()).await.unwrap();
    assert_eq!(wait_for(&mut a, "[").await, "[direct] and back");
    let _ = std::fs::remove_file(ka);
    let _ = std::fs::remove_file(kb);
}

#[test]
fn the_command_line_is_parsed_strictly() {
    let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert!(chat::parse_args(&args(&["--key"])).is_err());
    assert!(chat::parse_args(&args(&["--peer", "abc"])).is_err());
    assert!(chat::parse_args(&args(&["--relay", "no-at-sign"])).is_err());
    assert!(chat::parse_args(&args(&["--loud", "yes"])).is_err());
    assert!(chat::parse_args(&args(&["--direct", "192.0.2.1:7400"])).is_ok());
}
