//! TLS around the relay link (feature `tls`), on real sockets over the
//! loopback: the relay serving both kinds of link on one port, and the node
//! trusting the relay's key alone.

#![cfg(feature = "tls")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use convesso_core::endpoint::{LinkFailure, RelayError};
use convesso_core::identity::Identity;
use convesso_relay::{Config as RelayConfig, Open, Relay};
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::tls::{TlsAcceptor, TlsError};
use convesso_tokio::{
    Config, Context, ContextEvent, ContextEvents, ContextOptions, Events, Node, NodeEvent,
    RelayLocation,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

fn identity(seed: u8) -> Identity {
    Identity::from_ed25519_seed(&[seed; 32]).unwrap()
}

/// A self-signed certificate for `name`, and its key, both PEM.
fn certificate(name: &str) -> (String, String) {
    use ed25519_dalek::Signer;
    // A new key at each call: two calls never match.
    static NEXT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
    let seed = [NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed); 32];
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    // X.509 by hand (RFC 5280), the least rustls takes: Ed25519, a common
    // name, no extension. Nothing checks it but the key match.
    let ed25519 = der(0x30, &der(0x06, &[0x2b, 0x65, 0x70]));
    let common_name = der(
        0x30,
        &der(
            0x31,
            &der(
                0x30,
                &[der(0x06, &[0x55, 0x04, 0x03]), der(0x0c, name.as_bytes())].concat(),
            ),
        ),
    );
    let validity = der(
        0x30,
        &[der(0x17, b"250101000000Z"), der(0x18, b"99991231235959Z")].concat(),
    );
    let public = der(
        0x30,
        &[
            ed25519.clone(),
            der(
                0x03,
                &[&[0u8][..], &key.verifying_key().to_bytes()].concat(),
            ),
        ]
        .concat(),
    );
    let tbs = der(
        0x30,
        &[
            der(0xa0, &der(0x02, &[2])),
            der(0x02, &[1]),
            ed25519.clone(),
            common_name.clone(),
            validity,
            common_name,
            public,
        ]
        .concat(),
    );
    let signature = key.sign(&tbs).to_bytes();
    let cert = der(
        0x30,
        &[tbs, ed25519, der(0x03, &[&[0u8][..], &signature].concat())].concat(),
    );
    // PKCS #8 (RFC 8410): the seed after a fixed prefix.
    let pkcs8 = [
        &[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ][..],
        &seed,
    ]
    .concat();
    (pem("CERTIFICATE", &cert), pem("PRIVATE KEY", &pkcs8))
}

/// A DER element: `tag`, its length, `content`.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    // The shortest form, as DER requires.
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend([0x81, len as u8]);
    } else {
        out.extend([0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
    out
}

/// `bytes` as a PEM block labelled `label`.
fn pem(label: &str, bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            text.push(if i <= chunk.len() {
                ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    let lines: Vec<&str> = text
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// UDP and TCP on one loopback port.
async fn sockets() -> (UdpSocket, TcpListener, u16) {
    loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
            return (udp, listener, port);
        }
    }
}

/// A relay with the key of `seed`, serving TLS with a self-signed
/// certificate for another name when `tls`; returns its key and port.
async fn relay(seed: u8, tls: bool) -> (convesso_core::identity::Address, u16) {
    let identity = identity(seed);
    let address = *identity.address();
    let (udp, listener, port) = sockets().await;
    let relay = Relay::new(
        identity,
        Open,
        OsEntropy,
        RelayConfig::default(),
        convesso_core::time::Instant::from_millis(0),
    )
    .unwrap();
    let acceptor = tls.then(|| {
        let (cert, key) = certificate("elsewhere.example");
        TlsAcceptor::from_pem(cert.as_bytes(), key.as_bytes()).unwrap()
    });
    tokio::spawn(convesso_tokio::relay_server::serve_with(
        relay, udp, listener, acceptor,
    ));
    (address, port)
}

async fn node(seed: u8, relay: RelayLocation) -> (Node, Events, Context, ContextEvents) {
    let (node, events) = convesso_tokio::start(
        identity(seed),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            relay: Some(relay),
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let (app, app_events) = node
        .context(b"app", ContextOptions::default())
        .await
        .unwrap();
    (node, events, app, app_events)
}

/// The next node event that `pick` takes, within `secs` seconds.
async fn node_event<T>(
    events: &mut Events,
    secs: u64,
    mut pick: impl FnMut(&NodeEvent) -> Option<T>,
) -> T {
    timeout(Duration::from_secs(secs), async {
        loop {
            let event = events.next().await.expect("the node stopped");
            if let Some(found) = pick(&event) {
                return found;
            }
        }
    })
    .await
    .expect("a node event in time")
}

async fn registered(node: &Node, events: &mut Events) {
    node.set_reachable(true).await.unwrap();
    node_event(events, 5, |event| {
        matches!(event, NodeEvent::RelayAvailable).then_some(())
    })
    .await;
}

async fn datagram(events: &mut ContextEvents) -> (Vec<u8>, bool) {
    timeout(Duration::from_secs(2), async {
        loop {
            if let Some(ContextEvent::Datagram { data, relayed, .. }) = events.next().await {
                return (data, relayed);
            }
        }
    })
    .await
    .expect("a datagram within two seconds")
}

/// What a connection that sent `first` gets back before the relay closes it.
async fn answer_to(port: u16, first: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(first).await.unwrap();
    let mut got = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut got))
        .await
        .expect("closed in time")
        .unwrap_or_default();
    got
}

// --- the relay server ------------------------------------------------------------------

/// Scenario: one port, both kinds: a client over TLS and one in the clear
/// both register on the same TCP port, and each reaches the other.
#[tokio::test]
async fn one_port_both_kinds() {
    let (address, port) = relay(100, true).await;
    let host = format!("127.0.0.1:{port}");
    let plain = RelayLocation {
        address,
        host: host.clone(),
        tls: false,
    };
    let wrapped = RelayLocation {
        address,
        host,
        tls: true,
    };
    let (a, mut a_node, a_app, mut a_events) = node(1, plain).await;
    let (b, mut b_node, b_app, mut b_events) = node(2, wrapped).await;
    registered(&a, &mut a_node).await;
    registered(&b, &mut b_node).await;
    a_app.send(b.address(), b"to tls".to_vec()).await.unwrap();
    assert_eq!(datagram(&mut b_events).await, (b"to tls".to_vec(), true));
    b_app.send(a.address(), b"to plain".to_vec()).await.unwrap();
    assert_eq!(datagram(&mut a_events).await, (b"to plain".to_vec(), true));
}

/// Scenario: a relay without a certificate refuses TLS quietly: a TLS
/// handshake is closed with nothing sent, and plain links are still served.
#[tokio::test]
async fn a_relay_without_a_certificate_refuses_tls_quietly() {
    let (address, port) = relay(100, false).await;
    // The start of a ClientHello: a handshake record.
    assert!(
        answer_to(port, &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01])
            .await
            .is_empty()
    );
    let (a, mut a_node, _a_app, _a_events) = node(
        3,
        RelayLocation {
            address,
            host: format!("127.0.0.1:{port}"),
            tls: false,
        },
    )
    .await;
    registered(&a, &mut a_node).await;
}

/// Scenario: neither a preamble nor TLS is refused: the connection is closed
/// with nothing sent.
#[tokio::test]
async fn neither_a_preamble_nor_tls_is_refused() {
    let (_, port) = relay(100, true).await;
    assert!(answer_to(port, b"GET / HTTP/1.1\r\n\r\n").await.is_empty());
}

/// A certificate and a key that do not belong together are refused, naming
/// the mismatch; and neither a certificate nor a key is taken for the other.
#[test]
fn a_key_that_does_not_match_is_refused() {
    let (cert, _) = certificate("relay.example");
    let (_, other_key) = certificate("relay.example");
    assert_eq!(
        TlsAcceptor::from_pem(cert.as_bytes(), other_key.as_bytes()).err(),
        Some(TlsError::Mismatch)
    );
    assert!(matches!(
        TlsAcceptor::from_pem(other_key.as_bytes(), other_key.as_bytes()).err(),
        Some(TlsError::Certificate(_))
    ));
    assert!(matches!(
        TlsAcceptor::from_pem(cert.as_bytes(), cert.as_bytes()).err(),
        Some(TlsError::Key(_))
    ));
}

// --- the node --------------------------------------------------------------------------

/// Scenario: a node behind a network that allows only TLS reaches its relay:
/// nothing answers UDP at the relay's port, so everything goes over the
/// wrapped link, both ways.
#[tokio::test]
async fn a_node_on_a_network_that_allows_only_tls_reaches_its_relay() {
    let identity = identity(100);
    let address = *identity.address();
    // The relay's UDP on a port of its own: UDP to the TCP port is lost.
    let (udp, listener, port) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        if udp.local_addr().unwrap().port() != port {
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
    let (cert, key) = certificate("relay.example");
    let acceptor = TlsAcceptor::from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
    tokio::spawn(convesso_tokio::relay_server::serve_with(
        relay,
        udp,
        listener,
        Some(acceptor),
    ));
    let wrapped = RelayLocation {
        address,
        host: format!("127.0.0.1:{port}"),
        tls: true,
    };
    let (a, mut a_node, a_app, mut a_events) = node(7, wrapped.clone()).await;
    let (b, mut b_node, b_app, mut b_events) = node(8, wrapped).await;
    registered(&a, &mut a_node).await;
    registered(&b, &mut b_node).await;
    a_app.send(b.address(), b"over tls".to_vec()).await.unwrap();
    assert_eq!(datagram(&mut b_events).await, (b"over tls".to_vec(), true));
    b_app.send(a.address(), b"back".to_vec()).await.unwrap();
    assert_eq!(datagram(&mut a_events).await, (b"back".to_vec(), true));
    for node in [&a, &b] {
        assert!(!node.relay_udp_proven().await.unwrap());
        assert!(node.stats().await.unwrap().frames_received > 0);
    }
}

/// Scenario: a certificate does not decide trust: a self-signed certificate
/// for another name than the one the node gives completes the handshake, and
/// the node registers once its relay session with the pinned key is live.
#[tokio::test]
async fn a_certificate_does_not_decide_trust() {
    let (address, port) = relay(100, true).await;
    let (a, mut a_node, _a_app, _a_events) = node(
        4,
        RelayLocation {
            address,
            // A name, given in the handshake, that the certificate is not for.
            host: format!("localhost:{port}"),
            tls: true,
        },
    )
    .await;
    registered(&a, &mut a_node).await;
}

/// Scenario: a TLS endpoint without the relay's key is not the relay: the
/// handshake completes, no relay session does, and the node is told the
/// relay is unavailable.
#[tokio::test]
async fn a_tls_endpoint_without_the_relays_key_is_not_the_relay() {
    let (_, port) = relay(100, true).await;
    let (a, mut a_node, _a_app, _a_events) = node(
        5,
        RelayLocation {
            // The key of another relay than the one there.
            address: *identity(101).address(),
            host: format!("127.0.0.1:{port}"),
            tls: true,
        },
    )
    .await;
    a.set_reachable(true).await.unwrap();
    let (available, error) = node_event(&mut a_node, 30, |event| match event {
        NodeEvent::RelayAvailable => Some((true, None)),
        NodeEvent::RelayUnavailable { error } => Some((false, Some(*error))),
        _ => None,
    })
    .await;
    assert!(!available, "registered on a relay without its key");
    assert!(
        !matches!(error, Some(RelayError::Link(LinkFailure::NotOpened))),
        "the link opened: {error:?}"
    );
}

/// Scenario: a failed TLS handshake is told and retried: a port answering
/// the handshake with garbage gives a relay-unavailable event for a link not
/// opened, and the next attempt comes after the backoff, a second or more.
#[tokio::test]
async fn a_failed_tls_handshake_is_told_and_retried() {
    let (udp, listener, port) = sockets().await;
    let (accepted_tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let _udp = udp;
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = accepted_tx.send(Instant::now());
            let _ = stream.write_all(b"this is not TLS at all\r\n").await;
        }
    });
    let (a, mut a_node, _a_app, _a_events) = node(
        6,
        RelayLocation {
            address: *identity(100).address(),
            host: format!("127.0.0.1:{port}"),
            tls: true,
        },
    )
    .await;
    a.set_reachable(true).await.unwrap();
    let error = node_event(&mut a_node, 5, |event| match event {
        NodeEvent::RelayUnavailable { error } => Some(*error),
        _ => None,
    })
    .await;
    assert_eq!(error, RelayError::Link(LinkFailure::NotOpened));
    let first = accepted.recv().await.unwrap();
    let second = timeout(Duration::from_secs(5), accepted.recv())
        .await
        .expect("a second attempt")
        .unwrap();
    let after = second - first;
    assert!(after >= Duration::from_millis(900), "too soon: {after:?}");
}

// --- the relay binary ------------------------------------------------------------------

#[cfg(feature = "relay-bin")]
mod binary {
    use super::*;
    use convesso_tokio::relay_config::{RelayStartError, parse, start};

    fn scratch(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("convesso-relay-tls-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn toml_path(path: &std::path::Path) -> String {
        path.display().to_string().replace('\\', "/")
    }

    /// Writes `text` to a private scratch file.
    fn private(name: &str, text: &str) -> std::path::PathBuf {
        let path = scratch(name);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    /// Starts the relay a file with `[tls]` describes, on a TCP port held
    /// here: had it bound anything, it would fail binding.
    async fn start_with(
        cert: &std::path::Path,
        key: &std::path::Path,
        name: &str,
    ) -> RelayStartError {
        let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let identity = scratch(&format!("{name}.key"));
        let text = format!(
            "udp = \"127.0.0.1:0\"\ntcp = \"{}\"\nidentity = \"{}\"\n\n[tls]\ncertificate = \"{}\"\nkey = \"{}\"\n",
            held.local_addr().unwrap(),
            toml_path(&identity),
            toml_path(cert),
            toml_path(key),
        );
        let error = start(&parse(&text).unwrap()).await.err().expect("refused");
        assert!(!identity.exists(), "nothing created");
        error
    }

    /// Scenario: a key that does not match is refused at start, naming the
    /// key file, before any socket is opened.
    #[tokio::test]
    async fn a_key_that_does_not_match_is_refused_at_start() {
        let (cert, _) = certificate("relay.example");
        let (_, other) = certificate("relay.example");
        let cert = private("mismatch.crt", &cert);
        let key = private("mismatch.pem", &other);
        let error = start_with(&cert, &key, "mismatch").await;
        let RelayStartError::Tls(message) = error else {
            panic!("another error: {error}")
        };
        assert!(
            message.contains(key.file_name().unwrap().to_str().unwrap()),
            "{message}"
        );
        assert!(message.contains("does not belong"), "{message}");
    }

    /// A certificate file that cannot be read is refused, naming it.
    #[tokio::test]
    async fn a_missing_certificate_is_refused_at_start() {
        let (_, key) = certificate("relay.example");
        let cert = scratch("missing.crt");
        let key = private("missing.pem", &key);
        let error = start_with(&cert, &key, "missing").await;
        assert!(
            matches!(&error, RelayStartError::Tls(message) if message.contains(cert.file_name().unwrap().to_str().unwrap())),
            "{error}"
        );
    }

    /// A key file others can read is refused on Unix, as the identity file
    /// is.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_key_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (cert, key) = certificate("relay.example");
        let cert = private("open.crt", &cert);
        let key = private("open.pem", &key);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = start_with(&cert, &key, "open").await;
        assert!(
            matches!(&error, RelayStartError::Tls(message) if message.contains("mode 0600")),
            "{error}"
        );
    }
}
