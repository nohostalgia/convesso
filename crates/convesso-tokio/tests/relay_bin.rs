//! The relay binary's configuration and start.

#![cfg(feature = "relay-bin")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::time::Duration;

use convesso_core::endpoint::RelayError;
use convesso_core::handshake::{DialError, RefusalCode};
use convesso_core::identity::Identity;
use convesso_tokio::relay_config::{hex, parse, start};
use convesso_tokio::{
    Config, Context, ContextEvent, ContextEvents, ContextOptions, Events, Node, NodeEvent,
    RelayLocation,
};
use tokio::time::timeout;

fn scratch(name: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("convesso-relay-{}-{name}.key", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn toml_path(path: &std::path::Path) -> String {
    path.display().to_string().replace('\\', "/")
}

async fn node(seed: u8, relay: &RelayLocation) -> (Node, Events, Context, ContextEvents) {
    let (node, events) = convesso_tokio::start(
        Identity::from_ed25519_seed(&[seed; 32]).unwrap(),
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            relay: Some(relay.clone()),
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

/// A relay from a file, on one loopback port for UDP and TCP.
async fn relay_from(extra: &str, name: &str) -> (RelayLocation, std::path::PathBuf) {
    let identity = scratch(name);
    loop {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let text = format!(
            "udp = \"127.0.0.1:{port}\"\ntcp = \"127.0.0.1:{port}\"\nidentity = \"{}\"\n{extra}",
            toml_path(&identity)
        );
        let config = parse(&text).unwrap();
        if let Ok(started) = start(&config).await {
            let location = RelayLocation {
                address: started.address,
                host: format!("127.0.0.1:{port}"),
                tls: false,
            };
            tokio::spawn(started.serve());
            return (location, identity);
        }
    }
}

/// Scenario: a first start creates the identity, readable only by its owner,
/// and gives the address; a second start loads the same one.
#[tokio::test]
async fn a_first_start_creates_the_identity() {
    let identity = scratch("first");
    let text = format!(
        "udp = \"127.0.0.1:0\"\ntcp = \"127.0.0.1:0\"\nidentity = \"{}\"\n",
        toml_path(&identity)
    );
    let config = parse(&text).unwrap();
    let first = start(&config).await.unwrap();
    assert!(first.created);
    assert_eq!(hex(&first.address).len(), 64);
    let address = first.address;
    drop(first);
    let second = start(&config).await.unwrap();
    assert!(!second.created);
    assert_eq!(second.address, address);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&identity).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    std::fs::remove_file(&identity).unwrap();
}

/// Scenario: a bad configuration names its fault.
#[test]
fn a_bad_configuration_names_its_fault() {
    let error = parse(
        "udp = \"0.0.0.0:7400\"\ntcp = \"0.0.0.0:7400\"\nidentity = \"r.key\"\n[limits]\nbytes_per_second = \"fast\"\n",
    )
    .unwrap_err();
    assert!(error.contains("bytes_per_second"), "{error}");
    let error =
        parse("udp = \"0.0.0.0:7400\"\ntcp = \"0.0.0.0:7400\"\nidentity = \"r.key\"\nspeed = 3\n")
            .unwrap_err();
    assert!(error.contains("speed"), "{error}");
    let config = parse(
        "udp = \"0.0.0.0:7400\"\ntcp = \"0.0.0.0:7400\"\nidentity = \"r.key\"\n[allowlist]\nkeys = [\"zz\"]\nrefusal_code = 256\n",
    )
    .unwrap();
    assert!(config.policy().unwrap_err().contains("allowlist.keys"));
    let config = parse(
        "udp = \"0.0.0.0:7400\"\ntcp = \"0.0.0.0:7400\"\nidentity = \"r.key\"\n[allowlist]\nkeys = []\nrefusal_code = 7\n",
    )
    .unwrap();
    assert!(
        config
            .policy()
            .unwrap_err()
            .contains("allowlist.refusal_code")
    );
}

const HEAD: &str = "udp = \"0.0.0.0:7400\"\ntcp = \"0.0.0.0:7400\"\nidentity = \"r.key\"\n";

/// Every limit of the relay can be set in `[limits]`; those left out keep the
/// relay's defaults.
#[test]
fn every_limit_is_configurable() {
    let config = parse(&format!(
        "{HEAD}[limits]\nbytes_per_second = 1\nbytes_burst = 2000\npackets_per_second = 3\n\
         packets_burst = 4\nfirst_contacts_per_recipient = 5\nfirst_contacts_burst = 6\n\
         handshakes_per_ip = 7\nhandshakes_burst = 8\nlinks_per_ip = 9\n\
         new_links_per_second = 200\nnew_links_burst = 1000\nqueue_per_recipient = 4096\n\
         link_silence_seconds = 300\nnot_connected_every_ms = 250\n"
    ))
    .unwrap()
    .relay_config()
    .unwrap();
    let expected = convesso_relay::Config {
        limits: convesso_relay::Limits {
            bytes_per_second: 1,
            bytes_burst: 2000,
            packets_per_second: 3,
            packets_burst: 4,
        },
        first_contacts_per_recipient: 5,
        first_contacts_burst: 6,
        handshakes_per_ip: 7,
        handshakes_burst: 8,
        links_per_ip: 9,
        new_links_per_second: 200,
        new_links_burst: 1000,
        queue_per_recipient: 4096,
        link_silence: Duration::from_secs(300),
        not_connected_every: Duration::from_millis(250),
    };
    assert_eq!(config, expected);

    let defaults = parse(HEAD).unwrap().relay_config().unwrap();
    assert_eq!(defaults, convesso_relay::Config::default());
    let one = parse(&format!("{HEAD}[limits]\nnew_links_per_second = 200\n"))
        .unwrap()
        .relay_config()
        .unwrap();
    assert_eq!(
        one,
        convesso_relay::Config {
            new_links_per_second: 200,
            ..convesso_relay::Config::default()
        }
    );
}

/// A limit that would stop the relay from working is refused, naming it.
#[test]
fn a_limit_that_would_stop_the_relay_is_refused() {
    for (line, field) in [
        ("new_links_per_second = 0", "new_links_per_second"),
        ("new_links_burst = 0", "new_links_burst"),
        ("handshakes_per_ip = 0", "handshakes_per_ip"),
        ("links_per_ip = 0", "links_per_ip"),
        ("bytes_burst = 1000", "bytes_burst"),
        ("queue_per_recipient = 100", "queue_per_recipient"),
        ("link_silence_seconds = 60", "link_silence_seconds"),
    ] {
        let error = parse(&format!("{HEAD}[limits]\n{line}\n"))
            .unwrap()
            .relay_config()
            .unwrap_err();
        assert!(
            error.contains(&format!("limits.{field}")),
            "{line}: {error}"
        );
    }
}

/// The binary's relay forwards between two nodes on the loopback.
#[tokio::test]
async fn the_binary_forwards_between_two_nodes() {
    let (relay, identity) = relay_from("", "forward").await;
    let (_a, _a_node, a_app, _a_events) = node(31, &relay).await;
    let (b, _b_node, _b_app, mut b_events) = node(32, &relay).await;
    b.set_reachable(true).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    a_app
        .send(b.address(), b"through the binary".to_vec())
        .await
        .unwrap();
    let got = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(ContextEvent::Datagram { data, relayed, .. }) = b_events.next().await {
                return (data, relayed);
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(got, (b"through the binary".to_vec(), true));
    std::fs::remove_file(&identity).unwrap();
}

/// Scenario: an allowlist refuses everyone else, with the configured code,
/// and serves the listed keys.
#[tokio::test]
async fn an_allowlist_refuses_everyone_else() {
    let listed = Identity::from_ed25519_seed(&[41; 32]).unwrap();
    let extra = format!(
        "[allowlist]\nkeys = [\"{}\"]\nrefusal_code = 257\n",
        hex(listed.address())
    );
    let (relay, identity) = relay_from(&extra, "allowlist").await;
    let (_outsider, mut outsider_events, outsider_app, _outsider_app_events) =
        node(42, &relay).await;
    let (member, _member_events, _member_app, _member_app_events) = node(41, &relay).await;
    outsider_app
        .send(member.address(), b"let me in".to_vec())
        .await
        .unwrap();
    let refused = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(NodeEvent::RelayUnavailable { error }) = outsider_events.next().await {
                return error;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        refused,
        RelayError::Dial(DialError::Refused(RefusalCode::application(257).unwrap()))
    );
    member.set_reachable(true).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        member.stats().await.unwrap().keepalives_received >= 1,
        "the member is served"
    );
    std::fs::remove_file(&identity).unwrap();
}

/// Without the feature `tls`, a `[tls]` table is refused at start, naming the
/// feature.
#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn tls_without_the_feature_is_refused() {
    let identity = scratch("no-tls");
    let text = format!(
        "udp = \"127.0.0.1:0\"\ntcp = \"127.0.0.1:0\"\nidentity = \"{}\"\n\n[tls]\ncertificate = \"relay.crt\"\nkey = \"relay.pem\"\n",
        toml_path(&identity)
    );
    let error = start(&parse(&text).unwrap()).await.err().expect("refused");
    assert!(error.to_string().contains("feature `tls`"), "{error}");
    assert!(!identity.exists(), "nothing created");
}
