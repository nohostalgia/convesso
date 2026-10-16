//! `chat`: two applications that know each other's key, talking through a
//! relay, or directly when one is given the other's address.
//!
//! ```text
//! cargo run --example chat -- --key alice.key --relay <relay-hex>@<host:port> --peer <bob-hex>
//! cargo run --example chat -- --key bob.key   --relay <relay-hex>@<host:port> --peer <alice-hex>
//!     [--direct <ip:port>]   the peer's address on the LAN, as a hint
//!     [--bind <ip:port>]     the local UDP address (default 0.0.0.0:0)
//! ```
//!
//! Each line typed goes to the peer; each line received is printed with how it
//! came: `[relayed]` or `[direct]`. The first run creates the key file and
//! prints this chat's address, which the other side passes as `--peer`.

use std::net::SocketAddr;
use std::path::PathBuf;

use convesso_core::identity::Address;
use convesso_tokio::identity::load_or_create;
use convesso_tokio::{Config, ContextEvent, ContextOptions, NodeEvent, RelayLocation};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

/// What the command line gives.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// The key file.
    pub key: PathBuf,
    /// The relay: its address and `host:port`.
    pub relay: Option<RelayLocation>,
    /// The peer's address.
    pub peer: Option<Address>,
    /// The peer's direct address, as a hint.
    pub direct: Option<SocketAddr>,
    /// The local UDP address.
    pub bind: Option<SocketAddr>,
}

fn address(text: &str) -> Result<Address, String> {
    if text.len() != 64 {
        return Err(format!("{text:?} is not a 64-digit hex address"));
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2).unwrap_or("zz"), 16)
            .map_err(|_| format!("{text:?} is not hex"))?;
    }
    Address::parse(bytes).map_err(|_| format!("{text:?} is not a valid address"))
}

/// Parses the command line, without the program's name.
///
/// # Errors
///
/// A message naming what is wrong.
pub fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut parsed = Args {
        key: PathBuf::from("chat.key"),
        ..Args::default()
    };
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--key" => parsed.key = PathBuf::from(value),
            "--relay" => {
                let (key, host) = value
                    .split_once('@')
                    .ok_or("--relay is <relay-hex>@<host:port>")?;
                parsed.relay = Some(RelayLocation {
                    address: address(key)?,
                    host: host.to_owned(),
                    tls: false,
                });
            }
            "--peer" => parsed.peer = Some(address(value)?),
            "--direct" => {
                parsed.direct = Some(value.parse().map_err(|_| "--direct is <ip:port>")?);
            }
            "--bind" => parsed.bind = Some(value.parse().map_err(|_| "--bind is <ip:port>")?),
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(parsed)
}

/// Runs a chat: sends each line `input` yields to the peer, and gives
/// `output` every line to print. Ends when `input` ends.
///
/// # Errors
///
/// A message when the key, the node or a send fails.
pub async fn run(
    args: Args,
    mut input: mpsc::Receiver<String>,
    mut output: impl FnMut(String) + Send,
) -> Result<(), String> {
    let (identity, created) = load_or_create(&args.key).map_err(|e| e.to_string())?;
    if created {
        output(format!("created a key in {}", args.key.display()));
    }
    let hex: String = identity
        .address()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    output(format!("address {hex}"));
    let reachable = args.relay.is_some();
    let (node, mut node_events) = convesso_tokio::start(
        identity,
        Config {
            bind: args
                .bind
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
            relay: args.relay,
            ..Config::default()
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    let (chat, mut events) = node
        .context(b"example/chat/1", ContextOptions::default())
        .await
        .map_err(|e| e.to_string())?;
    if reachable {
        node.set_reachable(true).await.map_err(|e| e.to_string())?;
    }
    if let (Some(peer), Some(direct)) = (args.peer, args.direct) {
        node.set_hint(peer.peer_id(), direct)
            .await
            .map_err(|e| e.to_string())?;
    }
    loop {
        tokio::select! {
            line = input.recv() => {
                let Some(line) = line else { return Ok(()) };
                let Some(peer) = args.peer else {
                    output("no --peer to send to".into());
                    continue;
                };
                if let Err(error) = chat.send(peer, line.into_bytes()).await {
                    output(format!("not sent: {error}"));
                }
            }
            event = events.next() => match event {
                Some(ContextEvent::Datagram { data, relayed, .. }) => {
                    let how = if relayed { "relayed" } else { "direct" };
                    output(format!("[{how}] {}", String::from_utf8_lossy(&data)));
                }
                Some(_) => {}
                None => return Err("the node stopped".into()),
            },
            event = node_events.next() => match event {
                Some(NodeEvent::PeerNotAtRelay { .. }) => output("the peer is not at the relay".into()),
                Some(NodeEvent::RelayUnavailable { error }) => output(format!("the relay: {error:?}")),
                Some(_) => {}
                None => return Err("the node stopped".into()),
            },
        }
    }
}

#[allow(
    dead_code,
    reason = "the tests include this file and run `run` instead"
)]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("chat: {error}");
            std::process::exit(2);
        }
    };
    let (lines, input) = mpsc::channel(16);
    tokio::spawn(async move {
        let mut stdin = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = stdin.next_line().await {
            if lines.send(line).await.is_err() {
                return;
            }
        }
    });
    if let Err(error) = run(args, input, |line| println!("{line}")).await {
        eprintln!("chat: {error}");
        std::process::exit(1);
    }
}
