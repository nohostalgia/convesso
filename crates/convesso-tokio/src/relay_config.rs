//! The relay binary's configuration file, and starting a relay from it.
//!
//! ```toml
//! udp = "0.0.0.0:7400"
//! tcp = "0.0.0.0:7400"
//! identity = "relay.key"          # a 32-byte seed, created on first start
//!
//! [limits]                        # optional, each field: the defaults of convesso-relay
//! bytes_per_second = 2500000      # forwards per client
//! bytes_burst = 10000000
//! packets_per_second = 5000
//! packets_burst = 5000
//! first_contacts_per_recipient = 20
//! first_contacts_burst = 5
//! handshakes_per_ip = 20          # handshakes with the relay
//! handshakes_burst = 20
//! links_per_ip = 64               # TCP links at once
//! new_links_per_second = 5        # new TCP links, over all addresses
//! new_links_burst = 50
//! queue_per_recipient = 262144    # bytes waiting on one link
//! link_silence_seconds = 180      # a silent link is closed
//! not_connected_every_ms = 1000   # one not-connected notice per sender and recipient
//!
//! [allowlist]                     # optional: only these clients
//! keys = ["d75a9801..."]          # Ed25519 addresses, in hex
//! refusal_code = 256              # what every other key is refused with
//!
//! [tls]                           # optional, feature `tls`: TLS links beside plain ones
//! certificate = "relay.crt"       # PEM, the relay's certificate first
//! key = "relay.pem"               # PEM; on Unix readable by its owner alone
//! ```
//!
//! TLS authenticates nothing: clients accept any certificate, and trust the
//! relay's key alone (`PROTOCOL.md §6`). A self-signed certificate does.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use convesso_core::endpoint::{LINK_ANSWER_WITHIN, MIN_KEEPALIVE};
use convesso_core::handshake::RefusalCode;
use convesso_core::identity::{Address, PeerId};
use convesso_core::relay::MAX_CARRIED;
use convesso_relay::{Admit, Config, Limits, Policy, Relay};
use serde::Deserialize;
use tokio::net::{TcpListener, UdpSocket};

use crate::entropy::OsEntropy;
use crate::identity::{IdentityFileError, load_or_create};

/// The configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Where to listen for UDP.
    pub udp: SocketAddr,
    /// Where to listen for TCP links.
    pub tcp: SocketAddr,
    /// The identity file.
    pub identity: PathBuf,
    /// Limits, over the defaults.
    #[serde(default)]
    pub limits: LimitsFile,
    /// Only these clients, if set.
    pub allowlist: Option<AllowlistFile>,
    /// TLS on the TCP port, beside plain links, if set.
    pub tls: Option<TlsFile>,
}

/// The `[tls]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFile {
    /// The certificate chain, PEM, the relay's own certificate first.
    pub certificate: PathBuf,
    /// Its private key, PEM.
    pub key: PathBuf,
}

/// The `[limits]` table: each field optional.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsFile {
    /// Bytes of forwards a second, per client.
    pub bytes_per_second: Option<u64>,
    /// Bytes of forwards at once, per client.
    pub bytes_burst: Option<u64>,
    /// Forwards a second, per client.
    pub packets_per_second: Option<u64>,
    /// Forwards at once, per client.
    pub packets_burst: Option<u64>,
    /// First contacts carried to one recipient a second.
    pub first_contacts_per_recipient: Option<u64>,
    /// First contacts carried to one recipient at once.
    pub first_contacts_burst: Option<u64>,
    /// Handshakes with the relay a second from one IP address.
    pub handshakes_per_ip: Option<u64>,
    /// Handshakes with the relay at once from one IP address.
    pub handshakes_burst: Option<u64>,
    /// TCP links at once from one IP address.
    pub links_per_ip: Option<usize>,
    /// New TCP links a second, over all addresses: what bounds how fast
    /// clients come back after a restart.
    pub new_links_per_second: Option<u64>,
    /// New TCP links at once, over all addresses.
    pub new_links_burst: Option<u64>,
    /// Bytes waiting on one recipient's link before packets for it drop.
    pub queue_per_recipient: Option<usize>,
    /// Seconds without anything arriving on a link before it is closed.
    pub link_silence_seconds: Option<u64>,
    /// Milliseconds between two not-connected notices for one sender and
    /// recipient.
    pub not_connected_every_ms: Option<u64>,
}

/// The `[allowlist]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistFile {
    /// Ed25519 addresses, hex.
    pub keys: Vec<String>,
    /// The application refusal code for everyone else, `256` to `65535`.
    pub refusal_code: u16,
}

/// Parses a configuration file.
///
/// # Errors
///
/// The parser's message, which names the field at fault.
pub fn parse(text: &str) -> Result<FileConfig, String> {
    toml::from_str(text).map_err(|error| error.to_string())
}

/// Who may use the relay.
#[derive(Debug, Clone)]
pub enum FilePolicy {
    /// Everyone.
    Open,
    /// Only these keys; the others are refused with `code`.
    Allowlist {
        /// The keys.
        keys: HashSet<PeerId>,
        /// The refusal.
        code: RefusalCode,
    },
}

impl Policy for FilePolicy {
    fn admit(&mut self, peer: &PeerId) -> Admit {
        match self {
            Self::Open => Admit::Accept(None),
            Self::Allowlist { keys, code } if !keys.contains(peer) => Admit::Refuse(*code),
            Self::Allowlist { .. } => Admit::Accept(None),
        }
    }
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

impl FileConfig {
    /// The relay's limits: the defaults, with the file's over them.
    ///
    /// # Errors
    ///
    /// A message naming the `limits` field whose value would stop the relay
    /// from working: a rate or a bound of zero, a byte burst smaller than the
    /// largest packet, a link silence the clients' keep-alives cannot beat.
    pub fn relay_config(&self) -> Result<Config, String> {
        let d = Config::default();
        let l = &self.limits;
        let at_least = |name: &str, value: Option<u64>, default: u64, min: u64| match value {
            Some(v) if v < min => Err(format!("limits.{name}: {v} is below {min}")),
            Some(v) => Ok(v),
            None => Ok(default),
        };
        let silence_min = (MIN_KEEPALIVE + LINK_ANSWER_WITHIN).as_secs() + 10;
        let carried = u64::try_from(MAX_CARRIED).unwrap_or(u64::MAX);
        let links_per_ip = match l.links_per_ip {
            Some(0) => return Err("limits.links_per_ip: 0 is below 1".into()),
            Some(v) => v,
            None => d.links_per_ip,
        };
        let queue_per_recipient = match l.queue_per_recipient {
            Some(v) if v < MAX_CARRIED => {
                return Err(format!(
                    "limits.queue_per_recipient: {v} is below {MAX_CARRIED}, the largest packet"
                ));
            }
            Some(v) => v,
            None => d.queue_per_recipient,
        };
        Ok(Config {
            limits: Limits {
                bytes_per_second: at_least(
                    "bytes_per_second",
                    l.bytes_per_second,
                    d.limits.bytes_per_second,
                    1,
                )?,
                bytes_burst: at_least("bytes_burst", l.bytes_burst, d.limits.bytes_burst, carried)?,
                packets_per_second: at_least(
                    "packets_per_second",
                    l.packets_per_second,
                    d.limits.packets_per_second,
                    1,
                )?,
                packets_burst: at_least(
                    "packets_burst",
                    l.packets_burst,
                    d.limits.packets_burst,
                    1,
                )?,
            },
            first_contacts_per_recipient: at_least(
                "first_contacts_per_recipient",
                l.first_contacts_per_recipient,
                d.first_contacts_per_recipient,
                1,
            )?,
            first_contacts_burst: at_least(
                "first_contacts_burst",
                l.first_contacts_burst,
                d.first_contacts_burst,
                1,
            )?,
            handshakes_per_ip: at_least(
                "handshakes_per_ip",
                l.handshakes_per_ip,
                d.handshakes_per_ip,
                1,
            )?,
            handshakes_burst: at_least(
                "handshakes_burst",
                l.handshakes_burst,
                d.handshakes_burst,
                1,
            )?,
            links_per_ip,
            new_links_per_second: at_least(
                "new_links_per_second",
                l.new_links_per_second,
                d.new_links_per_second,
                1,
            )?,
            new_links_burst: at_least("new_links_burst", l.new_links_burst, d.new_links_burst, 1)?,
            queue_per_recipient,
            link_silence: Duration::from_secs(at_least(
                "link_silence_seconds",
                l.link_silence_seconds,
                d.link_silence.as_secs(),
                silence_min,
            )?),
            not_connected_every: l
                .not_connected_every_ms
                .map_or(d.not_connected_every, Duration::from_millis),
        })
    }

    /// The admission policy.
    ///
    /// # Errors
    ///
    /// A message naming `allowlist.keys` or `allowlist.refusal_code` when one
    /// is not usable.
    pub fn policy(&self) -> Result<FilePolicy, String> {
        let Some(list) = &self.allowlist else {
            return Ok(FilePolicy::Open);
        };
        let code = RefusalCode::application(list.refusal_code).ok_or_else(|| {
            format!(
                "allowlist.refusal_code: {} is not an application code (256 to 65535)",
                list.refusal_code
            )
        })?;
        let keys = list
            .keys
            .iter()
            .map(|key| {
                hex32(key)
                    .and_then(|bytes| Address::parse(bytes).ok())
                    .map(|address| address.peer_id())
                    .ok_or_else(|| format!("allowlist.keys: {key:?} is not an address"))
            })
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(FilePolicy::Allowlist { keys, code })
    }
}

/// Why a relay did not start.
#[derive(Debug)]
pub enum RelayStartError {
    /// The configuration.
    Config(String),
    /// The identity file.
    Identity(IdentityFileError),
    /// Binding a socket.
    Bind(std::io::Error),
    /// The certificate or the key, naming the file.
    Tls(String),
}

impl std::fmt::Display for RelayStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) => write!(f, "the configuration: {error}"),
            Self::Identity(error) => error.fmt(f),
            Self::Bind(error) => write!(f, "binding: {error}"),
            Self::Tls(error) => write!(f, "TLS: {error}"),
        }
    }
}

impl std::error::Error for RelayStartError {}

/// A relay ready to serve: its address, whether its identity was just
/// created, and where it listens.
pub struct Started {
    /// The relay's address, which clients pin.
    pub address: Address,
    /// Whether the identity file was created now.
    pub created: bool,
    /// The bound UDP address.
    pub udp: SocketAddr,
    /// The bound TCP address.
    pub tcp: SocketAddr,
    /// Whether the TCP port serves TLS links too.
    pub tls: bool,
    serve: Serving,
}

impl Started {
    /// Serves until an I/O error.
    ///
    /// # Errors
    ///
    /// The sockets failing.
    pub async fn serve(self) -> std::io::Result<()> {
        self.serve.await
    }
}

/// Loads the identity, binds the sockets, and builds the relay a file
/// describes.
///
/// # Errors
///
/// A [`RelayStartError`].
pub async fn start(config: &FileConfig) -> Result<Started, RelayStartError> {
    let policy = config.policy().map_err(RelayStartError::Config)?;
    let limits = config.relay_config().map_err(RelayStartError::Config)?;
    // Before the identity and the sockets: a relay that cannot serve what it
    // is configured for creates nothing and binds nothing.
    let tls = config.tls.as_ref().map(load_tls).transpose()?;
    let (identity, created) =
        load_or_create(&config.identity).map_err(RelayStartError::Identity)?;
    let address = *identity.address();
    let udp = UdpSocket::bind(config.udp)
        .await
        .map_err(RelayStartError::Bind)?;
    let listener = TcpListener::bind(config.tcp)
        .await
        .map_err(RelayStartError::Bind)?;
    let (udp_at, tcp_at) = (
        udp.local_addr().map_err(RelayStartError::Bind)?,
        listener.local_addr().map_err(RelayStartError::Bind)?,
    );
    let relay = Relay::new(
        identity,
        policy,
        OsEntropy,
        limits,
        convesso_core::time::Instant::from_millis(0),
    )
    .map_err(|error| RelayStartError::Config(error.to_string()))?;
    Ok(Started {
        address,
        created,
        udp: udp_at,
        tcp: tcp_at,
        tls: tls.is_some(),
        serve: serve(relay, udp, listener, tls),
    })
}

/// What serves the relay: with TLS when it has a certificate.
type Serving = std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>;

#[cfg(feature = "tls")]
type Acceptor = crate::tls::TlsAcceptor;
#[cfg(not(feature = "tls"))]
type Acceptor = std::convert::Infallible;

#[cfg(feature = "tls")]
fn serve(
    relay: Relay<FilePolicy, OsEntropy>,
    udp: UdpSocket,
    listener: TcpListener,
    tls: Option<Acceptor>,
) -> Serving {
    Box::pin(crate::relay_server::serve_with(relay, udp, listener, tls))
}

#[cfg(not(feature = "tls"))]
fn serve(
    relay: Relay<FilePolicy, OsEntropy>,
    udp: UdpSocket,
    listener: TcpListener,
    _tls: Option<Acceptor>,
) -> Serving {
    Box::pin(crate::relay_server::serve(relay, udp, listener))
}

/// The certificate and the key of `[tls]`, read and checked.
#[cfg(feature = "tls")]
fn load_tls(file: &TlsFile) -> Result<Acceptor, RelayStartError> {
    use crate::tls::{TlsAcceptor, TlsError};
    let read = |path: &std::path::Path| {
        std::fs::read(path)
            .map_err(|error| RelayStartError::Tls(format!("{}: {error}", path.display())))
    };
    let certificate = read(&file.certificate)?;
    private(&file.key)?;
    let key = read(&file.key)?;
    TlsAcceptor::from_pem(&certificate, &key).map_err(|error| {
        let at = match error {
            TlsError::Certificate(_) => &file.certificate,
            TlsError::Key(_) | TlsError::Mismatch => &file.key,
        };
        RelayStartError::Tls(format!("{}: {error}", at.display()))
    })
}

#[cfg(not(feature = "tls"))]
fn load_tls(_file: &TlsFile) -> Result<Acceptor, RelayStartError> {
    Err(RelayStartError::Config(
        "tls: this relay was built without the feature `tls`".into(),
    ))
}

/// Refuses a key file that its group or others can read, as the identity
/// file is refused.
#[cfg(all(unix, feature = "tls"))]
fn private(path: &std::path::Path) -> Result<(), RelayStartError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|error| RelayStartError::Tls(format!("{}: {error}", path.display())))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(RelayStartError::Tls(format!(
            "{}: the key can be read by others than its owner; make it mode 0600",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(all(not(unix), feature = "tls"))]
#[allow(clippy::unnecessary_wraps, reason = "as on Unix")]
fn private(_path: &std::path::Path) -> Result<(), RelayStartError> {
    Ok(())
}

/// An address in hex, as the configuration and the binary print it.
#[must_use]
pub fn hex(address: &Address) -> String {
    address
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
