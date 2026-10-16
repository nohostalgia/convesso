//! TLS 1.3 around the relay link (feature `tls`): camouflage on networks that
//! let out only TLS, never trust (`PROTOCOL.md §6`).
//!
//! The node accepts any certificate: the relay is authenticated by its pinned
//! key, in the relay session inside the link, and by nothing TLS says. The
//! relay server presents the certificate its operator gives it, and serves
//! TLS and plain links on one port.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// Why a certificate or a key was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// The certificate chain: no certificate in it, or one that is not PEM.
    Certificate(String),
    /// The private key: none, or one that is not PEM or not usable.
    Key(String),
    /// The key does not belong to the certificate.
    Mismatch,
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Certificate(error) => write!(f, "the certificate: {error}"),
            Self::Key(error) => write!(f, "the key: {error}"),
            Self::Mismatch => f.write_str("the key does not belong to the certificate"),
        }
    }
}

impl std::error::Error for TlsError {}

/// The relay server's side: a certificate chain and its key, checked.
#[derive(Clone)]
pub struct TlsAcceptor(pub(crate) tokio_rustls::TlsAcceptor);

impl TlsAcceptor {
    /// An acceptor presenting the PEM certificate chain `certificate`, the
    /// relay's own certificate first, with the PEM private key `key`.
    ///
    /// # Errors
    ///
    /// A [`TlsError`] naming the part at fault.
    pub fn from_pem(certificate: &[u8], key: &[u8]) -> Result<Self, TlsError> {
        let chain = CertificateDer::pem_slice_iter(certificate)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| TlsError::Certificate(error.to_string()))?;
        if chain.is_empty() {
            return Err(TlsError::Certificate("no certificate".into()));
        }
        let key =
            PrivateKeyDer::from_pem_slice(key).map_err(|error| TlsError::Key(error.to_string()))?;
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| TlsError::Key(error.to_string()))?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|error| match error {
                rustls::Error::InconsistentKeys(_) => TlsError::Mismatch,
                other => TlsError::Key(other.to_string()),
            })?;
        Ok(Self(tokio_rustls::TlsAcceptor::from(Arc::new(config))))
    }
}

/// The node's side: TLS 1.3, any certificate accepted.
pub(crate) fn connector() -> tokio_rustls::TlsConnector {
    let provider = provider();
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map(|builder| {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
                .with_no_client_auth()
        });
    // The ring provider has TLS 1.3: the builder cannot fail.
    #[allow(clippy::expect_used)]
    let config = config.expect("TLS 1.3 with ring");
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// The name the node gives in the handshake for `host` (`host:port`): the
/// host when it is a name; an IP address otherwise, which rustls keeps out of
/// the handshake.
pub(crate) fn server_name(host: &str) -> ServerName<'static> {
    let name = host.rsplit_once(':').map_or(host, |(name, _)| name);
    let name = name.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(name.to_owned()).unwrap_or_else(|_| {
        // A host the system resolved that TLS cannot name: an IP address is
        // never sent, so any one stands for it.
        ServerName::IpAddress(std::net::Ipv4Addr::UNSPECIFIED.into())
    })
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Accepts every certificate and every handshake signature: TLS decides
/// nothing here, the relay session does.
#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_given_and_an_ip_address_is_not() {
        assert!(matches!(
            server_name("relay.example:7400"),
            ServerName::DnsName(name) if name.as_ref() == "relay.example"
        ));
        assert!(matches!(
            server_name("192.0.2.1:7400"),
            ServerName::IpAddress(_)
        ));
        assert!(matches!(
            server_name("[2001:db8::1]:7400"),
            ServerName::IpAddress(_)
        ));
    }
}
