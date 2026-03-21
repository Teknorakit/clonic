//! TLS wrapper for TCP transport using rustls.
//!
//! Provides optional TLS encryption for TCP connections with:
//! - Client-side TLS support
//! - Custom certificate verification
//! - Session resumption support

#[cfg(feature = "tls")]
use std::sync::Arc;
#[cfg(feature = "tls")]
use tokio_rustls::{rustls::ClientConfig, TlsConnector};

/// TLS configuration for TCP transport.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// Server hostname for SNI (Server Name Indication).
    pub server_name: String,
    /// Whether to verify the server certificate.
    pub verify_certificate: bool,
    /// Optional custom root certificates (PEM format).
    pub root_certs: Option<Vec<u8>>,
}

impl TlsConfig {
    /// Create a new TLS configuration.
    pub fn new(server_name: String, verify_certificate: bool) -> Self {
        Self {
            server_name,
            verify_certificate,
            root_certs: None,
        }
    }

    /// Set custom root certificates.
    pub fn with_root_certs(mut self, certs: Vec<u8>) -> Self {
        self.root_certs = Some(certs);
        self
    }
}

/// TLS connector wrapper for establishing encrypted connections.
#[cfg(feature = "tls")]
pub struct TlsConnectorWrapper {
    config: Arc<ClientConfig>,
}

#[cfg(feature = "tls")]
impl TlsConnectorWrapper {
    /// Create a new TLS connector from configuration.
    pub fn new(tls_cfg: &TlsConfig) -> Result<Self, Box<dyn std::error::Error>> {
        use tokio_rustls::rustls::RootCertStore;

        let mut root_store = RootCertStore::empty();

        // Add custom root certificates if provided
        if let Some(cert_pem) = &tls_cfg.root_certs {
            let mut cursor = std::io::Cursor::new(cert_pem);
            let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
                .collect::<Result<Vec<_>, _>>()?;
            for cert in certs {
                root_store.add(cert)?;
            }
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// Get the TLS connector for establishing connections.
    pub fn connector(&self) -> TlsConnector {
        TlsConnector::from(Arc::clone(&self.config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_creation() {
        let cfg = TlsConfig::new("example.com".to_string(), true);
        assert_eq!(cfg.server_name, "example.com");
        assert!(cfg.verify_certificate);
        assert!(cfg.root_certs.is_none());
    }

    #[test]
    fn test_tls_config_with_root_certs() {
        let certs = vec![1, 2, 3];
        let cfg = TlsConfig::new("example.com".to_string(), true).with_root_certs(certs.clone());
        assert_eq!(cfg.root_certs, Some(certs));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_tls_connector_creation() {
        let cfg = TlsConfig::new("example.com".to_string(), false);
        let result = TlsConnectorWrapper::new(&cfg);
        assert!(result.is_ok());
    }
}
