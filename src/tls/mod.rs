//! HTTPS served by armada itself, so nothing needs to sit in front of it.
//!
//! A certificate for `public_url`'s domain comes from an ACME CA, Let's
//! Encrypt by default, and is renewed in the background and swapped in
//! without a restart (see [`acme`]). The CA proves armada holds the domain
//! by TLS-ALPN-01, answered on the HTTPS port itself, or failing that by
//! HTTP-01 on port 80, which otherwise redirects to HTTPS (see [`redirect`]).
//!
//! The certificate and the ACME account are kept beneath the storage
//! directory, so a restart serves at once instead of asking again.

mod acme;
mod redirect;
mod serve;
mod store;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::storage::Storage;
pub use serve::{Limits, serve};
use store::Store;

/// The ALPN protocol a CA's TLS-ALPN-01 validation offers (RFC 8737).
const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// Everything armada needs to serve HTTPS for one domain.
pub struct Tls {
    domain: String,
    state: Arc<State>,
    acme: acme::Acme,
}

/// What the HTTPS listener, the HTTP listener, and the ACME client share.
#[derive(Default)]
struct State {
    /// The certificate served, once there is one.
    certificate: ArcSwapOption<CertifiedKey>,
    /// The certificate a pending TLS-ALPN-01 challenge is answered with.
    alpn_challenge: ArcSwapOption<CertifiedKey>,
    /// Pending HTTP-01 challenges: token to key authorization.
    http_challenges: Mutex<HashMap<String, String>>,
}

impl Tls {
    /// TLS for the domain `config` names, with any certificate already
    /// kept in `storage` loaded and ready to serve. `None` if armada doesn't
    /// serve TLS itself.
    pub fn open(config: &Config, storage: &Storage) -> Result<Option<Tls>> {
        let Some(domain) = config.acme_domain() else { return Ok(None) };
        let store = Store::open(&storage.service_dir("tls")?, &config.tls.directory)?;
        let state = Arc::new(State::default());
        match store.load_certificate(&domain)? {
            Some(certificate) => {
                tracing::info!(domain, expires = %certificate.not_after_text(), "TLS certificate loaded");
                state.certificate.store(Some(certificate.key));
            }
            None => tracing::info!(domain, directory = config.tls.directory, "no TLS certificate yet; asking the CA for one"),
        }
        let acme = acme::Acme {
            domain: domain.clone(),
            directory: config.tls.directory.clone(),
            email: config.tls.email.clone(),
            http01: config.tls.redirect_http,
            root: None,
            store,
            state: state.clone(),
        };
        Ok(Some(Tls { domain, state, acme }))
    }

    /// The configuration HTTPS connections are accepted with. Its
    /// certificate follows renewals.
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        server_config(self.state.clone())
    }

    /// Answers the CA's HTTP-01 challenges, and redirects the rest.
    pub fn redirect_router(&self) -> axum::Router {
        redirect::router(self.domain.clone(), self.state.clone())
    }

    /// Get a certificate if there isn't a current one, and renew it as it
    /// nears expiry, until `cancel` fires.
    pub fn start(self, cancel: CancellationToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.acme.run(cancel))
    }
}

fn server_config(state: Arc<State>) -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(state);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];
    Arc::new(config)
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State").field("certificate", &self.certificate.load().is_some()).finish_non_exhaustive()
    }
}

impl ResolvesServerCert for State {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Only a CA validating a challenge offers acme-tls/1, and it offers
        // nothing else (RFC 8737 §3).
        let validating = hello.alpn().is_some_and(|mut protocols| protocols.any(|protocol| protocol == ACME_TLS_ALPN));
        if validating { self.alpn_challenge.load_full() } else { self.certificate.load_full() }
    }
}
