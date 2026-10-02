//! Getting and renewing the certificate over ACME (RFC 8555).
//!
//! A certificate is asked for when there's none, and again once a third of
//! its lifetime is left. Each attempt tries TLS-ALPN-01 first, answered on
//! the HTTPS port, then HTTP-01 if port 80 is being listened on. A failed
//! attempt is retried after a minute, then two, and so on up to an hour:
//! Let's Encrypt allows only a few failed validations an hour, and a
//! misconfigured DNS record doesn't fix itself any faster.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use instant_acme::{Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;

use super::State;
use super::store::{Certificate, Store};
use crate::util::now;

/// The longest between checks on the certificate, so a clock that jumps
/// or a machine that sleeps can't carry it past its renewal.
const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
const FIRST_RETRY: Duration = Duration::from_secs(60);
const LAST_RETRY: Duration = Duration::from_secs(60 * 60);
/// How long the CA has to validate a challenge, and then to issue.
const ORDER_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Acme {
    pub domain: String,
    pub directory: String,
    pub email: Option<String>,
    /// Whether HTTP-01 challenges can be answered, on port 80.
    pub http01: bool,
    /// A CA certificate to trust the directory by instead of the system's,
    /// for a test CA.
    pub root: Option<PathBuf>,
    pub store: Store,
    pub state: Arc<State>,
}

impl Acme {
    pub async fn run(self, cancel: CancellationToken) {
        let mut retry = FIRST_RETRY;
        loop {
            let due = match self.store.load_certificate(&self.domain) {
                Ok(Some(certificate)) => Some(certificate.renew_at()),
                Ok(None) => None,
                Err(error) => {
                    tracing::warn!(domain = self.domain, "{error:#}; getting a new one");
                    None
                }
            };
            let wait = match due {
                Some(at) if at > now() => Duration::from_secs((at - now()) as u64).min(CHECK_INTERVAL),
                _ => match tokio::select! { issued = self.issue() => issued, _ = cancel.cancelled() => return } {
                    Ok(certificate) => {
                        tracing::info!(domain = self.domain, expires = %certificate.not_after_text(), "TLS certificate issued");
                        self.state.certificate.store(Some(certificate.key));
                        retry = FIRST_RETRY;
                        continue;
                    }
                    Err(error) => {
                        tracing::error!(domain = self.domain, retry_in = retry.as_secs(), "could not get a TLS certificate: {error:#}");
                        let wait = retry;
                        retry = (retry * 2).min(LAST_RETRY);
                        wait
                    }
                },
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = cancel.cancelled() => return,
            }
        }
    }

    /// Get a certificate from the CA, trying each challenge it can answer.
    async fn issue(&self) -> Result<Certificate> {
        let account = self.account().await?;
        let mut kinds = vec![ChallengeType::TlsAlpn01];
        if self.http01 {
            kinds.push(ChallengeType::Http01);
        }
        let mut failure = None;
        for kind in kinds {
            match self.order(&account, &kind).await {
                Ok((chain, key)) => return self.store.save_certificate(&self.domain, &chain, &key),
                Err(error) => {
                    tracing::warn!(domain = self.domain, challenge = ?kind, "validation failed: {error:#}");
                    failure = Some(error);
                }
            }
        }
        Err(failure.expect("TLS-ALPN-01 is always tried"))
    }

    pub(super) async fn account(&self) -> Result<Account> {
        let builder = || match &self.root {
            Some(root) => Account::builder_with_root(root),
            None => Account::builder(),
        };
        if let Some(credentials) = self.store.load_account()? {
            return builder()?.from_credentials(credentials).await.context("Could not reach the ACME CA");
        }
        let contact = self.email.as_ref().map(|email| format!("mailto:{email}"));
        let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
        let new = NewAccount { contact: &contact, terms_of_service_agreed: true, only_return_existing: false };
        let (account, credentials) = builder()?.create(&new, self.directory.clone(), None).await.context("Could not create an ACME account")?;
        self.store.save_account(&credentials)?;
        tracing::info!(directory = self.directory, "ACME account created");
        Ok(account)
    }

    /// One order, validated by `kind`: the certificate chain and its key,
    /// both PEM.
    pub(super) async fn order(&self, account: &Account, kind: &ChallengeType) -> Result<(String, String)> {
        let identifiers = [Identifier::Dns(self.domain.clone())];
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await.context("Could not place an order")?;
        // However the order ends, the challenge stops being answered.
        let _cleanup = Cleanup(&self.state);

        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization?;
            match authorization.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                status => bail!("The CA has the authorization {status:?}"),
            }
            let mut challenge = authorization.challenge(kind.clone()).ok_or_else(|| anyhow!("The CA doesn't offer {kind:?}"))?;
            let key_authorization = challenge.key_authorization();
            match kind {
                ChallengeType::TlsAlpn01 => {
                    let certificate = alpn_challenge_certificate(&self.domain, key_authorization.digest().as_ref())?;
                    self.state.alpn_challenge.store(Some(Arc::new(certificate)));
                }
                _ => {
                    self.state.http_challenges.lock().insert(challenge.token.clone(), key_authorization.as_str().to_string());
                }
            }
            challenge.set_ready().await?;
        }

        let retries = RetryPolicy::new().initial_delay(Duration::from_secs(1)).timeout(ORDER_TIMEOUT);
        let status = order.poll_ready(&retries).await?;
        if status != OrderStatus::Ready {
            bail!("The CA left the order {status:?}");
        }
        let key = order.finalize().await.context("Could not finalize the order")?;
        let chain = order.poll_certificate(&retries).await.context("Could not fetch the certificate")?;
        Ok((chain, key))
    }
}

struct Cleanup<'a>(&'a State);

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        self.0.alpn_challenge.store(None);
        self.0.http_challenges.lock().clear();
    }
}

/// The self-signed certificate a TLS-ALPN-01 challenge is answered with:
/// for the domain, carrying the key authorization's digest (RFC 8737 §3).
pub fn alpn_challenge_certificate(domain: &str, digest: &[u8]) -> Result<CertifiedKey> {
    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    params.custom_extensions = vec![CustomExtension::new_acme_identifier(digest)];
    let key = KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)?;
    Ok(CertifiedKey::new(vec![certificate.der().clone()], signer))
}
