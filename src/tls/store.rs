//! The ACME account and certificates, kept on disk.
//!
//! Each CA gets a directory of its own, named for its directory URL's host,
//! since an account belongs to one CA and switching between Let's Encrypt
//! and its staging CA shouldn't serve one's certificate under the other:
//!
//! ```text
//! tls/acme-v02.api.letsencrypt.org/account.json
//! tls/acme-v02.api.letsencrypt.org/<domain>.pem   chain, then key
//! tls/acme-v02.api.letsencrypt.org/<domain>.http-01   if HTTP-01 worked last
//! ```
//!
//! Both hold private keys, so they're readable by armada's user alone.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use instant_acme::AccountCredentials;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;

use crate::util::write_private;

pub struct Store {
    dir: PathBuf,
}

/// A certificate and its key, ready to serve.
pub struct Certificate {
    pub key: Arc<CertifiedKey>,
    /// Its validity period, in Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
}

impl Store {
    pub fn open(root: &Path, directory: &str) -> Result<Store> {
        let url = url::Url::parse(directory).with_context(|| format!("Not a valid ACME directory URL: {directory}"))?;
        let host = url.host_str().ok_or_else(|| anyhow!("The ACME directory URL has no host: {directory}"))?;
        let name = match url.port() {
            Some(port) => format!("{host}_{port}"),
            None => host.to_string(),
        };
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
        Ok(Store { dir })
    }

    fn account_path(&self) -> PathBuf {
        self.dir.join("account.json")
    }

    fn certificate_path(&self, domain: &str) -> PathBuf {
        self.dir.join(format!("{domain}.pem"))
    }

    fn http01_path(&self, domain: &str) -> PathBuf {
        self.dir.join(format!("{domain}.http-01"))
    }

    /// Whether `domain`'s last certificate was validated over HTTP-01.
    pub fn http01_worked(&self, domain: &str) -> bool {
        self.http01_path(domain).exists()
    }

    pub fn remember_http01(&self, domain: &str, worked: bool) -> Result<()> {
        let path = self.http01_path(domain);
        let result = match worked {
            true => write_private(&path, b""),
            false => match std::fs::remove_file(&path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
                _ => Ok(()),
            },
        };
        result.with_context(|| format!("Could not note which challenge worked in {}", path.display()))
    }

    pub fn load_account(&self) -> Result<Option<AccountCredentials>> {
        let path = self.account_path();
        let Some(text) = read_if_exists(&path)? else { return Ok(None) };
        let credentials = serde_json::from_slice(&text).with_context(|| format!("{} is not an ACME account", path.display()))?;
        Ok(Some(credentials))
    }

    pub fn save_account(&self, credentials: &AccountCredentials) -> Result<()> {
        write_private(&self.account_path(), &serde_json::to_vec_pretty(credentials)?)
    }

    pub fn load_certificate(&self, domain: &str) -> Result<Option<Certificate>> {
        let path = self.certificate_path(domain);
        let Some(pem) = read_if_exists(&path)? else { return Ok(None) };
        let certificate = Certificate::from_pem(&pem).with_context(|| format!("{} is not a usable certificate", path.display()))?;
        Ok(Some(certificate))
    }

    /// Keep `chain` and `key`, both PEM, for `domain`, and return them ready
    /// to serve.
    pub fn save_certificate(&self, domain: &str, chain: &str, key: &str) -> Result<Certificate> {
        let pem = format!("{}\n{}", chain.trim_end(), key);
        let certificate = Certificate::from_pem(pem.as_bytes()).context("The CA issued an unusable certificate")?;
        write_private(&self.certificate_path(domain), pem.as_bytes())?;
        Ok(certificate)
    }
}

impl Certificate {
    pub fn from_pem(pem: &[u8]) -> Result<Certificate> {
        let chain = CertificateDer::pem_slice_iter(pem).collect::<Result<Vec<_>, _>>().context("Its certificates can't be read")?;
        let Some(leaf) = chain.first() else { bail!("It holds no certificate") };
        let key = PrivateKeyDer::from_pem_slice(pem).context("Its private key can't be read")?;
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf).map_err(|error| anyhow!("Its certificate can't be parsed: {error}"))?;
        let validity = parsed.validity();
        let (not_before, not_after) = (validity.not_before.timestamp(), validity.not_after.timestamp());
        let signer = rustls::crypto::ring::sign::any_supported_type(&key).context("Its private key isn't a supported type")?;
        let key = CertifiedKey::new(chain, signer);
        key.keys_match().context("Its private key doesn't match its certificate")?;
        Ok(Certificate { key: Arc::new(key), not_before, not_after })
    }

    /// When to renew it: with a third of its lifetime left, which is a month
    /// for a 90-day certificate and two days for a six-day one.
    pub fn renew_at(&self) -> i64 {
        self.not_after - (self.not_after - self.not_before).max(0) / 3
    }

    pub fn not_after_text(&self) -> String {
        crate::util::http_date(self.not_after)
    }
}

fn read_if_exists(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Could not read {}", path.display())),
    }
}

