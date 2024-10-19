//! Comprenehsive [`Resource`] for loading a TLS key and certificate.
//!
//! Usage:
//!
//! ```
//! #[derive(comprehensive::ResourceDependencies)]
//! struct ServerDependencies {
//!     tls: std::sync::Arc<comprehensive::tls::TlsConfig>,
//! }
//!
//! # struct Server;
//! # use tokio_rustls::rustls;
//! impl comprehensive::Resource for Server {
//!     type Args = comprehensive::NoArgs;
//!     type Dependencies = ServerDependencies;
//!     const NAME: &str = "Very secure!";
//!
//!     fn new(d: ServerDependencies, _: comprehensive::NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
//!         let _ = rustls::ServerConfig::builder()
//!             .with_no_client_auth()
//!             .with_cert_resolver(d.tls.cert_resolver()?);
//!         // ...more setup...
//!         Ok(Self)
//!     }
//! }
//! ```

use arc_swap::ArcSwap;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio_rustls::rustls;

use super::ComprehensiveError;
use super::Resource;

#[cfg(test)]
pub(crate) mod testdata;

const RELOAD_INTERVAL: std::time::Duration = std::time::Duration::new(900, 0);

/// Command line arguments for the [`TlsConfig`] [`Resource`]. These are
/// all pathnames to files on disk.
#[derive(clap::Args, Debug, Default)]
#[group(id = "comprehensive_tls_args")]
pub struct Args {
    #[arg(
        long,
        help = "Path to TLS key in PEM format. If unset, secure servers cannot be configured."
    )]
    key_path: Option<PathBuf>,

    #[arg(
        long,
        help = "Path to TLS certificate in PEM format. If unset, secure servers cannot be configured."
    )]
    cert_path: Option<PathBuf>,

    #[arg(
        long,
        help = "Path to TLS root certificate for verifying gRPCs clients, in PEM format."
    )]
    cacert: Option<PathBuf>,
}

#[derive(Debug)]
struct ReloadableKeyAndCertLoader {
    provider: &'static Arc<CryptoProvider>,
    key_path: PathBuf,
    key_meta: Option<(u64, SystemTime)>,
    cert_path: PathBuf,
    cert_meta: Option<(u64, SystemTime)>,
}

fn reload_sentinel(md: std::io::Result<std::fs::Metadata>) -> Option<(u64, SystemTime)> {
    md.ok().and_then(|m| Some((m.len(), m.modified().ok()?)))
}

struct LoadResult {
    key: PrivateKeyDer<'static>,
    key_pem: Vec<u8>, // for tonic's benefit only
    key_sentinel: Option<(u64, SystemTime)>,
    cert: Vec<CertificateDer<'static>>,
    cert_pem: Vec<u8>, // for tonic's benefit only
    cert_sentinel: Option<(u64, SystemTime)>,
}

fn load_files(key_path: &PathBuf, cert_path: &PathBuf) -> std::io::Result<LoadResult> {
    let mut key_file = File::open(key_path)?;
    let key_sentinel = reload_sentinel(key_file.metadata());
    let mut key_pem = Vec::new();
    key_file.read_to_end(&mut key_pem)?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(&key_pem))?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no private key found in {}", key_path.display()),
        )
    })?;

    let mut cert_file = File::open(cert_path)?;
    let cert_sentinel = reload_sentinel(cert_file.metadata());
    let mut cert_pem = Vec::new();
    cert_file.read_to_end(&mut cert_pem)?;
    let cert = rustls_pemfile::certs(&mut Cursor::new(&cert_pem)).collect::<Result<Vec<_>, _>>()?;

    Ok(LoadResult {
        key,
        key_sentinel,
        key_pem,
        cert,
        cert_sentinel,
        cert_pem,
    })
}

fn sentinel_mismatch(old: &Option<(u64, SystemTime)>, path: &Path) -> bool {
    match old {
        None => true,
        Some(ref old_md) => match reload_sentinel(path.metadata()) {
            None => true,
            Some(ref new_md) => old_md != new_md,
        },
    }
}

impl ReloadableKeyAndCertLoader {
    fn load(&mut self) -> Result<(CertifiedKey, Vec<u8>, Vec<u8>), ComprehensiveError> {
        let f = load_files(&self.key_path, &self.cert_path)?;
        let private_key = self.provider.key_provider.load_private_key(f.key)?;
        let certified_key = CertifiedKey::new(f.cert, private_key);
        certified_key.keys_match()?;
        self.key_meta = f.key_sentinel;
        self.cert_meta = f.cert_sentinel;
        Ok((certified_key, f.key_pem, f.cert_pem))
    }

    fn needs_reload(&self) -> bool {
        sentinel_mismatch(&self.key_meta, &self.key_path)
            || sentinel_mismatch(&self.cert_meta, &self.cert_path)
    }
}

/// Certificate resolver for configuring into HTTPS etc... servers.
#[derive(Debug)]
pub struct ReloadableKeyAndCertResolver(ArcSwap<CertifiedKey>);

impl ReloadableKeyAndCertResolver {
    fn real_resolve(&self) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0.load()))
    }
}

impl ResolvesServerCert for ReloadableKeyAndCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.real_resolve()
    }
}

struct ReloadableKeyAndCert {
    loader: ReloadableKeyAndCertLoader,
    resolver: Arc<ReloadableKeyAndCertResolver>,
    #[cfg(feature = "grpc")]
    pem_key_and_cert: [Vec<u8>; 2],
}

impl ReloadableKeyAndCert {
    fn new(key_path: PathBuf, cert_path: PathBuf) -> Result<Self, ComprehensiveError> {
        let mut loader = ReloadableKeyAndCertLoader {
            provider: CryptoProvider::get_default().expect("default CryptoProvider"),
            key_path: key_path,
            key_meta: None,
            cert_path: cert_path,
            cert_meta: None,
        };
        #[cfg(feature = "grpc")]
        let (certified_key, key_pem, cert_pem) = loader.load()?;
        #[cfg(not(feature = "grpc"))]
        let (certified_key, _, _) = loader.load()?;
        Ok(Self {
            loader,
            resolver: Arc::new(ReloadableKeyAndCertResolver(ArcSwap::from_pointee(
                certified_key,
            ))),
            #[cfg(feature = "grpc")]
            pem_key_and_cert: [key_pem, cert_pem],
        })
    }

    fn maybe_reload(&mut self) {
        if self.loader.needs_reload() {
            match self.loader.load() {
                Ok((certified_key, _, _)) => {
                    // We throw away the key&cert bytes data here since we only
                    // have it in the first place for tonic's benefit and tonic
                    // has no way to take a reload anyway.
                    self.resolver.0.store(certified_key.into());
                    log::info!("Reloaded changed TLS key and/or cert.");
                }
                Err(e) => {
                    log::warn!(
                        "Could not reload TLS key and cert from {} and {}: {}",
                        self.loader.key_path.display(),
                        self.loader.cert_path.display(),
                        e
                    );
                }
            }
        }
    }
}

/// Comprenehsive [`Resource`] for loading a TLS key and certificate.
///
/// This resource will load:
/// * a TLS private key
/// * a corresponding certificate (chain)
/// * a CA certificate for verifying peers' certificates.
///
/// These are made available to other resources which depend on this one.
///
/// The private key and corresponding certificate are reread from disk
/// whenever they change to allow for hitless occasional renewals. But
/// for now only consumers who use the [`TlsConfig::cert_resolver`]
/// interface can take advantage of that.
pub struct TlsConfig {
    inner: std::sync::Mutex<Option<ReloadableKeyAndCert>>,
    #[allow(dead_code)]
    cacert: Option<Vec<u8>>,
}

impl Resource for TlsConfig {
    type Args = Args;
    type Dependencies = crate::NoDependencies;
    const NAME: &str = "TLS certificate store";

    fn new(_: crate::NoDependencies, args: Args) -> Result<Self, Box<dyn std::error::Error>> {
        let inner = if let (Some(key_path), Some(cert_path)) = (args.key_path, args.cert_path) {
            Some(ReloadableKeyAndCert::new(key_path, cert_path)?)
        } else {
            None
        };
        Ok(Self {
            inner: std::sync::Mutex::new(inner),
            cacert: args.cacert.map(|path| std::fs::read(path)).transpose()?,
        })
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let inner = self.inner.lock().unwrap().take();
        Ok(match inner {
            None => (),
            Some(mut inner) => loop {
                tokio::time::sleep(RELOAD_INTERVAL).await;
                inner.maybe_reload();
            },
        })
    }
}

impl TlsConfig {
    /// Returns a struct that implements the
    /// [`rustls::server::ResolvesServerCert`] trait. This can be
    /// configured into HTTPS etc... servers. The object will make
    /// use of the valid key and certificate most recently read from disk.
    pub fn cert_resolver(&self) -> Result<Arc<ReloadableKeyAndCertResolver>, ComprehensiveError> {
        let inner = self.inner.lock().unwrap();
        match inner.as_ref() {
            None => Err(ComprehensiveError::NoTlsFlags),
            Some(ref inner) => Ok(Arc::clone(&inner.resolver)),
        }
    }

    /// Returns a preloaded [`tonic::transport::ServerTlsConfig`] object
    /// with the currently loaded key and certificate. This is unreloadable
    /// unfortunately so it should only be used for `tonic`, which
    /// currently cannot consume a [`rustls::server::ResolvesServerCert`].
    #[cfg(feature = "grpc")]
    pub fn snapshot(&self) -> Result<tonic::transport::ServerTlsConfig, ComprehensiveError> {
        let inner = self.inner.lock().unwrap();
        match inner.as_ref() {
            None => Err(ComprehensiveError::NoTlsFlags),
            Some(ref inner) => {
                let identity = tonic::transport::Identity::from_pem(
                    &inner.pem_key_and_cert[1],
                    &inner.pem_key_and_cert[0],
                );
                let mut tls = tonic::transport::ServerTlsConfig::new().identity(identity);
                if let Some(ref cacert) = self.cacert {
                    let cert = tonic::transport::Certificate::from_pem(cacert);
                    tls = tls.client_ca_root(cert);
                }
                Ok(tls)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn for_tests(
        active: bool,
    ) -> Result<(Self, Option<tempfile::TempDir>), Box<dyn std::error::Error>> {
        if active {
            let d = testdata::CertAndKeyFiles::user1()?;
            let cacert_path = d.dir.path().join("cacert");
            std::fs::write(&cacert_path, testdata::CACERT)?;
            let args = Args {
                key_path: Some(d.key_path().into()),
                cert_path: Some(d.cert_path().into()),
                cacert: Some(cacert_path),
            };
            Ok((Self::new(crate::NoDependencies, args)?, Some(d.dir)))
        } else {
            Ok((Self::new(crate::NoDependencies, Args::default())?, None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_load() {
        let (tlsc, tempdir) = TlsConfig::for_tests(true).expect("creating test TLS");
        let resolver = tlsc.cert_resolver().expect("get resolver");

        let got = resolver.real_resolve().expect("resolve");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER1_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER1_CERT");
        assert_eq!(got.cert, want);
        std::mem::drop(tempdir);
    }

    #[test]
    fn reload_success() {
        let (tlsc, tempdir) = TlsConfig::for_tests(true).expect("creating test TLS");
        let resolver = tlsc.cert_resolver().expect("get resolver");
        let p = tempdir.as_ref().unwrap().path();
        std::fs::write(p.join("key"), testdata::USER2_KEY).expect("rewrite key");
        std::fs::write(p.join("cert"), testdata::USER2_CERT).expect("rewrite cert");
        tlsc.inner.lock().unwrap().as_mut().unwrap().maybe_reload();

        let got = resolver.real_resolve().expect("resolve");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER2_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER2_CERT");
        assert_eq!(got.cert, want);
        std::mem::drop(tempdir);
    }

    #[test]
    fn reload_fail() {
        let (tlsc, tempdir) = TlsConfig::for_tests(true).expect("creating test TLS");
        let resolver = tlsc.cert_resolver().expect("get resolver");
        let p = tempdir.as_ref().unwrap().path();
        std::fs::write(p.join("key"), "not valid").expect("rewrite key");
        std::fs::write(p.join("cert"), "not valid").expect("rewrite cert");
        tlsc.inner.lock().unwrap().as_mut().unwrap().maybe_reload();

        let got = resolver.real_resolve().expect("resolve");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER1_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER1_CERT");
        assert_eq!(got.cert, want);
        std::mem::drop(tempdir);
    }
}
