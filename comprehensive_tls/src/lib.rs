//! Comprenehsive [`Resource`] for loading a TLS key and certificate.
//!
//! Usage:
//!
//! ```
//! use comprehensive::ResourceDependencies;
//! use comprehensive::v1::{AssemblyRuntime, Resource, resource};
//! use std::sync::Arc;
//!
//! #[derive(ResourceDependencies)]
//! struct ServerDependencies {
//!     tls: Arc<comprehensive_tls::TlsConfig>,
//! }
//!
//! # struct Server;
//! # use tokio_rustls::rustls;
//! #[resource]
//! impl Resource for Server {
//!     fn new(
//!         d: ServerDependencies,
//!         _: comprehensive::NoArgs,
//!         _: &mut AssemblyRuntime<'_>,
//!     ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
//!         let _ = rustls::ServerConfig::builder()
//!             .with_no_client_auth()
//!             .with_cert_resolver(d.tls.cert_resolver()?);
//!         // ...more setup...
//!         Ok(Arc::new(Self))
//!     }
//! }
//! ```

use arc_swap::ArcSwap;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use rustls::RootCertStore;
use rustls::client::{ClientConfig, ResolvesClientCert};
use rustls::crypto::{CryptoProvider, KeyProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
use tokio_rustls::rustls;

#[cfg(test)]
pub(crate) mod testdata;

const RELOAD_INTERVAL: std::time::Duration = std::time::Duration::new(900, 0);

/// Error type returned by comprehensive_tls functions
#[derive(Debug, Error)]
pub enum ComprehensiveTlsError {
    /// Wrapper for std::io::Error
    #[error("{0}")]
    IOError(#[from] std::io::Error),
    /// Wrapper for rustls::Error
    #[error("{0}")]
    TLSError(#[from] rustls::Error),
    /// Indicates an attempt to configure one of the secure servers
    /// (gRPCs or HTTPS) without supplying the necessary command line
    /// flags for the private key and certificate.
    #[error("cannot create secure server: --key_path and --cert_path not given")]
    NoTlsFlags,
}

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
    provider: Option<&'static dyn KeyProvider>,
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
        Some(old_md) => match reload_sentinel(path.metadata()) {
            None => true,
            Some(ref new_md) => old_md != new_md,
        },
    }
}

impl ReloadableKeyAndCertLoader {
    fn load(&mut self) -> Result<(CertifiedKey, Vec<u8>, Vec<u8>), ComprehensiveTlsError> {
        let f = load_files(&self.key_path, &self.cert_path)?;
        let private_key = match self.provider {
            Some(p) => p.load_private_key(f.key)?,
            None => rustls::crypto::aws_lc_rs::sign::any_supported_type(&f.key)?,
        };
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

    fn maybe_reload(&mut self, resolver: &ReloadableKeyAndCertResolver) {
        if self.needs_reload() {
            match self.load() {
                Ok((certified_key, _, _)) => {
                    // We throw away the key&cert bytes data here since we only
                    // have it in the first place for tonic's benefit and tonic
                    // has no way to take a reload anyway.
                    resolver.0.store(certified_key.into());
                    log::info!("Reloaded changed TLS key and/or cert.");
                }
                Err(e) => {
                    log::warn!(
                        "Could not reload TLS key and cert from {} and {}: {}",
                        self.key_path.display(),
                        self.cert_path.display(),
                        e
                    );
                }
            }
        }
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

impl ResolvesClientCert for ReloadableKeyAndCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.real_resolve()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

struct ReloadableKeyAndCert {
    resolver: Arc<ReloadableKeyAndCertResolver>,
    #[cfg(feature = "unreloadable_tls")]
    pem_key_and_cert: [Vec<u8>; 2],
}

impl ReloadableKeyAndCert {
    fn new(loader: &mut ReloadableKeyAndCertLoader) -> Result<Self, ComprehensiveTlsError> {
        #[cfg(feature = "unreloadable_tls")]
        let (certified_key, key_pem, cert_pem) = loader.load()?;
        #[cfg(not(feature = "unreloadable_tls"))]
        let (certified_key, _, _) = loader.load()?;
        Ok(Self {
            resolver: Arc::new(ReloadableKeyAndCertResolver(ArcSwap::from_pointee(
                certified_key,
            ))),
            #[cfg(feature = "unreloadable_tls")]
            pem_key_and_cert: [key_pem, cert_pem],
        })
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
    inner: Option<ReloadableKeyAndCert>,
    client_config: Arc<ClientConfig>,
    #[allow(dead_code)]
    cacert: Option<Vec<u8>>,
}

#[resource]
impl Resource for TlsConfig {
    const NAME: &str = "TLS certificate store";

    fn new(
        _: comprehensive::NoDependencies,
        args: Args,
        api: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, ComprehensiveTlsError> {
        let crypto_provider = CryptoProvider::get_default();
        let inner = if let (Some(key_path), Some(cert_path)) = (args.key_path, args.cert_path) {
            let mut loader = ReloadableKeyAndCertLoader {
                provider: crypto_provider.map(|p| p.key_provider),
                key_path,
                key_meta: None,
                cert_path,
                cert_meta: None,
            };
            let result = ReloadableKeyAndCert::new(&mut loader)?;
            let resolver_for_updating = Arc::clone(&result.resolver);
            api.set_task(async move {
                loop {
                    tokio::time::sleep(RELOAD_INTERVAL).await;
                    loader.maybe_reload(&resolver_for_updating);
                }
            });
            Some(result)
        } else {
            None
        };
        let mut roots = RootCertStore::empty();
        let raw_roots = if let Some(cacert_file) = args.cacert {
            let contents = std::fs::read(&cacert_file)?;
            roots.add_parsable_certificates(
                rustls_pemfile::certs(&mut Cursor::new(&contents)).filter_map(|r| match r {
                    Ok(cert) => Some(cert),
                    Err(e) => {
                        log::warn!("Error reading TLS root certificate: {}", e);
                        None
                    }
                }),
            );
            if roots.is_empty() {
                log::warn!(
                    "No root certificates loaded from file {}",
                    cacert_file.display()
                );
            }
            Some(contents)
        } else {
            None
        };
        let roots = Arc::new(roots);
        let provider = match crypto_provider {
            Some(p) => Arc::clone(p),
            None => Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        };
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots);
        let client_config = match inner {
            Some(ref inner) => {
                let resolver = Arc::clone(&inner.resolver);
                client_config.with_client_cert_resolver(resolver)
            }
            None => client_config.with_no_client_auth(),
        };
        Ok(Arc::new(Self {
            inner,
            client_config: Arc::new(client_config),
            cacert: raw_roots,
        }))
    }
}

/// struct returned by [`TlsConfig::snapshot`] that contains a snapshot of
/// the currently loaded TLS certificate and corresponding key, as well as
/// a CA certificate for verifying peers.
#[cfg(feature = "unreloadable_tls")]
pub struct TlsDataSnapshot {
    /// X.509 key in PEM format.
    pub key: Vec<u8>,
    /// X.509 certificate in PEM format.
    pub cert: Vec<u8>,
    /// X.509 CA certificate in PEM format.
    pub cacert: Option<Vec<u8>>,
}

impl TlsConfig {
    /// Returns a struct that implements the
    /// [`rustls::server::ResolvesServerCert`] trait. This can be
    /// configured into HTTPS etc... servers. The object will make
    /// use of the valid key and certificate most recently read from disk.
    pub fn cert_resolver(
        &self,
    ) -> Result<Arc<ReloadableKeyAndCertResolver>, ComprehensiveTlsError> {
        match self.inner.as_ref() {
            None => Err(ComprehensiveTlsError::NoTlsFlags),
            Some(inner) => Ok(Arc::clone(&inner.resolver)),
        }
    }

    /// Returns a TLS [`ClientConfig`] built from the runtime configuration.
    /// If a local key and certificate are supplied then this will do client auth.
    pub fn client_config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.client_config)
    }

    /// Returns an object with raw [`Vec<u8>`] PEM representations of the
    /// currently loaded key and certificate. This is unreloadable
    /// unfortunately so it should only be used for `tonic`, which
    /// currently cannot consume a [`rustls::server::ResolvesServerCert`].
    #[cfg(feature = "unreloadable_tls")]
    pub fn snapshot(&self) -> Result<TlsDataSnapshot, ComprehensiveTlsError> {
        match self.inner.as_ref() {
            None => Err(ComprehensiveTlsError::NoTlsFlags),
            Some(inner) => Ok(TlsDataSnapshot {
                key: inner.pem_key_and_cert[0].clone(),
                cert: inner.pem_key_and_cert[1].clone(),
                cacert: self.cacert.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use comprehensive::{Assembly, ResourceDependencies};
    use futures::poll;
    use std::pin::pin;

    #[derive(ResourceDependencies)]
    struct TopDependencies(Arc<TlsConfig>);

    fn test_assembly(
        active: bool,
    ) -> Result<(Assembly<TopDependencies>, Option<tempfile::TempDir>), Box<dyn std::error::Error>>
    {
        let (argv, dir): (Vec<std::ffi::OsString>, _) = if active {
            let d = testdata::CertAndKeyFiles::user1()?;
            let cacert_path = d.dir.path().join("cacert");
            std::fs::write(&cacert_path, testdata::CACERT)?;
            (
                vec![
                    "cmd".into(),
                    "--key-path".into(),
                    d.key_path().into(),
                    "--cert-path".into(),
                    d.cert_path().into(),
                    "--cacert".into(),
                    cacert_path.into(),
                ],
                Some(d.dir),
            )
        } else {
            (vec!["cmd".into()], None)
        };
        Ok((Assembly::<TopDependencies>::new_from_argv(argv)?, dir))
    }

    #[test]
    fn first_load() {
        let (a, tempdir) = test_assembly(true).expect("creating test TLS");
        let resolver = a.top.0.cert_resolver().expect("get resolver");

        let got = resolver.real_resolve().expect("resolve");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER1_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER1_CERT");
        assert_eq!(got.cert, want);
        std::mem::drop(tempdir);
    }

    #[tokio::test(start_paused = true)]
    async fn reload_success() {
        let (a, tempdir) = test_assembly(true).expect("creating test TLS");
        let resolver = a.top.0.cert_resolver().expect("get resolver");
        let p = tempdir.as_ref().unwrap().path();
        std::fs::write(p.join("key"), testdata::USER2_KEY).expect("rewrite key");
        std::fs::write(p.join("cert"), testdata::USER2_CERT).expect("rewrite cert");

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        assert!(poll!(&mut r).is_pending());
        let _ = futures::future::select(&mut r, pin!(tokio::time::advance(RELOAD_INTERVAL))).await;
        assert!(poll!(&mut r).is_pending());

        let got = resolver.real_resolve().expect("resolve");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER2_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER2_CERT");
        assert_eq!(got.cert, want);
        std::mem::drop(tempdir);
    }

    #[tokio::test(start_paused = true)]
    async fn reload_fail() {
        let (a, tempdir) = test_assembly(true).expect("creating test TLS");
        let resolver = a.top.0.cert_resolver().expect("get resolver");
        let p = tempdir.as_ref().unwrap().path();
        std::fs::write(p.join("key"), "not valid").expect("rewrite key");
        std::fs::write(p.join("cert"), "not valid").expect("rewrite cert");

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        assert!(poll!(&mut r).is_pending());
        let _ = futures::future::select(&mut r, pin!(tokio::time::advance(RELOAD_INTERVAL))).await;
        assert!(poll!(&mut r).is_pending());

        let got = resolver.real_resolve().expect("resolve");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER1_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER1_CERT");
        assert_eq!(got.cert, want);
        std::mem::drop(tempdir);
    }
}
