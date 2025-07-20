//! A TLS key and certificate provider that reads PEM files on disk.
//!
//! # Command line flags
//!
//! | Flag          | Default  | Meaning                 |
//! |---------------|----------|-------------------------|
//! | `--key-path`  | Required | Name of file containing PEM-format X.509 private key |
//! | `--cert-path` | Required | Name of file containing PEM-format X.509 certificate(s) |
//! | `--cacert`    | None     | Name of file containing PEM-format X.509 trust anchor certificate(s) |

use async_stream::stream;
use comprehensive::ResourceDependencies;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use futures::{FutureExt, SinkExt, Stream, StreamExt};
use http::Uri;
use rustls::DistinguishedName;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::TrustAnchor;
use rustls::sign::CertifiedKey;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::Context;
use std::time::SystemTime;
use thiserror::Error;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::api::{
    IdentityHints, LatestValueStream, TlsConfigInstance, TlsConfigProvider,
    VerifyExpectedIdentityResult,
};

const RELOAD_INTERVAL: std::time::Duration = std::time::Duration::new(900, 0);

/// Command line arguments for the [`TlsConfigFiles`] [`Resource`]. These are
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
        help = "Path to TLS root certificate for verifying peers, in PEM format."
    )]
    cacert: Option<PathBuf>,
}

#[derive(Default)]
struct Sentinels {
    key_sentinel: Option<(u64, SystemTime)>,
    cert_sentinel: Option<(u64, SystemTime)>,
    cacert_sentinel: Option<(u64, SystemTime)>,
}

struct Loader {
    key_path: PathBuf,
    cert_path: PathBuf,
    cacert_path: Option<PathBuf>,
    sentinels: Sentinels,
    crypto_provider: Arc<CryptoProvider>,
}

#[derive(Debug)] // OK to have: PrivateKeyDer's Debug elides the key.
struct Snapshot {
    certified_key: Arc<CertifiedKey>,
    cacert: Option<Arc<[TrustAnchor<'static>]>>,
    names: HashSet<Uri>,
}

impl Snapshot {
    fn maybe_get_identity(
        &self,
        try_harder: bool,
        requested: Option<&Uri>,
        sni: Option<&str>,
    ) -> Option<Arc<CertifiedKey>> {
        if try_harder
            || [requested, sni.and_then(inet_name_to_uri).as_ref()]
                .into_iter()
                .any(|maybe_uri| {
                    maybe_uri
                        .map(|uri| self.names.contains(uri))
                        .unwrap_or_default()
                })
        {
            Some(Arc::clone(&self.certified_key))
        } else {
            None
        }
    }
}

fn inet_name_to_uri(n: &str) -> Option<Uri> {
    Uri::builder()
        .scheme(http::uri::Scheme::HTTPS)
        .authority(n)
        .path_and_query("/")
        .build()
        .ok()
}

impl TlsConfigInstance for Snapshot {
    fn has_any_identity(&self) -> bool {
        true
    }

    fn select_identity(
        &self,
        try_harder: bool,
        hints: &IdentityHints<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        self.maybe_get_identity(try_harder, hints.requested, hints.sni)
    }

    fn choose_root_hint_subjects(
        &self,
        _local_identity: Option<&Uri>,
        _remote_identity: Option<&Uri>,
    ) -> Option<Arc<[DistinguishedName]>> {
        None
    }

    fn trust_anchors_for_cert(
        &self,
        try_harder: bool,
        _end_entity: &X509Certificate<'_>,
        _intermediates: &[X509Certificate<'_>],
    ) -> Option<Arc<[TrustAnchor<'static>]>> {
        if try_harder {
            self.cacert.as_ref().cloned()
        } else {
            None
        }
    }

    fn verify_expected_identity(
        &self,
        _: &X509Certificate<'_>,
        _: &Uri,
    ) -> VerifyExpectedIdentityResult {
        VerifyExpectedIdentityResult::UseWebpki
    }
}

fn reload_sentinel(md: std::io::Result<std::fs::Metadata>) -> Option<(u64, SystemTime)> {
    md.ok().and_then(|m| Some((m.len(), m.modified().ok()?)))
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

impl Loader {
    fn new(
        key_path: PathBuf,
        cert_path: PathBuf,
        cacert_path: Option<PathBuf>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Self {
        Self {
            key_path,
            cert_path,
            cacert_path,
            sentinels: Sentinels::default(),
            crypto_provider,
        }
    }

    fn load_files(&mut self) -> Result<Box<Snapshot>, TlsConfigFilesError> {
        let mut key_file = File::open(&self.key_path)?;
        let key_sentinel = reload_sentinel(key_file.metadata());
        let mut key_pem = Vec::new();
        key_file.read_to_end(&mut key_pem)?;
        let key = rustls_pemfile::private_key(&mut Cursor::new(&key_pem))?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no private key found in {}", self.key_path.display()),
            )
        })?;

        let mut cert_file = File::open(&self.cert_path)?;
        let cert_sentinel = reload_sentinel(cert_file.metadata());
        let mut cert_pem = Vec::new();
        cert_file.read_to_end(&mut cert_pem)?;
        let cert =
            rustls_pemfile::certs(&mut Cursor::new(&cert_pem)).collect::<Result<Vec<_>, _>>()?;

        let names = cert
            .first()
            .and_then(|end_entity| X509Certificate::from_der(end_entity).ok())
            .map(|(_, end_entity)| {
                end_entity
                    .subject_alternative_name()
                    .ok()
                    .flatten()
                    .map(|ext| ext.value.general_names.iter())
                    .into_iter()
                    .flatten()
                    .filter_map(|san| match san {
                        GeneralName::URI(s) => s.parse::<Uri>().ok(),
                        GeneralName::DNSName(s) => inet_name_to_uri(s),
                        _ => None,
                    })
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        log::info!("Loaded identity with names {:?}", names);

        let (cacert, cacert_sentinel) = if let Some(ref path) = self.cacert_path {
            let mut cert_file = File::open(path)?;
            let cert_sentinel = reload_sentinel(cert_file.metadata());
            let mut cert_pem = Vec::new();
            cert_file.read_to_end(&mut cert_pem)?;
            let cert = rustls_pemfile::certs(&mut Cursor::new(&cert_pem))
                .map(|der| Ok(webpki::anchor_from_trusted_cert(&der?)?.to_owned()))
                .collect::<Result<Arc<[_]>, TlsConfigFilesError>>()?;
            if cert.is_empty() {
                log::warn!("No root certificates loaded from file {}", path.display());
            }
            (Some(cert), cert_sentinel)
        } else {
            (None, None)
        };

        self.sentinels = Sentinels {
            key_sentinel,
            cert_sentinel,
            cacert_sentinel,
        };
        let private_key = self.crypto_provider.key_provider.load_private_key(key)?;
        let certified_key = CertifiedKey::new(cert, private_key);
        certified_key.keys_match()?;
        Ok(Box::new(Snapshot {
            certified_key: certified_key.into(),
            cacert,
            names,
        }))
    }

    fn needs_reload(&self) -> bool {
        sentinel_mismatch(&self.sentinels.key_sentinel, &self.key_path)
            || sentinel_mismatch(&self.sentinels.cert_sentinel, &self.cert_path)
            || self
                .cacert_path
                .as_ref()
                .map(|p| sentinel_mismatch(&self.sentinels.cacert_sentinel, p))
                .unwrap_or(false)
    }

    fn reload_loop(
        mut self,
    ) -> impl Stream<Item = Result<Box<dyn TlsConfigInstance>, std::convert::Infallible>> {
        stream! {
            loop {
                tokio::time::sleep(RELOAD_INTERVAL).await;
                if self.needs_reload() {
                    match self.load_files() {
                        Ok(snapshot) => {
                            let snapshot: Box<dyn TlsConfigInstance> = snapshot;
                            yield Ok(snapshot);
                        }
                        Err(e) => {
                            if let Some(ref path) = self.cacert_path {
                                log::warn!(
                                    "Could not reload TLS key and cert from {}, {}, and {}: {}",
                                    self.key_path.display(),
                                    self.cert_path.display(),
                                    path.display(),
                                    e
                                );
                            } else {
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
        }
    }
}

/// Error type returned by TlsConfigFiles
#[derive(Debug, Error)]
pub enum TlsConfigFilesError {
    /// Wrapper for std::io::Error
    #[error("{0}")]
    IOError(#[from] std::io::Error),
    /// Wrapper for rustls::Error
    #[error("{0}")]
    RustlsError(#[from] rustls::Error),
    /// TlsConfigFiles is missing flags.
    #[error("--key_path and --cert_path not given")]
    NoTlsFlags,
    /// Wrapper for webpki::Error
    #[error("{0}")]
    WebpkiError(#[from] webpki::Error),
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct TlsConfigFilesDependencies(Arc<crate::crypto_provider::RustlsCryptoProvider>);

/// A TLS key and certificate provider that reads PEM files on disk.
pub struct TlsConfigFiles(LatestValueStream);

#[resource]
#[export(dyn TlsConfigProvider)]
impl Resource for TlsConfigFiles {
    fn new(
        d: TlsConfigFilesDependencies,
        args: Args,
        api: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, TlsConfigFilesError> {
        let (Some(key_path), Some(cert_path)) = (args.key_path, args.cert_path) else {
            return Err(TlsConfigFilesError::NoTlsFlags);
        };
        let mut loader = Loader::new(key_path, cert_path, args.cacert, d.0.crypto_provider());
        let snapshot = loader.load_files()?;
        let exchange = LatestValueStream::default();
        let _ = exchange
            .writer()
            .send(snapshot)
            .poll_unpin(&mut Context::from_waker(std::task::Waker::noop()));
        let shared = Arc::new(Self(exchange));
        let shared2 = Arc::clone(&shared);
        api.set_task(async move {
            let _ = loader.reload_loop().forward(shared.0.writer()).await;
            Ok(())
        });
        Ok(shared2)
    }
}

impl TlsConfigProvider for TlsConfigFiles {
    fn stream(&self) -> crate::api::Reader<'_> {
        self.0.reader()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata;

    use comprehensive::Assembly;
    use futures::poll;
    use std::pin::pin;
    use std::task::Poll;

    struct CertAndKeyFiles {
        dir: tempfile::TempDir,
    }

    impl CertAndKeyFiles {
        fn user1() -> std::io::Result<Self> {
            let this = Self {
                dir: tempfile::tempdir()?,
            };
            std::fs::write(this.key_path(), testdata::USER1_KEY)?;
            std::fs::write(this.cert_path(), testdata::USER1_CERT)?;
            Ok(this)
        }

        fn key_path(&self) -> PathBuf {
            self.dir.path().join("key")
        }

        fn cert_path(&self) -> PathBuf {
            self.dir.path().join("cert")
        }
    }

    #[derive(ResourceDependencies)]
    struct TopDependencies(Arc<TlsConfigFiles>);

    fn test_assembly(
        active: bool,
    ) -> Result<(Assembly<TopDependencies>, Option<tempfile::TempDir>), Box<dyn std::error::Error>>
    {
        let (argv, dir): (Vec<std::ffi::OsString>, _) = if active {
            let d = CertAndKeyFiles::user1()?;
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

    fn fetch(
        stream: &mut crate::api::Reader<'_>,
    ) -> Result<Box<dyn TlsConfigInstance>, Poll<Option<Box<dyn TlsConfigInstance>>>> {
        match stream.poll_next_unpin(&mut Context::from_waker(std::task::Waker::noop())) {
            Poll::Ready(Some(got)) => Ok(got),
            x => Err(x),
        }
    }

    #[test]
    fn first_load() {
        let (a, tempdir) = test_assembly(true).expect("creating test TLS");
        let mut stream = a.top.0.stream();
        let got = fetch(&mut stream).expect("initial snapshot");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER1_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER1_CERT");
        assert_eq!(
            got.select_identity(true, &IdentityHints::default())
                .expect("select_identity should return identity")
                .cert,
            want
        );
        assert!(matches!(fetch(&mut stream), Err(Poll::Pending)));
        std::mem::drop(tempdir);
    }

    #[tokio::test(start_paused = true)]
    async fn reload_success() {
        let (a, tempdir) = test_assembly(true).expect("creating test TLS");
        let files = Arc::clone(&a.top.0);
        let mut stream = files.stream();
        let _ = fetch(&mut stream).expect("initial snapshot");
        let p = tempdir.as_ref().unwrap().path();
        std::fs::write(p.join("key"), testdata::USER2_KEY).expect("rewrite key");
        std::fs::write(p.join("cert"), testdata::USER2_CERT).expect("rewrite cert");

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        assert!(poll!(&mut r).is_pending());
        let _ = futures::future::select(&mut r, pin!(tokio::time::advance(RELOAD_INTERVAL))).await;
        assert!(poll!(&mut r).is_pending());

        let got = fetch(&mut stream).expect("reloaded snapshot");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER2_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER2_CERT");
        assert_eq!(
            got.select_identity(true, &IdentityHints::default())
                .expect("select_identity should return identity")
                .cert,
            want
        );
        std::mem::drop(tempdir);
    }

    #[tokio::test(start_paused = true)]
    async fn reload_fail() {
        let (a, tempdir) = test_assembly(true).expect("creating test TLS");
        let files = Arc::clone(&a.top.0);
        let mut stream = files.stream();
        let _ = fetch(&mut stream).expect("initial snapshot");
        let p = tempdir.as_ref().unwrap().path();
        std::fs::write(p.join("key"), "not valid").expect("rewrite key");
        std::fs::write(p.join("cert"), "not valid").expect("rewrite cert");

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        assert!(poll!(&mut r).is_pending());
        let _ = futures::future::select(&mut r, pin!(tokio::time::advance(RELOAD_INTERVAL))).await;
        assert!(poll!(&mut r).is_pending());

        assert!(matches!(fetch(&mut stream), Err(Poll::Pending)));
        std::mem::drop(tempdir);
    }

    fn user1_snapshot() -> Box<Snapshot> {
        let d = CertAndKeyFiles::user1().expect("user1");
        Loader::new(
            d.key_path(),
            d.cert_path(),
            None,
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .load_files()
        .expect("Loader::load_files")
    }

    #[test]
    fn no_hints() {
        assert!(
            user1_snapshot()
                .maybe_get_identity(false, None, None)
                .is_none()
        );
    }

    #[test]
    fn try_harder() {
        assert!(
            user1_snapshot()
                .maybe_get_identity(true, None, None)
                .is_some()
        );
    }

    #[test]
    fn wrong_sni() {
        assert!(
            user1_snapshot()
                .maybe_get_identity(false, None, Some("unrelated"))
                .is_none()
        );
    }

    #[test]
    fn matching_sni() {
        assert!(
            user1_snapshot()
                .maybe_get_identity(false, None, Some("user1"))
                .is_some()
        );
    }

    #[test]
    fn wrong_uri() {
        assert!(
            user1_snapshot()
                .maybe_get_identity(false, Some(&Uri::from_static("http://user1/")), None)
                .is_none()
        );
    }

    #[test]
    fn matching_uri() {
        assert!(
            user1_snapshot()
                .maybe_get_identity(false, Some(&Uri::from_static("https://user1/")), None)
                .is_some()
        );
    }
}
