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
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive_traits::tls_config::{Exchange, Snapshot, TlsConfigProvider};
use futures::{FutureExt, SinkExt, Stream, StreamExt};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::Context;
use std::time::SystemTime;
use thiserror::Error;

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
    fn new(key_path: PathBuf, cert_path: PathBuf, cacert_path: Option<PathBuf>) -> Self {
        Self {
            key_path,
            cert_path,
            cacert_path,
            sentinels: Sentinels::default(),
        }
    }

    fn load_files(&mut self) -> std::io::Result<Box<Snapshot>> {
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

        let (cacert, cacert_sentinel) = if let Some(ref path) = self.cacert_path {
            let mut cert_file = File::open(path)?;
            let cert_sentinel = reload_sentinel(cert_file.metadata());
            let mut cert_pem = Vec::new();
            cert_file.read_to_end(&mut cert_pem)?;
            let cert = rustls_pemfile::certs(&mut Cursor::new(&cert_pem))
                .collect::<Result<Vec<_>, _>>()?;
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
        Ok(Box::new(Snapshot { key, cert, cacert }))
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
    ) -> impl Stream<Item = Result<Box<Snapshot>, std::convert::Infallible>> {
        stream! {
            loop {
                tokio::time::sleep(RELOAD_INTERVAL).await;
                if self.needs_reload() {
                    match self.load_files() {
                        Ok(snapshot) => {
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
    /// TlsConfigFiles is missing flags.
    #[error("--key_path and --cert_path not given")]
    NoTlsFlags,
}

/// A TLS key and certificate provider that reads PEM files on disk.
pub struct TlsConfigFiles(Exchange);

#[resource]
#[export(dyn TlsConfigProvider)]
impl Resource for TlsConfigFiles {
    fn new(
        _: comprehensive::NoDependencies,
        args: Args,
        api: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, TlsConfigFilesError> {
        let (Some(key_path), Some(cert_path)) = (args.key_path, args.cert_path) else {
            return Err(TlsConfigFilesError::NoTlsFlags);
        };
        let mut loader = Loader::new(key_path, cert_path, args.cacert);
        let snapshot = loader.load_files()?;
        let exchange = Exchange::default();
        let _ = exchange
            .writer()
            .unwrap()
            .send(snapshot)
            .poll_unpin(&mut Context::from_waker(std::task::Waker::noop()));
        let shared = Arc::new(Self(exchange));
        let shared2 = Arc::clone(&shared);
        api.set_task(async move {
            let _ = loader
                .reload_loop()
                .forward(shared.0.writer().unwrap())
                .await;
            Ok(())
        });
        Ok(shared2)
    }
}

impl TlsConfigProvider for TlsConfigFiles {
    fn stream(&self) -> Option<comprehensive_traits::tls_config::Reader<'_>> {
        self.0.reader()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata;

    use comprehensive::{Assembly, ResourceDependencies};
    use futures::poll;
    use std::pin::pin;
    use std::task::Poll;

    #[derive(ResourceDependencies)]
    struct TopDependencies(Arc<TlsConfigFiles>);

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

    fn fetch(
        stream: &mut comprehensive_traits::tls_config::Reader<'_>,
    ) -> Result<Box<Snapshot>, Poll<Option<Box<Snapshot>>>> {
        match stream.poll_next_unpin(&mut Context::from_waker(std::task::Waker::noop())) {
            Poll::Ready(Some(got)) => Ok(got),
            x => Err(x),
        }
    }

    #[test]
    fn first_load() {
        let (a, tempdir) = test_assembly(true).expect("creating test TLS");
        let mut stream = a.top.0.stream().expect("get stream");
        let got = fetch(&mut stream).expect("initial snapshot");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER1_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER1_CERT");
        assert_eq!(got.cert, want);
        assert!(matches!(fetch(&mut stream), Err(Poll::Pending)));
        std::mem::drop(tempdir);
    }

    #[tokio::test(start_paused = true)]
    async fn reload_success() {
        let (a, tempdir) = test_assembly(true).expect("creating test TLS");
        let files = Arc::clone(&a.top.0);
        let mut stream = files.stream().expect("get stream");
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
        assert_eq!(got.cert, want);
        std::mem::drop(tempdir);
    }

    #[tokio::test(start_paused = true)]
    async fn reload_fail() {
        let (a, tempdir) = test_assembly(true).expect("creating test TLS");
        let files = Arc::clone(&a.top.0);
        let mut stream = files.stream().expect("get stream");
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
}
