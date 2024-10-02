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

#[cfg(test)]
pub(crate) mod testdata;

const RELOAD_INTERVAL: std::time::Duration = std::time::Duration::new(900, 0);

#[derive(clap::Args, Debug, Default)]
#[group(id = "comprehensive_tls_args")]
pub(crate) struct Args {
    #[arg(long)]
    key_path: Option<PathBuf>,

    #[arg(long)]
    cert_path: Option<PathBuf>,

    #[arg(long)]
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

#[derive(Debug)]
pub(crate) struct ReloadableKeyAndCertResolver(ArcSwap<CertifiedKey>);

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

pub(crate) struct TlsConfig {
    inner: Option<ReloadableKeyAndCert>,
    #[allow(dead_code)]
    cacert: Option<Vec<u8>>,
}

impl TlsConfig {
    pub(crate) fn new(args: Args) -> Result<Self, ComprehensiveError> {
        let inner = if let (Some(key_path), Some(cert_path)) = (args.key_path, args.cert_path) {
            Some(ReloadableKeyAndCert::new(key_path, cert_path)?)
        } else {
            None
        };
        Ok(Self {
            inner,
            cacert: args.cacert.map(|path| std::fs::read(path)).transpose()?,
        })
    }

    pub(crate) fn cert_resolver(
        &self,
    ) -> Result<Arc<ReloadableKeyAndCertResolver>, ComprehensiveError> {
        match self.inner {
            None => Err(ComprehensiveError::NoTlsFlags),
            Some(ref inner) => Ok(Arc::clone(&inner.resolver)),
        }
    }

    #[cfg(feature = "grpc")]
    pub(crate) fn snapshot(&self) -> Result<tonic::transport::ServerTlsConfig, ComprehensiveError> {
        match self.inner {
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

    pub(crate) async fn run(self) -> Result<(), ComprehensiveError> {
        Ok(match self.inner {
            None => (),
            Some(mut inner) => loop {
                tokio::time::sleep(RELOAD_INTERVAL).await;
                inner.maybe_reload();
            },
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests(
        active: bool,
    ) -> Result<(Self, Option<tempfile::TempDir>), ComprehensiveError> {
        if active {
            let d = testdata::CertAndKeyFiles::user1()?;
            let cacert_path = d.dir.path().join("cacert");
            std::fs::write(&cacert_path, testdata::CACERT)?;
            let args = Args {
                key_path: Some(d.key_path().into()),
                cert_path: Some(d.cert_path().into()),
                cacert: Some(cacert_path),
            };
            Ok((Self::new(args)?, Some(d.dir)))
        } else {
            Ok((Self::new(Args::default())?, None))
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
        tlsc.inner.unwrap().maybe_reload();

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
        tlsc.inner.unwrap().maybe_reload();

        let got = resolver.real_resolve().expect("resolve");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER1_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER1_CERT");
        assert_eq!(got.cert, want);
        std::mem::drop(tempdir);
    }
}
