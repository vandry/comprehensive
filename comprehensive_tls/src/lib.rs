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

#![warn(missing_docs)]

use arc_swap::ArcSwap;
use comprehensive::ResourceDependencies;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive_traits::tls_config::{Snapshot, TlsConfigProvider};
use futures::StreamExt;
use rustls::RootCertStore;
use rustls::client::{ClientConfig, ResolvesClientCert};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use std::task::{Context, Poll};
use thiserror::Error;
use tokio_rustls::rustls;

pub mod files;

#[cfg(test)]
pub(crate) mod testdata;

/// Error type returned by comprehensive_tls functions
#[derive(Debug, Error)]
pub enum ComprehensiveTlsError {
    /// Wrapper for rustls::Error
    #[error("{0}")]
    TLSError(#[from] rustls::Error),
    /// Indicates an attempt to configure one of the secure servers
    /// (gRPCs or HTTPS) without supplying the necessary command line
    /// flags for the private key and certificate.
    #[error("No provider for TLS parameters is available")]
    NoTlsProvider,
    /// Error PEM-encoding data
    #[cfg(feature = "unreloadable_tls")]
    #[error("No provider for TLS parameters is available")]
    PEMError(#[from] pem_rfc7468::Error),
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

struct Update {
    certified_key: CertifiedKey,
    cacerts: Vec<CertificateDer<'static>>,
    #[cfg(feature = "unreloadable_tls")]
    snapshot: Snapshot,
}

fn accept_update(
    snapshot: Snapshot,
    crypto_provider: &Option<Arc<CryptoProvider>>,
) -> Result<Update, rustls::Error> {
    #[cfg(feature = "unreloadable_tls")]
    let snapshot2 = Snapshot {
        key: snapshot.key.clone_key(),
        cert: snapshot.cert.clone(),
        cacert: snapshot.cacert.clone(),
    };
    let private_key = match crypto_provider {
        Some(p) => p.key_provider.load_private_key(snapshot.key)?,
        None => rustls::crypto::aws_lc_rs::sign::any_supported_type(&snapshot.key)?,
    };
    let certified_key = CertifiedKey::new(snapshot.cert, private_key);
    certified_key.keys_match()?;
    Ok(Update {
        certified_key,
        cacerts: snapshot.cacert.unwrap_or_default(),
        #[cfg(feature = "unreloadable_tls")]
        snapshot: snapshot2,
    })
}

struct TlsConfigInner {
    resolver: Arc<ReloadableKeyAndCertResolver>,
    #[cfg(feature = "unreloadable_tls")]
    snapshot: Snapshot,
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
    inner: Option<TlsConfigInner>,
    client_config: Arc<ClientConfig>,
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct TlsConfigDependencies {
    #[may_fail]
    providers: Vec<Arc<dyn TlsConfigProvider>>,
    _default_built_in_provider: std::marker::PhantomData<files::TlsConfigFiles>,
}

fn setup(
    d: TlsConfigDependencies,
    api: &mut AssemblyRuntime<'_>,
    crypto_provider: Option<Arc<CryptoProvider>>,
) -> Result<(Option<TlsConfigInner>, Vec<CertificateDer<'static>>), rustls::Error> {
    let mut providers_it = d.providers.into_iter();
    let Some(provider) = providers_it.next() else {
        return Ok((None, Vec::new()));
    };
    if providers_it.len() > 0 {
        log::warn!(
            "TlsConfig: {} providers successfully initialised. Using the first.",
            providers_it.len() + 1
        );
    }

    // For now, we require that the provider has already supplied as initial
    // value. This will not work for all providers, so it will need to change.
    let Poll::Ready(Some(initial)) = provider
        .stream()
        .unwrap()
        .poll_next_unpin(&mut Context::from_waker(std::task::Waker::noop()))
    else {
        return Ok((None, Vec::new()));
    };

    let Update {
        certified_key,
        cacerts,
        #[cfg(feature = "unreloadable_tls")]
        snapshot,
    } = accept_update(*initial, &crypto_provider)?;
    let resolver = Arc::new(ReloadableKeyAndCertResolver(ArcSwap::from_pointee(
        certified_key,
    )));
    let resolver_for_updating = Arc::clone(&resolver);
    api.set_task(async move {
        let mut update_stream = provider.stream().unwrap();
        while let Some(update) = update_stream.next().await {
            match accept_update(*update, &crypto_provider) {
                Ok(Update {
                    certified_key,
                    cacerts: _,
                    #[cfg(feature = "unreloadable_tls")]
                        snapshot: _,
                }) => resolver_for_updating.0.store(certified_key.into()),
                Err(e) => {
                    log::error!(
                        "Received updated TLS parameters but they couldn't be applied: {}",
                        e
                    );
                }
            }
        }
        Ok(())
    });
    Ok((
        Some(TlsConfigInner {
            resolver,
            #[cfg(feature = "unreloadable_tls")]
            snapshot,
        }),
        cacerts,
    ))
}

#[resource]
impl Resource for TlsConfig {
    const NAME: &str = "TLS certificate store";

    fn new(
        d: TlsConfigDependencies,
        _: comprehensive::NoArgs,
        api: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, ComprehensiveTlsError> {
        let crypto_provider = CryptoProvider::get_default();
        let (inner, cacerts) = setup(d, api, crypto_provider.cloned())?;
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(cacerts);
        let client_config = ClientConfig::builder_with_provider(
            crypto_provider
                .cloned()
                .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
        )
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

#[cfg(feature = "unreloadable_tls")]
mod pem {
    use super::{CertificateDer, Snapshot, TlsDataSnapshot};
    use pem_rfc7468::{Error, LineEnding, encode, encoded_len};

    fn pem_certs(certs: &[CertificateDer<'static>]) -> Result<Vec<u8>, Error> {
        const CERTIFICATE: &str = "CERTIFICATE";

        let expected_len = certs.iter().try_fold(0, |acc, c| {
            Ok::<_, Error>(acc + encoded_len(CERTIFICATE, LineEnding::LF, c.as_ref())?)
        })?;
        let mut out = vec![0u8; expected_len];
        let mut l = 0;
        for c in certs {
            l += encode(CERTIFICATE, LineEnding::LF, c.as_ref(), &mut out[l..])?.len();
        }
        Ok(out)
    }

    pub(super) fn make_pem_snapshot(snapshot: &Snapshot) -> Result<TlsDataSnapshot, Error> {
        const PRIVATE_KEY: &str = "PRIVATE KEY";

        let expected_len = encoded_len(PRIVATE_KEY, LineEnding::LF, snapshot.key.secret_der())?;
        let mut key = vec![0u8; expected_len];
        let _ = encode(
            PRIVATE_KEY,
            LineEnding::LF,
            snapshot.key.secret_der(),
            &mut key,
        )?;
        Ok(TlsDataSnapshot {
            key,
            cert: pem_certs(&snapshot.cert)?,
            cacert: snapshot.cacert.as_ref().map(|c| pem_certs(c)).transpose()?,
        })
    }

    #[cfg(test)]
    mod tests {
        use crate::{Snapshot, testdata};
        use std::io::Cursor;

        #[test]
        fn pem() {
            let user1 = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER1_CERT))
                .next()
                .unwrap()
                .unwrap();
            let user2 = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER2_CERT))
                .next()
                .unwrap()
                .unwrap();
            let s = Snapshot {
                key: rustls_pemfile::private_key(&mut Cursor::new(&testdata::USER1_KEY))
                    .unwrap()
                    .unwrap(),
                cert: vec![user1.clone()],
                cacert: vec![user1, user2].into(),
            };
            let ds = super::make_pem_snapshot(&s).unwrap();
            assert_eq!(ds.key, &testdata::USER1_KEY[1..]);
            assert_eq!(ds.cert, &testdata::USER1_CERT[1..]);
            let mut cat =
                Vec::with_capacity(testdata::USER1_CERT.len() + testdata::USER2_CERT.len() - 2);
            cat.extend(&testdata::USER1_CERT[1..]);
            cat.extend(&testdata::USER2_CERT[1..]);
            assert_eq!(ds.cacert.unwrap(), cat);
        }
    }
}

impl TlsConfig {
    /// Returns a struct that implements the
    /// [`rustls::server::ResolvesServerCert`] trait. This can be
    /// configured into HTTPS etc... servers. The object will make
    /// use of the valid key and certificate most recently read from disk.
    pub fn cert_resolver(
        &self,
    ) -> Result<Arc<ReloadableKeyAndCertResolver>, ComprehensiveTlsError> {
        Ok(Arc::clone(
            &self
                .inner
                .as_ref()
                .ok_or(ComprehensiveTlsError::NoTlsProvider)?
                .resolver,
        ))
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
        Ok(pem::make_pem_snapshot(
            &self
                .inner
                .as_ref()
                .ok_or(ComprehensiveTlsError::NoTlsProvider)?
                .snapshot,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use comprehensive::{Assembly, ResourceDependencies};
    use comprehensive_traits::tls_config::Exchange;
    use futures::{FutureExt, SinkExt, poll};
    use std::io::Cursor;
    use std::pin::pin;

    const EMPTY: &[std::ffi::OsString] = &[];

    fn mksnapshot(key: &[u8], cert: &[u8], cacert: &[u8]) -> Box<Snapshot> {
        Box::new(Snapshot {
            key: rustls_pemfile::private_key(&mut Cursor::new(key))
                .unwrap()
                .unwrap(),
            cert: rustls_pemfile::certs(&mut Cursor::new(cert))
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            cacert: rustls_pemfile::certs(&mut Cursor::new(cacert))
                .collect::<Result<Vec<_>, _>>()
                .ok(),
        })
    }

    struct TestTlsConfig(Exchange);

    #[resource]
    #[export(dyn TlsConfigProvider)]
    impl Resource for TestTlsConfig {
        fn new(
            _: comprehensive::NoDependencies,
            _: comprehensive::NoArgs,
            _: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            let exchange = Exchange::default();
            let _ = exchange
                .writer()
                .unwrap()
                .send(mksnapshot(
                    &testdata::USER1_KEY,
                    &testdata::USER1_CERT,
                    &testdata::CACERT,
                ))
                .poll_unpin(&mut Context::from_waker(std::task::Waker::noop()));
            Ok(Arc::new(Self(exchange)))
        }
    }

    impl TlsConfigProvider for TestTlsConfig {
        fn stream(&self) -> Option<comprehensive_traits::tls_config::Reader<'_>> {
            self.0.reader()
        }
    }

    #[derive(ResourceDependencies)]
    struct TopDependencies(Arc<TlsConfig>, Arc<TestTlsConfig>);

    #[test]
    fn first_load() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let resolver = a.top.0.cert_resolver().expect("get resolver");

        let got = resolver.real_resolve().expect("resolve");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER1_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER1_CERT");
        assert_eq!(got.cert, want);
    }

    #[tokio::test(start_paused = true)]
    async fn reload_success() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let provider = Arc::clone(&a.top.1);
        let mut writer = provider.0.writer().unwrap();
        let resolver = a.top.0.cert_resolver().expect("get resolver");

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        let _ = futures::future::select(
            &mut r,
            writer.send(mksnapshot(
                &testdata::USER2_KEY,
                &testdata::USER2_CERT,
                &testdata::CACERT,
            )),
        )
        .await;
        assert!(poll!(&mut r).is_pending());

        let got = resolver.real_resolve().expect("resolve");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER2_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER2_CERT");
        assert_eq!(got.cert, want);
    }

    #[tokio::test(start_paused = true)]
    async fn reload_fail() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let provider = Arc::clone(&a.top.1);
        let mut writer = provider.0.writer().unwrap();
        let resolver = a.top.0.cert_resolver().expect("get resolver");

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        // Mismatched key and cert
        let _ = futures::future::select(
            &mut r,
            writer.send(mksnapshot(
                &testdata::USER1_KEY,
                &testdata::USER2_CERT,
                &testdata::CACERT,
            )),
        )
        .await;
        assert!(poll!(&mut r).is_pending());

        let got = resolver.real_resolve().expect("resolve");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER1_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER2_CERT");
        assert_eq!(got.cert, want);
    }
}
