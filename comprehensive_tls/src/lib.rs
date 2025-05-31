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

use arc_swap::{ArcSwap, ArcSwapOption};
use comprehensive::ResourceDependencies;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive_traits::tls_config::{Snapshot, TlsConfigProvider};
use delegate::delegate;
use futures::StreamExt;
use rustls::RootCertStore;
use rustls::client::danger::ServerCertVerifier;
use rustls::client::{ClientConfig, ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName};
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

#[derive(Debug)]
struct NullPeerVerifier;

impl ServerCertVerifier for NullPeerVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        Vec::new()
    }
}

#[derive(Debug, Default)]
struct PeerVerifier(ArcSwapOption<WebPkiServerVerifier>);

impl PeerVerifier {
    fn make_inner(
        roots: RootCertStore,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Result<Arc<WebPkiServerVerifier>, rustls::server::VerifierBuilderError> {
        WebPkiServerVerifier::builder_with_provider(roots.into(), crypto_provider).build()
    }

    fn new(inner: Option<Arc<WebPkiServerVerifier>>) -> Self {
        Self(ArcSwapOption::from(inner))
    }

    fn replace(&self, inner: Option<Arc<WebPkiServerVerifier>>) {
        self.0.store(inner);
    }
}

impl ServerCertVerifier for PeerVerifier {
    delegate! {
        #[through(ServerCertVerifier)]
        #[expr(let inner = self.0.load(); $)]
        to match *inner {
            Some(ref v) => &**v,
            None => &NullPeerVerifier,
        } {
            fn verify_server_cert(
                &self,
                end_entity: &CertificateDer<'_>,
                intermediates: &[CertificateDer<'_>],
                server_name: &ServerName<'_>,
                ocsp_response: &[u8],
                now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error>;
            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>;
            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>;
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme>;
            fn requires_raw_public_keys(&self) -> bool;
        }
    }
}

struct Update {
    certified_key: CertifiedKey,
    peer_verifier: Option<Arc<WebPkiServerVerifier>>,
    #[cfg(feature = "unreloadable_tls")]
    snapshot: Snapshot,
}

fn accept_update(
    snapshot: Snapshot,
    crypto_provider: Arc<CryptoProvider>,
) -> Result<Update, rustls::Error> {
    #[cfg(feature = "unreloadable_tls")]
    let snapshot2 = Snapshot {
        key: snapshot.key.clone_key(),
        cert: snapshot.cert.clone(),
        cacert: snapshot.cacert.clone(),
    };
    let private_key = crypto_provider
        .key_provider
        .load_private_key(snapshot.key)?;
    let certified_key = CertifiedKey::new(snapshot.cert, private_key);
    certified_key.keys_match()?;

    let peer_verifier = snapshot.cacert.and_then(|cacerts| {
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(cacerts);
        PeerVerifier::make_inner(roots, crypto_provider)
            .inspect_err(|e| log::warn!("Error constructing server certificate verifier: {}; TLS connections will likely fail.", e))
            .ok()
    });

    Ok(Update {
        certified_key,
        peer_verifier,
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
    crypto_provider: Arc<CryptoProvider>,
) -> Result<(Option<TlsConfigInner>, Arc<PeerVerifier>), rustls::Error> {
    let mut providers_it = d.providers.into_iter();
    let Some(provider) = providers_it.next() else {
        return Ok((None, Arc::new(PeerVerifier::default())));
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
        return Ok((None, Arc::new(PeerVerifier::default())));
    };

    let Update {
        certified_key,
        peer_verifier,
        #[cfg(feature = "unreloadable_tls")]
        snapshot,
    } = accept_update(*initial, Arc::clone(&crypto_provider))?;
    let resolver = Arc::new(ReloadableKeyAndCertResolver(ArcSwap::from_pointee(
        certified_key,
    )));
    let peer_verifier = Arc::new(PeerVerifier::new(peer_verifier));
    let peer_verifier_for_updating = Arc::clone(&peer_verifier);
    let resolver_for_updating = Arc::clone(&resolver);
    api.set_task(async move {
        let mut update_stream = provider.stream().unwrap();
        while let Some(update) = update_stream.next().await {
            match accept_update(*update, Arc::clone(&crypto_provider)) {
                Ok(Update {
                    certified_key,
                    peer_verifier,
                    #[cfg(feature = "unreloadable_tls")]
                        snapshot: _,
                }) => {
                    resolver_for_updating.0.store(certified_key.into());
                    peer_verifier_for_updating.replace(peer_verifier);
                }
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
        peer_verifier,
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
        let crypto_provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        let (inner, peer_verifier) = setup(d, api, Arc::clone(&crypto_provider))?;
        let client_config = ClientConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(peer_verifier);
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
    use futures::future::Either;
    use futures::{FutureExt, SinkExt, poll};
    use std::io::Cursor;
    use std::pin::pin;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio_rustls::{Accept, Connect, TlsAcceptor, TlsConnector};

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

    fn pair_with_client_config(
        cc: Arc<ClientConfig>,
    ) -> (Connect<DuplexStream>, Accept<DuplexStream>) {
        let p = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let sc = rustls::ServerConfig::builder_with_provider(p)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                rustls_pemfile::certs(&mut Cursor::new(&testdata::USER2_CERT))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                rustls_pemfile::private_key(&mut Cursor::new(&testdata::USER2_KEY))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();

        let (client, server) = tokio::io::duplex(64);
        let client = TlsConnector::from(cc).connect(ServerName::try_from("user2").unwrap(), client);
        let server = TlsAcceptor::from(Arc::new(sc)).accept(server);
        (client, server)
    }

    #[tokio::test]
    async fn client_verifies_server_cert() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let (client, server) = pair_with_client_config(a.top.0.client_config());
        let client_task = pin!(async move {
            let mut stream = client.await.expect("client connected");
            stream
                .write_all(b"hello")
                .await
                .expect("write hello to client");
            let mut buf = vec![0u8; 3];
            stream
                .read_exact(&mut buf)
                .await
                .expect("read bye from server");
            assert_eq!(buf, b"bye");
        });
        let server_task = pin!(async move {
            let mut stream = server.await.expect("server accepted");
            let mut buf = vec![0u8; 5];
            stream
                .read_exact(&mut buf)
                .await
                .expect("read hello from client");
            assert_eq!(buf, b"hello");
            stream.write_all(b"bye").await.expect("write bye to client");
            stream.shutdown().await.expect("shutdown");
        });
        match futures::future::select(client_task, server_task).await {
            Either::Left((_, _)) => (),
            Either::Right((_, client_task)) => client_task.await,
        }
    }

    #[tokio::test]
    async fn client_refuses_server_cert() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let cc = a.top.0.client_config();
        let provider = Arc::clone(&a.top.1);
        let mut writer = provider.0.writer().unwrap();

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        let _ = futures::future::select(
            &mut r,
            writer.send(mksnapshot(
                &testdata::USER1_KEY,
                &testdata::USER1_CERT,
                &testdata::USER1_CERT, // Not the correct trust root
            )),
        )
        .await;
        assert!(poll!(&mut r).is_pending());

        let (client, server) = pair_with_client_config(cc);
        let client_task = pin!(async move {
            let err = client.await.expect_err("should refuse");
            assert!(err.to_string().contains("certificate"));
        });
        match futures::future::select(client_task, server).await {
            Either::Left((_, _)) => (),
            Either::Right((_, client_task)) => client_task.await,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn no_roots() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let provider = Arc::clone(&a.top.1);
        let mut writer = provider.0.writer().unwrap();
        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        let _ = futures::future::select(
            &mut r,
            writer.send(mksnapshot(&testdata::USER2_KEY, &testdata::USER2_CERT, b"")),
        )
        .await;
        assert!(poll!(&mut r).is_pending());
    }
}
