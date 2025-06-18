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
//!         let server_config_with_client_auth = d.tls.server_config_mtls();
//!
//!         let server_config_no_client_auth = rustls::ServerConfig::builder()
//!             .with_no_client_auth()
//!             .with_cert_resolver(d.tls.cert_resolver()?);
//!         // ...more setup...
//!         Ok(Arc::new(Self))
//!     }
//! }
//! ```

#![warn(missing_docs)]

use arc_swap::ArcSwapOption;
use comprehensive::ResourceDependencies;
use comprehensive::health::HealthReporter;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive_traits::tls_config::{Snapshot, TlsConfigProvider};
use delegate::delegate;
use futures::StreamExt;
use rustls::RootCertStore;
use rustls::client::danger::ServerCertVerifier;
use rustls::client::{ClientConfig, ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig, WebPkiClientVerifier};
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
    /// Health signal registration error.
    #[error("{0}")]
    ComprehensiveError(#[from] comprehensive::ComprehensiveError),
}

#[derive(Debug)]
struct ReloadableContents {
    certified_key: Arc<CertifiedKey>,
    server_verifier: Option<Arc<WebPkiServerVerifier>>,
    roots: Option<Arc<RootCertStore>>,
}

/// Certificate resolver for configuring into HTTPS etc... servers.
#[derive(Debug)]
pub struct ReloadableKeyAndCertResolver(ArcSwapOption<ReloadableContents>);

impl ReloadableKeyAndCertResolver {
    fn real_resolve(&self) -> Option<Arc<CertifiedKey>> {
        self.0.load().as_ref().map(|s| Arc::clone(&s.certified_key))
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
struct NullServerCertVerifier<'a>(&'a CryptoProvider);

impl ServerCertVerifier for NullServerCertVerifier<'_> {
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
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct ServerVerifier(Arc<ReloadableKeyAndCertResolver>, Arc<CryptoProvider>);

impl ServerVerifier {
    fn new(
        reloadable: Arc<ReloadableKeyAndCertResolver>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Self {
        Self(reloadable, crypto_provider)
    }
}

impl ServerCertVerifier for ServerVerifier {
    delegate! {
        #[through(ServerCertVerifier)]
        #[expr(let reloadable = self.0.0.load(); $)]
        to match reloadable.as_ref().map(|s| &s.server_verifier) {
            Some(Some(v)) => &**v,
            Some(None) => &NullServerCertVerifier(&self.1),
            None => &NullServerCertVerifier(&self.1),
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

#[derive(Debug)]
struct NullClientCertVerifier(Arc<CryptoProvider>);

impl ClientCertVerifier for NullClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
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
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn accept_update(
    snapshot: Snapshot,
    crypto_provider: &Arc<CryptoProvider>,
) -> Result<ReloadableContents, rustls::Error> {
    let private_key = crypto_provider
        .key_provider
        .load_private_key(snapshot.key)?;
    let certified_key = CertifiedKey::new(snapshot.cert, private_key);
    certified_key.keys_match()?;

    let roots = snapshot.cacert.and_then(|cacerts| {
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(cacerts);
        if roots.is_empty() {
            log::warn!("Empty TLS trust anchors. TLS connections will likely fail.");
            None
        } else {
            Some(Arc::new(roots))
        }
    });
    let server_verifier = roots.as_ref().and_then(|roots| {
        WebPkiServerVerifier::builder_with_provider(Arc::clone(roots), Arc::clone(crypto_provider)).build()
            .inspect_err(|e| log::warn!("Error constructing server certificate verifier: {}; TLS connections will likely fail.", e))
            .ok()
    });

    Ok(ReloadableContents {
        certified_key: Arc::new(certified_key),
        server_verifier,
        roots,
    })
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
    reloadable: Arc<ReloadableKeyAndCertResolver>,
    client_config: Arc<ClientConfig>,
    server_config_builder: rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>,
    crypto_provider: Arc<CryptoProvider>,
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct TlsConfigDependencies {
    #[may_fail]
    providers: Vec<Arc<dyn TlsConfigProvider>>,
    health: Arc<HealthReporter>,
    _default_built_in_provider: std::marker::PhantomData<files::TlsConfigFiles>,
}

fn setup(
    d: TlsConfigDependencies,
    api: &mut AssemblyRuntime<'_>,
    crypto_provider: &Arc<CryptoProvider>,
) -> Result<Arc<ReloadableKeyAndCertResolver>, ComprehensiveTlsError> {
    let mut providers_it = d.providers.into_iter();
    let Some(provider) = providers_it.next() else {
        return Err(ComprehensiveTlsError::NoTlsProvider);
    };
    if providers_it.len() > 0 {
        log::warn!(
            "TlsConfig: {} providers successfully initialised. Using the first.",
            providers_it.len() + 1
        );
    }

    // If the provider has already supplied as initial value, get it now.
    // That is more efficient and potentially less confusing than starting
    // out with empty config and filling it in later. Providers that have
    // the ability to make their config available early enough for this
    // should do so.
    let (resolver_inner, mut health) = match provider
        .stream()
        .unwrap()
        .poll_next_unpin(&mut Context::from_waker(std::task::Waker::noop()))
    {
        Poll::Ready(Some(snapshot)) => (
            ArcSwapOption::from_pointee(accept_update(*snapshot, crypto_provider)?),
            // We already have a config, no need to interact with health.
            None,
        ),
        Poll::Ready(None) => {
            log::error!("TlsConfig: provider delivered a 0-length stream");
            return Err(ComprehensiveTlsError::NoTlsProvider);
        }
        Poll::Pending => (
            ArcSwapOption::empty(),
            // Withhold healthy status until we have something loaded.
            Some(d.health.register("TlsConfig")?),
        ),
    };
    let resolver = Arc::new(ReloadableKeyAndCertResolver(resolver_inner));
    let resolver_for_updating = Arc::clone(&resolver);
    let crypto_provider = Arc::clone(crypto_provider);
    api.set_task(async move {
        let mut update_stream = provider.stream().unwrap();
        while let Some(update) = update_stream.next().await {
            match accept_update(*update, &crypto_provider) {
                Ok(contents) => {
                    if let Some(s) = health.take() {
                        s.set_healthy(true);
                    }
                    resolver_for_updating.0.store(Some(contents.into()));
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
    Ok(resolver)
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
        let reloadable = setup(d, api, &crypto_provider)?;

        let resolver = Arc::clone(&reloadable);
        let server_verifier = Arc::new(ServerVerifier::new(
            Arc::clone(&reloadable),
            Arc::clone(&crypto_provider),
        ));
        let client_config = ClientConfig::builder_with_provider(Arc::clone(&crypto_provider))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(server_verifier)
            .with_client_cert_resolver(resolver);
        let server_config_builder =
            ServerConfig::builder_with_provider(Arc::clone(&crypto_provider))
                .with_safe_default_protocol_versions()?;
        Ok(Arc::new(Self {
            reloadable,
            client_config: Arc::new(client_config),
            server_config_builder,
            crypto_provider,
        }))
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
        Ok(Arc::clone(&self.reloadable))
    }

    /// Returns a TLS [`ClientConfig`] built from the runtime configuration.
    /// If a local key and certificate are supplied then this will do client auth.
    pub fn client_config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.client_config)
    }

    /// Returns a TLS [`ServerConfig`] built from the runtime configuration
    /// and is suitable for mTLS (mutual TLS).
    ///
    /// Due to a [limitation](https://github.com/rustls/rustls/issues/2497)
    /// of the [`ClientCertVerifier`] trait, the output of this method is
    /// built from a snapshot of the [`TlsConfig`] and becomes stale after
    /// the underlying config is reloaded. Therefore a fresh [`ServerConfig`]
    /// should be regenerated before each handshake, or at least at intervals.
    pub fn server_config_mtls(&self) -> ServerConfig {
        let client_verifier = self.reloadable.0.load().as_ref().and_then(|s| s.roots
            .as_ref()
            .and_then(|roots| {
                WebPkiClientVerifier::builder_with_provider(
                    Arc::clone(roots),
                    Arc::clone(&self.crypto_provider),
                ).build()
                    .inspect_err(|e| log::warn!("Error constructing client certificate verifier: {}; TLS connections will likely fail.", e))
                    .ok()
            }))
            .unwrap_or_else(|| Arc::new(NullClientCertVerifier(Arc::clone(&self.crypto_provider))));
        let resolver = Arc::clone(&self.reloadable);
        self.server_config_builder
            .clone()
            .with_client_cert_verifier(client_verifier)
            .with_cert_resolver(resolver)
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

    #[derive(clap::Args)]
    #[group(skip)]
    struct TestTlsConfigArgs {
        #[arg(long)]
        delayed: bool,
    }

    #[resource]
    #[export(dyn TlsConfigProvider)]
    impl Resource for TestTlsConfig {
        fn new(
            _: comprehensive::NoDependencies,
            a: TestTlsConfigArgs,
            _: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            let exchange = Exchange::default();
            if !a.delayed {
                let _ = exchange
                    .writer()
                    .unwrap()
                    .send(mksnapshot(
                        &testdata::USER1_KEY,
                        &testdata::USER1_CERT,
                        &testdata::CACERT,
                    ))
                    .poll_unpin(&mut Context::from_waker(std::task::Waker::noop()));
            }
            Ok(Arc::new(Self(exchange)))
        }
    }

    impl TlsConfigProvider for TestTlsConfig {
        fn stream(&self) -> Option<comprehensive_traits::tls_config::Reader<'_>> {
            self.0.reader()
        }
    }

    #[derive(ResourceDependencies)]
    struct TopDependencies(Arc<TlsConfig>, Arc<TestTlsConfig>, Arc<HealthReporter>);

    #[test]
    fn first_load() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        assert!(a.top.2.is_healthy());
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

    #[tokio::test(start_paused = true)]
    async fn delayed_load() {
        let argv: Vec<std::ffi::OsString> = vec!["cmd".into(), "--delayed".into()];
        let a = Assembly::<TopDependencies>::new_from_argv(argv).unwrap();
        let health = Arc::clone(&a.top.2);
        assert!(!health.is_healthy());
        let provider = Arc::clone(&a.top.1);
        let mut writer = provider.0.writer().unwrap();
        let resolver = a.top.0.cert_resolver().expect("get resolver");

        assert!(resolver.real_resolve().is_none());

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        let _ = futures::future::select(
            &mut r,
            writer.send(mksnapshot(
                &testdata::USER1_KEY,
                &testdata::USER1_CERT,
                &testdata::CACERT,
            )),
        )
        .await;
        assert!(poll!(&mut r).is_pending());

        assert!(health.is_healthy());
        assert!(resolver.real_resolve().is_some());
    }

    fn pair_with_client_config(
        cc: Arc<ClientConfig>,
    ) -> (Connect<DuplexStream>, Accept<DuplexStream>) {
        let p = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let sc = ServerConfig::builder_with_provider(p)
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

    fn pair_with_server_config(
        sc: Arc<ServerConfig>,
    ) -> (Connect<DuplexStream>, Accept<DuplexStream>) {
        let p = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(
            rustls_pemfile::certs(&mut Cursor::new(&testdata::CACERT))
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
        );
        let cc = ClientConfig::builder_with_provider(p)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(Arc::new(roots))
            .with_client_auth_cert(
                rustls_pemfile::certs(&mut Cursor::new(&testdata::USER2_CERT))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                rustls_pemfile::private_key(&mut Cursor::new(&testdata::USER2_KEY))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();

        let (client, server) = tokio::io::duplex(64);
        let client = TlsConnector::from(Arc::new(cc))
            .connect(ServerName::try_from("user1").unwrap(), client);
        let server = TlsAcceptor::from(sc).accept(server);
        (client, server)
    }

    async fn talk(client: Connect<DuplexStream>, server: Accept<DuplexStream>) {
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
    async fn client_verifies_server_cert() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let (client, server) = pair_with_client_config(a.top.0.client_config());
        talk(client, server).await;
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

    #[tokio::test]
    async fn server_verifies_client_cert() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let (client, server) = pair_with_server_config(Arc::new(a.top.0.server_config_mtls()));
        talk(client, server).await;
    }

    #[tokio::test]
    async fn server_refuses_client_cert() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let tlsc = Arc::clone(&a.top.0);
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

        let (client, server) = pair_with_server_config(Arc::new(tlsc.server_config_mtls()));
        let server_task = pin!(async move {
            let err = server.await.expect_err("should refuse");
            assert!(err.to_string().contains("certificate"));
        });
        match futures::future::select(client, server_task).await {
            Either::Left((_, server_task)) => server_task.await,
            Either::Right((_, _)) => (),
        }
    }
}
