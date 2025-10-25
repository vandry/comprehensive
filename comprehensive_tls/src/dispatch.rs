//! Comprenehsive [`Resource`] for loading a TLS key and certificate.
//!
//! Resources wishing to make TLS connections should depend on [`TlsConfig`]:
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
//! #[resource]
//! impl Resource for Server {
//!     fn new(
//!         d: ServerDependencies,
//!         _: comprehensive::NoArgs,
//!         _: &mut AssemblyRuntime<'_>,
//!     ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
//!         let server_config_with_client_auth = d.tls
//!             .server_config::<comprehensive_tls::ClientAuthEnabled>();
//!         // ...more setup...
//!         Ok(Arc::new(Self))
//!     }
//! }
//! ```

use arc_swap::ArcSwapOption;
use comprehensive::health::{HealthReporter, HealthSignaller};
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive::{ComprehensiveError, ResourceDependencies};
use futures::{FutureExt, Stream, StreamExt};
use http::Uri;
use pin_project_lite::pin_project;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::client::{
    ClientConfig, ResolvesClientCert, verify_server_cert_signed_by_trust_anchor, verify_server_name,
};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::CertificateDer;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{
    ClientHello, ParsedCertificate, ResolvesServerCert, ServerConfig, ServerSessionMemoryCache,
    WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, ConfigBuilder, DistinguishedName, RootCertStore};
use slice_dst::SliceWithHeader;
use std::marker::PhantomData;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::SystemTime;
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{error, info, warn};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::api::{
    IdentityHints, TlsConfigInstance, TlsConfigProvider, VerifyExpectedIdentityResult, rustls,
};

const UNHEALTHY_TTL_THRESHOLD: time::Duration = time::Duration::seconds(30);

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
    ComprehensiveError(#[from] ComprehensiveError),
}

trait Clock {
    fn now(&self) -> SystemTime;
}

#[cfg(test)]
mod clock {
    use std::sync::Arc;
    use std::time::SystemTime;

    pub(super) struct Clock(tokio::time::Instant);

    impl super::Clock for Arc<Clock> {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + self.0.elapsed()
        }
    }

    #[comprehensive::v1::resource]
    impl comprehensive::v1::Resource for Clock {
        fn new(
            _: comprehensive::NoDependencies,
            _: comprehensive::NoArgs,
            _: &mut comprehensive::v1::AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            Ok(Arc::new(Self(tokio::time::Instant::now())))
        }
    }
}

#[cfg(not(test))]
mod clock {
    use std::time::SystemTime;

    pub(super) struct Clock;

    impl super::Clock for Clock {
        fn now(&self) -> SystemTime {
            SystemTime::now()
        }
    }
}

/// Healthy is defined as any_config_received and dangerous_close_to_expiry == 0
struct HealthManager {
    signaller: Option<HealthSignaller>,
    // 0: no config ever received: unhealthy
    // 1: config received, none dangerous_close_to_expiry
    // more: config received, at least one dangerous_close_to_expiry
    dangerous_close_to_expiry_plus_any_config_received: AtomicUsize,
}

impl std::fmt::Debug for HealthManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "HealthManager {{ ... }}")
    }
}

impl HealthManager {
    fn new(reporter: &Arc<HealthReporter>) -> Self {
        Self {
            signaller: reporter.register("TlsConfig").ok(),
            dangerous_close_to_expiry_plus_any_config_received: AtomicUsize::new(0),
        }
    }

    fn first_report(&self, healthy: bool) {
        let mut old = self
            .dangerous_close_to_expiry_plus_any_config_received
            .load(Ordering::Acquire);
        if let Some(new_health) = loop {
            let (new, update) = if old == 0 {
                // Nobody has reported before.
                if healthy { (1, Some(true)) } else { (2, None) }
            } else if healthy {
                // If old == 1: Nothing to do: still healthy.
                // If old > 1: Nothing to do: another provider keeps us unhealthy.
                return;
            } else {
                // One more unhealthy provider, update if we're the first.
                (old + 1, if old == 1 { Some(false) } else { None })
            };
            match self
                .dangerous_close_to_expiry_plus_any_config_received
                .compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    break update;
                }
                Err(updated_old) => {
                    old = updated_old;
                }
            }
        } {
            if let Some(s) = &self.signaller {
                s.set_healthy(new_health);
            }
        }
    }

    fn update(&self, old: bool, new: bool) {
        if old == new {
            return;
        }
        if new {
            if self
                .dangerous_close_to_expiry_plus_any_config_received
                .fetch_sub(1, Ordering::AcqRel)
                == 2
            {
                if let Some(s) = &self.signaller {
                    s.set_healthy(true);
                }
            }
        } else if self
            .dangerous_close_to_expiry_plus_any_config_received
            .fetch_add(1, Ordering::AcqRel)
            == 1
        {
            if let Some(s) = &self.signaller {
                s.set_healthy(false);
            }
        }
    }
}

struct SingleProviderHealthTrackerInner {
    healthy: bool,
    expiry: Option<OffsetDateTime>,
}

struct SingleProviderHealthTracker<C>(Option<SingleProviderHealthTrackerInner>, C);

pin_project! {
    struct SingleProviderHealthTrackerStream<'a, S, C> {
        #[pin] inner: S,
        tracker: SingleProviderHealthTracker<C>,
        health: &'a HealthManager,
        #[pin] sleeper: Option<tokio::time::Sleep>,
    }
}

fn should_be_healthy<C>(expiry: OffsetDateTime, clock: &C) -> Option<time::Duration>
where
    C: Clock,
{
    let ttl = expiry - clock.now();
    if ttl < UNHEALTHY_TTL_THRESHOLD {
        warn!(
            "TLS identity valid until {} is already expired or very close to expiry",
            expiry
        );
        None
    } else {
        Some(ttl)
    }
}

impl<C: Clock> SingleProviderHealthTracker<C> {
    fn new(clock: C) -> Self {
        Self(None, clock)
    }

    fn configure(&mut self, health: &HealthManager, contents: &dyn TlsConfigInstance) {
        let expiry = contents.identity_valid_until();
        let healthy = expiry
            .map(|e| should_be_healthy(e, &self.1).is_some())
            .unwrap_or(true);
        match self
            .0
            .replace(SingleProviderHealthTrackerInner { healthy, expiry })
        {
            None => health.first_report(healthy),
            Some(previous) => {
                if healthy && !previous.healthy {
                    info!("TLS identity is no longer in danger of expiry");
                }
                health.update(previous.healthy, healthy);
            }
        }
    }

    fn mksleep(&mut self, health: &HealthManager) -> Option<tokio::time::Sleep> {
        let Some(inner) = &mut self.0 else {
            return None; // will not change until initial config received
        };
        match inner {
            SingleProviderHealthTrackerInner {
                healthy: false,
                expiry: _,
            } => None, // already unhealthy
            SingleProviderHealthTrackerInner {
                healthy: _,
                expiry: None,
            } => None, // cannot become unhealthy
            SingleProviderHealthTrackerInner {
                healthy: true,
                expiry: Some(e),
            } => match should_be_healthy(*e, &self.1) {
                None => {
                    health.update(true, false);
                    inner.healthy = false;
                    None
                }
                Some(ttl) => ttl.try_into().ok().map(tokio::time::sleep),
            },
        }
    }

    fn stream<S>(
        mut self,
        inner: S,
        health: &HealthManager,
    ) -> SingleProviderHealthTrackerStream<'_, S, C> {
        SingleProviderHealthTrackerStream {
            sleeper: self.mksleep(health),
            inner,
            tracker: self,
            health,
        }
    }
}

impl<S, I, C> Stream for SingleProviderHealthTrackerStream<'_, S, C>
where
    S: Stream<Item = I>,
    I: AsRef<dyn TlsConfigInstance>,
    C: Clock,
{
    type Item = I;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<I>> {
        let mut this = self.project();
        loop {
            if let Some(sleeper) = this.sleeper.as_mut().as_pin_mut() {
                if sleeper.poll(cx).is_ready() {
                    this.sleeper.set(this.tracker.mksleep(this.health));
                    continue;
                }
            }
            let r = this.inner.poll_next(cx);
            if let Poll::Ready(Some(x)) = &r {
                this.tracker.configure(this.health, x.as_ref());
                this.sleeper.set(this.tracker.mksleep(this.health));
            }
            break r;
        }
    }
}

#[derive(Debug)]
struct TlsConfigInnerHeader {
    crypto_provider: Arc<CryptoProvider>,
    health: OnceLock<HealthManager>,
}

impl TlsConfigInnerHeader {
    fn init_health(&self, reporter: &'_ mut Option<Arc<HealthReporter>>) -> &HealthManager {
        match reporter.take() {
            Some(h) => self.health.get_or_init(move || HealthManager::new(&h)),
            None => self.health.get().unwrap(),
        }
    }

    fn get_health(&self) -> &HealthManager {
        self.health.get().unwrap()
    }
}

type TlsConfigInner =
    SliceWithHeader<TlsConfigInnerHeader, ArcSwapOption<Box<dyn TlsConfigInstance>>>;

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
/// whenever they change to allow for hitless occasional renewals.
pub struct TlsConfig {
    inner: Arc<TlsConfigInner>,
    client_config_builder: rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>,
    server_config_builder: rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>,
    session_storage: Arc<dyn rustls::server::StoresServerSessions>,
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct TlsConfigDependencies {
    #[may_fail]
    providers: Vec<Arc<dyn TlsConfigProvider>>,
    health: Arc<HealthReporter>,
    crypto_provider: Arc<crate::crypto_provider::RustlsCryptoProvider>,
    #[cfg(feature = "files")]
    _default_built_in_provider: PhantomData<crate::files::TlsConfigFiles>,
    #[cfg(feature = "diag")]
    _diag: PhantomData<crate::diag::TlsConfigDiag>,
    #[cfg(test)]
    clock: Arc<clock::Clock>,
}

#[cfg(feature = "metrics")]
mod metrics {
    use lazy_static::lazy_static;
    use num::NumCast;
    use prometheus::register_gauge;

    lazy_static! {
        static ref TLS_CERTIFICATE_EXPIRATION: prometheus::Gauge = register_gauge!(
            "tls_certificate_valid_until",
            "Earliest expiration time of a configured TLS certificate",
        )
        .unwrap();
    }

    pub(super) fn update(inner: &super::TlsConfigInner) {
        TLS_CERTIFICATE_EXPIRATION.set(
            inner
                .slice
                .iter()
                .filter_map(|c| c.load().as_ref().and_then(|i| i.identity_valid_until()))
                .min()
                .and_then(|exp| <f64 as NumCast>::from(exp.unix_timestamp()))
                .unwrap_or_default(),
        )
    }
}

fn setup(
    d: TlsConfigDependencies,
    api: &mut AssemblyRuntime<'_>,
    crypto_provider: &Arc<CryptoProvider>,
) -> Result<Arc<TlsConfigInner>, ComprehensiveTlsError> {
    let inner: Arc<TlsConfigInner> = SliceWithHeader::new(
        TlsConfigInnerHeader {
            crypto_provider: Arc::clone(crypto_provider),
            health: OnceLock::new(),
        },
        std::iter::repeat_n((), d.providers.len()).map(|_| ArcSwapOption::empty()),
    );
    let mut health = Some(d.health);
    let mut p = d
        .providers
        .into_iter()
        .enumerate()
        .filter_map(|(i, provider)| {
            #[cfg(not(test))]
            let clock = clock::Clock;
            #[cfg(test)]
            let clock = Arc::clone(&d.clock);
            let mut tracker = SingleProviderHealthTracker::new(clock);
            // If the provider has already supplied as initial value, get it now.
            // That is more efficient and potentially less confusing than starting
            // out with empty config and filling it in later. Providers that have
            // the ability to make their config available early enough for this
            // should do so.
            let first_delivery = provider
                .stream()
                .poll_next_unpin(&mut Context::from_waker(std::task::Waker::noop()));
            match first_delivery {
                Poll::Ready(Some(snapshot)) => {
                    tracker.configure(inner.header.init_health(&mut health), &*snapshot);
                    inner.slice[i].store(Some(Arc::new(snapshot)));
                }
                Poll::Ready(None) => {
                    error!("TlsConfig: provider delivered a 0-length stream");
                    return None;
                }
                Poll::Pending => {
                    inner.header.init_health(&mut health);
                }
            }
            #[cfg(feature = "metrics")]
            metrics::update(&inner);
            let inner_for_updating = Arc::clone(&inner);
            Some(async move {
                let mut update_stream =
                    pin!(tracker.stream(provider.stream(), inner_for_updating.header.get_health()));
                while let Some(update) = update_stream.next().await {
                    inner_for_updating.slice[i].store(Some(Arc::new(update)));
                    #[cfg(feature = "metrics")]
                    metrics::update(&inner_for_updating);
                }
            })
        })
        .peekable();
    if p.peek().is_none() {
        return Err(ComprehensiveTlsError::NoTlsProvider);
    };
    api.set_task(futures::future::join_all(p).map(|_| Ok(())));
    Ok(inner)
}

#[resource]
impl Resource for TlsConfig {
    const NAME: &str = "TLS certificate store";

    fn new(
        d: TlsConfigDependencies,
        _: comprehensive::NoArgs,
        api: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, ComprehensiveTlsError> {
        let crypto_provider = d.crypto_provider.crypto_provider();
        let inner = setup(d, api, &crypto_provider)?;

        let client_config_builder =
            ClientConfig::builder_with_provider(Arc::clone(&crypto_provider))
                .with_safe_default_protocol_versions()?;
        let server_config_builder = ServerConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()?;
        Ok(Arc::new(Self {
            inner,
            client_config_builder,
            server_config_builder,
            session_storage: ServerSessionMemoryCache::new(256),
        }))
    }
}

#[derive(Debug, Default)]
struct RootHintsSubjetsHolder {
    arena: boxcar::Vec<Arc<[DistinguishedName]>>,
    latest: AtomicUsize,
}

impl RootHintsSubjetsHolder {
    fn intern(&self, original: Arc<[DistinguishedName]>) -> &[DistinguishedName] {
        let max_i = self.latest.load(Ordering::Acquire);
        // See if we can reuse any of the 5 most recently interned values.
        // Earlier entries are forgotten.
        for i in (max_i.saturating_sub(5)..max_i).rev() {
            if let Some(entry) = self.arena.get(i) {
                if entry.as_ptr() == original.as_ptr() {
                    return entry.as_ref();
                }
            }
        }
        // Otherwise intern.
        let i = self.arena.push(original);
        self.latest.fetch_max(i + 1, Ordering::Release);
        self.arena[i].as_ref()
    }
}

fn root_hint_subjects_common<'a>(
    inner: &TlsConfigInner,
    holder: &'a RootHintsSubjetsHolder,
    local: Option<&Uri>,
    remote: Option<&Uri>,
) -> Option<&'a [DistinguishedName]> {
    inner
        .slice
        .iter()
        .filter_map(|c| {
            c.load()
                .as_ref()
                .and_then(|c| c.choose_root_hint_subjects(local, remote))
        })
        .next()
        .map(|l| holder.intern(l))
}

fn resolve_common(inner: &TlsConfigInner, hints: &IdentityHints) -> Option<Arc<CertifiedKey>> {
    [false, true]
        .into_iter()
        .flat_map(|try_harder| {
            inner.slice.iter().filter_map(move |c| {
                c.load()
                    .as_ref()
                    .and_then(|c| c.select_identity(try_harder, hints))
            })
        })
        .next()
}

#[derive(Debug)]
struct ClientConfigBackend {
    inner: Arc<TlsConfigInner>,
    server_identity: Uri,
    client_identity_hint: Option<Uri>,
    supported_algs: WebPkiSupportedAlgorithms,
    chosen_root_hint_subjects: RootHintsSubjetsHolder,
}

impl ResolvesClientCert for ClientConfigBackend {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let dns = root_hint_subjects
            .iter()
            .map(|raw| raw.to_vec().into())
            .collect::<Vec<_>>();
        let hints = IdentityHints {
            sni: None,
            root_hint_subjects: Some(&dns),
            requested: self.client_identity_hint.as_ref(),
        };
        resolve_common(&self.inner, &hints)
    }

    fn has_certs(&self) -> bool {
        self.inner.slice.iter().any(|c| {
            c.load()
                .as_ref()
                .map(|c| c.has_any_identity())
                .unwrap_or(false)
        })
    }
}

fn uri_to_server_name(uri: &Uri) -> Result<rustls_pki_types::ServerName<'_>, rustls::Error> {
    if uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
        uri.host()
    } else {
        None
    }
    .and_then(|host| rustls_pki_types::ServerName::try_from(host).ok())
    .ok_or(rustls::Error::UnsupportedNameType)
}

fn not_valid_for_name_error(presented: &X509Certificate<'_>, expected: &Uri) -> rustls::Error {
    uri_to_server_name(expected)
        .map(|sn| {
            rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext {
                expected: sn.to_owned(),
                presented: presented
                    .subject_alternative_name()
                    .ok()
                    .flatten()
                    .map(|ext| {
                        ext.value
                            .general_names
                            .iter()
                            .map(|gn| format!("{:?}", gn))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            })
        })
        .unwrap_or(rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName,
        ))
}

impl ServerCertVerifier for ClientConfigBackend {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed_cert = ParsedCertificate::try_from(end_entity)?;
        let (_, p_end_entity) = X509Certificate::from_der(end_entity.as_ref()).or(Err(
            rustls::Error::InvalidCertificate(CertificateError::BadEncoding),
        ))?;
        let p_intermediates = intermediates
            .iter()
            .map(|der| X509Certificate::from_der(der.as_ref()).map(|(_, c)| c))
            .collect::<Result<Vec<_>, _>>()
            .or(Err(rustls::Error::InvalidCertificate(
                CertificateError::BadEncoding,
            )))?;
        let r_end_entity = &p_end_entity;
        let r_intermediates = &p_intermediates;
        let r_parsed_cert = &parsed_cert;
        [false, true]
            .into_iter()
            .flat_map(|try_harder| {
                self.inner.slice.iter().filter_map(move |c| {
                    c.load().as_ref().and_then(|c| {
                        c.trust_anchors_for_cert(try_harder, r_end_entity, r_intermediates)
                            .and_then(|roots| {
                                let store = RootCertStore {
                                    roots: roots.to_vec(),
                                };
                                match verify_server_cert_signed_by_trust_anchor(
                                    r_parsed_cert,
                                    &store,
                                    intermediates,
                                    now,
                                    self.supported_algs.all,
                                ) {
                                    // A different provider with different issuers might accept it.
                                    // None means skip this provider.
                                    Err(rustls::Error::InvalidCertificate(
                                        CertificateError::UnknownIssuer,
                                    )) => None,
                                    Err(any_other_error) => Some(Err(any_other_error)),
                                    Ok(()) => Some(Ok(c.verify_expected_identity(
                                        r_end_entity,
                                        &self.server_identity,
                                    ))),
                                }
                            })
                    })
                })
            })
            .map(|verdict| match verdict {
                Err(e) => Err(e),
                Ok(VerifyExpectedIdentityResult::Yes) => Ok(ServerCertVerified::assertion()),
                Ok(VerifyExpectedIdentityResult::No) => Err(not_valid_for_name_error(
                    r_end_entity,
                    &self.server_identity,
                )),
                Ok(VerifyExpectedIdentityResult::UseWebpki) => {
                    uri_to_server_name(&self.server_identity).and_then(|sn| {
                        verify_server_name(&parsed_cert, &sn)
                            .and(Ok(ServerCertVerified::assertion()))
                    })
                }
            })
            .next()
            .unwrap_or(Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner
            .header
            .crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        root_hint_subjects_common(
            &self.inner,
            &self.chosen_root_hint_subjects,
            self.client_identity_hint.as_ref(),
            Some(&self.server_identity),
        )
    }
}

#[derive(Debug)]
struct ServerConfigBackend {
    inner: Arc<TlsConfigInner>,
    supported_algs: WebPkiSupportedAlgorithms,
    chosen_root_hint_subjects: RootHintsSubjetsHolder,
}

impl ResolvesServerCert for ServerConfigBackend {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name();
        let root_hint_subjects = client_hello.certificate_authorities();
        let hints = IdentityHints {
            sni,
            root_hint_subjects,
            requested: None,
        };
        resolve_common(&self.inner, &hints)
    }
}

impl ClientCertVerifier for ServerConfigBackend {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        root_hint_subjects_common(&self.inner, &self.chosen_root_hint_subjects, None, None)
            .unwrap_or_default()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let (_, p_end_entity) = X509Certificate::from_der(end_entity.as_ref()).or(Err(
            rustls::Error::InvalidCertificate(CertificateError::BadEncoding),
        ))?;
        let p_intermediates = intermediates
            .iter()
            .map(|der| X509Certificate::from_der(der.as_ref()).map(|(_, c)| c))
            .collect::<Result<Vec<_>, _>>()
            .or(Err(rustls::Error::InvalidCertificate(
                CertificateError::BadEncoding,
            )))?;
        let r_end_entity = &p_end_entity;
        let r_intermediates = &p_intermediates;
        [false, true]
            .into_iter()
            .flat_map(|try_harder| {
                self.inner.slice.iter().filter_map(move |c| {
                    c.load().as_ref().and_then(|c| {
                        c.trust_anchors_for_cert(try_harder, r_end_entity, r_intermediates)
                            .and_then(|roots| {
                                WebPkiClientVerifier::builder_with_provider(
                                    Arc::new(RootCertStore {
                                        roots: roots.to_vec(),
                                    }),
                                    Arc::clone(&self.inner.header.crypto_provider),
                                )
                                .build()
                                .ok()
                            })
                            .and_then(|verifier| {
                                match verifier.verify_client_cert(end_entity, intermediates, now) {
                                    // A different provider with different issuers might accept it.
                                    // None means skip this provider.
                                    Err(rustls::Error::InvalidCertificate(
                                        CertificateError::UnknownIssuer,
                                    )) => None,
                                    Err(any_other_error) => Some(Err(any_other_error)),
                                    Ok(_) => Some(Ok(ClientCertVerified::assertion())),
                                }
                            })
                    })
                })
            })
            .next()
            .unwrap_or(Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner
            .header
            .crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Trait for either [`ClientAuthEnabled`] or [`ClientAuthDisabled`].
pub trait ClientAuthMode {
    #[doc(hidden)]
    #[allow(private_interfaces)]
    fn configure_client_auth(
        backend: &Arc<ServerConfigBackend>,
        scb: ConfigBuilder<ServerConfig, rustls::WantsVerifier>,
    ) -> ConfigBuilder<ServerConfig, rustls::server::WantsServerCert>;
}

/// Type argument for [`TlsConfig::server_config`] to request mutual TLS auth.
pub enum ClientAuthEnabled {}

impl ClientAuthMode for ClientAuthEnabled {
    #[allow(private_interfaces)]
    fn configure_client_auth(
        backend: &Arc<ServerConfigBackend>,
        scb: ConfigBuilder<ServerConfig, rustls::WantsVerifier>,
    ) -> ConfigBuilder<ServerConfig, rustls::server::WantsServerCert> {
        let verifier = Arc::clone(backend);
        scb.with_client_cert_verifier(verifier)
    }
}

/// Type argument for [`TlsConfig::server_config`] to request no client auth.
pub enum ClientAuthDisabled {}

impl ClientAuthMode for ClientAuthDisabled {
    #[allow(private_interfaces)]
    fn configure_client_auth(
        _: &Arc<ServerConfigBackend>,
        scb: ConfigBuilder<ServerConfig, rustls::WantsVerifier>,
    ) -> ConfigBuilder<ServerConfig, rustls::server::WantsServerCert> {
        scb.with_no_client_auth()
    }
}

impl TlsConfig {
    fn client_config_backend(
        &self,
        server_identity: Uri,
        client_identity_hint: Option<Uri>,
    ) -> ClientConfigBackend {
        ClientConfigBackend {
            inner: Arc::clone(&self.inner),
            server_identity,
            client_identity_hint,
            supported_algs: self
                .inner
                .header
                .crypto_provider
                .signature_verification_algorithms,
            chosen_root_hint_subjects: RootHintsSubjetsHolder::default(),
        }
    }

    /// Returns a TLS [`ClientConfig`] built from the runtime configuration.
    ///
    /// *expected_server_identity*: The server's identity must match this
    /// during TLS verification.
    ///
    /// *client_identity_hint*: Useful in case more than one local identity
    /// is available, this provides a hint on which one to use. If the hint
    /// fails to match any available identity or no hint is given, an
    /// arbitrary client identity will be chosen.
    pub fn client_config(
        &self,
        expected_server_identity: &Uri,
        client_identity_hint: Option<&Uri>,
    ) -> Result<ClientConfig, ComprehensiveTlsError> {
        let backend = Arc::new(self.client_config_backend(
            expected_server_identity.clone(),
            client_identity_hint.cloned(),
        ));
        let backend2 = Arc::clone(&backend);
        Ok(self
            .client_config_builder
            .clone()
            .dangerous()
            .with_custom_certificate_verifier(backend)
            .with_client_cert_resolver(backend2))
    }

    fn server_config_backend(&self) -> ServerConfigBackend {
        ServerConfigBackend {
            inner: Arc::clone(&self.inner),
            supported_algs: self
                .inner
                .header
                .crypto_provider
                .signature_verification_algorithms,
            chosen_root_hint_subjects: RootHintsSubjetsHolder::default(),
        }
    }

    /// Returns a TLS [`ServerConfig`] built from the runtime configuration
    /// and is suitable for mTLS (mutual TLS).
    ///
    /// Due to a [limitation](https://github.com/rustls/rustls/issues/2497)
    /// of the [`ClientCertVerifier`] trait, the output of this method is
    /// built from a snapshot of the [`TlsConfig`] and becomes stale after
    /// the underlying config is reloaded. Therefore a fresh [`ServerConfig`]
    /// should be regenerated before each handshake, or at least at intervals.
    pub fn server_config<CA: ClientAuthMode>(&self) -> ServerConfig {
        let backend = Arc::new(self.server_config_backend());
        let mut sc = CA::configure_client_auth(&backend, self.server_config_builder.clone())
            .with_cert_resolver(backend);
        sc.session_storage = Arc::clone(&self.session_storage);
        sc
    }

    #[cfg(feature = "diag")]
    pub(crate) fn count_for_diag(&self) -> usize {
        self.inner.slice.len()
    }

    #[cfg(feature = "diag")]
    pub(crate) fn iter_for_diag(&self) -> impl Iterator<Item = String> {
        self.inner.slice.iter().map(|c| match c.load().as_ref() {
            None => "<li><i>Empty</i></li>\n".into(),
            Some(i) => i
                .diag()
                .unwrap_or_else(|| "<li><i>Diagnostic output not supported</i></li>\n".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use comprehensive::{Assembly, ResourceDependencies};
    use futures::future::Either;
    use futures::{FutureExt, SinkExt, poll};
    use rustls_pki_types::{ServerName, TrustAnchor};
    use std::io::Cursor;
    use std::pin::pin;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio_rustls::{Accept, Connect, TlsAcceptor, TlsConnector};

    use crate::api::LatestValueStream;
    use crate::crypto_provider::RustlsCryptoProvider;
    use crate::testdata;

    const EMPTY: &[std::ffi::OsString] = &[];

    #[derive(Debug, Eq, PartialEq)]
    enum Action {
        HasAnyIdentity,
        SelectIdentity(bool, Option<String>, Option<Uri>, Option<Vec<Vec<u8>>>),
        RootHintSubjects,
        TrustAnchorsForCert(bool),
        VerifyExpectedIdentity,
    }

    #[derive(Debug)]
    struct GlobalActionLog(Mutex<Vec<Action>>);

    #[resource]
    impl Resource for GlobalActionLog {
        fn new(
            _: comprehensive::NoDependencies,
            _: comprehensive::NoArgs,
            _: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            Ok(Arc::new(Self(Mutex::new(Vec::new()))))
        }
    }

    #[derive(Clone, Debug)]
    struct TestInstance {
        certified_key: Option<Arc<CertifiedKey>>,
        cacert: Option<Arc<[TrustAnchor<'static>]>>,
        log: Arc<GlobalActionLog>,
        only_try_harder: bool,
        verification_result: VerifyExpectedIdentityResult,
    }

    impl TlsConfigInstance for TestInstance {
        fn has_any_identity(&self) -> bool {
            self.log.0.lock().unwrap().push(Action::HasAnyIdentity);
            self.certified_key.is_some()
        }

        fn select_identity(
            &self,
            try_harder: bool,
            hints: &IdentityHints<'_>,
        ) -> Option<Arc<CertifiedKey>> {
            self.log.0.lock().unwrap().push(Action::SelectIdentity(
                try_harder,
                hints.sni.map(ToOwned::to_owned),
                hints.requested.cloned(),
                hints
                    .root_hint_subjects
                    .map(|dns| dns.into_iter().map(|dn| dn.as_ref().to_vec()).collect()),
            ));
            if self.only_try_harder && !try_harder {
                None
            } else {
                self.certified_key.as_ref().cloned()
            }
        }

        fn choose_root_hint_subjects(
            &self,
            _local_identity: Option<&Uri>,
            _remote_identity: Option<&Uri>,
        ) -> Option<Arc<[DistinguishedName]>> {
            self.log.0.lock().unwrap().push(Action::RootHintSubjects);
            self.cacert.as_ref().map(|cacert| {
                RootCertStore {
                    roots: cacert.to_vec(),
                }
                .subjects()
                .into()
            })
        }

        fn trust_anchors_for_cert(
            &self,
            try_harder: bool,
            _end_entity: &X509Certificate<'_>,
            _intermediates: &[X509Certificate<'_>],
        ) -> Option<Arc<[TrustAnchor<'static>]>> {
            self.log
                .0
                .lock()
                .unwrap()
                .push(Action::TrustAnchorsForCert(try_harder));
            if self.only_try_harder && !try_harder {
                None
            } else {
                self.cacert.as_ref().cloned()
            }
        }

        fn verify_expected_identity(
            &self,
            _end_entity: &X509Certificate<'_>,
            _expected_identity: &Uri,
        ) -> VerifyExpectedIdentityResult {
            self.log
                .0
                .lock()
                .unwrap()
                .push(Action::VerifyExpectedIdentity);
            self.verification_result
        }
    }

    impl TestInstance {
        fn empty(log: Arc<GlobalActionLog>) -> Self {
            Self {
                certified_key: None,
                cacert: None,
                only_try_harder: false,
                verification_result: VerifyExpectedIdentityResult::UseWebpki,
                log,
            }
        }

        fn user1(crypto_provider: &CryptoProvider, log: Arc<GlobalActionLog>) -> Self {
            Self::new(
                &testdata::USER1_KEY,
                &testdata::USER1_CERT,
                &testdata::CACERT,
                crypto_provider,
                log,
            )
        }

        fn new(
            key: &[u8],
            cert: &[u8],
            cacert: &[u8],
            crypto_provider: &CryptoProvider,
            log: Arc<GlobalActionLog>,
        ) -> Self {
            let key = rustls_pemfile::private_key(&mut Cursor::new(key))
                .unwrap()
                .unwrap();
            let cert = rustls_pemfile::certs(&mut Cursor::new(cert))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let private_key = crypto_provider.key_provider.load_private_key(key).unwrap();
            let certified_key = Some(Arc::new(CertifiedKey::new(cert, private_key)));
            let cacert = rustls_pemfile::certs(&mut Cursor::new(cacert))
                .map(|der| {
                    webpki::anchor_from_trusted_cert(&der.unwrap())
                        .unwrap()
                        .to_owned()
                })
                .collect::<Arc<[_]>>();
            Self {
                certified_key,
                cacert: Some(cacert),
                only_try_harder: false,
                verification_result: VerifyExpectedIdentityResult::UseWebpki,
                log,
            }
        }

        fn verify_only(cacert: &[u8], log: Arc<GlobalActionLog>) -> Self {
            let cacert = rustls_pemfile::certs(&mut Cursor::new(cacert))
                .map(|der| {
                    webpki::anchor_from_trusted_cert(&der.unwrap())
                        .unwrap()
                        .to_owned()
                })
                .collect::<Arc<[_]>>();
            Self {
                certified_key: None,
                cacert: Some(cacert),
                only_try_harder: false,
                verification_result: VerifyExpectedIdentityResult::UseWebpki,
                log,
            }
        }
    }

    struct TestTlsConfig(LatestValueStream);

    #[derive(clap::Args)]
    #[group(skip)]
    struct TestTlsConfigArgs {
        #[arg(long)]
        delayed: bool,
    }

    #[derive(ResourceDependencies)]
    struct TestTlsConfigDependencies(Arc<RustlsCryptoProvider>, Arc<GlobalActionLog>);

    #[resource]
    #[export(dyn TlsConfigProvider)]
    impl Resource for TestTlsConfig {
        fn new(
            d: TestTlsConfigDependencies,
            a: TestTlsConfigArgs,
            _: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            let exchange = LatestValueStream::default();
            if !a.delayed {
                let _ = exchange
                    .writer()
                    .send(Box::new(TestInstance::user1(&d.0.crypto_provider(), d.1)))
                    .poll_unpin(&mut Context::from_waker(std::task::Waker::noop()));
            }
            Ok(Arc::new(Self(exchange)))
        }
    }

    impl TlsConfigProvider for TestTlsConfig {
        fn stream(&self) -> crate::api::Reader<'_> {
            self.0.reader()
        }
    }

    #[derive(ResourceDependencies)]
    struct TopDependencies {
        dispatcher: Arc<TlsConfig>,
        provider: Arc<TestTlsConfig>,
        health: Arc<HealthReporter>,
        crypto_provider: Arc<RustlsCryptoProvider>,
        log: Arc<GlobalActionLog>,
    }

    #[test]
    fn first_load() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        assert!(a.top.health.is_healthy());
        let got = a
            .top
            .dispatcher
            .client_config_backend(Uri::default(), None)
            .resolve(&[], &[])
            .expect("identity");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER1_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER1_CERT");
        assert_eq!(got.cert, want);
    }

    #[tokio::test(start_paused = true)]
    async fn reload_success() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let provider = Arc::clone(&a.top.provider);
        let mut writer = provider.0.writer();
        let resolver = a.top.dispatcher.client_config_backend(Uri::default(), None);
        let crypto_provider = a.top.crypto_provider.crypto_provider();
        let log = Arc::clone(&a.top.log);

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        let _ = futures::future::select(
            &mut r,
            writer.send(Box::new(TestInstance::new(
                &testdata::USER2_KEY,
                &testdata::USER2_CERT,
                &testdata::CACERT,
                &crypto_provider,
                log,
            ))),
        )
        .await;
        assert!(poll!(&mut r).is_pending());

        let got = resolver.resolve(&[], &[]).expect("identity");
        let want = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER2_CERT))
            .collect::<Result<Vec<_>, _>>()
            .expect("testdata::USER2_CERT");
        assert_eq!(got.cert, want);
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_load() {
        let argv: Vec<std::ffi::OsString> = vec!["cmd".into(), "--delayed".into()];
        let a = Assembly::<TopDependencies>::new_from_argv(argv).unwrap();
        let health = Arc::clone(&a.top.health);
        assert!(!health.is_healthy());
        let provider = Arc::clone(&a.top.provider);
        let mut writer = provider.0.writer();
        let resolver = a.top.dispatcher.client_config_backend(Uri::default(), None);
        let crypto_provider = a.top.crypto_provider.crypto_provider();
        let log = Arc::clone(&a.top.log);

        assert!(resolver.resolve(&[], &[]).is_none());

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        let _ = futures::future::select(
            &mut r,
            writer.send(Box::new(TestInstance::user1(&crypto_provider, log))),
        )
        .await;
        assert!(poll!(&mut r).is_pending());

        assert!(health.is_healthy());
        assert!(resolver.resolve(&[], &[]).is_some());
    }

    fn pair_with_client_config(
        cc: Arc<ClientConfig>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> (Connect<DuplexStream>, Accept<DuplexStream>) {
        let sc = ServerConfig::builder_with_provider(crypto_provider)
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
        let client = TlsConnector::from(cc).connect(ServerName::try_from("_").unwrap(), client);
        let server = TlsAcceptor::from(Arc::new(sc)).accept(server);
        (client, server)
    }

    fn pair_with_server_config(
        sc: Arc<ServerConfig>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> (Connect<DuplexStream>, Accept<DuplexStream>) {
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(
            rustls_pemfile::certs(&mut Cursor::new(&testdata::CACERT))
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
        );
        let cc = ClientConfig::builder_with_provider(crypto_provider)
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
        let cc = a
            .top
            .dispatcher
            .client_config(&Uri::from_static("https://user2/"), None)
            .unwrap();
        let (client, server) =
            pair_with_client_config(cc.into(), a.top.crypto_provider.crypto_provider());
        talk(client, server).await;
    }

    #[tokio::test]
    async fn client_refuses_server_cert() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let cc = a
            .top
            .dispatcher
            .client_config(&Uri::from_static("https://user2/"), None)
            .unwrap();
        let provider = Arc::clone(&a.top.provider);
        let mut writer = provider.0.writer();
        let crypto_provider = a.top.crypto_provider.crypto_provider();
        let log = Arc::clone(&a.top.log);

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        let _ = futures::future::select(
            &mut r,
            writer.send(Box::new(TestInstance::new(
                &testdata::USER1_KEY,
                &testdata::USER1_CERT,
                &testdata::USER1_CERT, // Not the correct trust root
                &crypto_provider,
                log,
            ))),
        )
        .await;
        assert!(poll!(&mut r).is_pending());

        let (client, server) = pair_with_client_config(cc.into(), crypto_provider);
        let client_task = pin!(async move {
            let err = client.await.expect_err("should refuse");
            assert!(err.to_string().contains("certificate"));
        });
        match futures::future::select(client_task, server).await {
            Either::Left((_, _)) => (),
            Either::Right((_, client_task)) => client_task.await,
        }
    }

    #[tokio::test]
    async fn server_verifies_client_cert() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let (client, server) = pair_with_server_config(
            Arc::new(a.top.dispatcher.server_config::<ClientAuthEnabled>()),
            a.top.crypto_provider.crypto_provider(),
        );
        talk(client, server).await;
    }

    #[tokio::test]
    async fn server_refuses_client_cert() {
        let a = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let tlsc = Arc::clone(&a.top.dispatcher);
        let provider = Arc::clone(&a.top.provider);
        let mut writer = provider.0.writer();
        let crypto_provider = a.top.crypto_provider.crypto_provider();
        let log = Arc::clone(&a.top.log);

        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        let _ = futures::future::select(
            &mut r,
            writer.send(Box::new(TestInstance::new(
                &testdata::USER1_KEY,
                &testdata::USER1_CERT,
                &testdata::USER1_CERT, // Not the correct trust root
                &crypto_provider,
                log,
            ))),
        )
        .await;
        assert!(poll!(&mut r).is_pending());

        let (client, server) = pair_with_server_config(
            Arc::new(tlsc.server_config::<ClientAuthEnabled>()),
            crypto_provider,
        );
        let server_task = pin!(async move {
            let err = server.await.expect_err("should refuse");
            assert!(err.to_string().contains("certificate"));
        });
        match futures::future::select(client, server_task).await {
            Either::Left((_, server_task)) => server_task.await,
            Either::Right((_, _)) => (),
        }
    }

    struct MultiTestTlsConfig<const N: usize>(LatestValueStream);

    #[resource]
    #[export(dyn TlsConfigProvider)]
    impl<const N: usize> Resource for MultiTestTlsConfig<N> {
        fn new(
            _: comprehensive::NoDependencies,
            _: comprehensive::NoArgs,
            _: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            Ok(Arc::new(Self(LatestValueStream::default())))
        }
    }

    impl<const N: usize> TlsConfigProvider for MultiTestTlsConfig<N> {
        fn stream(&self) -> crate::api::Reader<'_> {
            self.0.reader()
        }
    }

    #[derive(Clone, ResourceDependencies)]
    struct MultiDependencies {
        dispatcher: Arc<TlsConfig>,
        log: Arc<GlobalActionLog>,
        crypto_provider: Arc<RustlsCryptoProvider>,
        provider0: Arc<MultiTestTlsConfig<0>>,
        provider1: Arc<MultiTestTlsConfig<1>>,
    }

    async fn run_2_instances(a: Assembly<MultiDependencies>, i: TestInstance) {
        let writer0 = Arc::clone(&a.top.provider0);
        let writer1 = Arc::clone(&a.top.provider1);
        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        let mut writer = pin!(async move {
            let _ = writer0.0.writer().send(Box::new(i.clone())).await;
            let _ = writer1.0.writer().send(Box::new(i)).await;
        });
        let _ = futures::future::select(&mut r, &mut writer).await;
        assert!(poll!(&mut r).is_pending());
    }

    #[tokio::test]
    async fn client_resolve_no_identities() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let i = TestInstance::empty(Arc::clone(&a.top.log));
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.client_config_backend(Uri::default(), None);
        assert!(backend.resolve(&[], &[]).is_none());
        assert!(!backend.has_certs());
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                Action::SelectIdentity(false, None, None, Some(Vec::new())),
                Action::SelectIdentity(false, None, None, Some(Vec::new())),
                Action::SelectIdentity(true, None, None, Some(Vec::new())),
                Action::SelectIdentity(true, None, None, Some(Vec::new())),
                Action::HasAnyIdentity,
                Action::HasAnyIdentity,
            ]
        );
    }

    #[tokio::test]
    async fn client_resolve_easy() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let p = a.top.crypto_provider.crypto_provider();
        let i = TestInstance::user1(&p, Arc::clone(&a.top.log));
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.client_config_backend(Uri::default(), None);
        assert!(backend.resolve(&[], &[]).is_some());
        assert!(backend.has_certs());
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                Action::SelectIdentity(false, None, None, Some(Vec::new())),
                Action::HasAnyIdentity,
            ]
        );
    }

    #[tokio::test]
    async fn client_resolve_easy_with_hints() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let p = a.top.crypto_provider.crypto_provider();
        let i = TestInstance::user1(&p, Arc::clone(&a.top.log));
        let root_subject_names = i
            .cacert
            .as_ref()
            .map(|cacert| {
                RootCertStore {
                    roots: cacert.to_vec(),
                }
                .subjects()
                .into_iter()
                .map(|dn| dn.as_ref().to_vec())
                .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let root_subject_name_refs = root_subject_names
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let pickme = Uri::from_static("https://pickme/");
        assert!(
            tlsc.client_config_backend(
                Uri::from_static("https://servername/"),
                Some(pickme.clone())
            )
            .resolve(&root_subject_name_refs, &[])
            .is_some()
        );
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[Action::SelectIdentity(
                false,
                None,
                Some(pickme),
                Some(vec![testdata::CACERT_DN.to_vec()])
            ),]
        );
    }

    #[tokio::test]
    async fn client_resolve_only_try_harder() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let p = a.top.crypto_provider.crypto_provider();
        let mut i = TestInstance::user1(&p, Arc::clone(&a.top.log));
        i.only_try_harder = true;
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        assert!(
            tlsc.client_config_backend(Uri::default(), None)
                .resolve(&[], &[])
                .is_some()
        );
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                Action::SelectIdentity(false, None, None, Some(Vec::new())),
                Action::SelectIdentity(false, None, None, Some(Vec::new())),
                Action::SelectIdentity(true, None, None, Some(Vec::new())),
            ]
        );
    }

    fn verify_user2_server_cert_with_time(
        backend: &ClientConfigBackend,
        d: Duration,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let certs = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER2_CERT))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        backend.verify_server_cert(
            &certs[0],
            &certs[1..],
            &ServerName::try_from("_").unwrap(),
            &[],
            rustls::pki_types::UnixTime::since_unix_epoch(d),
        )
    }

    fn verify_user2_server_cert(
        backend: &ClientConfigBackend,
    ) -> Result<ServerCertVerified, rustls::Error> {
        verify_user2_server_cert_with_time(backend, Duration::from_secs(1727733659))
    }

    #[tokio::test]
    async fn verify_server_cert_no_roots() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let i = TestInstance::empty(Arc::clone(&a.top.log));
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.client_config_backend(Uri::default(), None);
        assert!(matches!(
            verify_user2_server_cert(&backend),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer
            )),
        ));
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                Action::TrustAnchorsForCert(false),
                Action::TrustAnchorsForCert(false),
                Action::TrustAnchorsForCert(true),
                Action::TrustAnchorsForCert(true),
            ]
        );
    }

    #[tokio::test]
    async fn verify_server_cert_easy_yes() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let mut i = TestInstance::verify_only(&testdata::CACERT, Arc::clone(&a.top.log));
        i.verification_result = VerifyExpectedIdentityResult::Yes;
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.client_config_backend(Uri::default(), None);
        assert!(verify_user2_server_cert(&backend).is_ok());
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                Action::TrustAnchorsForCert(false),
                Action::VerifyExpectedIdentity,
            ]
        );
    }

    #[tokio::test]
    async fn verify_server_cert_easy_no() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let mut i = TestInstance::verify_only(&testdata::CACERT, Arc::clone(&a.top.log));
        i.verification_result = VerifyExpectedIdentityResult::No;
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.client_config_backend(Uri::default(), None);
        assert!(matches!(
            verify_user2_server_cert(&backend),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName
            )),
        ));
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                Action::TrustAnchorsForCert(false),
                Action::VerifyExpectedIdentity,
            ]
        );
    }

    #[tokio::test]
    async fn verify_server_cert_easy_webpki_correct_name() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let i = TestInstance::verify_only(&testdata::CACERT, Arc::clone(&a.top.log));
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.client_config_backend(Uri::from_static("https://user2/"), None);
        assert!(verify_user2_server_cert(&backend).is_ok());
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                Action::TrustAnchorsForCert(false),
                Action::VerifyExpectedIdentity,
            ]
        );
    }

    #[tokio::test]
    async fn verify_server_cert_easy_webpki_wrong_name() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let i = TestInstance::verify_only(&testdata::CACERT, Arc::clone(&a.top.log));
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.client_config_backend(Uri::from_static("https://wrong/"), None);
        assert!(matches!(
            verify_user2_server_cert(&backend),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForNameContext {
                    expected: _,
                    presented: _
                }
            )),
        ));
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                Action::TrustAnchorsForCert(false),
                Action::VerifyExpectedIdentity,
            ]
        );
    }

    #[tokio::test]
    async fn verify_server_cert_only_try_harder() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let mut i = TestInstance::verify_only(&testdata::CACERT, Arc::clone(&a.top.log));
        i.only_try_harder = true;
        i.verification_result = VerifyExpectedIdentityResult::Yes;
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.client_config_backend(Uri::default(), None);
        assert!(verify_user2_server_cert(&backend).is_ok());
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                Action::TrustAnchorsForCert(false),
                Action::TrustAnchorsForCert(false),
                Action::TrustAnchorsForCert(true),
                Action::VerifyExpectedIdentity,
            ]
        );
    }

    #[tokio::test]
    async fn verify_server_cert_outside_validity() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let i = TestInstance::verify_only(&testdata::CACERT, Arc::clone(&a.top.log));
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.client_config_backend(Uri::default(), None);
        assert!(matches!(
            verify_user2_server_cert_with_time(&backend, Duration::default()),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidYetContext {
                    time: _,
                    not_before: _
                }
            )),
        ));
        let actions = log.0.lock().unwrap();
        assert_eq!(&*actions, &[Action::TrustAnchorsForCert(false),]);
    }

    fn verify_user2_client_cert_with_time(
        backend: &ServerConfigBackend,
        d: Duration,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let certs = rustls_pemfile::certs(&mut Cursor::new(&testdata::USER2_CERT))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        backend.verify_client_cert(
            &certs[0],
            &certs[1..],
            rustls::pki_types::UnixTime::since_unix_epoch(d),
        )
    }

    fn verify_user2_client_cert(
        backend: &ServerConfigBackend,
    ) -> Result<ClientCertVerified, rustls::Error> {
        verify_user2_client_cert_with_time(backend, Duration::from_secs(1727733659))
    }

    #[tokio::test]
    async fn verify_client_cert_no_roots() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let i = TestInstance::empty(Arc::clone(&a.top.log));
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.server_config_backend();
        assert!(matches!(
            verify_user2_client_cert(&backend),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer
            )),
        ));
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                Action::TrustAnchorsForCert(false),
                Action::TrustAnchorsForCert(false),
                Action::TrustAnchorsForCert(true),
                Action::TrustAnchorsForCert(true),
            ]
        );
    }

    #[tokio::test]
    async fn verify_client_cert_easy() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let i = TestInstance::verify_only(&testdata::CACERT, Arc::clone(&a.top.log));
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.server_config_backend();
        assert!(verify_user2_client_cert(&backend).is_ok());
        let actions = log.0.lock().unwrap();
        assert_eq!(&*actions, &[Action::TrustAnchorsForCert(false),]);
    }

    #[tokio::test]
    async fn verify_client_cert_only_try_harder() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let mut i = TestInstance::verify_only(&testdata::CACERT, Arc::clone(&a.top.log));
        i.only_try_harder = true;
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.server_config_backend();
        assert!(verify_user2_client_cert(&backend).is_ok());
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                Action::TrustAnchorsForCert(false),
                Action::TrustAnchorsForCert(false),
                Action::TrustAnchorsForCert(true),
            ]
        );
    }

    #[tokio::test]
    async fn verify_client_cert_outside_validity() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let i = TestInstance::verify_only(&testdata::CACERT, Arc::clone(&a.top.log));
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let backend = tlsc.server_config_backend();
        assert!(matches!(
            verify_user2_client_cert_with_time(&backend, Duration::default()),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidYetContext {
                    time: _,
                    not_before: _
                }
            )),
        ));
        let actions = log.0.lock().unwrap();
        assert_eq!(&*actions, &[Action::TrustAnchorsForCert(false),]);
    }

    #[tokio::test]
    async fn root_hint_subjects_no_roots() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let i = TestInstance::empty(Arc::clone(&a.top.log));
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let cbackend = tlsc.client_config_backend(Uri::default(), None);
        let sbackend = tlsc.server_config_backend();
        assert!(cbackend.root_hint_subjects().is_none());
        assert!(sbackend.root_hint_subjects().is_empty());
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                // Client
                Action::RootHintSubjects,
                Action::RootHintSubjects,
                // Server
                Action::RootHintSubjects,
                Action::RootHintSubjects,
            ]
        );
    }

    #[tokio::test]
    async fn root_hint_subjects_present() {
        let a = Assembly::<MultiDependencies>::new_from_argv(EMPTY).unwrap();
        let i = TestInstance::verify_only(&testdata::CACERT, Arc::clone(&a.top.log));
        let log = Arc::clone(&a.top.log);
        let tlsc = Arc::clone(&a.top.dispatcher);
        run_2_instances(a, i).await;
        let cbackend = tlsc.client_config_backend(Uri::default(), None);
        let sbackend = tlsc.server_config_backend();
        assert_eq!(
            cbackend
                .root_hint_subjects()
                .unwrap_or_default()
                .iter()
                .next()
                .expect("DistinguishedName")
                .as_ref(),
            testdata::CACERT_DN
        );
        assert_eq!(
            sbackend
                .root_hint_subjects()
                .iter()
                .next()
                .expect("DistinguishedName")
                .as_ref(),
            testdata::CACERT_DN
        );
        let actions = log.0.lock().unwrap();
        assert_eq!(
            &*actions,
            &[
                // Client
                Action::RootHintSubjects,
                // Server
                Action::RootHintSubjects,
            ]
        );
    }

    #[derive(Debug)]
    struct ExpiringInstance(Option<OffsetDateTime>);

    impl ExpiringInstance {
        fn new(secs: i64) -> Box<Self> {
            Box::new(Self(Some(
                OffsetDateTime::from_unix_timestamp(secs).unwrap(),
            )))
        }
    }

    impl TlsConfigInstance for ExpiringInstance {
        fn has_any_identity(&self) -> bool {
            true
        }

        fn select_identity(
            &self,
            _try_harder: bool,
            _hints: &IdentityHints<'_>,
        ) -> Option<Arc<CertifiedKey>> {
            None
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
            _try_harder: bool,
            _end_entity: &X509Certificate<'_>,
            _intermediates: &[X509Certificate<'_>],
        ) -> Option<Arc<[TrustAnchor<'static>]>> {
            None
        }

        fn verify_expected_identity(
            &self,
            _end_entity: &X509Certificate<'_>,
            _expected_identity: &Uri,
        ) -> VerifyExpectedIdentityResult {
            VerifyExpectedIdentityResult::No
        }

        fn identity_valid_until(&self) -> Option<OffsetDateTime> {
            self.0
        }
    }

    #[derive(ResourceDependencies)]
    struct ExpiryTopDependencies {
        _dispatcher: Arc<TlsConfig>,
        provider: Arc<TestTlsConfig>,
        health: Arc<HealthReporter>,
    }

    #[tokio::test(start_paused = true)]
    async fn alive_on_arrival_then_expires_then_renewed() {
        let argv: Vec<std::ffi::OsString> = vec!["cmd".into(), "--delayed".into()];
        let a = Assembly::<ExpiryTopDependencies>::new_from_argv(argv).unwrap();
        let provider = Arc::clone(&a.top.provider);
        let mut writer = provider.0.writer();
        tokio::time::advance(Duration::new(1001, 0)).await;
        let health = Arc::clone(&a.top.health);
        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        assert!(poll!(&mut r).is_pending());
        assert!(!health.is_healthy());

        let _ = futures::future::select(&mut r, writer.send(ExpiringInstance::new(2000))).await;
        assert!(poll!(&mut r).is_pending());
        assert!(health.is_healthy());

        tokio::time::advance(Duration::new(1000, 0)).await;
        assert!(poll!(&mut r).is_pending());
        assert!(!health.is_healthy());

        let _ = futures::future::select(&mut r, writer.send(ExpiringInstance::new(3000))).await;
        assert!(poll!(&mut r).is_pending());
        assert!(health.is_healthy());
    }

    #[tokio::test(start_paused = true)]
    async fn dead_on_arrival() {
        let argv: Vec<std::ffi::OsString> = vec!["cmd".into(), "--delayed".into()];
        let a = Assembly::<ExpiryTopDependencies>::new_from_argv(argv).unwrap();
        let provider = Arc::clone(&a.top.provider);
        let mut writer = provider.0.writer();
        tokio::time::advance(Duration::new(1001, 0)).await;
        let health = Arc::clone(&a.top.health);
        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        assert!(poll!(&mut r).is_pending());
        assert!(!health.is_healthy());

        let _ = futures::future::select(&mut r, writer.send(ExpiringInstance::new(1000))).await;
        assert!(poll!(&mut r).is_pending());
        assert!(!health.is_healthy());
    }
}
