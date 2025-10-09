//! API for providers of TLS connection parameters.
//!
//! To install a mechanism for supplying TLS serving key and certificates
//! to a [`comprehensive`] [`Assembly`], implement and expose the
//! [`TlsConfigProvider`] trait. Thereafter, new updated TLS serving
//! parameters should be streamed to recipients whenever they are
//! available (such as when keys and certificates are replaced or renewed
//! from under the server).
//!
//! Example provider:
//!
//! ```
//! use comprehensive::v1::{AssemblyRuntime, Resource, resource};
//! use comprehensive_tls::api::{LatestValueStream, TlsConfigInstance, TlsConfigProvider};
//! use futures::{FutureExt, SinkExt};
//! use std::sync::Arc;
//! use std::task::Context;
//!
//! struct ExampleProvider(LatestValueStream);
//!
//! impl TlsConfigProvider for ExampleProvider {
//!     fn stream(&self) -> comprehensive_tls::api::Reader<'_> {
//!         self.0.reader()
//!     }
//! }
//!
//! # #[derive(Debug)]
//! # struct Placeholder;
//! # use http::Uri;
//! # use comprehensive_tls::api::{IdentityHints, VerifyExpectedIdentityResult};
//! # use comprehensive_tls::api::rustls::DistinguishedName;
//! # use comprehensive_tls::api::rustls::pki_types::TrustAnchor;
//! # use comprehensive_tls::api::rustls::sign::CertifiedKey;
//! # use comprehensive_tls::api::x509_parser::certificate::X509Certificate;
//! # impl TlsConfigInstance for Placeholder {
//! #     fn has_any_identity(&self) -> bool { false }
//! #     fn select_identity(
//! #         &self, _: bool, _: &IdentityHints<'_>,
//! #     ) -> Option<Arc<CertifiedKey>> { None }
//! #     fn choose_root_hint_subjects(
//! #         &self, _: Option<&Uri>, _: Option<&Uri>,
//! #     ) -> Option<Arc<[DistinguishedName]>> { None }
//! #     fn trust_anchors_for_cert(
//! #         &self, _: bool, _: &X509Certificate<'_>, _: &[X509Certificate<'_>],
//! #     ) -> Option<Arc<[TrustAnchor<'static>]>> { None }
//! #     fn verify_expected_identity(
//! #         &self,  _: &X509Certificate<'_>, _: &Uri,
//! #     ) -> VerifyExpectedIdentityResult { VerifyExpectedIdentityResult::No }
//! # }
//! fn make_instance() -> Box<dyn TlsConfigInstance> {
//!     // ...
//!     # Box::new(Placeholder)
//! }
//!
//! #[resource]
//! #[export(dyn TlsConfigProvider)]
//! impl Resource for ExampleProvider {
//!     fn new(
//!         _: comprehensive::NoDependencies,
//!         _: comprehensive::NoArgs,
//!         api: &mut AssemblyRuntime<'_>,
//!     ) -> Result<Arc<Self>, std::convert::Infallible> {
//!         let shared = Arc::new(Self(LatestValueStream::default()));
//!
//!         // Optional: deliver initial configuration synchronously.
//!         // If the provider is able to do this, it should do so because
//!         // it allows all other Resources to have TLS parameters
//!         // available immediately on startup.
//!         let snapshot = make_instance();
//!         let _ = shared.0
//!             .writer()
//!             .send(snapshot)
//!             .poll_unpin(&mut Context::from_waker(std::task::Waker::noop()));
//!
//!         let we_support_dynamic_configuration_updates = true;
//!         if we_support_dynamic_configuration_updates {
//!             let shared2 = Arc::clone(&shared);
//!             api.set_task(async move {
//!                 let mut writer = shared2.0.writer();
//!                 loop {
//!                     // Wait for a change
//!                     writer.send(make_instance());
//!                 }
//!             });
//!         }
//!         Ok(shared)
//!     }
//! }
//! ```
//!
//! This trait is consumed by [`crate::dispatch::TlsConfig`] which will
//! coordinate identity and trust bundle selection among the available
//! providers.
//!
//! [`comprehensive`]: https://docs.rs/comprehensive/latest/comprehensive/
//! [`comprehensive_tls::TlsConfig`]: https://docs.rs/comprehensive_tls/latest/comprehensive_tls/struct.TlsConfig.html
//! [`Assembly`]: https://docs.rs/comprehensive/latest/comprehensive/assembly/struct.Assembly.html

use futures::Stream;
use futures::sink::Sink;
use http::Uri;
use rustls::DistinguishedName;
use rustls_pki_types::TrustAnchor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;

pub use rustls;
pub use rustls_pki_types;
pub use x509_parser;

/// Verdict from [`TlsConfigInstance::verify_expected_identity`]
#[derive(Copy, Clone, Debug)]
pub enum VerifyExpectedIdentityResult {
    /// The presented certificate does not match `expected_identity`.
    No,
    /// The presented certificate matches `expected_identity`.
    Yes,
    /// Identity verification via [`rustls::client::verify_server_name`]
    /// is requested. This exists for convenience because that utility
    /// function expects the wrong arguments compared with
    /// [`TlsConfigInstance::verify_expected_identity`] but we cannot
    /// switch to [`rustls::server::ParsedCertificate`] because that
    /// hides information that some verifiers might need.
    UseWebpki,
}

/// Hints that may help a [`TlsConfigInstance::select_identity`] select the
/// right local identity in case more than one is available.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct IdentityHints<'a> {
    /// Server Name Indication. Will exist on the server side only.
    pub sni: Option<&'a str>,
    /// Names of trust anchors acceptable to the peer.
    pub root_hint_subjects: Option<&'a [DistinguishedName]>,
    /// Uri of an identity requested by client configuration.
    pub requested: Option<&'a Uri>,
}

/// A snapshot of config from a [`TlsConfigProvider`].
pub trait TlsConfigInstance: Send + Sync + std::fmt::Debug {
    /// Indicates whether or not this [`TlsConfigInstance`] can provide
    /// any identity credentials. If not then it may still be capable of
    /// verifying remote identities.
    fn has_any_identity(&self) -> bool;

    /// Select identity credentials to use for a new TLS session.
    ///
    /// Each active [`TlsConfigInstance`] will first have this method called
    /// on it with `try_harder` false. During this round, instances should
    /// return credentials if the hints are judged to provide positive
    /// indication of a suitable identity. If no credentials are forthcoming
    /// after that then each instance will be called again with `try_harder`
    /// true. At that point, instances should return any identity they have,
    /// regardless of hints.
    fn select_identity(
        &self,
        try_harder: bool,
        hints: &IdentityHints<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>>;

    /// Optionally supply the names of acceptable trust anchors to the peer.
    ///
    /// On servers, both arguments will be `None`.
    /// On clients, *local_identity* is the same as [`IdentityHints`]'s
    /// *requested* and *remote_identity* is the same as
    /// [`TlsConfigInstance::verify_expected_identity`]'s *expected_identity*.
    fn choose_root_hint_subjects(
        &self,
        local_identity: Option<&Uri>,
        remote_identity: Option<&Uri>,
    ) -> Option<Arc<[DistinguishedName]>>;

    /// Select a set of [`TrustAnchor`] that are allowed and appropriate for
    /// verifying the presented *end_entity* certificate.
    ///
    /// Each active [`TlsConfigInstance`] will first have this method called
    /// on it with `try_harder` false. During this round, instances should
    /// return trust anchors only if they have good reason to expect
    /// (without performing full verification) that the trust anchors will
    /// be a match. If no verification is successful after that then each
    /// instance will be called again with `try_harder` true. At that
    /// point, instances should return any identity they know.
    ///
    /// If any verification fails for any reason other than
    /// [`rustls::CertificateError::UnknownIssuer`] then the entire
    /// verification fails. If no instance returns any trust anchors then
    /// the entire verification fails with
    /// [`rustls::CertificateError::UnknownIssuer`].
    fn trust_anchors_for_cert(
        &self,
        try_harder: bool,
        end_entity: &X509Certificate<'_>,
        intermediates: &[X509Certificate<'_>],
    ) -> Option<Arc<[TrustAnchor<'static>]>>;

    /// Verify the server against the identity the client expected it to
    /// present. Called only by clients and only on the specific
    /// [`TlsConfigInstance`] that returned the winning [`TrustAnchor`] set.
    fn verify_expected_identity(
        &self,
        end_entity: &X509Certificate<'_>,
        expected_identity: &Uri,
    ) -> VerifyExpectedIdentityResult;

    /// Report on when the identity presented by this provider is due to
    /// expire. This is used to emit warnings and eventually to turn the
    /// assembly unhealthy if the current time gets too close to it.
    fn identity_valid_until(&self) -> Option<OffsetDateTime> {
        None
    }

    /// Produce diagnostic output about this configuration in HTML
    /// format. The output will be rendered inside a `<ul>` block
    /// alongside other instances.
    fn diag(&self) -> Option<String> {
        None
    }
}

#[derive(Default)]
struct Inner {
    current: Option<Box<dyn TlsConfigInstance>>,
    waker: Option<Waker>,
}

/// Object which implementors of the [`TlsConfigProvider`] trait need to contain.
///
/// See module-level documentation for how to use.
#[derive(Default)]
pub struct LatestValueStream {
    inner: std::sync::Mutex<Inner>,
}

/// [`Stream`] of [`dyn TlsConfigInstance`] supplied to consumers
/// of [`TlsConfigProvider`].
pub struct Reader<'a>(&'a LatestValueStream);

impl Stream for Reader<'_> {
    type Item = Box<dyn TlsConfigInstance>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Box<dyn TlsConfigInstance>>> {
        let mut inner = self.0.inner.lock().unwrap();
        if let Some(v) = inner.current.take() {
            return Poll::Ready(Some(v));
        }
        let park = inner
            .waker
            .as_ref()
            .map(|w| !w.will_wake(cx.waker()))
            .unwrap_or(true);
        if park {
            let old = inner.waker.replace(cx.waker().clone());
            if let Some(w) = old {
                w.wake();
            }
        }
        Poll::Pending
    }
}

/// [`Sink`] for implementors of [`TlsConfigProvider`] to
/// supply [`dyn TlsConfigInstance`].
///
/// The sink is always ready to accept new values because the stream only
/// remembers the most recent value.
pub struct Writer<'a>(&'a LatestValueStream);

impl Sink<Box<dyn TlsConfigInstance>> for Writer<'_> {
    type Error = std::convert::Infallible;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(())) // always ready because new values squash old
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: Box<dyn TlsConfigInstance>,
    ) -> Result<(), Self::Error> {
        let mut inner = self.0.inner.lock().unwrap();
        inner.current = Some(item);
        if let Some(waker) = inner.waker.take() {
            waker.wake()
        }
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl LatestValueStream {
    /// Get a stream of TLS serving parameters. Intended to be called in the
    /// implementation of [`TlsConfigProvider::stream`].
    pub fn reader(&self) -> Reader<'_> {
        Reader(self)
    }

    /// Get a sink for writing TLS serving parameters. Intended to be called
    /// by implementors of [`TlsConfigProvider`].
    pub fn writer(&self) -> Writer<'_> {
        Writer(self)
    }
}

/// A trait exposed by a resource that provides TLS serving parameters.
pub trait TlsConfigProvider: Send + Sync {
    /// Obtain a stream which will emit new updated TLS serving parameters
    /// whenever they are available.
    fn stream(&self) -> Reader<'_>;
}
