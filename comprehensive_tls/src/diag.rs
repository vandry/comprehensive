//! Diagnostic handler for [`TlsConfig`]
//!
//! This module defines a single Comprehensive [`Resource`]
//! [`TlsConfigDiag`] which makes diagnostic information about all
//! TLS configuration providers available over HTTP. It is included
//! automatically when the **diag** feature is enabled.

use async_stream::stream;
use comprehensive::ResourceDependencies;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive_traits::http_diag::{HttpDiagHandler, HttpDiagHandlerInstaller};
use futures::Stream;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::util::BoxCloneSyncService;
use tower_service::Service;

use crate::dispatch::TlsConfig;

fn respond(tlsc: Arc<TlsConfig>) -> impl Stream<Item = Result<String, Infallible>> {
    stream! {
        yield Ok(format!(
            r#"
                <html><head>
                    <title>Debug: TLS configuration</title>
                </head>
                <body><h2><a href="https://docs.rs/comprehensive_tls/latest/comprehensive_tls/">TLS configuration</a> available from {} providers</h2>
                <ul>
            "#, tlsc.count_for_diag(),
        ));
        for x in tlsc.iter_for_diag() {
            yield Ok(x);
        }
        yield Ok("</ul></body></html>\n".into());
    }
}

struct DiagServiceFuture(Option<Arc<TlsConfig>>);

impl Future for DiagServiceFuture {
    type Output = Result<http::Response<axum_core::body::Body>, Infallible>;

    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(match self.0.take() {
            None => http::Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body("".into())
                .unwrap(),
            Some(tlsc) => http::Response::builder()
                .header("Content-Type", "text/html")
                .body(axum_core::body::Body::from_stream(respond(tlsc)))
                .unwrap(),
        }))
    }
}

#[derive(Clone)]
struct DiagService(Arc<TlsConfig>);

impl<B> Service<http::Request<B>> for DiagService {
    type Response = http::Response<axum_core::body::Body>;
    type Error = Infallible;
    type Future = DiagServiceFuture;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        DiagServiceFuture(if request.uri().path() == "/" {
            Some(Arc::clone(&self.0))
        } else {
            None
        })
    }
}

#[doc(hidden)]
#[derive(clap::Args, Debug)]
#[group(skip)]
pub struct Args {
    #[arg(long, default_value = "/debug/tls")]
    tls_diag_path: String,
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct Dependencies(Arc<TlsConfig>);

/// Diagnostics introspection HTTP handler for [`TlsConfig`].
///
/// If this resource and [`comprehensive_http::diag::HttpServer`] are both
/// in a [`comprehensive::Assembly`] then a diagnostics page about active
/// channels is made available, by default at path `/debug/tls`.
///
/// It should not be necessary to depend on this resource directly as
/// [`TlsConfig`] declares a dependency on it.
///
/// # Command line flags
///
/// | Flag              | Default      | Meaning               |
/// |-------------------|--------------|-----------------------|
/// | `--tls-diag-path` | `/debug/tls` | HTTP path to serve at |
///
/// [`comprehensive_http::diag::HttpServer`]: https://docs.rs/comprehensive_http/latest/comprehensive_http/diag/type.HttpServer.html
pub struct TlsConfigDiag(Dependencies, Args);

#[resource]
#[export(dyn HttpDiagHandler)]
impl Resource for TlsConfigDiag {
    fn new(d: Dependencies, a: Args, _: &mut AssemblyRuntime<'_>) -> Result<Arc<Self>, Infallible> {
        Ok(Arc::new(Self(d, a)))
    }
}

impl HttpDiagHandler for TlsConfigDiag {
    fn install_handlers(self: Arc<Self>, installer: &mut dyn HttpDiagHandlerInstaller) {
        if !self.1.tls_diag_path.is_empty() {
            installer.nest_service(
                &self.1.tls_diag_path,
                BoxCloneSyncService::new(DiagService(Arc::clone(&self.0.0))),
            );
        }
    }
}
