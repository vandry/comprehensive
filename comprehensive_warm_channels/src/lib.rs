//! [`comprehensive`] integration for [`warm_channels`]
//!
//! This crate defines a single Comprehensive [`Resource`]
//! [`WarmChannelsDiag`] which makes diagnostic information about all
//! [`warm_channels`] client channels available over HTTP.
//!
//! This is a separate crate for dependency reasons (to avoid a crate in the
//! `comprehensive` repo depending on `warm_channels` which depends back on
//! another crate in the `comprehensive` repo).

#![warn(missing_docs)]

use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive_traits::http_diag::{Body, HttpDiagHandler, HttpDiagHandlerInstaller};
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::util::BoxCloneSyncService;
use tower_service::Service;
use warm_channels::ChannelDiagService;

pub use warm_channels;

#[doc(hidden)]
#[derive(clap::Args, Debug)]
#[group(skip)]
pub struct WarmChannelsDiagArgs {
    #[arg(long, default_value = "/debug/channels")]
    warm_channels_diag_path: String,
}

/// Diagnostics introspection HTTP handler for [`warm_channels`].
///
/// If this resource and [`comprehensive_http::diag::HttpServer`] are both
/// in a [`comprehensive::Assembly`] then a diagnostics page about active
/// channels is made available, by default at path `/debug/channels`.
///
/// It should not be necessary to depend on this resource directly as gRPC
/// clients created with [`comprehensive_grpc::GrpcClient`] declare a
/// dependency on it.
///
/// # Command line flags
///
/// | Flag                        | Default           | Meaning               |
/// |-----------------------------|-------------------|-----------------------|
/// | `--warm-channels-diag-path` | `/debug/channels` | HTTP path to serve at |
///
/// [`comprehensive_http::diag::HttpServer`]: https://docs.rs/comprehensive_http/latest/comprehensive_http/diag/type.HttpServer.html
/// [`comprehensive_grpc::GrpcClient`]: https://docs.rs/comprehensive_grpc/latest/comprehensive_grpc/derive.GrpcClient.html
pub struct WarmChannelsDiag(WarmChannelsDiagArgs);

#[resource]
#[export(dyn HttpDiagHandler)]
impl Resource for WarmChannelsDiag {
    fn new(
        _: comprehensive::NoDependencies,
        a: WarmChannelsDiagArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        Ok(Arc::new(Self(a)))
    }
}

pin_project! {
    struct MapResponseBodyFuture<F> {
        #[pin] inner: F
    }
}

impl<F, B, E> Future for MapResponseBodyFuture<F>
where
    F: Future<Output = Result<http::Response<B>, E>>,
    B: Into<Body>,
{
    type Output = Result<http::Response<Body>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().inner.poll(cx) {
            Poll::Ready(Ok(r)) => {
                let (parts, body) = r.into_parts();
                Poll::Ready(Ok(http::Response::from_parts(parts, body.into())))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Clone)]
struct MapResponseBody<T>(T);

impl<T, R, B> Service<R> for MapResponseBody<T>
where
    T: Service<R, Response = http::Response<B>>,
    B: Into<Body>,
{
    type Response = http::Response<Body>;
    type Error = <T as Service<R>>::Error;
    type Future = MapResponseBodyFuture<<T as Service<R>>::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::poll_ready(&mut self.0, cx)
    }

    fn call(&mut self, request: R) -> Self::Future {
        MapResponseBodyFuture {
            inner: Service::call(&mut self.0, request),
        }
    }
}

impl HttpDiagHandler for WarmChannelsDiag {
    fn install_handlers(self: Arc<Self>, installer: &mut dyn HttpDiagHandlerInstaller) {
        if !self.0.warm_channels_diag_path.is_empty() {
            installer.nest_service(
                &self.0.warm_channels_diag_path,
                BoxCloneSyncService::new(MapResponseBody(ChannelDiagService::default())),
            );
        }
    }
}
