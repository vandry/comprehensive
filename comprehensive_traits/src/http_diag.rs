//! Shared trait definition for exposing diagnostics on a common HTTP server
//!
//! To expose diagnostic information on the shared [`comprehensive`]
//! diagnostics HTTP server, implement and expose the [`HttpDiagHandler`]
//! trait. If [`comprehensive_http::diag::HttpServer`] exists in the same
//! [`Assembly`] then this will be picked up and installed for serving.
//!
//! [`comprehensive`]: https://docs.rs/comprehensive/latest/comprehensive/
//! [`comprehensive_http::diag::HttpServer`]: https://docs.rs/comprehensive_http/latest/comprehensive_http/diag/type.HttpServer.html
//! [`Assembly`]: https://docs.rs/comprehensive/latest/comprehensive/assembly/struct.Assembly.html

pub use axum_core::body::Body;
use std::sync::Arc;

/// The type or [`tower`] [`Service`] that handlers should provide.
///
/// This unfortunately has to be a concrete type in order for
/// [`HttpDiagHandlerInstaller`] to be dyn-compatible, so implementors will
/// need to convert services to this type.
///
/// [`Service`]: https://docs.rs/tower-service/latest/tower_service/trait.Service.html
pub type Service = tower::util::BoxCloneSyncService<
    http::Request<Body>,
    http::Response<Body>,
    std::convert::Infallible,
>;

/// Helper trait which is implemented by the consumer of resources that expose
/// [`HttpDiagHandler`]. Only [`comprehensive_http::diag::HttpServer` needs to
/// implement this.
pub trait HttpDiagHandlerInstaller {
    /// Request to install a handler at `path` in the diagnostics HTTP
    /// server which will invoke `service`.
    fn nest_service(&mut self, path: &str, service: Service);
}

/// Trait for resources to offer handlers that expose diagnostic information
/// over HTTP.
///
/// Usage:
///
/// ```
/// use comprehensive::v1::{Resource, resource};
/// use comprehensive_traits::http_diag::{HttpDiagHandler, HttpDiagHandlerInstaller};
/// use std::sync::Arc;
/// use tower::util::BoxCloneSyncService;
///
/// #[derive(Debug)]
/// struct SomeResourceWithDebugInfo {
///     // [...]
/// }
///
/// #[resource]
/// #[export(dyn HttpDiagHandler)]
/// impl Resource for SomeResourceWithDebugInfo {
///     // [...]
/// #     fn new(
/// #         _: comprehensive::NoDependencies,
/// #         _: comprehensive::NoArgs,
/// #         _: &mut comprehensive::v1::AssemblyRuntime<'_>,
/// #     ) -> Result<std::sync::Arc<Self>, std::convert::Infallible> {
/// #         Ok(std::sync::Arc::new(Self { }))
/// #     }
/// }
///
/// impl HttpDiagHandler for SomeResourceWithDebugInfo {
///     fn install_handlers(self: Arc<Self>, installer: &mut dyn HttpDiagHandlerInstaller) {
///         installer.nest_service("/debug/some_resource", BoxCloneSyncService::new(
///             tower::service_fn(move |r| {
///                 let info = format!("My internals look like {:?}", self);
///                 async move { Ok(http::Response::builder().body(info.into()).unwrap()) }
///             })
///         ));
///     }
/// }
/// ```
pub trait HttpDiagHandler {
    /// Requests the resource to install the diagnostics handlers it wants
    /// to make available by calling `installer.install_handlers`.
    fn install_handlers(self: Arc<Self>, installer: &mut dyn HttpDiagHandlerInstaller);
}
