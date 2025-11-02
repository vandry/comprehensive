//! gRPC server support
//!
//! To use gRPC servers in Comprehensive, define a [`Resource`] that
//! also implements the [`GrpcService`] trait using the [`resource`] macro:
//!
//! ```
//! # mod pb {
//! #     tonic::include_proto!("comprehensive");
//! #     pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("fdset");
//! # }
//! # use std::sync::Arc;
//! use comprehensive::{NoArgs, NoDependencies, ResourceDependencies};
//! use comprehensive::v1::{AssemblyRuntime, Resource, resource};
//! use comprehensive_grpc::GrpcService;
//!
//! struct TestService;  // State goes in here if the server needs any.
//!
//! #[resource]
//! #[export_grpc(pb::test_server::TestServer)]
//! #[proto_descriptor(pb::FILE_DESCRIPTOR_SET)]
//! impl Resource for TestService {
//!     fn new(
//!         _: NoDependencies, _: NoArgs, _: &mut AssemblyRuntime<'_>
//!     ) -> Result<Arc<Self>, std::convert::Infallible> {
//!         Ok(Arc::new(Self))
//!     }
//! }
//!
//! #[tonic::async_trait]
//! impl pb::test_server::Test for TestService {
//!     // ...
//! #   async fn greet(&self, _: tonic::Request<()>) -> Result<tonic::Response<pb::GreetResponse>, tonic::Status> {
//! #       Err(tonic::Status::new(tonic::Code::Unimplemented, "x"))
//! #   }
//! }
//! ```
//!
//! See also the crate-level documentation.

use bytes::Bytes;
use comprehensive::health::HealthReporter;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive::{AnyResource, NoArgs, ResourceDependencies};
use prost::Message;
use prost_types::FileDescriptorSet;
use std::collections::HashSet;
use std::convert::Infallible;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::sync::Arc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::body::Body;
use tonic::server::NamedService;
use tonic::service::Routes;
use tower_layer::Layer;
use tower_service::Service;
use tracing::Instrument as _;
use tracing::{error, info};

use super::{ComprehensiveGrpcError, GrpcService};
use crate::metrics::MetricsLayer;

/// Interface for installing services into a gRPC server. See the
/// [`GrpcService`] trait for where one of these comes from.
pub struct GrpcServiceAdder {
    routes: Option<Routes>,
    reflection: Option<ReflectionInfo>,
    relay: HealthRelay,
}

impl GrpcServiceAdder {
    fn new(health: &HealthReporter) -> Self {
        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        Self {
            routes: Some(Routes::new(health_service)),
            reflection: Some(ReflectionInfo::default()),
            relay: HealthRelay {
                health_subscriber: health.subscribe(),
                health_reporter,
            },
        }
    }

    /// Install a serialised `FileDescriptorSet` proto into the server for
    /// gRPC server reflection purposes. A `FileDescriptorSet` covering the
    /// services to be served must be installed before calling
    /// [`GrpcServiceAdder::add_service`], or else if reflection is not desired
    /// then [`GrpcServiceAdder::disable_grpc_reflection`] should be called first
    /// instead.
    pub fn register_encoded_file_descriptor_set(&mut self, serialised_fds: &[u8]) {
        if let Some(ref mut r) = self.reflection {
            match FileDescriptorSet::decode(serialised_fds) {
                Ok(fds) => {
                    for f in &fds.file {
                        for s in &f.service {
                            if let Some(ref name) = s.name {
                                r.registered_names.insert(if let Some(ref pkg) = f.package {
                                    format!("{}.{}", pkg, name)
                                } else {
                                    String::from(name)
                                });
                            }
                        }
                    }
                    r.fds.push(fds);
                }
                Err(e) => {
                    error!("Error deserialising fdset (ignoring): {}", e);
                }
            }
        }
    }

    /// Configure the server to disable server reflection.
    pub fn disable_grpc_reflection(&mut self) {
        self.reflection = None;
    }

    /// Add a gRPC service to the server. This delegates to
    /// [`Routes::add_service`].
    ///
    /// For services added to the server by deriving the [`GrpcService`]
    /// trait, this is called automatically.
    pub fn add_service<S>(&mut self, svc: S) -> Result<(), ComprehensiveGrpcError>
    where
        S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
            + NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        self.reflection
            .as_ref()
            .map(|r| {
                r.registered_names
                    .get(S::NAME)
                    .ok_or(ComprehensiveGrpcError::NoServiceDescriptor(S::NAME))
            })
            .transpose()?;
        let routes = self.routes.take().unwrap().add_service(svc);
        self.routes = Some(routes);
        Ok(())
    }

    fn into_routes_and_relay(self) -> (Routes, HealthRelay) {
        let mut routes = self.routes.unwrap();
        if let Some(r) = self.reflection {
            let mut rb = tonic_reflection::server::Builder::configure()
                .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET);
            for entry in r.fds.into_iter() {
                rb = rb.register_file_descriptor_set(entry);
            }
            match rb.build_v1() {
                Ok(svc) => {
                    routes = routes.add_service(svc);
                }
                Err(e) => {
                    error!("Error creating gRPC reflection service: {}", e);
                }
            }
        }
        (routes, self.relay)
    }
}

mod routes {
    use super::*;

    #[derive(ResourceDependencies)]
    pub struct GrpcServingRoutesDependencies {
        services: Vec<Arc<dyn GrpcService>>,
        health: Arc<HealthReporter>,
    }

    /// Common resource for collecting all gRPC services into a [`Routes`]
    /// object for serving.
    #[derive(Clone)]
    pub struct GrpcServingRoutes(Routes);

    #[resource]
    impl Resource for GrpcServingRoutes {
        fn new(
            d: GrpcServingRoutesDependencies,
            _: comprehensive::NoArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, crate::ComprehensiveGrpcError> {
            let mut adder = GrpcServiceAdder::new(&d.health);
            for dep in d.services.into_iter() {
                dep.add_to_server(&mut adder)?;
            }
            let (routes, mut relay) = adder.into_routes_and_relay();
            api.set_task(async move {
                relay.relay().await;
                Ok(())
            });
            Ok(Arc::new(Self(routes)))
        }
    }

    impl From<GrpcServingRoutes> for Routes {
        fn from(r: GrpcServingRoutes) -> Self {
            r.0
        }
    }
}

/// The default and recommended middleware layer for [`GrpcServer`].
///
/// This [`Resource`] is designed to be supplied to [`GrpcServer`] as a type
/// parameter:
///
/// ```
/// use comprehensive_grpc::server::{DefaultServingStack, GrpcServer};
///
/// type ServerWithDefaultMiddleware = GrpcServer<DefaultServingStack>;
/// ```
///
/// Alternate middleware can augment the default stack:
///
/// ```
/// # type NewLayer = ();
/// use comprehensive::v1::{AssemblyRuntime, Resource, resource};
/// use comprehensive_grpc::server::DefaultServingStack;
/// use std::sync::Arc;
/// use tower_layer::Layer;
///
/// type CombinedLayer = (DefaultServingStack, NewLayer);
///
/// struct ServingStackWithExtraLayer(CombinedLayer);
///
/// #[resource]
/// impl Resource for ServingStackWithExtraLayer {
///     fn new(
///         (standard,): (Arc<DefaultServingStack>,),
///         _: comprehensive::NoArgs,
///         _: &mut AssemblyRuntime<'_>,
///     ) -> Result<Arc<Self>, std::convert::Infallible> {
///         let l = (Arc::unwrap_or_clone(standard), NewLayer::default());
///         Ok(Arc::new(Self(l)))
///     }
/// }
///
/// impl<S> Layer<S> for ServingStackWithExtraLayer {
///     type Service = <CombinedLayer as Layer<S>>::Service;
///
///     fn layer(&self, inner: S) -> Self::Service {
///         self.0.layer(inner)
///     }
/// }
/// ```
#[derive(Clone)]
pub struct DefaultServingStack {
    metrics_layer: MetricsLayer,
}

#[resource]
impl Resource for DefaultServingStack {
    fn new(
        _: comprehensive::NoDependencies,
        _: comprehensive::NoArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        Ok(Arc::new(Self {
            metrics_layer: MetricsLayer,
        }))
    }
}

impl<S> Layer<S> for DefaultServingStack {
    type Service = <MetricsLayer as Layer<S>>::Service;

    fn layer(&self, inner: S) -> Self::Service {
        self.metrics_layer.layer(inner)
    }
}

mod service {
    use super::*;
    use std::task::{Context, Poll};

    #[derive(Clone)]
    pub struct SpannedService<S>(S, tracing::Span);

    impl<R, S: Service<R>> Service<R> for SpannedService<S> {
        type Response = S::Response;
        type Error = S::Error;
        type Future = tracing::instrument::Instrumented<S::Future>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let _g = self.1.enter();
            self.0.poll_ready(cx)
        }

        fn call(&mut self, r: R) -> Self::Future {
            {
                let _g = self.1.enter();
                self.0.call(r)
            }
            .instrument(self.1.clone())
        }
    }

    #[derive(Clone)]
    pub struct PropagateTracingSpanLayer;

    impl<S> Layer<S> for PropagateTracingSpanLayer {
        type Service = SpannedService<S>;

        fn layer(&self, inner: S) -> SpannedService<S> {
            SpannedService(inner, tracing::Span::current())
        }
    }

    /// This [`Resource`] supplies a tower [`Service`] that serves all of
    /// the gRPC services registered in this assembly. It is not usually
    /// requested directly but through [`GrpcServer`] which will listen
    /// on a TCP port (or two) and serve it over HTTP2. [`GrpcCommonService`]
    /// can be used instead to serve over some kind of different transport.
    #[derive(Clone)]
    pub struct GrpcCommonService<L = DefaultServingStack> {
        stack: Arc<L>,
        routes: Routes,
    }

    #[resource]
    impl<L> Resource for GrpcCommonService<L>
    where
        L: AnyResource + Send + Sync + 'static,
    {
        fn new(
            (routes, stack): (Arc<routes::GrpcServingRoutes>, Arc<L>),
            _: comprehensive::NoArgs,
            _: &mut comprehensive::v1::AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            Ok(Arc::new(Self {
                stack,
                routes: Arc::unwrap_or_clone(routes).into(),
            }))
        }
    }

    impl<L, B> GrpcCommonService<L>
    where
        L: Layer<Routes>,
        <L as Layer<Routes>>::Service:
            Service<http::Request<Body>, Response = http::Response<B>> + Clone,
        <<L as Layer<Routes>>::Service as Service<http::Request<Body>>>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
        <<L as Layer<Routes>>::Service as Service<http::Request<Body>>>::Future: Send,
    {
        /// Generate a tower [`Service`] for gRPC serving. The service will
        /// contain all of the configured middleware and all of the
        /// registered gRPC services.
        ///
        /// ```
        /// use comprehensive::v1::{AssemblyRuntime, Resource, resource};
        /// use comprehensive_grpc::server::GrpcCommonService;
        /// use futures::future::TryFutureExt;
        /// use std::sync::Arc;
        ///
        /// struct Demo;
        ///
        /// #[resource]
        /// impl Resource for Demo {
        ///     fn new(
        ///         (service,): (Arc<GrpcCommonService>,),
        ///         _: comprehensive::NoArgs,
        ///         api: &mut AssemblyRuntime<'_>,
        ///     ) -> Result<Arc<Self>, std::convert::Infallible> {
        ///         let server = tonic::transport::Server::builder()
        ///             .serve_with_shutdown(
        ///                 "[::1]:1234".parse().unwrap(),
        ///                 Arc::unwrap_or_clone(service).into_service(),
        ///                 api.self_stop(),
        ///             );
        ///         api.set_task(server.err_into());
        ///         Ok(Arc::new(Self))
        ///     }
        /// }
        /// ```
        // https://github.com/rust-lang/rust/pull/122055
        pub fn into_service(
            self,
        ) -> impl Service<
            http::Request<Body>,
            Response = http::Response<B>,
            Future: Send,
            Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
        > + Clone {
            PropagateTracingSpanLayer.layer(self.stack.layer(self.routes.prepare()))
        }
    }
}

pub use service::GrpcCommonService;

mod insecure_server {
    use super::*;

    #[derive(clap::Args, Debug)]
    #[group(skip)]
    pub struct InsecureGrpcListenerArgs {
        #[arg(
            long,
            help = "TCP port number for insecure gRPC server. If unset, plain gRPC is not served."
        )]
        grpc_port: Option<u16>,

        #[arg(
            long,
            default_value = "::",
            help = "Binding IP address for gRPC. Used only if --grpc_port is set."
        )]
        grpc_bind_addr: IpAddr,
    }

    pub struct InsecureGrpcServer<L>(PhantomData<L>);

    #[resource]
    impl<L, B> Resource for InsecureGrpcServer<L>
    where
        L: AnyResource + Layer<Routes> + Clone + Send + Sync + 'static,
        L::Service: Service<http::Request<Body>, Response = http::Response<B>> + Clone + Send,
        <L::Service as Service<http::Request<Body>>>::Future: Send,
        <L::Service as Service<http::Request<Body>>>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        const NAME: &str = "Plaintext gRPC server";

        fn new(
            (common_service,): (Arc<GrpcCommonService<L>>,),
            args: InsecureGrpcListenerArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, crate::ComprehensiveGrpcError> {
            if let Some(port) = args.grpc_port {
                let addr: std::net::SocketAddr = (args.grpc_bind_addr, port).into();
                let listener = std::net::TcpListener::bind(addr)?;
                listener.set_nonblocking(true)?;
                let incoming = TcpListenerStream::new(tokio::net::TcpListener::from_std(listener)?);
                info!("Insecure gRPC server listening on {}", addr);
                let service = Arc::unwrap_or_clone(common_service).into_service();

                let server = tonic::transport::Server::builder().serve_with_incoming_shutdown(
                    service,
                    incoming,
                    api.self_stop(),
                );
                api.set_task(async move {
                    tokio::spawn(server.in_current_span()).await??;
                    Ok(())
                });
            }
            Ok(Arc::new(Self(PhantomData)))
        }
    }
}

#[cfg(feature = "tls")]
mod secure_server {
    use super::*;

    #[derive(clap::Args, Debug)]
    #[group(skip)]
    pub struct SecureGrpcListenerArgs {
        #[arg(
            long,
            help = "TCP port number for secure gRPC server. If unset, gRPCs is not served."
        )]
        grpcs_port: Option<u16>,

        #[arg(
            long,
            default_value = "::",
            help = "Binding IP address for gRPCs. Used only if --grpcs_port is set."
        )]
        grpcs_bind_addr: IpAddr,
    }

    pub struct SecureGrpcServer<L>(PhantomData<L>);

    #[resource]
    impl<L, B> Resource for SecureGrpcServer<L>
    where
        L: AnyResource + Layer<Routes> + Clone + Send + Sync + 'static,
        L::Service: Service<http::Request<Body>, Response = http::Response<B>> + Clone + Send,
        <L::Service as Service<http::Request<Body>>>::Future: Send,
        <L::Service as Service<http::Request<Body>>>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        const NAME: &str = "Secure gRPC server";

        fn new(
            (common_service, tls): (
                Arc<GrpcCommonService<L>>,
                Option<Arc<comprehensive_tls::TlsConfig>>,
            ),
            args: SecureGrpcListenerArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, crate::ComprehensiveGrpcError> {
            if let Some(port) = args.grpcs_port {
                let Some(tlsc) = tls else {
                    return Err(crate::ComprehensiveGrpcError::NoTlsProvider);
                };
                let addr = (args.grpcs_bind_addr, port).into();
                let incoming = crate::incoming::tls_over_tcp(addr, tlsc)?;
                info!("Secure gRPC server listening on {}", addr);
                let service = Arc::unwrap_or_clone(common_service).into_service();
                let server = tonic::transport::Server::builder()
                    .layer(crate::incoming::AddUnderlyingConnectInfoLayer)
                    .serve_with_incoming_shutdown(service, incoming, api.self_stop());
                api.set_task(async move {
                    tokio::spawn(server.in_current_span()).await??;
                    Ok(())
                });
            }
            Ok(Arc::new(Self(PhantomData)))
        }
    }
}

#[derive(Default)]
struct ReflectionInfo {
    fds: Vec<FileDescriptorSet>,
    registered_names: HashSet<String>,
}

#[cfg(feature = "tls")]
type GrpcServerDependencies<L> = (
    Arc<insecure_server::InsecureGrpcServer<L>>,
    Arc<secure_server::SecureGrpcServer<L>>,
);

#[cfg(not(feature = "tls"))]
type GrpcServerDependencies<L> = (Arc<insecure_server::InsecureGrpcServer<L>>,);

struct HealthRelay {
    health_subscriber: tokio::sync::watch::Receiver<bool>,
    health_reporter: tonic_health::server::HealthReporter,
}

impl HealthRelay {
    async fn relay(&mut self) {
        loop {
            let s = match *self.health_subscriber.borrow_and_update() {
                true => tonic_health::ServingStatus::Serving,
                false => tonic_health::ServingStatus::NotServing,
            };
            self.health_reporter.set_service_status("ready", s).await;
            if self.health_subscriber.changed().await.is_err() {
                break;
            }
        }
    }
}

/// [`comprehensive`] [`Resource`] implementing a gRPC server using [`tonic`].
///
/// Including this [`Resource`] in an [`Assembly`] will cause it to run
/// either an insecure or secure gRPC server or both, depending on flags.
///
/// The server automatically provides some features above a standard [`tonic`]
/// server:
///
/// * RPC count metrics
/// * gRPC reflection
/// * graceful shutdown
/// * health reporting
///
/// # Health reporting
///
/// Although the gRPC health reporting supports fine-grained service-by-service
/// health status, Comprehensive does not use that. The entire assembly is
/// considered healthy if all signals are healthy, and unhealthy otherwise.
/// This translates to gRPC health reporting using 2 pseudo-services:
///
/// * "" (empty string): This service is always considered healthy.
///   Use this as a liveness check that the server is able to start and run.
/// * "ready": This service is considered healthy iff the assembly is healthy.
///   Use this as a readiness check that the server is willing to accept
///   traffic.
///
/// [`Assembly`]: comprehensive::Assembly
pub struct GrpcServer<L = DefaultServingStack> {
    _stack: PhantomData<L>,
}

#[resource]
impl<L, B> Resource for GrpcServer<L>
where
    L: AnyResource + Layer<Routes> + Clone + Send + Sync + 'static,
    L::Service: Service<http::Request<Body>, Response = http::Response<B>> + Clone + Send,
    <L::Service as Service<http::Request<Body>>>::Future: Send,
    <L::Service as Service<http::Request<Body>>>::Error:
        Into<Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    const NAME: &str = "gRPC server common";

    fn new(
        _: GrpcServerDependencies<L>,
        _: NoArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        Ok(Arc::new(Self {
            _stack: PhantomData,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use comprehensive::Assembly;
    use futures::future::Either;
    use futures::pin_mut;
    use pin_project_lite::pin_project;
    use std::pin::Pin;
    use std::task::{Context, Poll, ready};
    use tonic_health::pb::{
        HealthCheckRequest, HealthCheckResponse, health_check_response, health_client,
    };

    const EMPTY: &[std::ffi::OsString] = &[];

    async fn test_health<A, R, E1, E2>(assembly: A, rpc: R)
    where
        A: Future<Output = Result<(), E1>>,
        E1: std::fmt::Debug,
        R: Future<Output = Result<tonic::Response<HealthCheckResponse>, E2>>,
        E2: std::fmt::Debug,
    {
        pin_mut!(assembly);
        pin_mut!(rpc);
        let rpc_result = match futures::future::select(assembly, rpc).await {
            Either::Left((Ok(()), rpc)) => rpc.await,
            Either::Left((Err(e), _)) => {
                panic!("Assembly unexpectedly quit: {e:?}");
            }
            Either::Right((rpc, _)) => rpc,
        };
        assert_eq!(
            rpc_result.expect("rpc").into_inner().status,
            health_check_response::ServingStatus::Serving as i32
        );
    }

    #[tokio::test]
    async fn default_stack() {
        let assembly = Assembly::<(Arc<GrpcCommonService>,)>::new_from_argv(EMPTY).unwrap();
        let service = (*assembly.top.0).clone().into_service();
        let mut client = health_client::HealthClient::new(service);
        test_health(
            assembly.run_with_termination_signal(futures::stream::pending()),
            client.check(HealthCheckRequest::default()),
        )
        .await;
    }

    #[derive(Clone)]
    struct BodyChanger;

    #[resource]
    impl Resource for BodyChanger {
        fn new(
            _: comprehensive::NoDependencies,
            _: comprehensive::NoArgs,
            _: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            Ok(Arc::new(Self))
        }
    }

    pin_project! {
        struct OtherBody<B> {
            #[pin] inner: B,
        }
    }

    impl<B: http_body::Body> http_body::Body for OtherBody<B> {
        type Data = B::Data;
        type Error = B::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            self.project().inner.poll_frame(cx)
        }
    }

    pin_project! {
        struct BodyChangingServiceFuture<F> {
            #[pin] inner: F,
        }
    }

    impl<F, B, E> Future for BodyChangingServiceFuture<F>
    where
        F: Future<Output = Result<http::Response<B>, E>>,
    {
        type Output = Result<http::Response<OtherBody<B>>, E>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(match ready!(self.project().inner.poll(cx)) {
                Ok(r) => {
                    let (parts, body) = r.into_parts();
                    Ok(http::Response::from_parts(parts, OtherBody { inner: body }))
                }
                Err(e) => Err(e),
            })
        }
    }

    #[derive(Clone)]
    struct BodyChangingService<S>(S);

    impl<R, S, B> Service<R> for BodyChangingService<S>
    where
        S: Service<R, Response = http::Response<B>>,
    {
        type Response = http::Response<OtherBody<B>>;
        type Error = S::Error;
        type Future = BodyChangingServiceFuture<S::Future>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.0.poll_ready(cx)
        }

        fn call(&mut self, r: R) -> Self::Future {
            BodyChangingServiceFuture {
                inner: self.0.call(r),
            }
        }
    }

    impl<S> Layer<S> for BodyChanger {
        type Service = BodyChangingService<S>;

        fn layer(&self, inner: S) -> Self::Service {
            BodyChangingService(inner)
        }
    }

    #[tokio::test]
    async fn body_changing_stack() {
        let assembly =
            Assembly::<(Arc<GrpcCommonService<BodyChanger>>,)>::new_from_argv(EMPTY).unwrap();
        let service = (*assembly.top.0).clone().into_service();
        let mut client = health_client::HealthClient::new(service);
        test_health(
            assembly.run_with_termination_signal(futures::stream::pending()),
            client.check(HealthCheckRequest::default()),
        )
        .await;
    }
}
