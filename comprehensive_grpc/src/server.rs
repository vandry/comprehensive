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

use atomic_take::AtomicTake;
use comprehensive::health::HealthReporter;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive::{NoArgs, ResourceDependencies};
use prost::Message;
use prost_types::FileDescriptorSet;
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::body::BoxBody;
use tonic::server::NamedService;
use tonic::service::Routes;
use tower_layer::{Layer, Stack};
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
        S: Service<http::Request<BoxBody>, Response = http::Response<BoxBody>, Error = Infallible>
            + NamedService
            + Clone
            + Send
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

#[derive(Clone)]
struct SpannedService<S>(S, tracing::Span);

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
struct PropagateTracingSpanLayer;

impl<S> Layer<S> for PropagateTracingSpanLayer {
    type Service = SpannedService<S>;

    fn layer(&self, inner: S) -> SpannedService<S> {
        SpannedService(inner, tracing::Span::current())
    }
}

type BaseLayer = Stack<MetricsLayer, Stack<PropagateTracingSpanLayer, tower_layer::Identity>>;

fn new_base_layer() -> tonic::transport::Server<BaseLayer> {
    tonic::transport::Server::builder()
        .layer(PropagateTracingSpanLayer)
        .layer(MetricsLayer)
}

mod routes {
    use super::*;

    #[derive(ResourceDependencies)]
    pub struct GrpcServingRoutesDependencies {
        services: Vec<Arc<dyn GrpcService>>,
        health: Arc<HealthReporter>,
    }

    /// EXPERIMENTAL: Subject to change or removal in minor versions.
    ///
    /// Common resource for collecting all gRPC services into a [`Routes`]
    /// object for serving. This is exposed in order to make it possible
    /// to supply a custom gRPC server without having to rewrite this part
    /// of the logic, but the API for doing that is not firmly decided.
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

    impl GrpcServingRoutes {
        /// EXPERIMENTAL: Subject to change or removal in minor versions.
        ///
        /// Get a [`Routes`] object for gRPC serving.
        /// This is exposed in order to make it possible
        /// to supply a custom gRPC server without having to rewrite this part
        /// of the logic, but the API for doing that is not firmly decided.
        pub fn routes(&self) -> Routes {
            self.0.clone()
        }
    }
}

#[cfg(feature = "experimental")]
pub use routes::GrpcServingRoutes;

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

    /// EXPERIMENTAL: Subject to change or removal in minor versions.
    ///
    /// Helper resource for binding a plaintext gRPC listening socket.
    /// This is exposed in order to make it possible
    /// to supply a custom gRPC server without having to rewrite this part
    /// of the logic, but the API for doing that is not firmly decided.
    pub struct InsecureGrpcListener(AtomicTake<TcpListenerStream>);

    #[resource]
    impl Resource for InsecureGrpcListener {
        const NAME: &str = "Plaintext gRPC listener";

        fn new(
            _: comprehensive::NoDependencies,
            args: InsecureGrpcListenerArgs,
            _: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, crate::ComprehensiveGrpcError> {
            Ok(Arc::new(Self(
                args.grpc_port
                    .map(|port| {
                        let addr: std::net::SocketAddr = (args.grpc_bind_addr, port).into();
                        let listener = std::net::TcpListener::bind(addr)?;
                        listener.set_nonblocking(true)?;
                        let incoming =
                            TcpListenerStream::new(tokio::net::TcpListener::from_std(listener)?);
                        info!("Insecure gRPC server listening on {}", addr);
                        Ok::<_, crate::ComprehensiveGrpcError>(AtomicTake::new(incoming))
                    })
                    .transpose()?
                    .unwrap_or(AtomicTake::empty()),
            )))
        }
    }

    impl InsecureGrpcListener {
        /// EXPERIMENTAL: Subject to change or removal in minor versions.
        ///
        /// Get the plaintext gRPC listening socket. Can only be called once.
        /// This is exposed in order to make it possible
        /// to supply a custom gRPC server without having to rewrite this part
        /// of the logic, but the API for doing that is not firmly decided.
        pub fn take(&self) -> Option<TcpListenerStream> {
            self.0.take()
        }
    }

    #[derive(ResourceDependencies)]
    pub(super) struct InsecureGrpcServerDependencies {
        listener: Arc<InsecureGrpcListener>,
        routes: Arc<routes::GrpcServingRoutes>,
    }

    pub(super) struct InsecureGrpcServer;

    #[resource]
    impl Resource for InsecureGrpcServer {
        const NAME: &str = "Plaintext gRPC server";

        fn new(
            d: InsecureGrpcServerDependencies,
            _: comprehensive::NoArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, crate::ComprehensiveGrpcError> {
            if let Some(listener) = d.listener.take() {
                let server = new_base_layer()
                    .add_routes(d.routes.routes())
                    .serve_with_incoming_shutdown(listener, api.self_stop());
                api.set_task(async move {
                    tokio::spawn(server.in_current_span()).await??;
                    Ok(())
                });
            }
            Ok(Arc::new(Self))
        }
    }
}

#[cfg(feature = "experimental")]
pub use insecure_server::InsecureGrpcListener;

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

    #[derive(ResourceDependencies)]
    pub struct SecureGrpcListenerDependencies {
        tls: Option<Arc<comprehensive_tls::TlsConfig>>,
    }

    /// EXPERIMENTAL: Subject to change or removal in minor versions.
    ///
    /// Helper resource for binding a secure gRPC listening socket.
    /// This is exposed in order to make it possible
    /// to supply a custom gRPC server without having to rewrite this part
    /// of the logic, but the API for doing that is not firmly decided.
    pub struct SecureGrpcListener(
        AtomicTake<crate::incoming::Acceptor<TcpListenerStream, tokio::net::TcpStream>>,
    );

    #[resource]
    impl Resource for SecureGrpcListener {
        const NAME: &str = "Secure gRPC listener";

        fn new(
            d: SecureGrpcListenerDependencies,
            args: SecureGrpcListenerArgs,
            _: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, crate::ComprehensiveGrpcError> {
            Ok(Arc::new(Self(
                args.grpcs_port
                    .map(|port| {
                        let Some(tlsc) = d.tls else {
                            return Err(crate::ComprehensiveGrpcError::NoTlsProvider);
                        };
                        let addr = (args.grpcs_bind_addr, port).into();
                        let incoming = crate::incoming::tls_over_tcp(addr, tlsc)?;
                        info!("Secure gRPC server listening on {}", addr);
                        Ok(AtomicTake::new(incoming))
                    })
                    .transpose()?
                    .unwrap_or(AtomicTake::empty()),
            )))
        }
    }

    impl SecureGrpcListener {
        /// EXPERIMENTAL: Subject to change or removal in minor versions.
        ///
        /// Get the secure gRPC listening socket. Can only be called once.
        /// This is exposed in order to make it possible
        /// to supply a custom gRPC server without having to rewrite this part
        /// of the logic, but the API for doing that is not firmly decided.
        pub fn take(
            &self,
        ) -> Option<crate::incoming::Acceptor<TcpListenerStream, tokio::net::TcpStream>> {
            self.0.take()
        }
    }

    #[derive(ResourceDependencies)]
    pub(super) struct SecureGrpcServerDependencies {
        listener: Arc<SecureGrpcListener>,
        routes: Arc<routes::GrpcServingRoutes>,
    }

    pub(super) struct SecureGrpcServer;

    #[resource]
    impl Resource for SecureGrpcServer {
        const NAME: &str = "Secure gRPC server";

        fn new(
            d: SecureGrpcServerDependencies,
            _: comprehensive::NoArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, crate::ComprehensiveGrpcError> {
            if let Some(listener) = d.listener.take() {
                let server = new_base_layer()
                    .layer(crate::incoming::AddUnderlyingConnectInfoLayer)
                    .add_routes(d.routes.routes())
                    .serve_with_incoming_shutdown(listener, api.self_stop());
                api.set_task(async move {
                    tokio::spawn(server.in_current_span()).await??;
                    Ok(())
                });
            }
            Ok(Arc::new(Self))
        }
    }
}

#[cfg(all(feature = "tls", feature = "experimental"))]
pub use secure_server::SecureGrpcListener;

#[derive(Default)]
struct ReflectionInfo {
    fds: Vec<FileDescriptorSet>,
    registered_names: HashSet<String>,
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct GrpcServerDependencies {
    _grpc: Arc<insecure_server::InsecureGrpcServer>,
    #[cfg(feature = "tls")]
    _grpcs: Arc<secure_server::SecureGrpcServer>,
}

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
pub struct GrpcServer;

#[resource]
impl Resource for GrpcServer {
    const NAME: &str = "gRPC server common";

    fn new(
        _: GrpcServerDependencies,
        _: NoArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        Ok(Arc::new(Self))
    }
}
