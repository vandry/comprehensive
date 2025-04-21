//! gRPC server support
//!
//! To use gRPC servers in Comprehensive, define a [`Resource`] that
//! also implements the [`GrpcService`] trait using the [`resource`] macro:
//!
//! ```
//! # #[cfg(feature = "tls")]
//! # let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
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

use comprehensive::health::HealthReporter;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive::{NoArgs, ResourceDependencies};
use futures::future::Either;
use prost::Message;
use prost_types::FileDescriptorSet;
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::IpAddr;
use std::pin::pin;
use std::sync::Arc;
use tonic::body::BoxBody;
use tonic::server::NamedService;
use tonic::service::Routes;
use tonic_prometheus_layer::MetricsLayer;
use tower::Service;

use super::{ComprehensiveGrpcError, GrpcService};

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
                    log::error!("Error deserialising fdset (ignoring): {}", e);
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
                    log::error!("Error creating gRPC reflection service: {}", e);
                }
            }
        }
        (routes, self.relay)
    }
}

fn tonic_prometheus_layer_use_default_registry() {
    let _ = tonic_prometheus_layer::metrics::try_init_settings(
        tonic_prometheus_layer::metrics::GlobalSettings {
            registry: prometheus::default_registry().clone(), // Arc
            ..Default::default()
        },
    );
}

type Layer = tower_layer::Stack<MetricsLayer, tower_layer::Identity>;

fn new_base_layer() -> tonic::transport::Server<Layer> {
    tonic_prometheus_layer_use_default_registry();
    let metrics_layer = tonic_prometheus_layer::MetricsLayer::new();
    tonic::transport::Server::builder().layer(metrics_layer)
}

async fn serve(
    mut relay: HealthRelay,
    server: impl Future<Output = Result<(), tonic::transport::Error>> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error>> {
    let relay_task = pin!(relay.relay());
    let serve_task = pin!(tokio::spawn(server));
    match futures::future::select(relay_task, serve_task).await {
        Either::Left((_, serve_task)) => serve_task.await,
        Either::Right((serve_result, _)) => serve_result,
    }??;
    Ok(())
}

mod insecure_server {
    use super::*;

    #[derive(clap::Args, Debug)]
    #[group(skip)]
    pub(super) struct InsecureGrpcServerArgs {
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

    #[derive(ResourceDependencies)]
    pub(super) struct InsecureServerDependencies {
        services: Vec<Arc<dyn GrpcService>>,
        health: Arc<HealthReporter>,
    }

    pub(super) struct InsecureGrpcServer;

    #[resource]
    impl Resource for InsecureGrpcServer {
        const NAME: &str = "Plaintext gRPC server";

        fn new(
            d: InsecureServerDependencies,
            args: InsecureGrpcServerArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, crate::ComprehensiveGrpcError> {
            if let Some(port) = args.grpc_port {
                let mut adder = GrpcServiceAdder::new(&d.health);
                for dep in d.services.into_iter() {
                    dep.add_to_server(&mut adder)?;
                }
                let stop = api.self_stop();
                let (routes, relay) = adder.into_routes_and_relay();
                let addr = (args.grpc_bind_addr, port).into();
                api.set_task(async move {
                    log::info!("Insecure gRPC server listening on {}", addr);
                    serve(relay, async move {
                        new_base_layer()
                            .add_routes(routes)
                            .serve_with_shutdown(addr, stop)
                            .await
                    })
                    .await
                });
            }
            Ok(Arc::new(Self))
        }
    }
}

#[cfg(feature = "tls")]
mod secure_server {
    use super::*;

    #[derive(clap::Args, Debug)]
    #[group(skip)]
    pub(super) struct SecureGrpcServerArgs {
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
    pub(super) struct SecureGrpcServerDependencies {
        tls: Arc<comprehensive::tls::TlsConfig>,
        services: Vec<Arc<dyn GrpcService>>,
        health: Arc<HealthReporter>,
    }

    pub(super) struct SecureGrpcServer;

    #[resource]
    impl Resource for SecureGrpcServer {
        const NAME: &str = "Secure gRPC server";

        fn new(
            d: SecureGrpcServerDependencies,
            args: SecureGrpcServerArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, crate::ComprehensiveGrpcError> {
            if let Some(port) = args.grpcs_port {
                let snapshot = d.tls.snapshot()?;
                let identity = tonic::transport::Identity::from_pem(snapshot.cert, snapshot.key);
                let mut tls = tonic::transport::ServerTlsConfig::new().identity(identity);
                if let Some(cacert) = snapshot.cacert {
                    let cert = tonic::transport::Certificate::from_pem(cacert);
                    tls = tls.client_ca_root(cert);
                }

                let mut adder = GrpcServiceAdder::new(&d.health);
                for dep in d.services.into_iter() {
                    dep.add_to_server(&mut adder)?;
                }
                let stop = api.self_stop();
                let (routes, relay) = adder.into_routes_and_relay();
                let addr = (args.grpcs_bind_addr, port).into();
                let mut base = new_base_layer().tls_config(tls)?;
                api.set_task(async move {
                    log::info!("Secure gRPC server listening on {}", addr);
                    serve(relay, async move {
                        base.add_routes(routes)
                            .serve_with_shutdown(addr, stop)
                            .await
                    })
                    .await
                });
            }
            Ok(Arc::new(Self))
        }
    }
}

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
            let _ = self.health_subscriber.changed().await;
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
/// * RPC count metrics, courtesy or [`tonic_prometheus_layer`]
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
