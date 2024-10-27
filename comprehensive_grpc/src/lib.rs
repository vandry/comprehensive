//! [`comprehensive`] [`Resource`] types for gRPC serving
//!
//! This crate provides [`Resource`] types for use in a [`comprehensive`]
//! [`Assembly`]. To use it, build an [`Assembly`] and include resources
//! from this crate in the dependency graph.
//!
//! # Usage
//!
//! There are 2 ways to use it:
//!
//! ## Derive resources that conjure the server and install themselves in it
//!
//! A [`GrpcService`] is a [`Resource`] and depending upon it will cause
//! the server to run with the service in question (and others) installed:
//!
//! ```
//! # mod pb {
//! #     tonic::include_proto!("comprehensive");
//! #     pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("fdset");
//! # }
//! # struct Implementation {}
//! use comprehensive::{NoArgs, NoDependencies, Resource, ResourceDependencies};
//! use comprehensive_grpc::GrpcService;
//!
//! impl Resource for Implementation {
//!     type Args = NoArgs;
//!     type Dependencies = NoDependencies;
//!     const NAME: &str = "TestServer";
//!
//!     fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
//!         Ok(Self {})
//!     }
//! }
//!
//! #[tonic::async_trait]
//! impl pb::test_server::Test for Implementation {
//!     // ...
//! #   async fn greet(&self, _: tonic::Request<()>) -> Result<tonic::Response<pb::GreetResponse>, tonic::Status> {
//! #       Err(tonic::Status::new(tonic::Code::Unimplemented, "x"))
//! #   }
//! }
//!
//! #[derive(GrpcService)]
//! #[implementation(Implementation)]
//! #[service(pb::test_server::TestServer)]
//! #[descriptor(pb::FILE_DESCRIPTOR_SET)]
//! struct TestService;
//!
//! #[derive(ResourceDependencies)]
//! struct AutoServer {
//!     _s: std::sync::Arc<TestService>,
//! }
//! let assembly = comprehensive::Assembly::<AutoServer>::new().unwrap();
//! ```
//!
//! ## Depend on [`GrpcServer`] directly
//!
//! The server can bee configured to add gRPC services to it:
//!
//! ```
//! # mod pb {
//! #     tonic::include_proto!("comprehensive");
//! #     pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("fdset");
//! # }
//! # struct Implementation {}
//! # #[tonic::async_trait]
//! # impl pb::test_server::Test for Implementation {
//! #     async fn greet(&self, _: tonic::Request<()>) -> Result<tonic::Response<pb::GreetResponse>, tonic::Status> {
//! #         Err(tonic::Status::new(tonic::Code::Unimplemented, "x"))
//! #     }
//! # }
//! use comprehensive::ResourceDependencies;
//! use comprehensive_grpc::GrpcServer;
//!
//! #[derive(ResourceDependencies)]
//! struct JustAServer {
//!     server: std::sync::Arc<GrpcServer>,
//! }
//!
//! let assembly = comprehensive::Assembly::<JustAServer>::new().unwrap();
//! assembly.top.server.register_encoded_file_descriptor_set(
//!     pb::FILE_DESCRIPTOR_SET
//! );
//! assembly.top.server.add_service(
//!     pb::test_server::TestServer::new(Implementation{})
//! );
//! ```
//!
//! # Command line flags for the gRPC server
//!
//! | Flag                | Default    | Meaning                 |
//! |---------------------|------------|-------------------------|
//! | `--grpc_port`       | *none*     | TCP port number for insecure gRPC server. If unset, plain gRPC is not served. |
//! | `--grpc_bind_addr`  | `::`       | Binding IP address for gRPC. Used only if `--grpc_port` is set. |
//! | `--grpcs_port`      | *none*     | TCP port number for secure gRPC server. If unset, gRPCs is not served. |
//! | `--grpcs_bind_addr` | `::`       | Binding IP address for gRPCs. Used only if `--grpcs_port` is set. |
//!
//! # On descriptors
//!
//! Because gRPC server reflection is very useful for diagnostics yet it is
//! too easy to forget to install the descriptors needed to make it happen,
//! [`comprehensive_grpc`] tries to insist that descriptors are installed
//! before services are added to the server.
//!
//! To obtain file descriptors, put this in `build.rs`:
//!
//! ```ignore
//! let fds_path =
//!     std::path::PathBuf::from(std::env::var("OUT_DIR").expect("$OUT_DIR")).join("fdset.bin");
//! tonic_build::configure()
//!     .file_descriptor_set_path(fds_path)
//! ```
//!
//! And this where you include your protos:
//!
//! ```
//! pub(crate) const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("fdset");
//! ```
//!
//! [`Assembly`]: comprehensive::Assembly

#![warn(missing_docs)]

use atomic_take::AtomicTake;
use comprehensive::{NoArgs, NoDependencies, Resource, ResourceDependencies, ShutdownNotify};
use futures::{future::Either, pin_mut, FutureExt};
use prost::Message;
use prost_types::FileDescriptorSet;
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Notify;
use tonic::body::BoxBody;
use tonic::server::NamedService;
use tonic::service::Routes;
use tonic_prometheus_layer::MetricsLayer;
use tower::Service;

fn tonic_prometheus_layer_use_default_registry() {
    let _ = tonic_prometheus_layer::metrics::try_init_settings(
        tonic_prometheus_layer::metrics::GlobalSettings {
            registry: prometheus::default_registry().clone(), // Arc
            ..Default::default()
        },
    );
}

/// Error type returned by various Comprehensive gRPC functions
#[derive(Debug)]
pub enum ComprehensiveGrpcError {
    /// An attempt was made to configure a [`GrpcServer`] after the
    /// assembly has already started running. All configuration must
    /// happen before [`comprehensive::Assembly::run`] is called.
    TooLateToConfigure(&'static str),
    /// Indicates an attempt to add a gRPC service without supplying its
    /// service descriptor first. Descriptors must be registered using
    /// [`GrpcServer::register_encoded_file_descriptor_set`] before calling
    /// [`GrpcServer::add_service`] to add the service. The reason this is
    /// an error is to help encourage server reflection (which is a valuable
    /// diagnostic tool) to be always available for every service.
    /// Unfortunately Tonic does not currently attach service descriptors to
    /// service traits so that this can be done automatically.
    ///
    /// To decline server reflection, call [`GrpcServer::disable_grpc_reflection`]
    /// before [`GrpcServer::add_service`] instead.
    NoServiceDescriptor(&'static str),
    /// Indicates a bug!
    InternalMissingConfiguration,
}

impl std::fmt::Display for ComprehensiveGrpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::NoServiceDescriptor(name) => write!(f, "No file descriptor set registered covering {}. Register one with register_encoded_file_descriptor_set or call disable_reflection.", name),
            Self::TooLateToConfigure(name) => write!(f, "Too late to call {} after the server is already started.", name),
            Self::InternalMissingConfiguration => write!(f, "Internal error: missing GrpcServerInner."),
        }
    }
}

impl std::error::Error for ComprehensiveGrpcError {}

struct Conveyor<T> {
    data: std::sync::Mutex<Option<T>>,
    available: Notify,
}

impl<T> Conveyor<T> {
    fn new() -> Self {
        Self {
            data: std::sync::Mutex::new(None),
            available: Notify::new(),
        }
    }

    fn put(&self, data: T) {
        *(self.data.lock().unwrap()) = Some(data);
        self.available.notify_waiters();
    }

    async fn get(&self) -> T {
        let notified = self.available.notified();
        if let Some(data) = self.data.lock().unwrap().take() {
            return data;
        }
        notified.await;
        self.data
            .lock()
            .unwrap()
            .take()
            .expect("Conveyor unexpectedly empty")
    }
}

type Layer = tower_layer::Stack<MetricsLayer, tower_layer::Identity>;

struct ServingConfig {
    base: tonic::transport::Server<Layer>,
    routes: Routes,
}

async fn run_in_task<'a>(
    s: tonic::transport::server::Router<Layer>,
    a: SocketAddr,
    term_signal: &'a ShutdownNotify<'a>,
) -> Result<(), Box<dyn std::error::Error>> {
    // We need an adaptor because we cannot send term_signal directly
    // into the task due to its lifetime.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let term = term_signal.subscribe();
    let task = tokio::spawn(async move { s.serve_with_shutdown(a, rx.map(|_| ())).await });
    pin_mut!(term);
    pin_mut!(task);
    match futures::future::select(term, task).await {
        Either::Left(((), task)) => {
            let _ = tx.send(());
            task.await
        }
        Either::Right((result, _)) => result,
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

    pub(super) struct InsecureGrpcServer {
        pub(super) addr: Option<SocketAddr>,
        pub(super) conf: Conveyor<ServingConfig>,
    }

    impl Resource for InsecureGrpcServer {
        type Args = InsecureGrpcServerArgs;
        type Dependencies = NoDependencies;
        const NAME: &str = "Plaintext gRPC server";

        fn new(
            _: NoDependencies,
            args: InsecureGrpcServerArgs,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self {
                addr: args
                    .grpc_port
                    .map(|port| (args.grpc_bind_addr, port).into()),
                conf: Conveyor::new(),
            })
        }

        async fn run_with_termination_signal<'a>(
            &'a self,
            term: &'a ShutdownNotify<'a>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let Some(addr) = self.addr else {
                return Ok(());
            };
            let mut conf = self.conf.get().await;
            log::info!("Insecure gRPC server listening on {}", addr);
            run_in_task(conf.base.add_routes(conf.routes), addr, term).await?;
            Ok(())
        }
    }
}

#[cfg(feature = "tls")]
mod secure_server {
    use super::*;

    #[cfg(not(test))]
    type TlsConfig = comprehensive::tls::TlsConfig;
    #[cfg(test)]
    type TlsConfig = super::testutil::tls::MockTlsConfig;

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
        tls: Arc<TlsConfig>,
    }

    pub(super) struct SecureGrpcServer {
        pub(super) addr: Option<SocketAddr>,
        pub(super) conf: Conveyor<ServingConfig>,
        tls_config: std::sync::Mutex<Option<tonic::transport::ServerTlsConfig>>,
    }

    impl Resource for SecureGrpcServer {
        type Args = SecureGrpcServerArgs;
        type Dependencies = SecureGrpcServerDependencies;
        const NAME: &str = "Secure gRPC server";

        fn new(
            d: SecureGrpcServerDependencies,
            args: SecureGrpcServerArgs,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let addr: Option<SocketAddr> = args
                .grpcs_port
                .map(|port| (args.grpcs_bind_addr, port).into());
            if addr.is_some() {
                let snapshot = d.tls.snapshot()?;
                let identity = tonic::transport::Identity::from_pem(snapshot.cert, snapshot.key);
                let mut tls = tonic::transport::ServerTlsConfig::new().identity(identity);
                if let Some(cacert) = snapshot.cacert {
                    let cert = tonic::transport::Certificate::from_pem(cacert);
                    tls = tls.client_ca_root(cert);
                }
                Ok(Self {
                    addr: args
                        .grpcs_port
                        .map(|port| (args.grpcs_bind_addr, port).into()),
                    conf: Conveyor::new(),
                    tls_config: std::sync::Mutex::new(Some(tls)),
                })
            } else {
                Ok(Self {
                    addr: None,
                    conf: Conveyor::new(),
                    tls_config: std::sync::Mutex::new(None),
                })
            }
        }

        async fn run_with_termination_signal<'a>(
            &'a self,
            term: &'a ShutdownNotify<'a>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let Some(addr) = self.addr else {
                return Ok(());
            };
            let conf = self.conf.get().await;
            let tls_config = self.tls_config.lock().unwrap().take().unwrap();
            log::info!("Secure gRPC server listening on {}", addr);
            run_in_task(
                conf.base.tls_config(tls_config)?.add_routes(conf.routes),
                addr,
                term,
            )
            .await?;
            Ok(())
        }
    }
}

#[derive(Default)]
struct ReflectionInfo {
    fds: Vec<FileDescriptorSet>,
    registered_names: HashSet<String>,
}

struct GrpcServerInner {
    routes: Option<Routes>,
    reflection: Option<ReflectionInfo>,
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct GrpcServerDependencies {
    grpc: Arc<insecure_server::InsecureGrpcServer>,
    #[cfg(feature = "tls")]
    grpcs: Arc<secure_server::SecureGrpcServer>,
    health: Arc<comprehensive::health::HealthReporter>,
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
pub struct GrpcServer {
    inner: std::sync::Mutex<Option<GrpcServerInner>>,
    grpc: Arc<insecure_server::InsecureGrpcServer>,
    #[cfg(feature = "tls")]
    grpcs: Arc<secure_server::SecureGrpcServer>,
    health_relay: AtomicTake<HealthRelay>,
}

impl GrpcServer {
    /// Install a serialised `FileDescriptorSet` proto into the server for
    /// gRPC server reflection purposes. A `FileDescriptorSet` covering the
    /// services to be served must be installed before calling
    /// [`GrpcServer::add_service`], or else if reflection is not desired
    /// then [`GrpcServer::disable_grpc_reflection`] should be called first
    /// instead.
    pub fn register_encoded_file_descriptor_set(&self, serialised_fds: &[u8]) {
        let mut lock = self.inner.lock().unwrap();
        if let Some(ref mut r) = lock.as_mut().unwrap().reflection {
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
    pub fn disable_grpc_reflection(&self) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(ref mut inner) = *inner {
            inner.reflection = None;
        }
    }

    /// Add a gRPC service to the server. This delegates to
    /// [`Routes::add_service`].
    ///
    /// For services added to the server by deriving the [`GrpcService`]
    /// trait, this is called automatically.
    pub fn add_service<S>(&self, svc: S) -> Result<(), ComprehensiveGrpcError>
    where
        S: Service<http::Request<BoxBody>, Response = http::Response<BoxBody>, Error = Infallible>
            + NamedService
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        let mut lock = self.inner.lock().unwrap();
        let Some(ref mut inner) = *lock else {
            return Err(ComprehensiveGrpcError::TooLateToConfigure("add_service"));
        };
        inner
            .reflection
            .as_ref()
            .map(|r| {
                r.registered_names
                    .get(S::NAME)
                    .ok_or(ComprehensiveGrpcError::NoServiceDescriptor(S::NAME))
            })
            .transpose()?;
        let routes = inner.routes.take().unwrap().add_service(svc);
        inner.routes = Some(routes);
        Ok(())
    }
}

impl Resource for GrpcServer {
    type Args = NoArgs;
    type Dependencies = GrpcServerDependencies;
    const NAME: &str = "gRPC server common";

    fn new(d: GrpcServerDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
        tonic_prometheus_layer_use_default_registry();
        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        Ok(Self {
            inner: std::sync::Mutex::new(Some(GrpcServerInner {
                routes: Some(Routes::new(health_service)),
                reflection: Some(ReflectionInfo::default()),
            })),
            grpc: d.grpc,
            #[cfg(feature = "tls")]
            grpcs: d.grpcs,
            health_relay: AtomicTake::new(HealthRelay {
                health_subscriber: d.health.subscribe(),
                health_reporter,
            }),
        })
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(feature = "tls"))]
        if self.grpc.addr.is_none() {
            log::warn!("No insecure gRPC listener, and secure gRPC is not available because feature \"tls\" is not built.");
            return Ok(());
        }

        #[cfg(feature = "tls")]
        if self.grpc.addr.is_none() && self.grpcs.addr.is_none() {
            log::warn!("No insecure or secure gRPC listener.");
            return Ok(());
        }

        let metrics_layer = tonic_prometheus_layer::MetricsLayer::new();
        let base = tonic::transport::Server::builder().layer(metrics_layer);
        let inner = self
            .inner
            .lock()
            .unwrap()
            .take()
            .ok_or(ComprehensiveGrpcError::InternalMissingConfiguration)?;

        let mut routes = inner.routes.unwrap();
        if let Some(r) = inner.reflection {
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

        #[cfg(not(feature = "tls"))]
        self.grpc.conf.put(ServingConfig { base, routes });

        #[cfg(feature = "tls")]
        match (self.grpc.addr.is_some(), self.grpcs.addr.is_some()) {
            (false, false) => (),
            (true, false) => self.grpc.conf.put(ServingConfig { base, routes }),
            (false, true) => self.grpcs.conf.put(ServingConfig { base, routes }),
            (true, true) => {
                self.grpc.conf.put(ServingConfig {
                    base: base.clone(),
                    routes: routes.clone(),
                });
                self.grpcs.conf.put(ServingConfig { base, routes });
            }
        }

        if let Some(mut health_relay) = self.health_relay.take() {
            health_relay.relay().await;
        }
        Ok(())
    }
}

pub use comprehensive_macros::GrpcService;
#[doc(hidden)]
pub use const_format; // Assumed by the derive macro

// This is necessary for using the macros defined in comprehensive_macros
// within this crate.
extern crate self as comprehensive_grpc;

/// Trait which can be derived to create a [`Resource`] already attached to
/// the server and provided with an implementation. The implementation must
/// itself implement both the [`Resource`] trait and the codegen'd trait for
/// the RPC service.
///
/// See the crate-level documentation for how to derive.
pub trait GrpcService: Resource {}

// Used by comprehensive_macros
#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct GrpcServiceDependencies<T: Resource> {
    pub implementation: Arc<T>,
    pub server: Arc<GrpcServer>,
}

#[cfg(test)]
mod server_tests;
#[cfg(test)]
mod testutil;
#[cfg(all(test, feature = "tls"))]
mod tls_testdata;
