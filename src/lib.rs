//! A harness for creating consistently-shaped servers will less boilerplate.
//!
//! Production-ready servers require a *comprehensive* collection of basic
//! features to enable easy deployment, integration, diagnostics, monitoring,
//! lifecycle management, and so forth. Individual features may be available
//! in the ecosystem, but each requires its own boilerplate to add and
//! configure. Especially when operating with a microservices paradigm, the
//! effort to bootstrap a basic batteries-included server may even outweigh
//! the application logic.
//!
//! Comprehensive's goal is that it should be easy to create a server with
//! a number of important basic features included by default, including:
//!
//! * Secure servers available by default for both gRPC (mTLS) and HTTP
//!   * easy to provision with keys and certificates using infrastructure
//!     like [cert-manager](https://cert-manager.io/) in Kubernetes.
//!   * dynamically reloaded so that certificate renewals happen
//! * Health checking endpoints for servers enabled by default.
//! * Metrics (which can be scraped by Prometheus) exported.
//!   * Common metrics like RPC counters automatically installed.
//! * Graceful shutdown
//! * Server reflection, ACLs, and more.
//!
//! This framework is *opinionated*, not because its decisions are considered
//! better than alternatives but because it's important for consistency.
//! Deployment, configuration, diagnostics, metrics collection and more
//! should happen in the same way across a whole zoo of different servers in
//! a cluster (or other collective environment).
//!
//! # Status
//!
//! Comprehensive is still in early development. Many more features are planned.
//!
//! # Hello world server
//!
//! ```
//! // Generated protobufs for gRPC
//! # #[cfg(feature = "grpc")]
//! mod pb {
//!     tonic::include_proto!("comprehensive");
//!     pub const FILE_DESCRIPTOR_SET: &[u8] =
//!         tonic::include_file_descriptor_set!("fdset");
//! }
//! # #[cfg(feature = "grpc")]
//! use pb::*;
//!
//! #[derive(clap::Args, Debug)]
//! struct Args {
//!     #[arg(long)]
//!     app_flag: Option<String>,
//! }
//!
//! #[derive(comprehensive::ResourceDependencies)]
//! struct ApplicationDependencies {
//!     // Temporary resource type while migrating!
//!     monolith: std::sync::Arc<comprehensive::DeprecatedMonolith>,
//! }
//!
//! struct ApplicationWorkResource;
//!
//! impl comprehensive::Resource for ApplicationWorkResource {
//!     type Args = Args;
//!     type Dependencies = ApplicationDependencies;
//!     const NAME: &str = "application";
//!
//!     fn new(d: ApplicationDependencies, args: Args) -> Result<Self, Box<dyn std::error::Error>> {
//!         # #[cfg(feature = "grpc")]
//!         let srv = TestServer{};
//!         # #[cfg(feature = "grpc")]
//!         d.monolith.configure(|b| Ok(b
//!             .register_encoded_file_descriptor_set(pb::FILE_DESCRIPTOR_SET)
//!             .add_grpc_service(pb::test_server::TestServer::new(srv))?
//!         ))?;
//!         Ok(Self)
//!     }
//! }
//!
//! #[derive(comprehensive::ResourceDependencies)]
//! struct TopDependencies(std::sync::Arc<ApplicationWorkResource>);
//! # struct TestServer {}
//! # #[cfg(feature = "grpc")]
//! # #[tonic::async_trait]
//! # impl pb::test_server::Test for TestServer {
//! #     async fn greet(&self, _: tonic::Request<()>) -> Result<tonic::Response<pb::GreetResponse>, tonic::Status> {
//! #         Ok(tonic::Response::new(pb::GreetResponse::default()))
//! #     }
//! # }
//!
//! #[tokio::main]
//! pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Required if TLS is needed.
//!     # #[cfg(feature = "tls")]
//!     let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
//!
//!     // Will start a gRPC server with or without TLS depending on flags,
//!     // with extra features such as server reflection, and also serve
//!     // HTTP and/or HTTPS (again, depending on flags) at least for metrics.
//!     comprehensive::Assembly::<TopDependencies>::new()?.run().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Feature Flags
//!
//! - `grpc`: Enables the gRPC server. Requires [tonic](https://crates.io/crates/tonic).
//! - `tls`: Enables secure versions of each protocol (currently gRPC and HTTP).
//!   Requires [rustls](https://crates.io/crates/rustls).
//!
//! Most features, such as HTTP and Prometheus metrics, are always available.

#![warn(missing_docs)]

use futures::FutureExt;
use futures::{future::FusedFuture, pin_mut, select};
use std::future::Future;

#[cfg(feature = "tls")]
use tokio_rustls::rustls;

pub mod assembly;
mod server;

pub use assembly::{
    Assembly, NoArgs, NoDependencies, Resource, ResourceDependencies, ShutdownNotify,
};

// This is necessary for using the macros defined in comprehensive_macros
// within this crate.
extern crate self as comprehensive;

#[cfg(feature = "tls")]
pub mod tls;
#[cfg(not(feature = "tls"))]
mod tls {
    pub(crate) struct TlsConfig {}

    #[cfg(test)]
    impl TlsConfig {
        pub(crate) fn for_tests(
            _: bool,
        ) -> Result<(Self, Option<tempfile::TempDir>), super::ComprehensiveError> {
            Ok((TlsConfig {}, None))
        }
    }
}

#[cfg(test)]
mod testutil;

/// Command line flags for the monolith
///
/// This struct is meant to be used as part of a [clap](https://crates.io/crates/clap)
/// Command Line Argument Parser. It makes flags available that will be used
/// to configure the Comprehensive components when they are built.
///
/// | Flag                | Default    | Meaning                 |
/// |---------------------|------------|-------------------------|
/// | `--grpc_port`       | *none*     | TCP port number for insecure gRPC server. If unset, plain gRPC is not served. |
/// | `--grpc_bind_addr`  | `::`       | Binding IP address for gRPC. Used only if `--grpc_port` is set. |
/// | `--grpcs_port`      | *none*     | TCP port number for secure gRPC server. If unset, gRPCs is not served. |
/// | `--grpcs_bind_addr` | `::`       | Binding IP address for gRPCs. Used only if `--grpcs_port` is set. |
/// | `--http_port`       | *none*     | TCP port number for insecure HTTP server. If unset, plain HTTP is not served. |
/// | `--http_bind_addr`  | `::`       | Binding IP address for HTTP. Used only if `--http_port` is set. |
/// | `--https_port`      | *none*     | TCP port number for secure HTTP server. If unset, HTTPS is not served. |
/// | `--https_bind_addr` | `::`       | Binding IP address for HTTPS. Used only if `--https_port` is set. |
/// | `--metrics_path`    | `/metrics` | HTTP and/or HTTPS path where metrics are served. Set to empty to disable. |
#[derive(clap::Args, Debug)]
#[group(id = "comprehensive_args")]
pub struct Args {
    #[cfg(feature = "grpc")]
    #[command(flatten)]
    grpc_server: server::grpc::Args,

    #[command(flatten)]
    http_server: server::http::Args,
}

/// Error type returned by various Comprehensive functions
#[derive(Debug)]
pub enum ComprehensiveError {
    /// Wrapper for std::io::Error
    IOError(std::io::Error),
    /// Wrapper for rustls::Error
    #[cfg(feature = "tls")]
    TLSError(rustls::Error),
    /// Indicates an attempt to configure one of the secure servers
    /// (gRPCs or HTTPS) without supplying the necessary command line
    /// flags for the private key and certificate.
    #[cfg(feature = "tls")]
    NoTlsFlags,
    /// Wrapper for tonic::transport::Error
    #[cfg(feature = "grpc")]
    TonicTransportError(tonic::transport::Error),
    /// Indicates an attempt to add a gRPC service without supplying its
    /// service descriptor first. Descriptors must be registered using
    /// [`DeprecatedMonolithInner::register_encoded_file_descriptor_set`] before calling
    /// [`DeprecatedMonolithInner::add_grpc_service`] to add the service. The reason this is
    /// an error is to help encourage server reflection (which is a valuable
    /// diagnostic tool) to be always available for every service.
    /// Unfortunately Tonic does not currently attach service descriptors to
    /// service traits so that this can be done automatically.
    ///
    /// To decline server reflection, call [`DeprecatedMonolithInner::disable_grpc_reflection`]
    /// before [`DeprecatedMonolithInner::add_grpc_service`] instead.
    #[cfg(feature = "grpc")]
    NoServiceDescriptor(&'static str),
}

impl std::fmt::Display for ComprehensiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IOError(ref e) => write!(f, "{}", e),
            #[cfg(feature = "tls")]
            Self::TLSError(ref e) => write!(f, "{}", e),
            #[cfg(feature = "tls")]
            Self::NoTlsFlags => write!(
                f,
                "cannot create secure server: --key_path and --cert_path not given"
            ),
            #[cfg(feature = "grpc")]
            Self::TonicTransportError(ref e) => write!(f, "{}", e),
            #[cfg(feature = "grpc")]
            Self::NoServiceDescriptor(name) => write!(f, "No file descriptor set registered covering {}. Register one with register_encoded_file_descriptor_set or call disable_reflection.", name),
        }
    }
}

impl std::error::Error for ComprehensiveError {}

impl From<std::io::Error> for ComprehensiveError {
    fn from(e: std::io::Error) -> Self {
        Self::IOError(e)
    }
}

#[cfg(feature = "tls")]
impl From<rustls::Error> for ComprehensiveError {
    fn from(e: rustls::Error) -> Self {
        Self::TLSError(e)
    }
}

#[cfg(feature = "grpc")]
impl From<tonic::transport::Error> for ComprehensiveError {
    fn from(e: tonic::transport::Error) -> Self {
        Self::TonicTransportError(e)
    }
}

/// Provides access to the [`DeprecatedMonolith`] server.
///
/// This interface will be removed as components are factored out
/// from [`DeprecatedMonolith`] to their own [`Resource`] types.
pub struct DeprecatedMonolithInner {
    #[cfg(feature = "grpc")]
    grpc: server::grpc::GrpcServer,
    http: server::http::HttpServer,
}

/// A [builder](https://rust-unofficial.github.io/patterns/patterns/creational/builder.html)
/// for Comprehensive servers
///
/// This will construct a server with all of the components that are both
/// feature-enabled and either active by default or configured to be active
/// through command line flags.
///
/// This interface will be removed as components are factored out
/// from [`DeprecatedMonolith`] to their own [`Resource`] types.
pub struct DeprecatedMonolith(std::sync::Mutex<Option<DeprecatedMonolithInner>>);

async fn run_tasks<H, G>(http: H, grpc: G) -> Result<(), ComprehensiveError>
where
    H: Future<Output = Result<(), ComprehensiveError>> + FusedFuture,
    G: Future<Output = Result<(), ComprehensiveError>> + FusedFuture,
{
    pin_mut!(http);
    pin_mut!(grpc);
    loop {
        let (result, task_name) = select! {
            r = http => (r, "HTTP"),
            r = grpc => (r, "gRPC"),
            complete => {
                return Ok(());
            }
        };
        if let Err(e) = result {
            log::error!("{} failed: {}", task_name, e);
            return Err(e);
        }
        log::info!("{} exited successfully", task_name);
    }
}

impl DeprecatedMonolith {
    /// Configure this monolith server. Accepts a closure that can receive
    /// and return the server builder state.
    ///
    /// This interface will be removed as components are factored out
    /// from [`DeprecatedMonolith`] to their own [`Resource`] types.
    pub fn configure(
        &self,
        mutator: impl FnOnce(
            DeprecatedMonolithInner,
        ) -> Result<DeprecatedMonolithInner, Box<dyn std::error::Error>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut inner = self.0.lock().unwrap();
        let builder = mutator(inner.take().unwrap())?;
        inner.replace(builder);
        Ok(())
    }
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct DeprecatedMonolithDependencies {
    #[cfg(feature = "tls")]
    tls: std::sync::Arc<tls::TlsConfig>,
}

impl Resource for DeprecatedMonolith {
    type Args = Args;
    type Dependencies = DeprecatedMonolithDependencies;
    const NAME: &str = "DeprecatedMonolith";

    fn new(
        d: DeprecatedMonolithDependencies,
        args: Args,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(feature = "tls")]
        let tls = d.tls;
        #[cfg(not(feature = "tls"))]
        let tls = {
            let _ = d;
            tls::TlsConfig {}
        };

        #[cfg(feature = "grpc")]
        let grpc = server::grpc::GrpcServer::new(args.grpc_server, &tls)?;

        let http = server::http::HttpServer::new(args.http_server, &tls)?;
        Ok(Self(std::sync::Mutex::new(Some(DeprecatedMonolithInner {
            #[cfg(feature = "grpc")]
            grpc,
            http,
        }))))
    }

    async fn run_with_termination_signal<'a>(
        &'a self,
        term: &'a ShutdownNotify<'a>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let inner = self.0.lock().unwrap().take().unwrap();
        let http = inner.http.run(term).fuse();

        #[cfg(feature = "grpc")]
        let grpc = inner.grpc.run(term).fuse();
        #[cfg(not(feature = "grpc"))]
        let grpc = std::future::ready(Ok(())).fuse();

        run_tasks(http, grpc).fuse().await?;
        Ok(())
    }
}
