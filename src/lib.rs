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
//! use clap::Parser;
//!
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
//! #[derive(Parser, Debug)]
//! struct Args {
//!     // Adds Comprehensive's own command line flags to those defined below.
//!     #[command(flatten)]
//!     comprehensive: comprehensive::Args,
//!
//!     #[arg(long)]
//!     app_flag: Option<String>,
//! }
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
//!     let args = Args::parse();
//!     // Required if TLS is needed.
//!     # #[cfg(feature = "tls")]
//!     let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
//!
//!     // Will start a gRPC server with or without TLS depending on flags,
//!     // with extra features such as server reflection, and also serve
//!     // HTTP and/or HTTPS (again, depending on flags) at least for metrics.
//!     # #[cfg(feature = "grpc")]
//!     let srv = TestServer{};
//!     # #[cfg(feature = "grpc")]
//!     comprehensive::Server::builder(args.comprehensive)?
//!         .register_encoded_file_descriptor_set(pb::FILE_DESCRIPTOR_SET)
//!         .add_grpc_service(pb::test_server::TestServer::new(srv))?
//!         .run()
//!         .await?;
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
use tokio::sync::Notify;

#[cfg(feature = "tls")]
use tokio_rustls::rustls;

mod server;

#[cfg(feature = "tls")]
mod tls;
#[cfg(not(feature = "tls"))]
mod tls {
    pub(crate) struct TlsConfig {}

    impl TlsConfig {
        pub(crate) async fn run(self, _: &super::Notify) -> Result<(), super::ComprehensiveError> {
            Ok(())
        }

        #[cfg(test)]
        pub(crate) fn for_tests(
            _: bool,
        ) -> Result<(Self, Option<tempfile::TempDir>), super::ComprehensiveError> {
            Ok((TlsConfig {}, None))
        }
    }
}

#[cfg(test)]
mod testutil;

/// Command line flags for Comprehensive
///
/// This struct is meant to be used as part of a [clap](https://crates.io/crates/clap)
/// Command Line Argument Parser. It makes flags available that will be used
/// to configure the Comprehensive components when they are built.
///
/// | Flag                | Default    | Meaning                 |
/// |---------------------|------------|-------------------------|
/// | `--key_path`        | *none*     | Path to TLS key in PEM format. If unset, secure servers cannot be configured. |
/// | `--cert_path`       | *none*     | Path to TLS certificate in PEM format. If unset, secure servers cannot be configured. |
/// | `--cacert`          | *none*     | Path to TLS root certificate for verifying gRPCs clients, in PEM format. If unset, clients are not verified. |
/// | `--grpc_port`       | *none*     | TCP port number for insecure gRPC server. If unset, plain gRPC is not served. |
/// | `--grpc_bind_addr`  | `::`       | Binding IP address for gRPC. Used only if `--grpc_port` is set. |
/// | `--grpcs_port`      | *none*     | TCP port number for secure gRPC server. If unset, gRPCs is not served. |
/// | `--grpcs_bind_addr` | `::`       | Binding IP address for gRPCs. Used only if `--grpcs_port` is set. |
/// | `--http_port`       | *none*     | TCP port number for insecure HTTP server. If unset, plain HTTP is not served. |
/// | `--http_bind_addr`  | `::`       | Binding IP address for HTTP. Used only if `--http_port` is set. |
/// | `--https_port`      | *none*     | TCP port number for secure HTTP server. If unset, HTTPS is not served. |
/// | `--https_bind_addr` | `::`       | Binding IP address for HTTPS. Used only if `--https_port` is set. |
/// | `--metrics_path`    | `/metrics` | HTTP and/or HTTPS path where metrics are served. Set to empty to disable. |
///
/// Use it like this:
///
/// ```
/// use clap::Parser;
///
/// #[derive(Parser, Debug)]
/// struct Args {
///     // Adds Comprehensive's own command line flags to those defined below.
///     #[command(flatten)]
///     comprehensive: comprehensive::Args,
///
///     #[arg(long)]
///     app_flag: Option<String>,
/// }
///
/// #[tokio::main]
/// pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let args = Args::parse();
///     // [...]
///     let _ = comprehensive::Server::builder(args.comprehensive)?;
///     Ok(())
/// }
/// ```
#[derive(clap::Args, Debug)]
#[group(id = "comprehensive_args")]
pub struct Args {
    #[cfg(feature = "grpc")]
    #[command(flatten)]
    grpc_server: server::grpc::Args,

    #[command(flatten)]
    http_server: server::http::Args,

    #[cfg(feature = "tls")]
    #[command(flatten)]
    tls: tls::Args,
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
    /// [`Server::register_encoded_file_descriptor_set`] before calling
    /// [`Server::add_grpc_service`] to add the service. The reason this is
    /// an error is to help encourage server reflection (which is a valuable
    /// diagnostic tool) to be always available for every service.
    /// Unfortunately Tonic does not currently attach service descriptors to
    /// service traits so that this can be done automatically.
    ///
    /// To decline server reflection, call [`Server::disable_grpc_reflection`]
    /// before [`Server::add_grpc_service`] instead.
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

/// A [builder](https://rust-unofficial.github.io/patterns/patterns/creational/builder.html)
/// for Comprehensive servers
///
/// Call [`Server::builder`] to construct, and [`Server::run`] to execute.
///
/// This will construct a server with all of the components that are both
/// feature-enabled and either active by default or configured to be active
/// through command line flags.
pub struct Server {
    #[cfg(feature = "grpc")]
    grpc: server::grpc::GrpcServer,
    http: server::http::HttpServer,
    tls: tls::TlsConfig,
}

async fn run_tasks<T, H, G>(tls: T, http: H, grpc: G) -> Result<(), ComprehensiveError>
where
    T: Future<Output = Result<(), ComprehensiveError>> + FusedFuture,
    H: Future<Output = Result<(), ComprehensiveError>> + FusedFuture,
    G: Future<Output = Result<(), ComprehensiveError>> + FusedFuture,
{
    pin_mut!(tls);
    pin_mut!(http);
    pin_mut!(grpc);
    loop {
        let (result, task_name) = select! {
            r = tls => (r, "TLS"),
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

impl Server {
    /// Construct a Comprehensive server with all of the components that are
    /// both feature-enabled and either active by default or configured to be
    /// active through the command line flags supplied.
    pub fn builder(args: Args) -> Result<Self, ComprehensiveError> {
        #[cfg(feature = "tls")]
        let tls = tls::TlsConfig::new(args.tls)?;
        #[cfg(not(feature = "tls"))]
        let tls = tls::TlsConfig {};

        #[cfg(feature = "grpc")]
        let grpc = server::grpc::GrpcServer::new(args.grpc_server, &tls)?;

        let http = server::http::HttpServer::new(args.http_server, &tls)?;
        Ok(Self {
            #[cfg(feature = "grpc")]
            grpc,
            http,
            tls,
        })
    }

    /// Run a Comprehensive server asynchronously.
    ///
    /// This will return successfully either when there is no work to do
    /// (which is to say that none of the available servers have been
    /// configured to run) or when a graceful shutdown has happened (future
    /// feature). In this case, the return value is false if no work happened
    /// or true if some work happened but was shut down gracefully.
    /// Otherwise this will never return unless at least one of the configured
    /// servers fails. If this happens, all servers are stopped but only the
    /// first error is reported.
    pub async fn run(self) -> Result<bool, ComprehensiveError> {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut quitting = false;
        let shutdown_notify = Notify::new();

        let tls = self.tls.run(&shutdown_notify).fuse();
        let http = self.http.run(&shutdown_notify).fuse();

        #[cfg(feature = "grpc")]
        let grpc = self.grpc.run(&shutdown_notify).fuse();
        #[cfg(not(feature = "grpc"))]
        let grpc = std::future::ready(Ok(())).fuse();

        let tasks = run_tasks(tls, http, grpc).fuse();
        pin_mut!(tasks);
        loop {
            select! {
                _ = sigterm.recv().fuse() => {
                    if quitting {
                        log::warn!("SIGTERM received again; quitting immediately.");
                        break;
                    }
                    quitting = true;
                    log::warn!("SIGTERM received; shutting down");
                    shutdown_notify.notify_waiters();
                    continue;
                },
                r = tasks => {
                    return r.map(|_| quitting);
                }
            }
        }
        Ok(quitting)
    }
}
