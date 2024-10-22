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
//! # Feature Flags
//!
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
/// | `--http_port`       | *none*     | TCP port number for insecure HTTP server. If unset, plain HTTP is not served. |
/// | `--http_bind_addr`  | `::`       | Binding IP address for HTTP. Used only if `--http_port` is set. |
/// | `--https_port`      | *none*     | TCP port number for secure HTTP server. If unset, HTTPS is not served. |
/// | `--https_bind_addr` | `::`       | Binding IP address for HTTPS. Used only if `--https_port` is set. |
/// | `--metrics_path`    | `/metrics` | HTTP and/or HTTPS path where metrics are served. Set to empty to disable. |
#[derive(clap::Args, Debug)]
#[group(id = "comprehensive_args")]
pub struct Args {
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

/// Provides access to the [`DeprecatedMonolith`] server.
///
/// This interface will be removed as components are factored out
/// from [`DeprecatedMonolith`] to their own [`Resource`] types.
pub struct DeprecatedMonolithInner {
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

async fn run_tasks<H>(http: H) -> Result<(), ComprehensiveError>
where
    H: Future<Output = Result<(), ComprehensiveError>> + FusedFuture,
{
    pin_mut!(http);
    loop {
        let (result, task_name) = select! {
            r = http => (r, "HTTP"),
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

        let http = server::http::HttpServer::new(args.http_server, &tls)?;
        Ok(Self(std::sync::Mutex::new(Some(DeprecatedMonolithInner {
            http,
        }))))
    }

    async fn run_with_termination_signal<'a>(
        &'a self,
        term: &'a ShutdownNotify<'a>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let inner = self.0.lock().unwrap().take().unwrap();
        let http = inner.http.run(term).fuse();
        run_tasks(http).fuse().await?;
        Ok(())
    }
}
