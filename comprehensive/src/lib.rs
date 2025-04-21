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
//! Comprehensive is still in development. Many more features are planned.
//!
//! # Examples
//!
//! - [Hello World gRPC server]
//! - [Hello World gRPC client]
//!
//! # Feature Flags
//!
//! - `tls`: Enables secure versions of each protocol (currently gRPC and HTTP).
//!   Requires [rustls](https://crates.io/crates/rustls).
//!
//! Most features, such as HTTP and Prometheus metrics, are always available.
//!
//! [Hello World gRPC server]: https://github.com/vandry/comprehensive/blob/master/examples/src/helloworld-grpc-server.rs
//! [Hello World gRPC client]: https://github.com/vandry/comprehensive/blob/master/examples/src/helloworld-grpc-client.rs

#![warn(missing_docs)]

#[cfg(feature = "tls")]
use tokio_rustls::rustls;

pub mod assembly;
pub mod diag;
pub mod health;
pub mod http;
pub mod v0;
pub mod v1;

mod shutdown;

pub use assembly::{Assembly, NoArgs, NoDependencies, ResourceDependencies};
pub use v0::{Resource, ShutdownNotify};

// This is necessary for using the macros defined in comprehensive_macros
// within this crate.
extern crate self as comprehensive;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(test)]
mod testutil;

#[doc(hidden)]
pub enum ResourceVariety {
    V0,
    V1,
    #[cfg(test)]
    Test,
}

/// Trait for expressing any version of resource: either [`v0::Resource`]
/// or [`v1::Resource`].
///
/// A requirement for a resource of any variety may be expressed as:
///
/// ```
/// struct ContainsAResource<T: comprehensive::AnyResource<U>, const U: usize> {
///     resource: std::sync::Arc<T>,
/// }
/// ```
pub trait AnyResource<const T: usize>: assembly::sealed::ResourceBase<T> {
    /// The name of this resource. Used in logs and diagnostics.
    const NAME: &str;
    /// The const generic parameter of this Resource. Occasionally
    /// necessary for hinting whicg variety of Resource is being supplied
    /// to meet a `T: AnyResource<U>` bound.
    const RESOURCE_VARIETY: usize = T;
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
