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
//! # Examples
//!
//! [Hello World gRPC server]
//!
//! # Feature Flags
//!
//! - `tls`: Enables secure versions of each protocol (currently gRPC and HTTP).
//!   Requires [rustls](https://crates.io/crates/rustls).
//!
//! Most features, such as HTTP and Prometheus metrics, are always available.
//!
//! [Hello World gRPC server]: https://github.com/vandry/comprehensive/blob/master/examples/src/helloworld-grpc-server.rs

#![warn(missing_docs)]

#[cfg(feature = "tls")]
use tokio_rustls::rustls;

pub mod assembly;
pub mod diag;
pub mod http;

pub use assembly::{
    Assembly, NoArgs, NoDependencies, Resource, ResourceDependencies, ShutdownNotify,
};

// This is necessary for using the macros defined in comprehensive_macros
// within this crate.
extern crate self as comprehensive;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(test)]
mod testutil;

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
