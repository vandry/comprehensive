//! [`comprehensive`] [`Resource`] types for gRPC client and server.
//!
//! This crate provides [`Resource`] types for use in a [`comprehensive`]
//! [`Assembly`]. To use it, build an [`Assembly`] and include resources
//! from this crate in the dependency graph.
//!
//! # Client Usage
//!
//! Define a struct containing a [`tonic`] client wrapped around a channel
//! and derive [`GrpcClient`] on it. This will become a
//! [`comprehensive::v1::Resource`] that can be depended upon. Call `.client()`
//! to get a (cheap) clone of the gRPC client.
//!
//! ```
//! # mod pb {
//! #     tonic::include_proto!("comprehensive");
//! # }
//! use comprehensive_grpc::GrpcClient;
//! use comprehensive_grpc::client::Channel;
//!
//! #[derive(GrpcClient)]
//! struct MyClientResource(
//!     pb::test_client::TestClient<Channel>,
//! );
//!
//! struct OtherResourceThatConsumesClient {
//!     the_client: std::sync::Arc<MyClientResource>,
//! }
//!
//! impl OtherResourceThatConsumesClient {
//!     async fn something(&self) {
//!         let mut tonic_client = self.the_client.client();
//!         println!("{:?}", tonic_client.greet(()).await);
//!     }
//! }
//! ```
//!
//! # Server Usage
//!
//! Derive resources that conjure the server and install themselves in it:
//!
//! Any [`Resource`] that implements [`GrpcService`] and exports itself as a
//! trait resource for `dyn GrpcService` will be picked up automatically
//! by the server and served.
//!
//! The `#[export_grpc]` attribute argument to the [`comprehensive::v1::resource`]
//! macro is a shortcut for `#[export(dyn GrpcService)]` and also
//! implementing the [`GrpcService`] trait.
//!
//! ```
//! # mod pb {
//! #     tonic::include_proto!("comprehensive");
//! #     pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("fdset");
//! # }
//! # struct TestService {}
//! # use std::sync::Arc;
//! use comprehensive::{NoArgs, NoDependencies, ResourceDependencies};
//! use comprehensive::v1::{AssemblyRuntime, Resource, resource};
//! use comprehensive_grpc::GrpcService;
//!
//! #[resource]
//! #[export_grpc(pb::test_server::TestServer)]
//! #[proto_descriptor(pb::FILE_DESCRIPTOR_SET)]
//! impl Resource for TestService {
//!     fn new(
//!         _: NoDependencies, _: NoArgs, _: &mut AssemblyRuntime<'_>
//!     ) -> Result<Arc<Self>, std::convert::Infallible> {
//!         Ok(Arc::new(Self {}))
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
//!
//! #[derive(ResourceDependencies)]
//! struct AutoServer {
//!     _s: Arc<TestService>,
//!     _server: Arc<comprehensive_grpc::server::GrpcServer>,
//! }
//! let assembly = comprehensive::Assembly::<AutoServer>::new().unwrap();
//! ```
//!
//! # Command line flags for the gRPC client
//!
//! Each flag is prefixed with the name of the resource that it belongs to,
//! converted to kebab case (`struct VerySpecialClient` →
//! `--very-special-client-`). See [`warm_channels::grpc_channel`] and
//! [`warm_channels::grpc::GRPCChannelConfig`] for details on most
//! parameters.
//!
//! | Flag                       | Default    | Meaning                 |
//! |----------------------------|------------|-------------------------|
//! | `PREFIXuri`                | *none*     | URI identifying the backend gRPC server. |
//! | `PREFIXconnect-uri`        | *none*     | Alternate URI for name resolution. |
//! | `PREFIXn-subchannels-want` | 3          | Backend pool size. |
//! | etc...                     |            | More settings from [`warm_channels`] |
//!
//! # Command line flags for the gRPC server
//!
//! | Flag                | Default    | Meaning                 |
//! |---------------------|------------|-------------------------|
//! | `--grpc-port`       | *none*     | TCP port number for insecure gRPC server. If unset, plain gRPC is not served. |
//! | `--grpc-bind-addr`  | `::`       | Binding IP address for gRPC. Used only if `--grpc_port` is set. |
//! | `--grpcs-port`      | *none*     | TCP port number for secure gRPC server. If unset, gRPCs is not served. |
//! | `--grpcs-bind-addr` | `::`       | Binding IP address for gRPCs. Used only if `--grpcs_port` is set. |
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
//! [`Resource`]: comprehensive::v1::Resource

#![warn(missing_docs)]

use std::sync::Arc;
use thiserror::Error;

pub mod client;
pub mod server;

#[cfg(feature = "tls")]
mod incoming;
#[cfg(all(test, feature = "tls"))]
mod tls_test;

/// Trait which can be derived to create a [`Resource`] already attached to
/// the server and provided with an implementation. The implementation must
/// itself implement both the [`Resource`] trait and the codegen'd trait for
/// the RPC service.
///
/// See the crate-level documentation for how to derive.
///
/// [`Resource`]: comprehensive::v1::Resource
pub trait GrpcService {
    /// The gRPC server will call this method on every discovered
    /// [`GrpcService`] to request the service to install itself in the server.
    fn add_to_server(
        self: Arc<Self>,
        server: &mut server::GrpcServiceAdder,
    ) -> Result<(), ComprehensiveGrpcError>;
}

fn tonic_prometheus_layer_use_default_registry() {
    let _ = tonic_prometheus_layer::metrics::try_init_settings(
        tonic_prometheus_layer::metrics::GlobalSettings {
            registry: prometheus::default_registry().clone(), // Arc
            ..Default::default()
        },
    );
}

/// Error type returned by various Comprehensive gRPC functions
#[derive(Debug, Error)]
pub enum ComprehensiveGrpcError {
    /// Wrapper for [`std::io::Error`].
    #[error("{0}")]
    IOError(#[from] std::io::Error),
    /// An error from [`tonic`].
    #[error("{0}")]
    TonicTransportError(#[from] tonic::transport::Error),
    /// Indicates an attempt to add a gRPC service without supplying its
    /// service descriptor first. Descriptors must be registered using
    /// [`GrpcServiceAdder::register_encoded_file_descriptor_set`] before calling
    /// [`GrpcServiceAdder::add_service`] to add the service. The reason this is
    /// an error is to help encourage server reflection (which is a valuable
    /// diagnostic tool) to be always available for every service.
    /// Unfortunately Tonic does not currently attach service descriptors to
    /// service traits so that this can be done automatically.
    ///
    /// To decline server reflection, call
    /// [`GrpcServiceAdder::disable_grpc_reflection`]
    /// before [`GrpcServiceAdder::add_service`] instead.
    ///
    /// [`GrpcServiceAdder::add_service`]: server::GrpcServiceAdder::add_service
    /// [`GrpcServiceAdder::disable_grpc_reflection`]: server::GrpcServiceAdder::disable_grpc_reflection
    /// [`GrpcServiceAdder::register_encoded_file_descriptor_set`]: server::GrpcServiceAdder::register_encoded_file_descriptor_set
    #[error(
        "No file descriptor set registered covering {0}. Register one with register_encoded_file_descriptor_set or call disable_reflection."
    )]
    NoServiceDescriptor(&'static str),
    /// gRPCs serving is requested but no TLS parameters are available.
    #[cfg(feature = "tls")]
    #[error("gRPCs serving is requested but no TLS parameters are available")]
    NoTlsProvider,
}

pub use comprehensive_macros::GrpcClient;

// This is necessary for using the macros defined in comprehensive_macros
// within this crate.
extern crate self as comprehensive_grpc;
