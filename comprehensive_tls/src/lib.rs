//! TLS support for Comprenehsive
//!
//! TLS functionality is made available to the [`comprehensive::Assembly`]
//! through an abstract [`comprehensive::Resource`] called [`TlsConfig`]
//! which dispatches to various concrete providers. The concrete providers
//! may source TLS configuration from different places such as files on disk
//! or the local SPIFFE agent etc...All implement the trait
//! [`TlsConfigProvider`].
//!
//! TLS parameters for clients and servers will be available to the
//! assembly as long as one concrete provider is present, initialises
//! successfully, and supplies data. If more than one concrete provider
//! does so then [`TlsConfig`] will select between them using such hints
//! as might be available such as SNI; all providers will get a chance
//! to verify remote peers.
//!
//! A simple "built-in default" provider [`TlsConfigFiles`] is implemented
//! in this crate which just loads a key, certificate, and trust bundle from
//! files named on the command line. Others exist in other crates.

#![warn(missing_docs)]
// Would impose a requirement for rustc 1.88
// https://github.com/rust-lang/rust/pull/132833
#![allow(clippy::collapsible_if)]

pub mod api;
pub mod crypto_provider;
#[cfg(feature = "diag")]
pub mod diag;
#[cfg(feature = "dispatch")]
pub mod dispatch;
#[cfg(feature = "files")]
pub mod files;
#[cfg(test)]
mod testdata;

pub use api::TlsConfigProvider;
pub use crypto_provider::RustlsCryptoProvider;
#[cfg(feature = "dispatch")]
pub use dispatch::{ClientAuthDisabled, ClientAuthEnabled, ComprehensiveTlsError, TlsConfig};
#[cfg(feature = "files")]
pub use files::TlsConfigFiles;
