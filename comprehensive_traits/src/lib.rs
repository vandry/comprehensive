//! Shared trait definitions for common [`comprehensive`] resources
//!
//! This crate defines traits that are designed to be implemented and exported
//! by one [`Resource`] and consumed by another, so that the implementor and
//! consumer do not depend on one another.
//!
//! [`comprehensive`]: https://docs.rs/comprehensive/latest/comprehensive/
//! [`Resource`]: https://docs.rs/comprehensive/latest/comprehensive/v1/trait.Resource.html

#![warn(missing_docs)]

#[cfg(feature = "http_diag")]
pub mod http_diag;

#[cfg(feature = "tls_config")]
pub mod tls_config;
