//! Provide access to the process-global default [`CryptoProvider`] if there
//! is one, otherwise the Comprehensive-wide default one.

use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use rustls::crypto::CryptoProvider;
use std::sync::Arc;

/// A [`comprehensive`] [`Resource`] which makes a global [`CryptoProvider`]
/// available.
pub struct RustlsCryptoProvider(Arc<CryptoProvider>);

impl RustlsCryptoProvider {
    /// Provide access to the process-global default [`CryptoProvider`] if there
    /// is one, otherwise the Comprehensive-wide default one.
    pub fn crypto_provider(&self) -> Arc<CryptoProvider> {
        Arc::clone(&self.0)
    }
}

#[resource]
impl Resource for RustlsCryptoProvider {
    fn new(
        _: comprehensive::NoDependencies,
        _: comprehensive::NoArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        Ok(Arc::new(Self(
            CryptoProvider::get_default()
                .cloned()
                .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
        )))
    }
}
