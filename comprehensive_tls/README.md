<!-- cargo-rdme start -->

Comprenehsive [`Resource`] for loading a TLS key and certificate.

Usage:

```rust
use comprehensive::ResourceDependencies;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use std::sync::Arc;

#[derive(ResourceDependencies)]
struct ServerDependencies {
    tls: Arc<comprehensive_tls::TlsConfig>,
}

#[resource]
impl Resource for Server {
    fn new(
        d: ServerDependencies,
        _: comprehensive::NoArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let _ = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(d.tls.cert_resolver()?);
        // ...more setup...
        Ok(Arc::new(Self))
    }
}
```

<!-- cargo-rdme end -->
