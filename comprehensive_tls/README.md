<!-- cargo-rdme start -->

Comprenehsive [`Resource`] for loading a TLS key and certificate.

Usage:

```rust
#[derive(comprehensive::ResourceDependencies)]
struct ServerDependencies {
    tls: std::sync::Arc<comprehensive_tls::TlsConfig>,
}

impl comprehensive::Resource for Server {
    type Args = comprehensive::NoArgs;
    type Dependencies = ServerDependencies;
    const NAME: &str = "Very secure!";

    fn new(d: ServerDependencies, _: comprehensive::NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
        let _ = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(d.tls.cert_resolver()?);
        // ...more setup...
        Ok(Self)
    }
}
```

<!-- cargo-rdme end -->
