<!-- cargo-rdme start -->

A DNS resolver for [`comprehensive`]

This crate provides a DNS resolver for including in a
[`comprehensive::Assembly`]. Other [`Resource`]s that require DNS
resolution services can depend on this one to obtain a handle to
the singleton shared client.

It wraps a [`trust_dns_resolver::TokioAsyncResolver`].

There are currently no configuration parameters.

```rust
use comprehensive::{NoArgs, Resource, ResourceDependencies};
use comprehensive_dns::{DNSResolver, ResolverHandle};
use std::sync::Arc;

struct SomeResource(ResolverHandle);

#[derive(ResourceDependencies)]
struct SomeResourceDependencies(Arc<DNSResolver>);

impl Resource for SomeResource {
   type Args = NoArgs;
   type Dependencies = SomeResourceDependencies;
   const NAME: &str = "SomeResource";

   fn new(
       d: SomeResourceDependencies,
        _: NoArgs,
   ) -> Result<Self, Box<dyn std::error::Error>> {
       Ok(Self(d.0.resolver()))
   }

   async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
       println!("{:?}", self.0.as_ref().lookup_ip("example.org.").await);
       Ok(())
   }
}
```

<!-- cargo-rdme end -->
