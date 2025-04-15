//! A DNS resolver for [`comprehensive`]
//!
//! This crate provides a DNS resolver for including in a
//! [`comprehensive::Assembly`]. Other [`Resource`]s that require DNS
//! resolution services can depend on this one to obtain a handle to
//! the singleton shared client.
//!
//! It wraps a [`trust_dns_resolver::TokioAsyncResolver`].
//!
//! There are currently no configuration parameters.
//!
//! ```
//! use comprehensive::{NoArgs, Resource, ResourceDependencies};
//! use comprehensive_dns::{DNSResolver, ResolverHandle};
//! use std::sync::Arc;
//!
//! struct SomeResource(ResolverHandle);
//!
//! #[derive(ResourceDependencies)]
//! struct SomeResourceDependencies(Arc<DNSResolver>);
//!
//! impl Resource for SomeResource {
//!    type Args = NoArgs;
//!    type Dependencies = SomeResourceDependencies;
//!    const NAME: &str = "SomeResource";
//!
//!    fn new(
//!        d: SomeResourceDependencies,
//!         _: NoArgs,
//!    ) -> Result<Self, Box<dyn std::error::Error>> {
//!        Ok(Self(d.0.resolver()))
//!    }
//!
//!    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
//!        println!("{:?}", self.0.as_ref().lookup_ip("example.org.").await);
//!        Ok(())
//!    }
//! }
//! ```

#![warn(missing_docs)]

use comprehensive::{NoArgs, NoDependencies, Resource};
use std::sync::Arc;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::system_conf::read_system_conf;

/// [`comprehensive::Resource`] for DNS resolution. For DNS resolution
/// services, depend on this.
#[derive(Debug)]
pub struct DNSResolver(TokioAsyncResolver);

/// Handle to the DNS resolver. Call `.as_ref()` to get &[`TokioAsyncResolver`].
#[derive(Clone, Debug)]
pub struct ResolverHandle(Arc<DNSResolver>);

impl AsRef<TokioAsyncResolver> for ResolverHandle {
    fn as_ref(&self) -> &TokioAsyncResolver {
        &self.0.0
    }
}

impl DNSResolver {
    /// Obtain a shareable handle to the encapsulated resolver.
    pub fn resolver(self: Arc<Self>) -> ResolverHandle {
        ResolverHandle(self)
    }
}

impl Resource for DNSResolver {
    type Args = NoArgs;
    type Dependencies = NoDependencies;
    const NAME: &str = "trust-dns-resolver";

    fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
        let (resolver_config, mut resolver_opts) = read_system_conf()?;
        resolver_opts.ip_strategy = trust_dns_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
        Ok(Self(TokioAsyncResolver::tokio(
            resolver_config,
            resolver_opts,
        )))
    }
}
