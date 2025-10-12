//! A DNS resolver for [`comprehensive`]
//!
//! This crate provides a DNS resolver for including in a
//! [`comprehensive::Assembly`]. Other [`Resource`]s that require DNS
//! resolution services can depend on this one to obtain a handle to
//! the singleton shared client.
//!
//! It wraps a [`hickory_resolver::TokioResolver`].
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

use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive::{NoArgs, NoDependencies};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{Resolver, TokioResolver};
use std::sync::Arc;

/// [`comprehensive::Resource`] for DNS resolution. For DNS resolution
/// services, depend on this.
#[derive(Debug)]
pub struct DNSResolver(TokioResolver);

/// Handle to the DNS resolver. Call `.as_ref()` to get &[`TokioResolver`].
#[derive(Clone, Debug)]
pub struct ResolverHandle(Arc<DNSResolver>);

impl AsRef<TokioResolver> for ResolverHandle {
    fn as_ref(&self) -> &TokioResolver {
        &self.0.0
    }
}

impl DNSResolver {
    /// Obtain a shareable handle to the encapsulated resolver.
    pub fn resolver(self: Arc<Self>) -> ResolverHandle {
        ResolverHandle(self)
    }
}

#[resource]
impl Resource for DNSResolver {
    const NAME: &str = "hickory-resolver";

    fn new(
        _: NoDependencies,
        _: NoArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::io::Error> {
        let (resolver_config, mut resolver_opts) = read_system_conf()?;
        resolver_opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
        Ok(Arc::new(Self(
            Resolver::builder_with_config(resolver_config, TokioConnectionProvider::default())
                .with_options(resolver_opts)
                .build(),
        )))
    }
}
