<!-- cargo-rdme start -->

A harness for creating consistently-shaped servers will less boilerplate.

Production-ready servers require a *comprehensive* collection of basic
features to enable easy deployment, integration, diagnostics, monitoring,
lifecycle management, and so forth. Individual features may be available
in the ecosystem, but each requires its own boilerplate to add and
configure. Especially when operating with a microservices paradigm, the
effort to bootstrap a basic batteries-included server may even outweigh
the application logic.

Comprehensive's goal is that it should be easy to create a server with
a number of important basic features included by default, including:

* Secure servers available by default for both gRPC (mTLS) and HTTP
  * easy to provision with keys and certificates using infrastructure
    like [cert-manager](https://cert-manager.io/) in Kubernetes.
  * dynamically reloaded so that certificate renewals happen
* Health checking endpoints for servers enabled by default.
* Metrics (which can be scraped by Prometheus) exported.
  * Common metrics like RPC counters automatically installed.
* Graceful shutdown
* Server reflection, ACLs, and more.

This framework is *opinionated*, not because its decisions are considered
better than alternatives but because it's important for consistency.
Deployment, configuration, diagnostics, metrics collection and more
should happen in the same way across a whole zoo of different servers in
a cluster (or other collective environment).

# Status

Comprehensive is still in development. Many more features are planned.

# Examples

- [Hello World gRPC server]
- [Hello World gRPC client]

# Feature Flags

- `tls`: Enables secure versions of each protocol (currently gRPC and HTTP).
  Requires [rustls](https://crates.io/crates/rustls).

Most features, such as HTTP and Prometheus metrics, are always available.

[Hello World gRPC server]: https://github.com/vandry/comprehensive/blob/master/examples/src/helloworld-grpc-server.rs
[Hello World gRPC client]: https://github.com/vandry/comprehensive/blob/master/examples/src/helloworld-grpc-client.rs

<!-- cargo-rdme end -->
