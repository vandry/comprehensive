<!-- cargo-rdme start -->

[`comprehensive`] [`Resource`] types for HTTP server.

This crate provides [`Resource`] types for use in a [`comprehensive`]
[`Assembly`]. To use it, build an [`Assembly`] and include resources
from this crate in the dependency graph.

# HTTP (and HTTPS) Server

One or more HTTP servers can be run by including a [`Resource`] of
type `HttpServer<FooServer>` where `FooServer` has derived
[`HttpServingInstance`]. See the [`server`] module docs.

# Diagnostics Instance

The [`diag`] module implements a [`HttpServingInstance`] specifically
intended to serve content for diagnostics and other internal functions
like metrics serving. The idea is that the endpoint for this server
is not exposed to end users.

[`Assembly`]: comprehensive::Assembly
[`Resource`]: comprehensive::v1::Resource

<!-- cargo-rdme end -->
