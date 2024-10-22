<!-- cargo-rdme start -->

[`comprehensive`] [`Resource`] types for gRPC serving

This crate provides [`Resource`] types for use in a [`comprehensive`]
[`Assembly`]. To use it, build an [`Assembly`] and include resources
from this crate in the dependency graph.

# Usage

There are 2 ways to use it:

## Derive resources that conjure the server and install themselves in it

A [`GrpcService`] is a [`Resource`] and depending upon it will cause
the server to run with the service in question (and others) installed:

```rust
use comprehensive::{NoArgs, NoDependencies, Resource, ResourceDependencies};
use comprehensive_grpc::GrpcService;

impl Resource for Implementation {
    type Args = NoArgs;
    type Dependencies = NoDependencies;
    const NAME: &str = "TestServer";

    fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {})
    }
}

#[tonic::async_trait]
impl pb::test_server::Test for Implementation {
    // ...
}

#[derive(GrpcService)]
#[implementation(Implementation)]
#[service(pb::test_server::TestServer)]
#[descriptor(pb::FILE_DESCRIPTOR_SET)]
struct TestService;

#[derive(ResourceDependencies)]
struct AutoServer {
    _s: std::sync::Arc<TestService>,
}
let assembly = comprehensive::Assembly::<AutoServer>::new().unwrap();
```

## Depend on [`GrpcServer`] directly

The server can bee configured to add gRPC services to it:

```rust
use comprehensive::ResourceDependencies;
use comprehensive_grpc::GrpcServer;

#[derive(ResourceDependencies)]
struct JustAServer {
    server: std::sync::Arc<GrpcServer>,
}

let assembly = comprehensive::Assembly::<JustAServer>::new().unwrap();
assembly.top.server.register_encoded_file_descriptor_set(
    pb::FILE_DESCRIPTOR_SET
);
assembly.top.server.add_service(
    pb::test_server::TestServer::new(Implementation{})
);
```

# Command line flags for the gRPC server

| Flag                | Default    | Meaning                 |
|---------------------|------------|-------------------------|
| `--grpc_port`       | *none*     | TCP port number for insecure gRPC server. If unset, plain gRPC is not served. |
| `--grpc_bind_addr`  | `::`       | Binding IP address for gRPC. Used only if `--grpc_port` is set. |
| `--grpcs_port`      | *none*     | TCP port number for secure gRPC server. If unset, gRPCs is not served. |
| `--grpcs_bind_addr` | `::`       | Binding IP address for gRPCs. Used only if `--grpcs_port` is set. |

# On descriptors

Because gRPC server reflection is very useful for diagnostics yet it is
too easy to forget to install the descriptors needed to make it happen,
[`comprehensive_grpc`] tries to insist that descriptors are installed
before services are added to the server.

To obtain file descriptors, put this in `build.rs`:

```rust
let fds_path =
    std::path::PathBuf::from(std::env::var("OUT_DIR").expect("$OUT_DIR")).join("fdset.bin");
tonic_build::configure()
    .file_descriptor_set_path(fds_path)
```

And this where you include your protos:

```rust
pub(crate) const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("fdset");
```

[`Assembly`]: comprehensive::Assembly

<!-- cargo-rdme end -->
