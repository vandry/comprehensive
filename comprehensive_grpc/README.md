<!-- cargo-rdme start -->

[`comprehensive`] [`Resource`] types for gRPC client and server.

This crate provides [`Resource`] types for use in a [`comprehensive`]
[`Assembly`]. To use it, build an [`Assembly`] and include resources
from this crate in the dependency graph.

# Client Usage

Define a struct containing a [`tonic`] client wrapped around a channel
and derive [`GrpcClient`] on it. This will become a
[`comprehensive::v1::Resource`] that can be depended upon. Call `.client()`
to get a (cheap) clone of the gRPC client.

```rust
use comprehensive_grpc::GrpcClient;
use comprehensive_grpc::client::Channel;

#[derive(GrpcClient)]
struct MyClientResource(
    pb::test_client::TestClient<Channel>,
);

struct OtherResourceThatConsumesClient {
    the_client: std::sync::Arc<MyClientResource>,
}

impl OtherResourceThatConsumesClient {
    async fn something(&self) {
        let mut tonic_client = self.the_client.client();
        println!("{:?}", tonic_client.greet(()).await);
    }
}
```

# Server Usage

Derive resources that conjure the server and install themselves in it:

Any [`Resource`] that implements [`GrpcService`] and exports itself as a
trait resource for `dyn GrpcService` will be picked up automatically
by the server and served.

The `#[export_grpc]` attribute argument to the [`comprehensive::v1::resource`]
macro is a shortcut for `#[export(dyn GrpcService)]` and also
implementing the [`GrpcService`] trait.

```rust
use comprehensive::{NoArgs, NoDependencies, ResourceDependencies};
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive_grpc::GrpcService;

#[resource]
#[export_grpc(pb::test_server::TestServer)]
#[proto_descriptor(pb::FILE_DESCRIPTOR_SET)]
impl Resource for TestService {
    fn new(
        _: NoDependencies, _: NoArgs, _: &mut AssemblyRuntime<'_>
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        Ok(Arc::new(Self {}))
    }
}

#[tonic::async_trait]
impl pb::test_server::Test for TestService {
    // ...
}

#[derive(ResourceDependencies)]
struct AutoServer {
    _s: Arc<TestService>,
    _server: Arc<comprehensive_grpc::server::GrpcServer>,
}
let assembly = comprehensive::Assembly::<AutoServer>::new().unwrap();
```

# Command line flags for the gRPC client

Each flag is prefixed with the name of the resource that it belongs to,
converted to kebab case (`struct VerySpecialClient` →
`--very-special-client-`). See [`warm_channels::grpc_channel`] and
[`warm_channels::grpc::GRPCChannelConfig`] for details on most
parameters.

| Flag                       | Default    | Meaning                 |
|----------------------------|------------|-------------------------|
| `PREFIXuri`                | *none*     | URI identifying the backend gRPC server. |
| `PREFIXconnect-uri`        | *none*     | Alternate URI for name resolution. |
| `PREFIXn-subchannels-want` | 3          | Backend pool size. |
| etc...                     |            | More settings from [`warm_channels`] |

# Command line flags for the gRPC server

| Flag                | Default    | Meaning                 |
|---------------------|------------|-------------------------|
| `--grpc-port`       | *none*     | TCP port number for insecure gRPC server. If unset, plain gRPC is not served. |
| `--grpc-bind-addr`  | `::`       | Binding IP address for gRPC. Used only if `--grpc_port` is set. |
| `--grpcs-port`      | *none*     | TCP port number for secure gRPC server. If unset, gRPCs is not served. |
| `--grpcs-bind-addr` | `::`       | Binding IP address for gRPCs. Used only if `--grpcs_port` is set. |

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
[`Resource`]: comprehensive::v1::Resource

<!-- cargo-rdme end -->
