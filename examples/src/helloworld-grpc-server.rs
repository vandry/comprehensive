use comprehensive::{NoDependencies, Resource, ResourceDependencies};
use comprehensive_grpc::GrpcService;

// Generated protobufs for gRPC
mod pb {
    tonic::include_proto!("comprehensive");
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("fdset");
}

#[derive(clap::Args, Debug)]
struct ServiceImplementationArgs {
    #[arg(long)]
    app_flag: Option<String>,
}

struct ServiceImplementation;

impl Resource for ServiceImplementation {
    type Args = ServiceImplementationArgs;
    type Dependencies = NoDependencies;
    const NAME: &str = "gRPC service implementation";

    fn new(_: NoDependencies, args: ServiceImplementationArgs) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(app_flag) = args.app_flag {
            println!("Got --app_flag={}", app_flag);
        }
        Ok(Self)
    }
}

#[tonic::async_trait]
impl pb::test_server::Test for ServiceImplementation {
    async fn greet(&self, _: tonic::Request<()>) -> Result<tonic::Response<pb::GreetResponse>, tonic::Status> {
        Ok(tonic::Response::new(pb::GreetResponse::default()))
    }
}

#[derive(GrpcService)]
#[implementation(ServiceImplementation)]
#[service(pb::test_server::TestServer)]
#[descriptor(pb::FILE_DESCRIPTOR_SET)]
struct TestService;

#[derive(ResourceDependencies)]
struct TopDependencies {
    // Including this causes the gRPC server to run.
    _test_service: std::sync::Arc<TestService>,
    // Temporary resource type while migrating!
    _monolith: std::sync::Arc<comprehensive::DeprecatedMonolith>,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    // Required if TLS is needed.
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Will start a gRPC server with or without TLS depending on flags,
    // with extra features such as server reflection, and also serve
    // HTTP and/or HTTPS (again, depending on flags) at least for metrics.
    comprehensive::Assembly::<TopDependencies>::new()?.run().await?;
    Ok(())
}
