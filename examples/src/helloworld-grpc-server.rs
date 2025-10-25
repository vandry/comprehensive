use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use std::marker::PhantomData;
use std::sync::Arc;

// Generated protobufs for gRPC
mod pb {
    tonic::include_proto!("comprehensive");
    pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("fdset");
}

#[derive(clap::Args, Debug)]
struct ServiceImplementationArgs {
    #[arg(long)]
    app_flag: Option<String>,
}

struct TestService;

#[resource]
#[export_grpc(pb::test_server::TestServer)]
#[proto_descriptor(pb::FILE_DESCRIPTOR_SET)]
impl Resource for TestService {
    fn new(
        _: (),
        args: ServiceImplementationArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        if let Some(app_flag) = args.app_flag {
            println!("Got --app_flag={}", app_flag);
        }
        Ok(Arc::new(Self))
    }
}

#[tonic::async_trait]
impl pb::test_server::Test for TestService {
    async fn greet(
        &self,
        _: tonic::Request<()>,
    ) -> Result<tonic::Response<pb::GreetResponse>, tonic::Status> {
        Ok(tonic::Response::new(pb::GreetResponse::default()))
    }
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    // Required if TLS is needed.
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Will start a gRPC server with or without TLS depending on flags,
    // with extra features such as server reflection, and also serve
    // HTTP and/or HTTPS (again, depending on flags) at least for metrics.
    comprehensive::Assembly::<(
        // Request a server (HTTPS or HTTP or both) to run.
        Arc<comprehensive_grpc::server::GrpcServer>,
        // Including this causes the gRPC server to run.
        PhantomData<TestService>,
        // Serves metrics!
        Arc<comprehensive_http::diag::HttpServer>,
        // Make SPIFFE available as an option for configuring TLS.
        std::marker::PhantomData<comprehensive_spiffe::SpiffeTlsProvider>,
    )>::new()?
    .run()
    .await?;
    Ok(())
}
