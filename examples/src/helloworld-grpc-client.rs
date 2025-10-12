use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive_grpc::GrpcClient;
use std::sync::Arc;
use std::time::Duration;

// Generated protobufs for gRPC
mod pb {
    tonic::include_proto!("comprehensive");
}

#[derive(GrpcClient)]
struct Client(pb::test_client::TestClient<comprehensive_grpc::client::Channel>);

struct GreeterInALoop;

#[derive(clap::Args)]
struct GreeterInALoopArgs {
    #[arg(long, value_parser = humantime::parse_duration, default_value = "5s")]
    greet_interval: Duration,
}

#[resource]
impl Resource for GreeterInALoop {
    fn new(
        (client_resource, _): (
            Arc<Client>,
            std::marker::PhantomData<comprehensive_spiffe::SpiffeTlsProvider>,
        ),
        a: GreeterInALoopArgs,
        api: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        let mut client = client_resource.client();
        api.set_task(async move {
            loop {
                println!("{:?}", client.greet(tonic::Request::new(())).await);
                tokio::time::sleep(a.greet_interval).await;
            }
        });
        Ok(Arc::new(Self))
    }
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Will send gRPC greetings at regular intervals using a gRPC client
    // with or without TLS depending on flags, and also serve HTTP and/or
    // HTTPS (again, depending on flags) at least for metrics.
    comprehensive::Assembly::<(
        // Including this causes the greeter-in-a-loop to run.
        Arc<GreeterInALoop>,
        // Serves metrics!
        Arc<comprehensive_http::diag::HttpServer>,
    )>::new()?
    .run()
    .await?;
    Ok(())
}
