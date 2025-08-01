use comprehensive::ResourceDependencies;
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

#[derive(ResourceDependencies)]
struct GreeterInALoopDependencies {
    client: Arc<Client>,
    _spiffe: std::marker::PhantomData<comprehensive_spiffe::SpiffeTlsProvider>,
}

#[resource]
impl Resource for GreeterInALoop {
    fn new(
        d: GreeterInALoopDependencies,
        a: GreeterInALoopArgs,
        api: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        let mut client = d.client.client();
        api.set_task(async move {
            loop {
                println!("{:?}", client.greet(tonic::Request::new(())).await);
                tokio::time::sleep(a.greet_interval).await;
            }
        });
        Ok(Arc::new(Self))
    }
}

#[derive(ResourceDependencies)]
struct TopDependencies {
    // Including this causes the greeter-in-a-loop to run.
    _greeter: Arc<GreeterInALoop>,
    // Serves metrics!
    _diag: Arc<comprehensive_http::diag::HttpServer>,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Will send gRPC greetings at regular intervals using a gRPC client
    // with or without TLS depending on flags, and also serve HTTP and/or
    // HTTPS (again, depending on flags) at least for metrics.
    comprehensive::Assembly::<TopDependencies>::new()?
        .run()
        .await?;
    Ok(())
}
