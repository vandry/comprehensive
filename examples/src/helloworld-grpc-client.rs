use comprehensive::{Resource, ResourceDependencies};
use comprehensive_grpc::GrpcClient;
use std::sync::Arc;
use std::time::Duration;

// Generated protobufs for gRPC
mod pb {
    tonic::include_proto!("comprehensive");
}

#[derive(GrpcClient)]
struct Client(
    pb::test_client::TestClient<comprehensive_grpc::client::Channel>,
    comprehensive_grpc::client::ClientWorker,
);

struct GreeterInALoop {
    client: Arc<Client>,
    greet_interval: Duration,
}

#[derive(clap::Args)]
struct GreeterInALoopArgs {
    #[arg(long, value_parser = humantime::parse_duration, default_value = "5s")]
    greet_interval: Duration,
}

#[derive(ResourceDependencies)]
struct GreeterInALoopDependencies(Arc<Client>);

impl Resource for GreeterInALoop {
    type Args = GreeterInALoopArgs;
    type Dependencies = GreeterInALoopDependencies;
    const NAME: &str = "GreeterInALoop";

    fn new(
        d: GreeterInALoopDependencies,
        a: GreeterInALoopArgs,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            client: d.0,
            greet_interval: a.greet_interval,
        })
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.client.client();
        loop {
            println!("{:?}", client.greet(tonic::Request::new(())).await);
            tokio::time::sleep(self.greet_interval).await;
        }
    }
}

#[derive(ResourceDependencies)]
struct TopDependencies {
    // Including this causes the greeter-in-a-loop to run.
    _greeter: Arc<GreeterInALoop>,
    // Serves metrics!
    _diag: Arc<comprehensive::diag::HttpServer>,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    // Required if TLS is needed.
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Will send gRPC greetings at regular intervals using a gRPC client
    // with or without TLS depending on flags, and also serve HTTP and/or
    // HTTPS (again, depending on flags) at least for metrics.
    comprehensive::Assembly::<TopDependencies>::new()?
        .run()
        .await?;
    Ok(())
}
