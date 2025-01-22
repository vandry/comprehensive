use atomic_take::AtomicTake;
use comprehensive::{NoArgs, NoDependencies, Resource, ResourceDependencies};
use comprehensive_grpc::client::Channel;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;

pub mod pb {
    pub mod comprehensive {
        tonic::include_proto!("comprehensive");
        pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("fdset");
    }
}

use pb::comprehensive::GreetResponse;

pub fn pick_unused_port() -> u16 {
    static ALREADY_PICKED: Mutex<[u64; 32768 / 64]> = Mutex::new([0; 32768 / 64]);
    let start = rand::random::<u16>() & 0x7fff;
    let mut picked = ALREADY_PICKED.lock().unwrap();
    for low_bits in start..start + 50 {
        if picked[low_bits as usize / 64] & (1 << (low_bits & 63)) != 0 {
            continue;
        }
        let port = (low_bits & 0x7fff) | 0x8000;
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), port);
        if TcpListener::bind(addr).is_ok() {
            picked[low_bits as usize / 64] |= 1 << (low_bits & 63);
            return port;
        }
    }
    panic!("Cannot find a free TCP port");
}

pub async fn wait_until_serving(addr: &SocketAddr) {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

pub struct TestServer;

impl Resource for TestServer {
    type Args = NoArgs;
    type Dependencies = NoDependencies;
    const NAME: &str = "TestServer";

    fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self)
    }
}

#[tonic::async_trait]
impl pb::comprehensive::test_server::Test for TestServer {
    async fn greet(
        &self,
        _: tonic::Request<()>,
    ) -> Result<tonic::Response<pb::comprehensive::GreetResponse>, tonic::Status> {
        Ok(tonic::Response::new(pb::comprehensive::GreetResponse {
            message: Some(String::from("hello")),
        }))
    }
}

#[derive(comprehensive_grpc::GrpcService)]
#[implementation(TestServer)]
#[service(pb::comprehensive::test_server::TestServer)]
#[descriptor(pb::comprehensive::FILE_DESCRIPTOR_SET)]
pub struct HelloService;

pub trait EndToEndClient: Resource + Send + Sync + 'static {
    fn test_client(&self) -> pb::comprehensive::test_client::TestClient<Channel>;
}

#[derive(ResourceDependencies)]
pub struct EndToEndTesterDependencies<T: EndToEndClient>(Arc<T>);

type Msg = Result<tonic::Response<GreetResponse>, tonic::Status>;

pub struct EndToEndTester<T: EndToEndClient> {
    client: Arc<T>,
    tx: AtomicTake<tokio::sync::oneshot::Sender<Msg>>,
    pub rx: AtomicTake<tokio::sync::oneshot::Receiver<Msg>>,
}

impl<T: EndToEndClient> Resource for EndToEndTester<T> {
    type Args = NoArgs;
    type Dependencies = EndToEndTesterDependencies<T>;
    const NAME: &str = "EndToEndTester";

    fn new(
        d: EndToEndTesterDependencies<T>,
        _: NoArgs,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Ok(Self {
            client: d.0,
            tx: AtomicTake::new(tx),
            rx: AtomicTake::new(rx),
        })
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.client.test_client();
        let tx = self.tx.take().unwrap();
        let _ = tx.send(client.greet(()).await);
        Ok(())
    }
}

#[derive(ResourceDependencies)]
pub struct EndToEnd<T: EndToEndClient> {
    _s: Arc<HelloService>,
    pub tester: Arc<EndToEndTester<T>>,
}
