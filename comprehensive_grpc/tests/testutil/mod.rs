use atomic_take::AtomicTake;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive::{AnyResource, NoArgs, NoDependencies, ResourceDependencies};
use comprehensive_grpc::client::Channel;
use std::marker::PhantomData;
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

pub struct HelloService;

#[resource]
#[export_grpc(pb::comprehensive::test_server::TestServer)]
#[proto_descriptor(pb::comprehensive::FILE_DESCRIPTOR_SET)]
impl Resource for HelloService {
    fn new(
        _: NoDependencies,
        _: NoArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        Ok(Arc::new(Self))
    }
}

#[tonic::async_trait]
impl pb::comprehensive::test_server::Test for HelloService {
    async fn greet(
        &self,
        req: tonic::Request<()>,
    ) -> Result<tonic::Response<pb::comprehensive::GreetResponse>, tonic::Status> {
        if req
            .extensions()
            .get::<tonic::transport::server::TcpConnectInfo>()
            .is_none()
        {
            return Err(tonic::Status::data_loss("No remote_addr"));
        }
        Ok(tonic::Response::new(pb::comprehensive::GreetResponse {
            message: Some(String::from("hello")),
        }))
    }
}

pub trait EndToEndClient: AnyResource + Send + Sync + 'static {
    fn test_client(&self) -> pb::comprehensive::test_client::TestClient<Channel>;
}

#[derive(ResourceDependencies)]
pub struct EndToEndTesterDependencies<T: EndToEndClient>(Arc<T>);

type Msg = Result<tonic::Response<GreetResponse>, tonic::Status>;

pub struct EndToEndTester<T: EndToEndClient> {
    pub rx: AtomicTake<tokio::sync::oneshot::Receiver<Msg>>,
    _t: PhantomData<T>,
}

#[resource]
impl<T: EndToEndClient> Resource for EndToEndTester<T> {
    fn new(
        d: EndToEndTesterDependencies<T>,
        _: NoArgs,
        api: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        api.set_task(async move {
            let mut client = d.0.test_client();
            let _ = tx.send(client.greet(()).await);
            Ok(())
        });
        Ok(Arc::new(Self {
            rx: AtomicTake::new(rx),
            _t: PhantomData,
        }))
    }
}

#[derive(ResourceDependencies)]
pub struct EndToEnd<T: EndToEndClient> {
    _s: Arc<HelloService>,
    pub tester: Arc<EndToEndTester<T>>,
    _server: Arc<comprehensive_grpc::server::GrpcServer>,
}
