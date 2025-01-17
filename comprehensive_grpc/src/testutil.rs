use comprehensive::{NoArgs, NoDependencies, Resource};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener};
use tokio::net::TcpStream;

pub(crate) mod pb {
    pub(crate) mod comprehensive {
        tonic::include_proto!("comprehensive");
        pub(crate) const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("fdset");
    }
}

pub(crate) fn pick_unused_port(not_this_one: Option<u16>) -> u16 {
    let start = rand::random::<u16>() & 0x7fff;
    for low_bits in start..start + 50 {
        let port = (low_bits & 0x7fff) | 0x8000;
        if let Some(banned) = not_this_one {
            if port == banned {
                continue;
            }
        }
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), port);
        if TcpListener::bind(addr).is_ok() {
            return port;
        }
    }
    panic!("Cannot find a free TCP port");
}

pub(crate) async fn wait_until_serving(addr: &SocketAddr) {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[cfg(feature = "tls")]
pub(crate) mod tls {
    pub(crate) struct MockTlsConfig;

    impl comprehensive::Resource for MockTlsConfig {
        type Args = comprehensive::NoArgs;
        type Dependencies = comprehensive::NoDependencies;
        const NAME: &str = "Mock TlsConfig for tests";

        fn new(
            _: comprehensive::NoDependencies,
            _: comprehensive::NoArgs,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self)
        }
    }

    pub(crate) struct TlsDataSnapshot {
        pub(crate) key: Vec<u8>,
        pub(crate) cert: Vec<u8>,
        pub(crate) cacert: Option<Vec<u8>>,
    }

    impl MockTlsConfig {
        pub fn snapshot(&self) -> Result<TlsDataSnapshot, std::convert::Infallible> {
            Ok(TlsDataSnapshot {
                key: crate::tls_testdata::USER1_KEY.into(),
                cert: crate::tls_testdata::USER1_CERT.into(),
                cacert: Some(crate::tls_testdata::CACERT.into()),
            })
        }
    }
}

pub(crate) struct TestServer;

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
        Ok(tonic::Response::new(
            pb::comprehensive::GreetResponse {
                message: Some(String::from("hello")),
            },
        ))
    }
}

#[derive(crate::GrpcService)]
#[implementation(TestServer)]
#[service(pb::comprehensive::test_server::TestServer)]
#[descriptor(pb::comprehensive::FILE_DESCRIPTOR_SET)]
pub(crate) struct HelloService;
