use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive::{NoArgs, NoDependencies, ResourceDependencies};
use comprehensive_grpc::server::GrpcServer;
use futures::FutureExt;
use std::ffi::OsString;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(feature = "tls")]
use tokio_rustls::rustls;
#[cfg(feature = "tls")]
use tonic::transport::{Certificate, ClientTlsConfig};
use tonic_health::pb::{HealthCheckRequest, health_check_response, health_client};
use tonic_reflection::pb::v1::{
    ServerReflectionRequest, server_reflection_client, server_reflection_request,
    server_reflection_response,
};

pub mod testutil;

#[derive(ResourceDependencies)]
struct JustAServer {
    _server: Arc<GrpcServer>,
}

fn test_args(
    grpc_port: Option<u16>,
    grpcs_port: Option<u16>,
) -> impl IntoIterator<Item = OsString> {
    let mut v = vec!["cmd".into()];
    if let Some(p1) = grpc_port {
        v.push(format!("--grpc-port={}", p1).into());
        v.push("--grpc-bind-addr=::1".into());
    }
    #[cfg(feature = "tls")]
    if let Some(port) = grpcs_port {
        v.push(format!("--grpcs-port={}", port).into());
        v.push("--grpcs-bind-addr=::1".into());
        if let Some(p) = std::env::var_os("CARGO_MANIFEST_DIR") {
            let mut a = OsString::from("--key-path=");
            a.push(&p);
            a.push(OsString::from("/tls_testdata/user1.key.pem"));
            v.push(a);
            let mut a = OsString::from("--cert-path=");
            a.push(&p);
            a.push(OsString::from("/tls_testdata/user1.certificate.pem"));
            v.push(a);
            let mut a = OsString::from("--cacert=");
            a.push(p);
            a.push(OsString::from("/tls_testdata/ca.certificate.pem"));
            v.push(a);
        }
    }
    let _ = grpcs_port;
    v
}

fn plain_grpc_create() -> (comprehensive::Assembly<JustAServer>, SocketAddr) {
    let port = testutil::pick_unused_port();
    let argv = test_args(Some(port), None);
    let assembly = comprehensive::Assembly::<JustAServer>::new_from_argv(argv).unwrap();

    let addr = ([0, 0, 0, 0, 0, 0, 0, 1], port).into();
    (assembly, addr)
}

async fn plain_grpc_run<S, T, F>(assembly: comprehensive::Assembly<S>, addr: SocketAddr, t: T)
where
    S: ResourceDependencies + Send + 'static,
    T: FnOnce(tonic::transport::Channel) -> F,
    F: Future<Output = ()>,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    let j = tokio::spawn(async move {
        let _ = assembly
            .run_with_termination_signal(futures::stream::once(rx.map(|_| ())))
            .await;
    });
    testutil::wait_until_serving(&addr).await;

    let uri = format!("http://[::1]:{}/", addr.port()).parse().unwrap();
    let channel = tonic::transport::Channel::builder(uri)
        .connect()
        .await
        .expect("localhost channel");
    t(channel).await;

    let _ = tx.send(());
    let _ = j.await;
}

async fn plain_grpc_test<T, F>(t: T)
where
    T: FnOnce(tonic::transport::Channel) -> F,
    F: Future<Output = ()>,
{
    let (assembly, addr) = plain_grpc_create();
    plain_grpc_run(assembly, addr, t).await
}

async fn check_health(channel: tonic::transport::Channel) {
    let mut client = health_client::HealthClient::new(channel);
    let resp = client
        .check(HealthCheckRequest::default())
        .await
        .expect("Health.Check()")
        .into_inner();
    assert_eq!(
        resp.status,
        health_check_response::ServingStatus::Serving as i32
    );
}

#[tokio::test]
async fn nothing_enabled() {
    let argv = vec!["cmd"];
    let assembly = comprehensive::Assembly::<JustAServer>::new_from_argv(argv).unwrap();
    assert!(
        assembly
            .run_with_termination_signal(futures::stream::pending())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn grpc_health() {
    plain_grpc_test(check_health).await;
}

async fn check_server_reflection(channel: tonic::transport::Channel) {
    let mut client = server_reflection_client::ServerReflectionClient::new(channel);
    let stream = tokio_stream::iter([ServerReflectionRequest {
        message_request: Some(server_reflection_request::MessageRequest::ListServices(
            String::from(""),
        )),
        ..Default::default()
    }]);
    let resp = client
        .server_reflection_info(stream)
        .await
        .expect("ServerReflectionInfo()")
        .into_inner()
        .message()
        .await
        .expect("stream error")
        .expect("first stream item");
    assert!(match resp.message_response.expect("message_response") {
        server_reflection_response::MessageResponse::ListServicesResponse(_) => true,
        _ => false,
    });
}

#[tokio::test]
async fn grpc_reflection() {
    plain_grpc_test(check_server_reflection).await;
}

async fn check_greeter(channel: tonic::transport::Channel) {
    let mut client = testutil::pb::comprehensive::test_client::TestClient::new(channel);
    let resp = client.greet(()).await.expect("Test.Greet()").into_inner();
    assert_eq!(resp.message.expect("message field"), "hello");
}

#[derive(ResourceDependencies)]
struct OwnServer(Arc<testutil::HelloService>, Arc<GrpcServer>);

#[tokio::test]
async fn grpc_own_service() {
    let port = testutil::pick_unused_port();
    let argv = test_args(Some(port), None);
    let assembly = comprehensive::Assembly::<OwnServer>::new_from_argv(argv).unwrap();
    let _ = assembly.top.0;
    let _ = assembly.top.1;
    plain_grpc_run(
        assembly,
        ([0, 0, 0, 0, 0, 0, 0, 1], port).into(),
        check_greeter,
    )
    .await
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn grpcs_own_service() {
    let port = testutil::pick_unused_port();
    let argv = test_args(None, Some(port));
    let assembly = comprehensive::Assembly::<OwnServer>::new_from_argv(argv).unwrap();
    let _ = assembly.top.0;
    let _ = assembly.top.1;
    let addr = ([0, 0, 0, 0, 0, 0, 0, 1], port).into();

    let (tx, rx) = tokio::sync::oneshot::channel();
    let j = tokio::spawn(async move {
        let _ = assembly
            .run_with_termination_signal(futures::stream::once(rx.map(|_| ())))
            .await;
    });
    testutil::wait_until_serving(&addr).await;

    let channel = test_grpcs_channel(addr.port()).await;
    check_greeter(channel).await;

    let _ = tx.send(());
    let _ = j.await;
}

pub struct NoDescriptorService;

#[resource]
#[export_grpc(testutil::pb::comprehensive::test_server::TestServer)]
impl Resource for NoDescriptorService {
    fn new(
        _: NoDependencies,
        _: NoArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        Ok(Arc::new(Self))
    }
}

#[tonic::async_trait]
impl testutil::pb::comprehensive::test_server::Test for NoDescriptorService {
    async fn greet(
        &self,
        _: tonic::Request<()>,
    ) -> Result<tonic::Response<testutil::pb::comprehensive::GreetResponse>, tonic::Status> {
        Ok(tonic::Response::new(
            testutil::pb::comprehensive::GreetResponse {
                message: Some(String::from("hello")),
            },
        ))
    }
}

pub struct NoDescriptorButOverriddenService;

#[resource]
#[export(dyn comprehensive_grpc::GrpcService)]
impl Resource for NoDescriptorButOverriddenService {
    fn new(
        _: NoDependencies,
        _: NoArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        Ok(Arc::new(Self))
    }
}

impl comprehensive_grpc::GrpcService for NoDescriptorButOverriddenService {
    fn add_to_server(
        self: Arc<Self>,
        server: &mut comprehensive_grpc::server::GrpcServiceAdder,
    ) -> Result<(), comprehensive_grpc::ComprehensiveGrpcError> {
        // Disabling reflection is poorly supported right now, but if you
        // really want to do it, this is how.
        server.disable_grpc_reflection();
        server.add_service(testutil::pb::comprehensive::test_server::TestServer::from_arc(self))
    }
}

#[tonic::async_trait]
impl testutil::pb::comprehensive::test_server::Test for NoDescriptorButOverriddenService {
    async fn greet(
        &self,
        _: tonic::Request<()>,
    ) -> Result<tonic::Response<testutil::pb::comprehensive::GreetResponse>, tonic::Status> {
        Ok(tonic::Response::new(
            testutil::pb::comprehensive::GreetResponse {
                message: Some(String::from("hello")),
            },
        ))
    }
}

#[derive(ResourceDependencies)]
#[allow(dead_code)]
struct OwnBrokenServer(Arc<NoDescriptorService>, Arc<GrpcServer>);

#[tokio::test]
async fn fails_to_configure_without_descriptor() {
    let argv = test_args(Some(testutil::pick_unused_port()), None);
    match comprehensive::Assembly::<OwnBrokenServer>::new_from_argv(argv) {
        Ok(_) => {
            panic!("should fail");
        }
        Err(e) => {
            assert!(e.to_string().contains("No file descriptor set registered"));
        }
    }
}

async fn check_no_reflection(channel: tonic::transport::Channel) {
    let mut client = server_reflection_client::ServerReflectionClient::new(channel);
    let stream = tokio_stream::iter([ServerReflectionRequest {
        message_request: Some(server_reflection_request::MessageRequest::ListServices(
            String::from(""),
        )),
        ..Default::default()
    }]);
    let status = client
        .server_reflection_info(stream)
        .await
        .expect_err("reflection should be unimplemented")
        .code();
    assert_eq!(status, tonic::Code::Unimplemented);
}

#[derive(ResourceDependencies)]
struct NoReflectionServer(Arc<GrpcServer>, Arc<NoDescriptorButOverriddenService>);

#[tokio::test]
async fn without_reflection() {
    let port = testutil::pick_unused_port();
    let argv = test_args(Some(port), None);
    // This is not great at all, but at least it works.
    let assembly = comprehensive::Assembly::<NoReflectionServer>::new_from_argv(argv).unwrap();
    let _ = assembly.top.0;
    let _ = assembly.top.1;
    plain_grpc_run(
        assembly,
        ([0, 0, 0, 0, 0, 0, 0, 1], port).into(),
        check_no_reflection,
    )
    .await
}

#[cfg(feature = "tls")]
async fn test_grpcs_channel(port: u16) -> tonic::transport::Channel {
    let base: std::path::PathBuf = std::env::var_os("CARGO_MANIFEST_DIR").unwrap().into();
    let identity = tonic::transport::Identity::from_pem(
        std::fs::read(base.join("tls_testdata/user2.certificate.pem")).expect("cert"),
        std::fs::read(base.join("tls_testdata/user2.key.pem")).expect("key"),
    );
    let tls = ClientTlsConfig::new()
        .identity(identity)
        .ca_certificate(Certificate::from_pem(
            std::fs::read(base.join("tls_testdata/ca.certificate.pem")).expect("cacert"),
        ))
        .domain_name("user1");
    let uri = format!("https://[::1]:{}/", port).parse().unwrap();
    tonic::transport::Channel::builder(uri)
        .tls_config(tls)
        .expect("test ClientTlsConfig")
        .connect()
        .await
        .expect("localhost channel")
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn grpcs() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let port = testutil::pick_unused_port();
    let argv = test_args(None, Some(port));
    let assembly = comprehensive::Assembly::<JustAServer>::new_from_argv(argv).unwrap();

    let addr = ([0, 0, 0, 0, 0, 0, 0, 1], port).into();

    let (tx, rx) = tokio::sync::oneshot::channel();
    let j = tokio::spawn(async move {
        let _ = assembly
            .run_with_termination_signal(futures::stream::once(rx.map(|_| ())))
            .await;
    });
    testutil::wait_until_serving(&addr).await;

    let channel = test_grpcs_channel(addr.port()).await;
    check_health(channel).await;

    let _ = tx.send(());
    let _ = j.await;
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn grpc_and_grpcs() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let port_grpc = testutil::pick_unused_port();
    let port_grpcs = testutil::pick_unused_port();
    let argv = test_args(Some(port_grpc), Some(port_grpcs));
    let assembly = comprehensive::Assembly::<JustAServer>::new_from_argv(argv).unwrap();

    let addr_grpc = ([0, 0, 0, 0, 0, 0, 0, 1], port_grpc).into();
    let addr_grpcs = ([0, 0, 0, 0, 0, 0, 0, 1], port_grpcs).into();

    let (tx, rx) = tokio::sync::oneshot::channel();
    let j = tokio::spawn(async move {
        let _ = assembly
            .run_with_termination_signal(futures::stream::once(rx.map(|_| ())))
            .await;
    });
    testutil::wait_until_serving(&addr_grpc).await;
    testutil::wait_until_serving(&addr_grpcs).await;

    let uri = format!("http://[::1]:{}/", addr_grpc.port())
        .parse()
        .unwrap();
    let channel = tonic::transport::Channel::builder(uri)
        .connect()
        .await
        .expect("localhost channel");
    check_health(channel).await;

    let channel = test_grpcs_channel(addr_grpcs.port()).await;
    check_health(channel).await;

    let _ = tx.send(());
    let _ = j.await;
}
