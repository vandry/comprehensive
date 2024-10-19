#[cfg(feature = "tls")]
use futures::pin_mut;
use http::{Request, Response};
use prost::Message;
use prost_types::FileDescriptorSet;
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use tonic::body::BoxBody;
use tonic::server::NamedService;
use tonic::service::Routes;
use tonic::transport::Server;
use tonic_prometheus_layer::MetricsLayer;
use tower::Service;

use crate::tls;
use crate::ComprehensiveError;

#[derive(clap::Args, Debug)]
#[group(id = "comprehensive_grpc_args")]
pub(crate) struct Args {
    #[arg(long)]
    grpc_port: Option<u16>,

    #[arg(long, default_value = "::")]
    grpc_bind_addr: IpAddr,

    #[cfg(feature = "tls")]
    #[arg(long)]
    grpcs_port: Option<u16>,

    #[cfg(feature = "tls")]
    #[arg(long, default_value = "::")]
    grpcs_bind_addr: IpAddr,
}

pub type TonicServer = Server<tower_layer::Stack<MetricsLayer, tower_layer::Identity>>;

#[derive(Debug, Default)]
struct ReflectionInfo {
    fds: Vec<FileDescriptorSet>,
    registered_names: HashSet<String>,
}

#[derive(Debug)]
pub(crate) struct GrpcServer {
    routes: Routes,
    reflection: Option<ReflectionInfo>,
    grpc_server: Option<(SocketAddr, TonicServer)>,
    #[cfg(feature = "tls")]
    grpcs_server: Option<(SocketAddr, TonicServer)>,
}

#[cfg(feature = "tls")]
fn make_grpc(i: IpAddr, p: u16, base: TonicServer) -> Option<(SocketAddr, TonicServer)> {
    Some(((i, p).into(), base))
}

#[cfg(feature = "tls")]
fn make_grpcs(
    i: IpAddr,
    p: u16,
    base: TonicServer,
    tlsc: &tls::TlsConfig,
) -> Result<Option<(SocketAddr, TonicServer)>, ComprehensiveError> {
    Ok(Some(((i, p).into(), base.tls_config(tlsc.snapshot()?)?)))
}

impl GrpcServer {
    pub(crate) fn new(args: Args, tlsc: &tls::TlsConfig) -> Result<Self, ComprehensiveError> {
        let _ = tonic_prometheus_layer::metrics::try_init_settings(
            tonic_prometheus_layer::metrics::GlobalSettings {
                registry: prometheus::default_registry().clone(), // Arc
                ..Default::default()
            },
        );

        let metrics_layer = tonic_prometheus_layer::MetricsLayer::new();
        let base = Server::builder().layer(metrics_layer);

        #[cfg(feature = "tls")]
        let (grpc_server, grpcs_server) = match (args.grpc_port, args.grpcs_port) {
            (Some(gp), Some(gsp)) => {
                let g = make_grpc(args.grpc_bind_addr, gp, base.clone());
                let gs = make_grpcs(args.grpcs_bind_addr, gsp, base, tlsc)?;
                (g, gs)
            }
            (Some(gp), None) => (make_grpc(args.grpc_bind_addr, gp, base), None),
            (None, Some(gsp)) => (None, make_grpcs(args.grpcs_bind_addr, gsp, base, tlsc)?),
            (None, None) => (None, None),
        };

        #[cfg(not(feature = "tls"))]
        let grpc_server = args
            .grpc_port
            .map(|p| ((args.grpc_bind_addr, p).into(), base));

        #[cfg(not(feature = "tls"))]
        let _ = tlsc;

        let (_health_reporter, health_service) = tonic_health::server::health_reporter();
        Ok(Self {
            routes: Routes::new(health_service),
            reflection: Some(ReflectionInfo::default()),
            grpc_server,
            #[cfg(feature = "tls")]
            grpcs_server,
        })
    }

    pub(crate) async fn run<'a>(
        self,
        shutdown_signal: &'a crate::ShutdownNotify<'a>,
    ) -> Result<(), ComprehensiveError> {
        let mut routes = self.routes;

        if let Some(r) = self.reflection {
            let mut rb = tonic_reflection::server::Builder::configure()
                .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET);
            for entry in r.fds.into_iter() {
                rb = rb.register_file_descriptor_set(entry);
            }
            match rb.build_v1() {
                Ok(svc) => {
                    routes = routes.add_service(svc);
                }
                Err(e) => {
                    log::error!("Error creating gRPC reflection service: {}", e);
                }
            }
        }

        self.grpc_server.as_ref().inspect(|(ref a, _)| {
            log::info!("Insecure gRPC server listening on {}", a);
        });
        #[cfg(feature = "tls")]
        self.grpcs_server.as_ref().inspect(|(ref a, _)| {
            log::info!("Secure gRPC server listening on {}", a);
        });

        #[cfg(feature = "tls")]
        {
            match (self.grpc_server, self.grpcs_server) {
                (Some((a1, mut s1)), Some((a2, mut s2))) => {
                    let s1 = s1
                        .add_routes(routes.clone())
                        .serve_with_shutdown(a1, shutdown_signal.subscribe());
                    let s2 = s2
                        .add_routes(routes)
                        .serve_with_shutdown(a2, shutdown_signal.subscribe());
                    pin_mut!(s1);
                    pin_mut!(s2);
                    futures::future::select(s1, s2).await.factor_first().0
                }
                (Some((a1, mut s1)), None) => {
                    s1.add_routes(routes)
                        .serve_with_shutdown(a1, shutdown_signal.subscribe())
                        .await
                }
                (None, Some((a2, mut s2))) => {
                    s2.add_routes(routes)
                        .serve_with_shutdown(a2, shutdown_signal.subscribe())
                        .await
                }
                (None, None) => std::future::ready(Ok(())).await,
            }
            .map_err(|e| e.into())
        }

        #[cfg(not(feature = "tls"))]
        {
            match self.grpc_server {
                Some((a1, mut s1)) => {
                    s1.add_routes(routes)
                        .serve_with_shutdown(a1, shutdown_signal.subscribe())
                        .await
                }
                None => std::future::ready(Ok(())).await,
            }
            .map_err(|e| e.into())
        }
    }

    pub fn register_encoded_file_descriptor_set(self, serialised_fds: &[u8]) -> Self {
        let mut reflection = self.reflection;
        if let Some(ref mut r) = reflection {
            match FileDescriptorSet::decode(serialised_fds) {
                Ok(fds) => {
                    for f in &fds.file {
                        for s in &f.service {
                            if let Some(ref name) = s.name {
                                r.registered_names.insert(if let Some(ref pkg) = f.package {
                                    format!("{}.{}", pkg, name)
                                } else {
                                    String::from(name)
                                });
                            }
                        }
                    }
                    r.fds.push(fds);
                }
                Err(e) => {
                    log::error!("Error deserialising fdset (ignoring): {}", e);
                }
            }
        }
        Self { reflection, ..self }
    }

    pub fn disable_grpc_reflection(self) -> Self {
        Self {
            reflection: None,
            ..self
        }
    }

    pub fn add_grpc_service<S>(self, svc: S) -> Result<Self, ComprehensiveError>
    where
        S: Service<Request<BoxBody>, Response = Response<BoxBody>, Error = Infallible>
            + NamedService
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        self.reflection
            .as_ref()
            .map(|r| {
                r.registered_names
                    .get(S::NAME)
                    .ok_or(ComprehensiveError::NoServiceDescriptor(S::NAME))
            })
            .transpose()?;
        let routes = self.routes.add_service(svc);
        Ok(Self { routes, ..self })
    }
}

impl crate::DeprecatedMonolithInner {
    /// Register a set of descriptors for service reflection
    ///
    /// This method accepts a serialised
    /// [`FileDescriptorSet`](https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/descriptor.proto)
    /// proto. It should be called qith the relevant descriptors before calling
    /// [`add_grpc_service`].
    ///
    /// [`add_grpc_service`]: crate::Server::add_grpc_service
    pub fn register_encoded_file_descriptor_set(self, serialised_fds: &[u8]) -> Self {
        let grpc = self
            .grpc
            .register_encoded_file_descriptor_set(serialised_fds);
        Self { grpc, ..self }
    }

    /// Disable serving the server reflection service for gRPC.
    pub fn disable_grpc_reflection(self) -> Self {
        let grpc = self.grpc.disable_grpc_reflection();
        Self { grpc, ..self }
    }

    /// Add a gRPC service to the server.
    ///
    /// See documentation on [`tonic::service::Routes::add_service`].
    ///
    /// Either [`register_encoded_file_descriptor_set`] must have been already
    /// called with a descriptor for this service, or
    /// [`disable_grpc_reflection`] must have been called instead.
    ///
    /// [`register_encoded_file_descriptor_set`]: crate::Server::register_encoded_file_descriptor_set
    /// [`disable_grpc_reflection`]: crate::Server::disable_grpc_reflection
    pub fn add_grpc_service<S>(self, svc: S) -> Result<Self, ComprehensiveError>
    where
        S: Service<Request<BoxBody>, Response = Response<BoxBody>, Error = Infallible>
            + NamedService
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        let grpc = self.grpc.add_grpc_service(svc)?;
        Ok(Self { grpc, ..self })
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::Ipv6Addr;
    use std::sync::Arc;
    use tokio::sync::Notify;
    #[cfg(feature = "tls")]
    use tokio_rustls::rustls;
    #[cfg(feature = "tls")]
    use tonic::transport::{Certificate, ClientTlsConfig};
    use tonic_health::pb::{health_check_response, health_client, HealthCheckRequest};
    use tonic_reflection::pb::v1::{
        server_reflection_client, server_reflection_request, server_reflection_response,
        ServerReflectionRequest,
    };

    use super::*;
    use crate::testutil;
    use crate::tls;

    fn test_args(use_grpc: bool, use_grpcs: bool) -> Args {
        let p1 = testutil::pick_unused_port(None);
        #[cfg(not(feature = "tls"))]
        let _ = use_grpcs;
        Args {
            grpc_port: if use_grpc { Some(p1) } else { None },
            grpc_bind_addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            #[cfg(feature = "tls")]
            grpcs_port: if use_grpcs {
                Some(testutil::pick_unused_port(Some(p1)))
            } else {
                None
            },
            #[cfg(feature = "tls")]
            grpcs_bind_addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        }
    }

    async fn plain_grpc_test<S, T, F>(s: S, t: T)
    where
        S: FnOnce(GrpcServer) -> GrpcServer,
        T: FnOnce(tonic::transport::Channel) -> F,
        F: Future<Output = ()>,
    {
        let (tlsc, tempdir) = tls::TlsConfig::for_tests(false).expect("creating test TLS");
        let grpc = s(GrpcServer::new(test_args(true, false), &tlsc).unwrap());

        let addr = grpc
            .grpc_server
            .as_ref()
            .expect("grpc_server should be populated")
            .0;
        #[cfg(feature = "tls")]
        assert!(grpc.grpcs_server.is_none());

        let quit = Arc::new(Notify::new());
        let quit_rx = Arc::clone(&quit);
        let j = tokio::spawn(async move { grpc.run(&crate::ShutdownNotify::new(&quit_rx)).await });
        testutil::wait_until_serving(&addr).await;

        let uri = format!("http://[::1]:{}/", addr.port()).parse().unwrap();
        let channel = tonic::transport::Channel::builder(uri)
            .connect()
            .await
            .expect("localhost channel");
        t(channel).await;

        let _ = quit.notify_waiters();
        let _ = j.await;
        std::mem::drop(tempdir);
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
        let (tlsc, tempdir) = tls::TlsConfig::for_tests(false).expect("creating test TLS");
        let grpc = GrpcServer::new(test_args(false, false), &tlsc).unwrap();

        assert!(grpc.grpc_server.is_none());
        #[cfg(feature = "tls")]
        assert!(grpc.grpcs_server.is_none());

        let never_quit = Notify::new();
        assert!(grpc
            .run(&crate::ShutdownNotify::new(&never_quit))
            .await
            .is_ok());
        std::mem::drop(tempdir);
    }

    #[tokio::test]
    async fn grpc_health() {
        plain_grpc_test(|s| s, check_health).await;
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
        plain_grpc_test(|s| s, check_server_reflection).await;
    }

    async fn check_greeter(channel: tonic::transport::Channel) {
        let mut client = testutil::pb::comprehensive::test_client::TestClient::new(channel);
        let resp = client.greet(()).await.expect("Test.Greet()").into_inner();
        assert_eq!(resp.message.expect("message field"), "hello");
    }

    struct TestServer(());

    #[tonic::async_trait]
    impl testutil::pb::comprehensive::test_server::Test for TestServer {
        async fn greet(
            &self,
            _: tonic::Request<()>,
        ) -> Result<tonic::Response<testutil::pb::comprehensive::GreetResponse>, tonic::Status>
        {
            Ok(tonic::Response::new(
                testutil::pb::comprehensive::GreetResponse {
                    message: Some(String::from("hello")),
                },
            ))
        }
    }

    fn mk_test_server() -> testutil::pb::comprehensive::test_server::TestServer<TestServer> {
        testutil::pb::comprehensive::test_server::TestServer::new(TestServer(()))
    }

    #[tokio::test]
    async fn grpc_own_service() {
        plain_grpc_test(
            |s| {
                s.register_encoded_file_descriptor_set(
                    testutil::pb::comprehensive::FILE_DESCRIPTOR_SET,
                )
                .add_grpc_service(mk_test_server())
                .expect("add_grpc_service")
            },
            check_greeter,
        )
        .await;
    }

    #[tokio::test]
    async fn fails_to_configure_without_descriptor() {
        let (tlsc, _) = tls::TlsConfig::for_tests(false).expect("creating test TLS");
        match GrpcServer::new(test_args(true, false), &tlsc)
            .unwrap()
            .add_grpc_service(mk_test_server())
            .expect_err("add_grpc_service should fail")
        {
            ComprehensiveError::NoServiceDescriptor(_) => (),
            x => {
                panic!("wrong type of error {:?}", x);
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

    #[tokio::test]
    async fn without_reflection() {
        plain_grpc_test(
            |s| {
                s.disable_grpc_reflection()
                    .add_grpc_service(mk_test_server())
                    .expect("add_grpc_service")
            },
            check_no_reflection,
        )
        .await;
    }

    #[cfg(feature = "tls")]
    async fn test_grpcs_channel(port: u16) -> tonic::transport::Channel {
        let identity = tonic::transport::Identity::from_pem(
            tls::testdata::USER2_CERT,
            tls::testdata::USER2_KEY,
        );
        let tls = ClientTlsConfig::new()
            .identity(identity)
            .ca_certificate(Certificate::from_pem(tls::testdata::CACERT))
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
        let (tlsc, tempdir) = tls::TlsConfig::for_tests(true).expect("creating test TLS");
        let grpc = GrpcServer::new(test_args(false, true), &tlsc).unwrap();

        assert!(grpc.grpc_server.is_none());
        let addr = grpc
            .grpcs_server
            .as_ref()
            .expect("grpcs_server should be populated")
            .0;

        let quit = Arc::new(Notify::new());
        let quit_rx = Arc::clone(&quit);
        let j = tokio::spawn(async move { grpc.run(&crate::ShutdownNotify::new(&quit_rx)).await });
        testutil::wait_until_serving(&addr).await;

        let channel = test_grpcs_channel(addr.port()).await;
        check_health(channel).await;

        let _ = quit.notify_waiters();
        let _ = j.await;
        std::mem::drop(tempdir);
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn grpc_and_grpcs() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (tlsc, tempdir) = tls::TlsConfig::for_tests(true).expect("creating test TLS");
        let grpc = GrpcServer::new(test_args(true, true), &tlsc).unwrap();

        let addr_grpc = grpc
            .grpc_server
            .as_ref()
            .expect("grpc_server should be populated")
            .0;
        let addr_grpcs = grpc
            .grpcs_server
            .as_ref()
            .expect("grpcs_server should be populated")
            .0;

        let quit = Arc::new(Notify::new());
        let quit_rx = Arc::clone(&quit);
        let j = tokio::spawn(async move { grpc.run(&crate::ShutdownNotify::new(&quit_rx)).await });
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

        let _ = quit.notify_waiters();
        let _ = j.await;
        std::mem::drop(tempdir);
    }
}
