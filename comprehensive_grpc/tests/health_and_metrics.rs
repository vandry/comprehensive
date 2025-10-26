use comprehensive::{Assembly, ResourceDependencies};
use comprehensive_grpc::GrpcClient;
use comprehensive_grpc::client::Channel;
use comprehensive_warm_channels::warm_channels;
use futures::future::Either;
use futures::{FutureExt, pin_mut};
use http_body_util::BodyExt;
use std::net::{IpAddr, Ipv6Addr};
use std::pin::pin;
use std::sync::Arc;
use tonic::Code;
use tower::{Service, ServiceExt};
use warm_channels::stream::StreamConnector;

pub mod testutil;

use testutil::pb::comprehensive::test_client::TestClient;

#[derive(GrpcClient)]
struct SampleClient(TestClient<Channel>);

impl testutil::EndToEndClient for SampleClient {
    fn test_client(&self) -> TestClient<Channel> {
        self.client()
    }
}

#[derive(ResourceDependencies)]
struct CheckHealthAndMetricsTest {
    _diag: Arc<comprehensive_http::diag::HttpServer>,
    tester: Arc<testutil::EndToEndTester<SampleClient>>,
}

#[test_log::test(tokio::test)]
async fn health_and_metrics() {
    #[cfg(feature = "tls")]
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let port = crate::testutil::pick_unused_port();
    let diag_port = crate::testutil::pick_unused_port();
    let argv: Vec<std::ffi::OsString> = vec![
        "argv0".into(),
        format!("--sample-client-uri=http://[::1]:{}/", port).into(),
        "--sample-client-health-check-service=".into(),
        format!("--diag-http-port={}", diag_port).into(),
        "--diag-http-bind-addr=::1".into(),
    ];
    let a = Assembly::<CheckHealthAndMetricsTest>::new_from_argv(argv).unwrap();
    let tester_rx = pin!(a.top.tester.rx.take().unwrap());

    let (_, health_service) = tonic_health::server::health_reporter();
    let localhost = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    let standalone_server = pin!(
        tonic::transport::Server::builder()
            .add_service(health_service)
            .serve((localhost, port).into())
    );

    let (term_tx, term_rx) = tokio::sync::oneshot::channel();
    let j = tokio::spawn(async move {
        let _ = a
            .run_with_termination_signal(futures::stream::once(term_rx.map(|_| ())))
            .await;
    });

    let msg = match futures::future::select(standalone_server, tester_rx).await {
        Either::Left((e, _)) => {
            panic!("standalone_server quit unexpectedly: {:?}", e);
        }
        Either::Right((rx, _)) => rx.unwrap(),
    };
    assert_eq!(
        msg.expect_err("unsuccessful RPC").code(),
        Code::Unimplemented
    );

    let (mut http_client, worker) = warm_channels::http::http_channel(
        warm_channels::http::HTTPChannelConfig::default(),
        "metrics fetcher",
        StreamConnector::default(),
        futures::stream::once(futures::future::ready(Ok::<
            Vec<std::net::SocketAddr>,
            std::convert::Infallible,
        >(vec![
            (localhost, diag_port).into(),
        ]))),
    );
    let req = http::request::Builder::new()
        .method("GET")
        .uri("http://localhost/metrics")
        .body(http_body_util::Empty::<&[u8]>::new())
        .unwrap();
    let get_metrics = pin!(
        http_client
            .ready()
            .then(move |c| c.unwrap().call(req))
            .then(|r| r.expect("successful GET /metrics").into_body().collect())
    );
    pin_mut!(worker);
    let body = match futures::future::select(get_metrics, worker).await {
        Either::Left((rx, _)) => rx,
        Either::Right((e, _)) => {
            panic!("http_channel worker quit unexpectedly: {:?}", e);
        }
    };

    let _ = term_tx.send(());
    let _ = j.await;

    for line in body.expect("body").to_bytes().split(|chr| *chr == 10) {
        if let Ok(line) = std::str::from_utf8(line) {
            if line.starts_with("grpc_client_handled_total")
                && line.contains("grpc_code=\"Unimplemented\"")
                && line.contains("grpc_method=\"Greet\"")
            {
                return;
            }
        }
    }
    panic!("failed to find expected metric");
}
