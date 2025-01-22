use comprehensive::Assembly;
use comprehensive_grpc::client::{Channel, ClientWorker};
use comprehensive_grpc::GrpcClient;
use futures::FutureExt;

pub mod testutil;

use testutil::pb::comprehensive::test_client::TestClient;
use testutil::EndToEnd;

#[derive(GrpcClient)]
#[no_propagate_health]
struct Client(TestClient<Channel>, ClientWorker);

impl testutil::EndToEndClient for Client {
    fn test_client(&self) -> TestClient<Channel> {
        self.client()
    }
}

#[test_log::test(tokio::test)]
async fn end_to_end() {
    let port = testutil::pick_unused_port();
    let argv: Vec<std::ffi::OsString> = vec![
        "argv0".into(),
        format!("--grpc-port={}", port).into(),
        "--grpc-bind-addr=::1".into(),
        format!("--client-uri=http://[::1]:{}/", port).into(),
    ];
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let a = Assembly::<EndToEnd<Client>>::new_from_argv(argv).unwrap();
    let tester_rx = a.top.tester.rx.take().unwrap();

    let (term_tx, term_rx) = tokio::sync::oneshot::channel();
    let j = tokio::spawn(async move {
        let _ = a
            .run_with_termination_signal(futures::stream::once(term_rx.map(|_| ())))
            .await;
    });
    let msg = tester_rx.await.unwrap();
    let _ = term_tx.send(());
    let _ = j.await;
    let response = msg.expect("successful RPC").into_inner();
    assert_eq!(response.message.as_deref(), Some("hello"));
}
