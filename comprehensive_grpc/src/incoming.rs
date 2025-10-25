//! Roll our own TLS layer instead of using tonic's so we can supply ServerConfig.
//!
//! Based largely on
//! <https://github.com/hyperium/tonic/blob/master/tonic/src/transport/server/io_stream.rs>
//! and other tonic sources.

use comprehensive_tls::{ClientAuthEnabled, TlsConfig};
use futures::Stream;
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tower_service::Service;
use tracing::warn;

type StreamResult<S> = std::io::Result<TlsStream<S>>;

fn tls_accept<IO>(
    tlsc: &TlsConfig,
    s: IO,
) -> impl Future<Output = std::io::Result<TlsStream<IO>>> + 'static
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let mut sc = tlsc.server_config::<ClientAuthEnabled>();
    sc.alpn_protocols.push(b"h2".into());
    TlsAcceptor::from(Arc::new(sc)).accept(s)
}

pin_project! {
    struct AcceptorInner<S> {
        #[pin] upstream: S,
        tlsc: Arc<TlsConfig>,
    }
}

pin_project! {
    pub struct Acceptor<S, IO> {
        #[pin] inner: Option<AcceptorInner<S>>,
        handshaking: JoinSet<StreamResult<IO>>,
    }
}

impl<S, IO> Acceptor<S, IO> {
    fn new(upstream: S, tlsc: Arc<TlsConfig>) -> Self {
        Self {
            inner: Some(AcceptorInner { upstream, tlsc }),
            handshaking: JoinSet::new(),
        }
    }
}

impl<S, IO> Stream for Acceptor<S, IO>
where
    S: Stream<Item = std::io::Result<IO>>,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Item = StreamResult<IO>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            match this.handshaking.poll_join_next(cx) {
                // All TLS handshakes still in progress
                Poll::Pending => (),
                // No pending TLS handshakes at this time
                Poll::Ready(None) => (),
                // Pending TLS handshake JoinError (panic?)
                Poll::Ready(Some(Err(e))) => {
                    warn!("TLS accept task error: {}", e);
                    continue;
                }
                // TLS handshake succeeded
                Poll::Ready(Some(Ok(err_or_stream))) => {
                    return Poll::Ready(Some(err_or_stream));
                }
            }
            match this.inner.as_mut().as_pin_mut() {
                // Upstream was terminated previously
                None => {
                    return Poll::Ready(None);
                }
                Some(ref mut inner) => {
                    let inner_this = inner.as_mut().project();
                    match inner_this.upstream.poll_next(cx) {
                        // No new streams available
                        Poll::Pending => {
                            return Poll::Pending;
                        }
                        // Upstream terminated
                        Poll::Ready(None) => {
                            this.inner.set(None);
                            return Poll::Ready(None);
                        }
                        // Upstream accept error
                        Poll::Ready(Some(Err(e))) => {
                            return Poll::Ready(Some(Err(e)));
                        }
                        // Upstream accept succesful
                        Poll::Ready(Some(Ok(s))) => {
                            this.handshaking.spawn(tls_accept(inner_this.tlsc, s));
                        }
                    }
                }
            }
        }
    }
}

impl<S, IO> futures::stream::FusedStream for Acceptor<S, IO>
where
    S: Stream<Item = std::io::Result<IO>>,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn is_terminated(&self) -> bool {
        self.handshaking.is_empty() && self.inner.is_none()
    }
}

pub fn tls_over_tcp(
    addr: std::net::SocketAddr,
    tlsc: Arc<TlsConfig>,
) -> std::io::Result<Acceptor<TcpListenerStream, tokio::net::TcpStream>> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(Acceptor::new(
        TcpListenerStream::new(tokio::net::TcpListener::from_std(listener)?),
        tlsc,
    ))
}

#[derive(Clone)]
pub struct AddUnderlyingConnectInfoService<S>(S);

impl<S, B> Service<http::Request<B>> for AddUnderlyingConnectInfoService<S>
where
    S: Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> S::Future {
        // Due to logic in
        // https://github.com/hyperium/tonic/blob/master/tonic/src/transport/server/mod.rs
        // that doesn't get executed in our scenario, the plain TcpConnectInfo
        // does not get added, so add it here.
        if let Some(ci) = req.extensions().get::<TlsConnectInfo<TcpConnectInfo>>() {
            let ci = ci.get_ref().clone();
            req.extensions_mut().insert(ci);
        }
        self.0.call(req)
    }
}

#[derive(Clone)]
pub struct AddUnderlyingConnectInfoLayer;

impl<S> tower_layer::Layer<S> for AddUnderlyingConnectInfoLayer {
    type Service = AddUnderlyingConnectInfoService<S>;

    fn layer(&self, inner: S) -> AddUnderlyingConnectInfoService<S> {
        AddUnderlyingConnectInfoService(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use delegate::delegate;
    use futures::StreamExt;
    use futures::future::Either;
    use http::Uri;
    use hyper_util::rt::tokio::TokioIo;
    use std::pin::pin;
    use tokio::io::{AsyncReadExt, DuplexStream};
    use tokio_rustls::Connect;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tonic::transport::server::{Connected, TcpConnectInfo};

    mod pb {
        pub(super) mod comprehensive {
            tonic::include_proto!("comprehensive");
        }
    }

    const EMPTY: &[std::ffi::OsString] = &[];

    pin_project! {
        struct WrappedDuplexStream {
            #[pin] inner: DuplexStream,
        }
    }

    impl AsyncRead for WrappedDuplexStream {
        delegate! {
            #[through(AsyncRead)]
            to self.project().inner {
                fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>>;
            }
        }
    }

    impl AsyncWrite for WrappedDuplexStream {
        delegate! {
            #[through(AsyncWrite)]
            to self.project().inner {
                fn poll_write(
                    self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                    buf: &[u8],
                ) -> Poll<std::io::Result<usize>>;
                fn poll_flush(
                    self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                ) -> Poll<std::io::Result<()>>;
                fn poll_shutdown(
                    self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                ) -> Poll<std::io::Result<()>>;
            }
        }
    }

    impl Connected for WrappedDuplexStream {
        type ConnectInfo = TcpConnectInfo;

        fn connect_info(&self) -> TcpConnectInfo {
            TcpConnectInfo {
                local_addr: "[::1]:1".parse().ok(),
                remote_addr: "[::1]:2".parse().ok(),
            }
        }
    }

    #[derive(comprehensive::ResourceDependencies)]
    struct TlsTop(
        Arc<comprehensive_tls::TlsConfig>,
        std::marker::PhantomData<crate::tls_test::User1>,
    );

    fn pair() -> (
        Connect<DuplexStream>,
        impl Stream<Item = StreamResult<WrappedDuplexStream>>,
    ) {
        let tlsc = comprehensive::Assembly::<TlsTop>::new_from_argv(EMPTY)
            .unwrap()
            .top
            .0;
        let (client, server) = tokio::io::duplex(64);
        let server = WrappedDuplexStream { inner: server };
        let client = tokio_rustls::TlsConnector::from(Arc::new(
            tlsc.client_config(&Uri::from_static("https://user1/"), None)
                .unwrap(),
        ))
        .connect(ServerName::try_from("user1").unwrap(), client);
        let acceptor = Acceptor::new(
            futures::stream::select(
                futures::stream::once(std::future::ready(Ok(server))),
                futures::stream::pending(),
            ),
            tlsc,
        );
        (client, acceptor)
    }

    #[tokio::test]
    async fn tls() {
        let (client, mut acceptor) = pair();
        let client_task = pin!(async move {
            let mut stream = client.await.expect("client connected");
            let mut buf = vec![0u8; 1];
            stream.read(&mut buf).await.unwrap();
        });
        let r = match futures::future::select(client_task, acceptor.next()).await {
            Either::Left((_, server_task)) => server_task.await,
            Either::Right((io, _)) => io,
        };
        let server_io = r.expect("accepted stream").expect("not an error");
        let connect_info = server_io.connect_info();
        assert_eq!(connect_info.peer_certs().unwrap().len(), 1);
    }

    struct ConnectOnce(Option<tokio_rustls::client::TlsStream<DuplexStream>>);

    impl tower::Service<Uri> for ConnectOnce {
        type Response = TokioIo<tokio_rustls::client::TlsStream<DuplexStream>>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Uri) -> Self::Future {
            std::future::ready(Ok(TokioIo::new(self.0.take().unwrap())))
        }
    }

    struct TestServer;

    #[tonic::async_trait]
    impl pb::comprehensive::test_server::Test for TestServer {
        async fn greet(
            &self,
            req: tonic::Request<()>,
        ) -> Result<tonic::Response<pb::comprehensive::GreetResponse>, tonic::Status> {
            let reply = if req.peer_certs().is_none() {
                "missing peer_certs"
            } else if req.remote_addr().is_none() {
                "missing remote_addr"
            } else if req.extensions().get::<TcpConnectInfo>().is_none() {
                "missing underlying ConnectInfo"
            } else {
                "ok"
            };
            Ok(tonic::Response::new(pb::comprehensive::GreetResponse {
                message: Some(String::from(reply)),
            }))
        }
    }

    #[tokio::test]
    async fn grpc() {
        let (client, acceptor) = pair();
        let server = pin!(
            tonic::transport::Server::builder()
                .layer(AddUnderlyingConnectInfoLayer)
                .add_service(pb::comprehensive::test_server::TestServer::new(TestServer))
                .serve_with_incoming(acceptor)
        );
        let client_task = pin!(async move {
            let stream = client.await.unwrap();
            let channel = tonic::transport::Endpoint::from_static("http://user1/")
                .connect_with_connector(ConnectOnce(Some(stream)))
                .await
                .expect("channel");
            let mut client = pb::comprehensive::test_client::TestClient::new(channel);
            client.greet(()).await.expect("Greet()")
        });
        let r = match futures::future::select(client_task, server).await {
            Either::Left((resp, _)) => resp,
            Either::Right((_, client_task)) => client_task.await,
        }
        .into_inner();
        assert_eq!(r.message.unwrap(), "ok");
    }
}
