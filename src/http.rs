//! [`comprehensive`] [`Resource`] types for HTTP serving
//!
//! This module provides:
//! * A trait [`HttpServingInstance`] for resources that answer HTTP requests.
//! * [`HttpServer`], a generic [`Resource`] for serving such resources over
//!   HTTP and HTTPS.
//!
//! There can be several [`HttpServer`] resources in the same [`comprehensive::Assembly`],
//! each parameterised with a different [`HttpServingInstance`]. This is
//! expected to be used to have an internal server for metrics and
//! diagnostics and a different one for public serving. See
//! [`comprehensive::diag::HttpServer`] for the packaged instance of the
//! former.
//!
//! # Usage
//!
//! ```
//! use axum::Router;
//! use axum::response::IntoResponse;
//! use comprehensive::{NoArgs, NoDependencies, Resource, ResourceDependencies};
//! use comprehensive::http::{HttpServer, HttpServingInstance};
//!
//! async fn demo_page() -> impl axum::response::IntoResponse {
//!     "hello".into_response()
//! }
//!
//! #[derive(HttpServingInstance)]
//! #[flag_prefix = "foo-"]
//! pub struct FooServer(#[router] Router);
//!
//! impl Resource for FooServer {
//!     type Args = NoArgs;
//!     type Dependencies = NoDependencies;
//!     const NAME: &str = "Test HTTP server";
//!
//!     fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
//!         let app = Router::new()
//!             .route("/fooz", axum::routing::get(demo_page));
//!         Ok(Self(app))
//!     }
//! }
//!
//! #[derive(ResourceDependencies)]
//! struct JustAServer {
//!     server: std::sync::Arc<HttpServer<FooServer>>,
//! }
//!
//! let assembly = comprehensive::Assembly::<JustAServer>::new().unwrap();
//! ```

use atomic_take::AtomicTake;
use axum::Router;
#[cfg(feature = "tls")]
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use futures::future::Either;
use futures::pin_mut;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Notify;
#[cfg(feature = "tls")]
use tokio_rustls::rustls;

use crate::{NoArgs, NoDependencies, Resource, ResourceDependencies, ShutdownNotify};

async fn run_in_task<'a, A>(
    b: axum_server::Server<A>,
    term_signal: &'a ShutdownNotify<'a>,
    router: Router,
) -> Result<(), Box<dyn std::error::Error>>
where
    A: axum_server::accept::Accept<tokio::net::TcpStream, Router> + Clone + Send + Sync + 'static,
    A::Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    A::Service: axum_server::service::SendService<http::Request<hyper::body::Incoming>> + Send,
    A::Future: Send,
{
    let term = term_signal.subscribe();
    let handle = axum_server::Handle::new();
    let handle_for_task = handle.clone();
    let make_service = router.into_make_service();
    let task = tokio::spawn(async move { b.handle(handle_for_task).serve(make_service).await });
    pin_mut!(term);
    pin_mut!(task);
    match futures::future::select(term, task).await {
        Either::Left(((), task)) => {
            handle.graceful_shutdown(None);
            task.await
        }
        Either::Right((result, _)) => result,
    }??;
    Ok(())
}

/// A trait indicating a [`Resource`] that can back an [`HttpServer`].
///
/// This trait is normally derived like this:
///
/// ```
/// use axum::Router;
/// use comprehensive::{NoArgs, NoDependencies, Resource};
/// use comprehensive::http::HttpServingInstance;
///
/// #[derive(HttpServingInstance)]
/// #[flag_prefix = "foo-"]
/// pub struct FooServer(#[router] Router);
/// # impl Resource for FooServer {
/// #     type Args = NoArgs;
/// #     type Dependencies = NoDependencies;
/// #     const NAME: &str = "Test HTTP server";
/// #
/// #     fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
/// #         Ok(Self(Router::new()))
/// #     }
/// # }
/// ```
///
/// There are 2 required derive attributes:
///
/// * `#[flag_prefix = string literal]`: prefix that will be prepended to all
///   flags that the [`HttpServer`] installs, to disambiguate this instance.
/// * `#[router]` should be attached to exactly one of the fields of the struct
///   on which this trait is derived. That field must be of type [`axum::Router`]
///   and identifies the service that the HTTP server will dispatch to.
pub trait HttpServingInstance: Resource {
    #[doc(hidden)]
    const HTTP_PORT_FLAG_NAME: &str;
    #[doc(hidden)]
    const HTTP_BIND_ADDR_FLAG_NAME: &str;
    #[doc(hidden)]
    const HTTPS_PORT_FLAG_NAME: &str;
    #[doc(hidden)]
    const HTTPS_BIND_ADDR_FLAG_NAME: &str;

    #[doc(hidden)]
    fn get_router(&self) -> Router;
}

pub use comprehensive_macros::HttpServingInstance;

struct Conveyor<T> {
    data: std::sync::Mutex<Option<T>>,
    available: Notify,
}

impl<T> Conveyor<T> {
    fn new() -> Self {
        Self {
            data: std::sync::Mutex::new(None),
            available: Notify::new(),
        }
    }

    fn put(&self, data: T) {
        *(self.data.lock().unwrap()) = Some(data);
        self.available.notify_waiters();
    }

    async fn get(&self) -> T {
        let notified = self.available.notified();
        if let Some(data) = self.data.lock().unwrap().take() {
            return data;
        }
        notified.await;
        self.data
            .lock()
            .unwrap()
            .take()
            .expect("Conveyor unexpectedly empty")
    }
}

mod insecure_server {
    use super::*;

    #[derive(clap::Args, Debug)]
    #[group(skip)]
    pub(super) struct InsecureHttpServerArgs<I: HttpServingInstance> {
        #[arg(
            long(I::HTTP_PORT_FLAG_NAME),
            id(I::HTTP_PORT_FLAG_NAME),
            help = "TCP port number for insecure HTTP server. If unset, plain HTTP is not served."
        )]
        http_port: Option<u16>,

        #[arg(
            long(I::HTTP_BIND_ADDR_FLAG_NAME),
            id(I::HTTP_BIND_ADDR_FLAG_NAME),
            default_value = "::",
            help = "Binding IP address for HTTP. Used only if the corresponding port is set."
        )]
        http_bind_addr: IpAddr,

        #[clap(skip = PhantomData)]
        _i: PhantomData<I>,
    }

    pub(super) struct InsecureHttpServer<I>
    where
        I: HttpServingInstance,
    {
        server: AtomicTake<axum_server::Server>,
        pub(super) conf: Option<Conveyor<Router>>,
        _i: PhantomData<I>,
    }

    impl<I: HttpServingInstance> Resource for InsecureHttpServer<I> {
        type Args = InsecureHttpServerArgs<I>;
        type Dependencies = NoDependencies;
        const NAME: &str = "Plaintext HTTP server";

        fn new(
            _: NoDependencies,
            args: InsecureHttpServerArgs<I>,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(match args.http_port {
                Some(port) => {
                    let addr = (args.http_bind_addr, port).into();
                    log::info!("{}: Insecure HTTP server listening on {}", I::NAME, addr);
                    Self {
                        server: AtomicTake::new(axum_server::bind(addr)),
                        conf: Some(Conveyor::new()),
                        _i: PhantomData,
                    }
                }
                None => Self {
                    server: AtomicTake::empty(),
                    conf: None,
                    _i: PhantomData,
                },
            })
        }

        async fn run_with_termination_signal<'a>(
            &'a self,
            term: &'a ShutdownNotify<'a>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let Some(server) = self.server.take() else {
                return Ok(());
            };
            let s = self.conf.as_ref().unwrap().get().await;
            run_in_task(server, term, s).await?;
            Ok(())
        }
    }
}

#[cfg(feature = "tls")]
mod secure_server {
    use super::*;

    #[cfg(not(test))]
    type TlsConfig = crate::tls::TlsConfig;
    #[cfg(test)]
    type TlsConfig = crate::testutil::tls::MockTlsConfig;

    #[derive(clap::Args, Debug)]
    #[group(skip)]
    pub(super) struct SecureHttpServerArgs<I: HttpServingInstance> {
        #[arg(
            long(I::HTTPS_PORT_FLAG_NAME),
            id(I::HTTPS_PORT_FLAG_NAME),
            help = "TCP port number for HTTPS server. If unset, HTTPS is not served."
        )]
        https_port: Option<u16>,

        #[arg(
            long(I::HTTPS_BIND_ADDR_FLAG_NAME),
            id(I::HTTPS_BIND_ADDR_FLAG_NAME),
            default_value = "::",
            help = "Binding IP address for HTTPS. Used only if the corresponding port is set."
        )]
        https_bind_addr: IpAddr,

        #[clap(skip = PhantomData)]
        _i: PhantomData<I>,
    }

    #[derive(ResourceDependencies)]
    pub(super) struct SecureHttpServerDependencies {
        tls: Arc<TlsConfig>,
    }

    pub(super) struct SecureHttpServer<I>
    where
        I: HttpServingInstance,
    {
        server: AtomicTake<axum_server::Server<RustlsAcceptor>>,
        pub(super) conf: Option<Conveyor<Router>>,
        _i: PhantomData<I>,
    }

    impl<I: HttpServingInstance> Resource for SecureHttpServer<I> {
        type Args = SecureHttpServerArgs<I>;
        type Dependencies = SecureHttpServerDependencies;
        const NAME: &str = "HTTPS server";

        fn new(
            d: SecureHttpServerDependencies,
            args: SecureHttpServerArgs<I>,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let Some(port) = args.https_port else {
                return Ok(Self {
                    server: AtomicTake::empty(),
                    conf: None,
                    _i: PhantomData,
                });
            };
            let addr = (args.https_bind_addr, port).into();
            let mut sc = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(d.tls.cert_resolver()?);
            sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let config = RustlsConfig::from_config(Arc::new(sc));
            log::info!("{}: Secure HTTP server listening on {}", I::NAME, addr);
            Ok(Self {
                server: AtomicTake::new(axum_server::bind_rustls(addr, config)),
                conf: Some(Conveyor::new()),
                _i: PhantomData,
            })
        }

        async fn run_with_termination_signal<'a>(
            &'a self,
            term: &'a ShutdownNotify<'a>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let Some(server) = self.server.take() else {
                return Ok(());
            };
            let s = self.conf.as_ref().unwrap().get().await;
            run_in_task(server, term, s).await?;
            Ok(())
        }
    }
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct HttpServerDependencies<I>
where
    I: HttpServingInstance,
{
    instance: Arc<I>,
    http: Arc<insecure_server::InsecureHttpServer<I>>,
    #[cfg(feature = "tls")]
    https: Arc<secure_server::SecureHttpServer<I>>,
}

/// HTTP and HTTPS server [`Resource`].
///
/// Accepts another [`Resource`] as a parameter which must implement
/// [`HttpServingInstance`], and dispatches requests to the `axum`
/// server therein.
///
/// Each instance accepts flags with a different prefix:
///
/// | Flag                       | Default    | Meaning                 |
/// |----------------------------|------------|-------------------------|
/// | `--PREFIX-http_port`       | *none*     | TCP port number for insecure HTTP server. If unset, plain HTTP is not served. |
/// | `--PREFIX-http_bind_addr`  | `::`       | Binding IP address for HTTP. Used only if `--http_port` is set. |
/// | `--PREFIX-https_port`      | *none*     | TCP port number for secure HTTP server. If unset, HTTPS is not served. |
/// | `--PREFIX-https_bind_addr` | `::`       | Binding IP address for HTTPS. Used only if `--https_port` is set. |
pub struct HttpServer<I>
where
    I: HttpServingInstance,
{
    deps: HttpServerDependencies<I>,
}

impl<I: HttpServingInstance> Resource for HttpServer<I> {
    type Args = NoArgs;
    type Dependencies = HttpServerDependencies<I>;
    const NAME: &str = "HTTP server common";

    fn new(d: HttpServerDependencies<I>, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self { deps: d })
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(feature = "tls"))]
        if self.deps.http.conf.is_none() {
            log::warn!("{}: No insecure HTTP listener, and secure HTTP is not available because feature \"tls\" is not built.", I::NAME);
            return Ok(());
        }

        #[cfg(feature = "tls")]
        if self.deps.http.conf.is_none() && self.deps.https.conf.is_none() {
            log::warn!("{}: No insecure or secure HTTP listener.", I::NAME);
            return Ok(());
        }

        let router = self.deps.instance.get_router();

        #[cfg(not(feature = "tls"))]
        self.deps.http.conf.as_ref().unwrap().put(router);

        #[cfg(feature = "tls")]
        match (self.deps.http.conf.as_ref(), self.deps.https.conf.as_ref()) {
            (None, None) => (),
            (Some(s), None) => s.put(router),
            (None, Some(s)) => s.put(router),
            (Some(s1), Some(s2)) => {
                s1.put(router.clone());
                s2.put(router);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;
    use futures::FutureExt;
    use std::sync::Arc;

    use super::*;
    use crate::testutil;

    async fn demo_page() -> impl axum::response::IntoResponse {
        "hello".into_response()
    }

    #[derive(HttpServingInstance)]
    #[flag_prefix = "foo-"]
    pub struct FooServer(#[router] Router);

    impl Resource for FooServer {
        type Args = NoArgs;
        type Dependencies = NoDependencies;
        const NAME: &str = "Test HTTP server";

        fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
            let app = Router::new().route("/fooz", axum::routing::get(demo_page));
            Ok(Self(app))
        }
    }

    #[derive(ResourceDependencies)]
    struct JustAServer {
        server: Arc<HttpServer<FooServer>>,
    }

    fn test_args(
        http_port: Option<u16>,
        https_port: Option<u16>,
    ) -> impl IntoIterator<Item = std::ffi::OsString> {
        let mut v = vec!["cmd".into()];
        if let Some(port) = http_port {
            v.push(format!("--foo-http-port={}", port).into());
            v.push("--foo-http-bind-addr=::1".into());
        }
        #[cfg(feature = "tls")]
        if let Some(port) = https_port {
            v.push(format!("--foo-https-port={}", port).into());
            v.push("--foo-https-bind-addr=::1".into());
        }
        #[cfg(not(feature = "tls"))]
        let _ = https_port;
        v
    }

    #[tokio::test]
    async fn nothing_enabled() {
        let argv = vec!["cmd"];
        let assembly = comprehensive::Assembly::<JustAServer>::new_from_argv(argv).unwrap();

        assert!(assembly.top.server.deps.http.conf.is_none());
        #[cfg(feature = "tls")]
        assert!(assembly.top.server.deps.https.conf.is_none());

        assert!(assembly
            .run_with_termination_signal(futures::stream::pending())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn http_only() {
        let port = testutil::pick_unused_port(None);
        let argv = test_args(Some(port), None);
        let assembly = comprehensive::Assembly::<JustAServer>::new_from_argv(argv).unwrap();

        assert!(assembly.top.server.deps.http.conf.is_some());
        #[cfg(feature = "tls")]
        assert!(assembly.top.server.deps.https.conf.is_none());

        let (tx, rx) = tokio::sync::oneshot::channel();
        let j = tokio::spawn(async move {
            let _ = assembly
                .run_with_termination_signal(futures::stream::once(rx.map(|_| ())))
                .await;
        });
        let addr = testutil::localhost(port);
        testutil::wait_until_serving(&addr).await;

        let url = format!("http://[::1]:{}/", port);
        let resp = reqwest::get(&url).await.expect(&url);
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

        let url = format!("http://[::1]:{}/fooz", port);
        let text = reqwest::get(&url)
            .await
            .expect(&url)
            .text()
            .await
            .expect(&url);
        assert!(text.contains("hello"));

        let _ = tx.send(());
        let _ = j.await;
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn https_only() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let port = testutil::pick_unused_port(None);
        let argv = test_args(None, Some(port));
        let assembly = comprehensive::Assembly::<JustAServer>::new_from_argv(argv).unwrap();

        assert!(assembly.top.server.deps.http.conf.is_none());
        assert!(assembly.top.server.deps.https.conf.is_some());

        let (tx, rx) = tokio::sync::oneshot::channel();
        let j = tokio::spawn(async move {
            let _ = assembly
                .run_with_termination_signal(futures::stream::once(rx.map(|_| ())))
                .await;
        });
        let addr = testutil::localhost(port);
        testutil::wait_until_serving(&addr).await;

        let cacert = reqwest::Certificate::from_pem(crate::tls::testdata::CACERT).expect("cacert");
        let client = reqwest::ClientBuilder::new()
            .add_root_certificate(cacert)
            .resolve("user1", addr.clone())
            .build()
            .expect("cacert");

        let url = format!("https://user1:{}/", addr.port());
        let resp = client.get(&url).send().await.expect(&url);
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

        let _ = tx.send(());
        let _ = j.await;
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn http_and_https() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let port_http = testutil::pick_unused_port(None);
        let port_https = testutil::pick_unused_port(Some(port_http));
        let argv = test_args(Some(port_http), Some(port_https));
        let assembly = comprehensive::Assembly::<JustAServer>::new_from_argv(argv).unwrap();

        assert!(assembly.top.server.deps.http.conf.is_some());
        assert!(assembly.top.server.deps.https.conf.is_some());

        let (tx, rx) = tokio::sync::oneshot::channel();
        let j = tokio::spawn(async move {
            let _ = assembly
                .run_with_termination_signal(futures::stream::once(rx.map(|_| ())))
                .await;
        });
        let addr_http = testutil::localhost(port_http);
        let addr_https = testutil::localhost(port_https);
        testutil::wait_until_serving(&addr_http).await;
        testutil::wait_until_serving(&addr_https).await;

        let cacert = reqwest::Certificate::from_pem(crate::tls::testdata::CACERT).expect("cacert");
        let client = reqwest::ClientBuilder::new()
            .add_root_certificate(cacert)
            .resolve("user1", addr_https.clone())
            .build()
            .expect("cacert");

        let url = format!("http://user1:{}/", addr_http.port());
        let resp = client.get(&url).send().await.expect(&url);
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

        let url = format!("https://user1:{}/", addr_https.port());
        let resp = client.get(&url).send().await.expect(&url);
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

        let _ = tx.send(());
        let _ = j.await;
    }

    #[derive(HttpServingInstance)]
    #[flag_prefix = "bar-"]
    pub struct BarServer(#[router] Router);

    impl Resource for BarServer {
        type Args = NoArgs;
        type Dependencies = NoDependencies;
        const NAME: &str = "Second Test HTTP server";

        fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self(Router::new()))
        }
    }

    #[derive(ResourceDependencies)]
    struct JustTwoServers {
        _server1: Arc<HttpServer<FooServer>>,
        _server2: Arc<HttpServer<BarServer>>,
    }

    #[test]
    fn two_servers() {
        let argv = vec!["cmd"];
        let _ = comprehensive::Assembly::<JustTwoServers>::new_from_argv(argv).unwrap();
    }
}
