use axum::response::IntoResponse;
use axum::Router;
#[cfg(feature = "tls")]
use axum_server::tls_rustls::RustlsConfig;
#[cfg(feature = "tls")]
use futures::pin_mut;
use prometheus::Encoder;
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "tls")]
use std::sync::Arc;
#[cfg(feature = "tls")]
use tokio_rustls::rustls;

use crate::tls;
use crate::ComprehensiveError;

#[derive(clap::Args, Debug)]
#[group(id = "comprehensive_http_args")]
pub(crate) struct Args {
    #[arg(long)]
    http_port: Option<u16>,

    #[arg(long, default_value = "::")]
    http_bind_addr: IpAddr,

    #[cfg(feature = "tls")]
    #[arg(long)]
    https_port: Option<u16>,

    #[cfg(feature = "tls")]
    #[arg(long, default_value = "::")]
    https_bind_addr: IpAddr,

    #[arg(long, default_value = "/metrics")]
    metrics_path: String,
}

async fn serve_metrics_page() -> impl axum::response::IntoResponse {
    let encoder = prometheus::TextEncoder::new();

    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let mut res = buffer.into_response();
    if let Ok(hv) = encoder.format_type().try_into() {
        res.headers_mut().insert("Content-Type", hv);
    }
    res
}

pub(crate) struct HttpServer {
    app: Router,
    http_addr: Option<SocketAddr>,
    #[cfg(feature = "tls")]
    https_details: Option<(SocketAddr, Arc<tls::ReloadableKeyAndCertResolver>)>,
}

impl HttpServer {
    pub(crate) fn new(args: Args, tlsc: &tls::TlsConfig) -> Result<Self, ComprehensiveError> {
        let http_addr = args.http_port.map(|p| (args.http_bind_addr, p).into());

        #[cfg(feature = "tls")]
        let https_details = args
            .https_port
            .map(|p| {
                Ok::<_, ComprehensiveError>((
                    (args.https_bind_addr, p).into(),
                    tlsc.cert_resolver()?,
                ))
            })
            .transpose()?;
        #[cfg(not(feature = "tls"))]
        let _ = tlsc;

        let mut app = Router::new();
        if !args.metrics_path.is_empty() {
            app = app.route("/metrics", axum::routing::get(serve_metrics_page));
        }

        Ok(Self {
            app,
            http_addr,
            #[cfg(feature = "tls")]
            https_details,
        })
    }

    pub(crate) async fn run(self) -> Result<(), ComprehensiveError> {
        let http = self.http_addr.map(|a| {
            log::info!("Insecure HTTP listening on {}", a);
            axum_server::bind(a)
        });

        #[cfg(feature = "tls")]
        let https = self.https_details.map(|(a, resolver)| {
            let mut sc = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver);
            sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let config = RustlsConfig::from_config(Arc::new(sc));
            log::info!("HTTPS listening on {}", a);
            axum_server::bind_rustls(a, config)
        });

        let s = self.app.into_make_service();

        #[cfg(feature = "tls")]
        {
            match (http, https) {
                (Some(s1), Some(s2)) => {
                    let s1 = s1.serve(s.clone());
                    let s2 = s2.serve(s);
                    pin_mut!(s1);
                    pin_mut!(s2);
                    futures::future::select(s1, s2).await.factor_first().0
                }
                (Some(s1), None) => s1.serve(s).await,
                (None, Some(s2)) => s2.serve(s).await,
                (None, None) => std::future::ready(Ok(())).await,
            }
            .map_err(|e| e.into())
        }

        #[cfg(not(feature = "tls"))]
        {
            match http {
                Some(s1) => s1.serve(s).await,
                None => std::future::ready(Ok(())).await,
            }
            .map_err(|e| e.into())
        }
    }

    fn http_app(self, m: impl FnOnce(axum::Router) -> axum::Router) -> Self {
        let app = m(self.app);
        HttpServer { app, ..self }
    }
}

impl crate::Server {
    /// Configure the HTTP and/or HTTPS server
    ///
    /// The supplied closure is called with the [`axum::Router`] object that
    /// forms part of the embedded HTTP server builder, and the returned
    /// [`axum::Router`] object is used instead. In the closure, routes can
    /// be installed on the HTTP server:
    ///
    /// ```
    /// use axum::response::IntoResponse;
    ///
    /// # use clap::Parser;
    /// # #[derive(Parser, Debug)]
    /// # struct Args {
    /// #     #[command(flatten)]
    /// #     comprehensive: comprehensive::Args,
    /// # }
    /// async fn demo_page() -> impl axum::response::IntoResponse {
    ///     "hello".into_response()
    /// }
    ///
    /// let s = comprehensive::Server::builder(Args::parse().comprehensive)
    ///     .unwrap()
    ///     .http_app(|app| app.route("/fooz", axum::routing::get(demo_page)));
    /// ```
    pub fn http_app(self, m: impl FnOnce(axum::Router) -> axum::Router) -> Self {
        let http = self.http.http_app(m);
        Self { http, ..self }
    }
}

#[cfg(test)]
mod tests {
    use prometheus::register_int_counter;
    use std::net::Ipv6Addr;
    use tokio::sync::oneshot;

    use super::*;
    use crate::testutil;
    use crate::tls;

    fn test_args(use_http: bool, use_https: bool) -> Args {
        let p1 = testutil::pick_unused_port(None);
        #[cfg(not(feature = "tls"))]
        let _ = use_https;
        Args {
            http_port: if use_http { Some(p1) } else { None },
            http_bind_addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            #[cfg(feature = "tls")]
            https_port: if use_https {
                Some(testutil::pick_unused_port(Some(p1)))
            } else {
                None
            },
            #[cfg(feature = "tls")]
            https_bind_addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            metrics_path: String::from("/metrics"),
        }
    }

    async fn demo_page() -> impl axum::response::IntoResponse {
        "hello".into_response()
    }

    #[tokio::test]
    async fn http_only() {
        let counter = register_int_counter!("comprehensive_test_total", "Number of happy").unwrap();
        counter.inc_by(111);

        let (tlsc, tempdir) = tls::TlsConfig::for_tests(false).expect("creating test TLS");
        let http = HttpServer::new(test_args(true, false), &tlsc)
            .unwrap()
            .http_app(|app| app.route("/fooz", axum::routing::get(demo_page)));

        let addr = http.http_addr.expect("http_addr should be populated");
        #[cfg(feature = "tls")]
        assert!(http.https_details.is_none());

        let (tx, rx) = oneshot::channel();
        let j = testutil::run_until_signal(http.run(), rx).await;
        testutil::wait_until_serving(&addr).await;

        let url = format!("http://[::1]:{}/", addr.port());
        let resp = reqwest::get(&url).await.expect(&url);
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

        let url = format!("http://[::1]:{}/metrics", addr.port());
        let text = reqwest::get(&url)
            .await
            .expect(&url)
            .text()
            .await
            .expect(&url);
        assert!(text.contains("comprehensive_test_total"));
        assert!(text.contains("111"));

        let url = format!("http://[::1]:{}/fooz", addr.port());
        let text = reqwest::get(&url)
            .await
            .expect(&url)
            .text()
            .await
            .expect(&url);
        assert!(text.contains("hello"));

        let _ = tx.send(());
        let _ = j.await;
        std::mem::drop(tempdir);
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn https_only() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (tlsc, tempdir) = tls::TlsConfig::for_tests(true).expect("creating test TLS");
        let http = HttpServer::new(test_args(false, true), &tlsc).unwrap();

        assert!(http.http_addr.is_none());
        let addr = http
            .https_details
            .as_ref()
            .expect("https_details should be populated")
            .0;

        let (tx, rx) = oneshot::channel();
        let j = testutil::run_until_signal(http.run(), rx).await;
        testutil::wait_until_serving(&addr).await;

        let cacert = reqwest::Certificate::from_pem(tls::testdata::CACERT).expect("cacert");
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
        std::mem::drop(tempdir);
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn http_and_https() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (tlsc, tempdir) = tls::TlsConfig::for_tests(true).expect("creating test TLS");
        let http = HttpServer::new(test_args(true, true), &tlsc).unwrap();

        let addr_http = http.http_addr.expect("http_addr should be populated");
        let addr_https = http
            .https_details
            .as_ref()
            .expect("https_details should be populated")
            .0;

        let (tx, rx) = oneshot::channel();
        let j = testutil::run_until_signal(http.run(), rx).await;
        testutil::wait_until_serving(&addr_http).await;
        testutil::wait_until_serving(&addr_https).await;

        let cacert = reqwest::Certificate::from_pem(tls::testdata::CACERT).expect("cacert");
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
        std::mem::drop(tempdir);
    }
}
