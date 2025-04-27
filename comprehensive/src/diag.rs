//! HTTP server meant to serve diagnostics for a [`comprehensive`] server.
//!
//! Currently this serves only Prometheus metrics.

use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use prometheus::Encoder;
use std::sync::Arc;

use crate::health::HealthReporter;
use crate::http::HttpServingInstance;
use crate::ResourceDependencies;
use crate::v1::{AssemblyRuntime, Resource, resource};

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

async fn serve_health_page(
    State(state): State<Arc<HealthReporter>>,
) -> Result<axum::body::Bytes, http::StatusCode> {
    if state.is_healthy() {
        Ok("OK\r\n".into())
    } else {
        Err(http::StatusCode::INTERNAL_SERVER_ERROR)
    }
}

#[doc(hidden)]
#[derive(clap::Args, Debug)]
#[group(skip)]
pub struct Args {
    #[arg(long, default_value = "/metrics")]
    metrics_path: String,

    #[arg(long, default_value = "/healthz")]
    health_path: String,
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct DiagInstanceDependencies(Arc<HealthReporter>);

#[doc(hidden)]
#[derive(HttpServingInstance)]
#[flag_prefix = "diag-"]
pub struct DiagInstance(#[router] Router);

#[resource]
impl Resource for DiagInstance {
    const NAME: &str = "Diagnostics HTTP server";

    fn new(
        d: DiagInstanceDependencies,
        args: Args,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        let mut app = Router::new();
        if !args.metrics_path.is_empty() {
            app = app.route(&args.metrics_path, axum::routing::get(serve_metrics_page));
        }
        if !args.health_path.is_empty() {
            app = app.route(&args.health_path, axum::routing::get(serve_health_page));
        }
        Ok(Arc::new(Self(app.with_state(d.0))))
    }
}

/// HTTP server meant to serve diagnostics for a [`comprehensive`] server.
///
/// Depend on this [`Resource`] in a [`comprehensive::Assembly`] to get
/// an HTTP server that publishes Prometheus metrics.
///
/// # Command line flags
///
/// | Flag                     | Default    | Meaning                 |
/// |--------------------------|------------|-------------------------|
/// | `--diag-http_port`       | *none*     | TCP port number for insecure HTTP server. If unset, plain HTTP is not served. |
/// | `--diag-http_bind_addr`  | `::`       | Binding IP address for HTTP. Used only if `--http_port` is set. |
/// | `--diag-https_port`      | *none*     | TCP port number for secure HTTP server. If unset, HTTPS is not served. |
/// | `--diag-https_bind_addr` | `::`       | Binding IP address for HTTPS. Used only if `--https_port` is set. |
/// | `--metrics_path`         | `/metrics` | HTTP and/or HTTPS path where metrics are served. Set to empty to disable. |
/// | `--health_path`          | `/healthz` | HTTP and/or HTTPS path where health status is served. Set to empty to disable. |
pub type HttpServer = crate::http::HttpServer<DiagInstance>;

#[cfg(test)]
mod tests {
    use prometheus::register_int_counter;
    use tower_service::Service;

    use super::*;

    #[derive(comprehensive::ResourceDependencies)]
    struct NotValidForServingShouldUseHttpServer {
        i: std::sync::Arc<DiagInstance>,
    }

    #[tokio::test]
    async fn metrics() {
        let argv = vec!["cmd"];
        let assembly =
            comprehensive::Assembly::<NotValidForServingShouldUseHttpServer>::new_from_argv(argv)
                .unwrap();
        let counter = register_int_counter!("comprehensive_test_total", "Number of happy").unwrap();
        counter.inc_by(111);

        let mut router = assembly.top.i.get_router();
        let req = http::request::Builder::new()
            .method("GET")
            .uri("http://unused/metrics")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.expect("success");
        assert_eq!(resp.status().as_u16(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 10000)
            .await
            .expect("body");
        let body = std::str::from_utf8(&body).expect("text");
        assert!(body.contains("111"));
    }
}
