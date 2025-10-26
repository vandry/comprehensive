use http::{Request, Response};
use pin_project_lite::pin_project;
use prometheus::{CounterVec, HistogramVec, register_counter_vec, register_histogram_vec};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{Context, Poll, ready};
use std::time::Instant;
use tonic::Code;
use tower_layer::Layer;
use tower_service::Service;

const DEFAULT_HISTOGRAM_BUCKETS: [f64; 14] = [
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
];

// Metrics that mirror the ones commonly used in Go:
// https://github.com/grpc-ecosystem/go-grpc-middleware/blob/main/providers/prometheus/server_metrics.go

static COUNTER_STARTED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "grpc_server_started_total",
        "Total number of RPCs started on the server.",
        &["grpc_service", "grpc_method"],
    )
    .expect("failed to init grpc_server_started_total")
});

static COUNTER_FINISHED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "grpc_server_handled_total",
        "Total number of RPCs completed on the server, regardless of success or failure.",
        &["grpc_service", "grpc_method", "grpc_code"],
    )
    .expect("failed to init grpc_server_handled_total")
});

static HISTOGRAM: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "grpc_server_handling_seconds",
        "Histogram for tracking server RPC duration",
        &["grpc_service", "grpc_method", "grpc_code"],
        DEFAULT_HISTOGRAM_BUCKETS.to_vec(),
    )
    .expect("failed to init histogram_smc")
});

pin_project! {
    pub struct MetricsFuture<F> {
        path: String,
        service_method_separator: Option<NonZeroUsize>,
        started_at: Option<Instant>,
        #[pin] inner: F,
    }
}

impl<F> MetricsFuture<F> {
    pub fn new(path: String, service_method_separator: Option<NonZeroUsize>, inner: F) -> Self {
        Self {
            started_at: None,
            inner,
            path,
            service_method_separator,
        }
    }
}

impl<F, B, E> Future for MetricsFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let (rpc_service, rpc_method) = match this.service_method_separator {
            Some(sep) => (
                &this.path[1..(*sep).into()],
                &this.path[usize::from(*sep) + 1..],
            ),
            // If unparseable, say service is empty and method is the entire path
            None => ("", this.path as &str),
        };
        let started_at = this.started_at.get_or_insert_with(|| {
            COUNTER_STARTED
                .with_label_values(&[rpc_service, rpc_method])
                .inc();
            Instant::now()
        });
        let v = ready!(this.inner.poll(cx));
        let code = v.as_ref().map_or(Code::Unknown, |resp| {
            resp.headers()
                .get("grpc-status")
                .map(|s| Code::from_bytes(s.as_bytes()))
                .unwrap_or(Code::Ok)
        });
        let code_str = format!("{:?}", code);
        let elapsed = Instant::now().duration_since(*started_at).as_secs_f64();
        COUNTER_FINISHED
            .with_label_values(&[rpc_service, rpc_method, code_str.as_str()])
            .inc();
        HISTOGRAM
            .with_label_values(&[rpc_service, rpc_method, code_str.as_str()])
            .observe(elapsed);
        Poll::Ready(v)
    }
}

#[derive(Clone)]
pub struct MetricsService<S> {
    service: S,
}

impl<S, I, O> Service<Request<I>> for MetricsService<S>
where
    S: Service<Request<I>, Response = Response<O>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = MetricsFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Request<I>) -> Self::Future {
        let path = req.uri().path().to_owned();
        let service_method_separator: Option<NonZeroUsize> = match path.chars().next() {
            Some('/') => path[1..]
                .find('/')
                .map(|p| NonZeroUsize::new(p + 1).unwrap()),
            _ => None,
        };
        let f = self.service.call(req);
        MetricsFuture::new(path, service_method_separator, f)
    }
}

#[derive(Clone)]
pub struct MetricsLayer;

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService { service: inner }
    }
}
