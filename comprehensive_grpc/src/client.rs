//! gRPC client support
//!
//! To use gRPC clients in Comprehensive, define a struct with exactly 1 field:
//! a [`tonic`] gRPC client type, parameterised with [`Channel`].
//!
//! This field may be wrapped in an [`Option`].
//!   - If it is, then the client is considered optional and will
//!     be [`Some`] only if a URI for it is given on the command line.
//!   - If it is not, then the client is considered required and
//!     the program will fail at startup unless a URI for it is given.
//!
//! The struct may have either named or unnamed fields, it doesn't matter.
//! The field will not be accessed directly by user code.
//!
//! `#[derive(GrpcClient)]` on the struct.
//!
//! Normally, the health of the gRPC client will count toward the health of
//! the [`comprehensive::Assembly`] as a whole. To prevent that, add
//! `#[no_propagate_health]`.
//!
//! ```
//! # mod pb {
//! #     tonic::include_proto!("comprehensive");
//! # }
//! use comprehensive_grpc::GrpcClient;
//! use comprehensive_grpc::client::Channel;
//!
//! #[derive(GrpcClient)]
//! struct MyClientResource(
//!     pb::test_client::TestClient<Channel>,
//! );
//! ```

use atomic_take::AtomicTake;
use clap::{Arg, ArgMatches, Args, Command, FromArgMatches, value_parser};
use comprehensive::ResourceDependencies;
use comprehensive::health::HealthReporter;
use comprehensive_dns::DNSResolver;
use comprehensive_warm_channels::WarmChannelsDiag;
use futures::{Stream, StreamExt, TryStreamExt};
use http::Uri;
use humantime::{format_duration, parse_duration};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use warm_channels::grpc::{GRPCChannel, GRPCChannelConfig, grpc_channel};
use warm_channels::resolver::ResolveUriError;
use warm_channels::stream::{IPOrUNIXAddress, StreamConnector};
#[cfg(feature = "tls")]
use warm_channels::tls::TLSConnector;

/// Type of the gRPC channel as returned by [`warm_channels`].
#[cfg(feature = "tls")]
pub type Channel = GRPCChannel<IPOrUNIXAddress, TLSConnector<StreamConnector>>;
/// Type of the gRPC channel as returned by [`warm_channels`].
#[cfg(not(feature = "tls"))]
pub type Channel = GRPCChannel<IPOrUNIXAddress, StreamConnector>;

/// Opaque type of a worker task associated with the channel. This goes
/// into the second field of the gRPC client struct. The derived implementation
/// will take care of spawning the task when the
/// [`comprehensive::Assembly`] runs.
pub struct ClientWorker(AtomicTake<Pin<Box<dyn Future<Output = ()> + Send>>>);

impl ClientWorker {
    fn new<F>(fut: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Self(AtomicTake::new(Box::pin(fut)))
    }

    fn empty() -> Self {
        Self(AtomicTake::empty())
    }

    #[doc(hidden)]
    pub async fn go(&self) {
        if let Some(fut) = self.0.take() {
            fut.await;
        }
    }
}

#[doc(hidden)]
pub trait InstanceDescriptor {
    const REQUIRED: bool;
    const URI_FLAG_NAME: &str;
    const CONNECT_URI_FLAG_NAME: &str;
    const N_SUBCHANNELS_WANT_FLAG_NAME: &str;
    const N_SUBCHANNELS_HEALTHY_MIN_FLAG_NAME: &str;
    const N_SUBCHANNELS_HEALTHY_CRITICAL_MIN_FLAG_NAME: &str;
    const LOG_UNHEALTHY_INITIAL_DELAY_FLAG_NAME: &str;
    const LOG_UNHEALTHY_REPEAT_DELAY_FLAG_NAME: &str;
    const NO_HEALTH_CHECK_ENABLE_FLAG_NAME: &str;
    const HEALTH_CHECK_SERVICE_FLAG_NAME: &str;
    const HEALTH_CHECK_TIMEOUT_FLAG_NAME: &str;
    const HEALTH_CHECK_INTERVAL_FLAG_NAME: &str;
}

#[doc(hidden)]
#[macro_export]
macro_rules! declare_client_flag_name_constants {
    ($prefix:literal) => {
        const URI_FLAG_NAME: &str = concat!($prefix, "uri");
        const CONNECT_URI_FLAG_NAME: &str = concat!($prefix, "connect-uri");
        const N_SUBCHANNELS_WANT_FLAG_NAME: &str = concat!($prefix, "n-subchannels-want");
        const N_SUBCHANNELS_HEALTHY_MIN_FLAG_NAME: &str =
            concat!($prefix, "n-subchannels-healthy-min");
        const N_SUBCHANNELS_HEALTHY_CRITICAL_MIN_FLAG_NAME: &str =
            concat!($prefix, "n-subchannels-healthy-critical-min");
        const LOG_UNHEALTHY_INITIAL_DELAY_FLAG_NAME: &str =
            concat!($prefix, "log-unhealthy-initial-delay");
        const LOG_UNHEALTHY_REPEAT_DELAY_FLAG_NAME: &str =
            concat!($prefix, "log-unhealthy-repeat-delay");
        const NO_HEALTH_CHECK_ENABLE_FLAG_NAME: &str =
            concat!("no-", $prefix, "health-check-enable");
        const HEALTH_CHECK_SERVICE_FLAG_NAME: &str = concat!($prefix, "health-check-service");
        const HEALTH_CHECK_TIMEOUT_FLAG_NAME: &str = concat!($prefix, "health-check-timeout");
        const HEALTH_CHECK_INTERVAL_FLAG_NAME: &str = concat!($prefix, "health-check-interval");
    };
}

#[derive(Clone, Debug)]
enum UriOrPath {
    Uri(Uri),
    Path(std::path::PathBuf),
}

impl FromStr for UriOrPath {
    type Err = <Uri as FromStr>::Err;

    fn from_str(s: &str) -> Result<UriOrPath, Self::Err> {
        Ok(if s.starts_with("unix:") {
            UriOrPath::Path(s[5..].into())
        } else {
            UriOrPath::Uri(Uri::from_str(s)?)
        })
    }
}

#[doc(hidden)]
#[derive(Debug, Default)]
pub struct GrpcClientArgs<I> {
    uri: Option<Uri>,
    connect_uri: Option<UriOrPath>,
    config: GRPCChannelConfig,
    _i: PhantomData<I>,
}

fn format_optional_duration(d: Option<Duration>) -> clap::builder::Str {
    match d {
        None => "none".into(),
        Some(dd) => clap::builder::Str::from(format_duration(dd).to_string()),
    }
}

fn parse_optional_duration(d: &str) -> Result<Option<Duration>, humantime::DurationError> {
    Ok(if d == "none" {
        None
    } else {
        Some(parse_duration(d)?)
    })
}

impl<I: InstanceDescriptor> Args for GrpcClientArgs<I> {
    fn augment_args(cmd: Command) -> Command {
        let default = GRPCChannelConfig::default();
        let n_subchannels_want =
            clap::builder::Str::from(default.pool.n_subchannels_want.to_string());
        let n_subchannels_healthy_min =
            clap::builder::Str::from(default.pool.n_subchannels_healthy_min.to_string());
        let n_subchannels_healthy_critical_min =
            clap::builder::Str::from(default.pool.n_subchannels_healthy_critical_min.to_string());
        let log_unhealthy_initial_delay =
            format_optional_duration(default.pool.log_unhealthy_initial_delay);
        let log_unhealthy_repeat_delay =
            format_optional_duration(default.pool.log_unhealthy_repeat_delay);
        let health_check_timeout =
            clap::builder::Str::from(format_duration(default.health_checking.timeout).to_string());
        let health_check_interval =
            clap::builder::Str::from(format_duration(default.health_checking.interval).to_string());
        let mut hc_service_flag = Arg::new(I::HEALTH_CHECK_SERVICE_FLAG_NAME)
            .long(I::HEALTH_CHECK_SERVICE_FLAG_NAME)
            .conflicts_with(I::NO_HEALTH_CHECK_ENABLE_FLAG_NAME)
            .help("gRPC health checking protocol service name.");
        if let Some(ref service) = default.health_checking.service {
            hc_service_flag = hc_service_flag.default_value((**service).to_owned());
        }

        cmd
            .arg(
                Arg::new(I::URI_FLAG_NAME)
                    .long(I::URI_FLAG_NAME)
                    .required(I::REQUIRED)
                    .value_parser(value_parser!(Uri))
                    .help("URI of gRPC backend. The path and query are ignored.")
            )
            .arg(
                Arg::new(I::CONNECT_URI_FLAG_NAME)
                    .long(I::CONNECT_URI_FLAG_NAME)
                    .value_parser(value_parser!(UriOrPath))
                    .help("Alternate URI to resolve and connect to instead of the main URI. Can be http[s]://host:port/ or unix:/socket/path. Useful when a different TLS server name is required.")
            )
            .arg(
                Arg::new(I::N_SUBCHANNELS_WANT_FLAG_NAME)
                    .long(I::N_SUBCHANNELS_WANT_FLAG_NAME)
                    .value_parser(value_parser!(usize))
                    .default_value(&n_subchannels_want)
                    .help("Number of load-balanced subchannels to maintain open.")
            )
            .arg(
                Arg::new(I::N_SUBCHANNELS_HEALTHY_MIN_FLAG_NAME)
                    .long(I::N_SUBCHANNELS_HEALTHY_MIN_FLAG_NAME)
                    .value_parser(value_parser!(usize))
                    .default_value(&n_subchannels_healthy_min)
                    .help("Number of healthy subchannels below which we report ourselves as unhealthy.")
            )
            .arg(
                Arg::new(I::N_SUBCHANNELS_HEALTHY_CRITICAL_MIN_FLAG_NAME)
                    .long(I::N_SUBCHANNELS_HEALTHY_CRITICAL_MIN_FLAG_NAME)
                    .value_parser(value_parser!(usize))
                    .default_value(&n_subchannels_healthy_critical_min)
                    .help("Number of healthy subchannels below which ignore subchannel health and send requests anyway.")
            )
            .arg(
                Arg::new(I::LOG_UNHEALTHY_INITIAL_DELAY_FLAG_NAME)
                    .long(I::LOG_UNHEALTHY_INITIAL_DELAY_FLAG_NAME)
                    .value_parser(parse_optional_duration)
                    .default_value(&log_unhealthy_initial_delay)
                    .help("Log about unhealthy channels after this amount of time, or \"none\".")
            )
            .arg(
                Arg::new(I::LOG_UNHEALTHY_REPEAT_DELAY_FLAG_NAME)
                    .long(I::LOG_UNHEALTHY_REPEAT_DELAY_FLAG_NAME)
                    .value_parser(parse_optional_duration)
                    .default_value(&log_unhealthy_repeat_delay)
                    .help("Log again about unhealthy channels after this amount of time, or \"none\".")
            )
            .arg(
                Arg::new(I::NO_HEALTH_CHECK_ENABLE_FLAG_NAME)
                    .long(I::NO_HEALTH_CHECK_ENABLE_FLAG_NAME)
                    .value_parser(value_parser!(bool))
                    .help("Disable gRPC health checking.")
            )
            .arg(hc_service_flag)
            .arg(
                Arg::new(I::HEALTH_CHECK_TIMEOUT_FLAG_NAME)
                    .long(I::HEALTH_CHECK_TIMEOUT_FLAG_NAME)
                    .value_parser(parse_duration)
                    .default_value(&health_check_timeout)
                    .conflicts_with(I::NO_HEALTH_CHECK_ENABLE_FLAG_NAME)
                    .help("Timeout for each individual health check probe.")
            )
            .arg(
                Arg::new(I::HEALTH_CHECK_INTERVAL_FLAG_NAME)
                    .long(I::HEALTH_CHECK_INTERVAL_FLAG_NAME)
                    .value_parser(parse_duration)
                    .default_value(&health_check_interval)
                    .conflicts_with(I::NO_HEALTH_CHECK_ENABLE_FLAG_NAME)
                    .help("Interval between each individual health check probe.")
            )
    }

    fn augment_args_for_update(cmd: Command) -> Command {
        Self::augment_args(cmd)
    }
}

impl<I: InstanceDescriptor> FromArgMatches for GrpcClientArgs<I> {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let mut matches = matches.clone();
        Self::from_arg_matches_mut(&mut matches)
    }

    fn from_arg_matches_mut(matches: &mut ArgMatches) -> Result<Self, clap::Error> {
        let mut this = Self {
            uri: None,
            connect_uri: None,
            config: GRPCChannelConfig::default(),
            _i: PhantomData,
        };
        this.update_from_arg_matches_mut(matches)?;
        Ok(this)
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), clap::Error> {
        let mut matches = matches.clone();
        self.update_from_arg_matches_mut(&mut matches)
    }

    fn update_from_arg_matches_mut(&mut self, matches: &mut ArgMatches) -> Result<(), clap::Error> {
        self.uri = matches.remove_one(I::URI_FLAG_NAME);
        self.connect_uri = matches.remove_one(I::CONNECT_URI_FLAG_NAME);
        self.config.pool.n_subchannels_want = matches
            .remove_one(I::N_SUBCHANNELS_WANT_FLAG_NAME)
            .expect("has default_value");
        if self.config.pool.n_subchannels_want > self.config.pool.n_subchannels_max {
            self.config.pool.n_subchannels_max = self.config.pool.n_subchannels_want;
        }
        self.config.pool.n_subchannels_healthy_min = matches
            .remove_one(I::N_SUBCHANNELS_HEALTHY_MIN_FLAG_NAME)
            .expect("has default_value");
        self.config.pool.n_subchannels_healthy_critical_min = matches
            .remove_one(I::N_SUBCHANNELS_HEALTHY_CRITICAL_MIN_FLAG_NAME)
            .expect("has default_value");
        self.config.pool.log_unhealthy_initial_delay = matches
            .remove_one(I::LOG_UNHEALTHY_INITIAL_DELAY_FLAG_NAME)
            .expect("has default_value");
        self.config.pool.log_unhealthy_repeat_delay = matches
            .remove_one(I::LOG_UNHEALTHY_REPEAT_DELAY_FLAG_NAME)
            .expect("has default_value");
        if matches
            .remove_one(I::NO_HEALTH_CHECK_ENABLE_FLAG_NAME)
            .unwrap_or_default()
        {
            self.config.health_checking.service = None;
        } else {
            self.config.health_checking.service = matches
                .remove_one::<String>(I::HEALTH_CHECK_SERVICE_FLAG_NAME)
                .map(Into::into);
            self.config.health_checking.timeout = matches
                .remove_one::<Duration>(I::HEALTH_CHECK_TIMEOUT_FLAG_NAME)
                .expect("has default_value");
            self.config.health_checking.interval = matches
                .remove_one::<Duration>(I::HEALTH_CHECK_INTERVAL_FLAG_NAME)
                .expect("has default_value");
        }
        Ok(())
    }
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct GRPCClientDependencies {
    resolver: Arc<DNSResolver>,
    #[cfg(feature = "tls")]
    tls_config: Arc<comprehensive::tls::TlsConfig>,
    health: Arc<HealthReporter>,
    _include_me: Arc<WarmChannelsDiag>,
}

fn resolve<'a, R, RR>(
    uri: &Uri,
    connect_uri: Option<UriOrPath>,
    resolver: RR,
) -> Result<impl Stream<Item = Result<Vec<IPOrUNIXAddress>, R::Error>> + 'a, ResolveUriError>
where
    RR: AsRef<R> + Send + 'a,
    R: warm_channels::resolver::Resolve + 'a,
    R::Error: Send,
{
    let ruri = match connect_uri {
        None => uri,
        Some(UriOrPath::Uri(ref curi)) => curi,
        Some(UriOrPath::Path(path)) => {
            return Ok(
                futures::stream::once(std::future::ready(Ok(vec![IPOrUNIXAddress::UNIX(path)])))
                    .left_stream(),
            );
        }
    };
    Ok(warm_channels::resolver::resolve_uri(&ruri, resolver)?
        .map_ok(|v| v.into_iter().map(Into::into).collect())
        .right_stream())
}

#[doc(hidden)]
pub fn new<I>(
    a: GrpcClientArgs<I>,
    name: &'static str,
    propagate_health: bool,
    d: GRPCClientDependencies,
) -> Result<(Option<(Channel, Uri)>, ClientWorker), Box<dyn std::error::Error>> {
    let Some(uri) = a.uri else {
        return Ok((None, ClientWorker::empty()));
    };
    super::tonic_prometheus_layer_use_default_registry();

    #[cfg(feature = "tls")]
    let connector = {
        let tls_config = d.tls_config.client_config();
        TLSConnector::new(StreamConnector::default(), &uri, Some(&tls_config))?
    };
    #[cfg(not(feature = "tls"))]
    let connector = StreamConnector::default();

    let signaller = if propagate_health {
        Some(d.health.register(name)?)
    } else {
        None
    };
    let reso = resolve(&uri, a.connect_uri, d.resolver.resolver())?;
    let (stack, worker) = grpc_channel(uri.clone(), a.config, name, connector, reso, move |h| {
        signaller.as_ref().inspect(|s| s.set_healthy(h));
    });
    Ok((Some((stack, uri)), ClientWorker::new(worker)))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod pb {
        pub(crate) mod comprehensive {
            tonic::include_proto!("comprehensive");
        }
    }

    use crate::GrpcClient;
    use pb::comprehensive::test_client::TestClient;

    #[derive(GrpcClient)]
    struct OptionalTupleStructV0(Option<TestClient<Channel>>, ClientWorker);

    #[derive(GrpcClient)]
    #[no_propagate_health]
    struct RequiredTupleStructV0(TestClient<Channel>, ClientWorker);

    #[derive(GrpcClient)]
    struct OptionalNamedStructV0 {
        client: Option<TestClient<Channel>>,
        worker: ClientWorker,
    }

    #[derive(GrpcClient)]
    struct RequiredNamedStructV0 {
        field_names: TestClient<Channel>,
        dont_matter: ClientWorker,
    }

    #[derive(ResourceDependencies)]
    struct TestClientsV0 {
        optional_tuple_struct: Arc<OptionalTupleStructV0>,
        required_tuple_struct: Arc<RequiredTupleStructV0>,
        optional_named_struct: Arc<OptionalNamedStructV0>,
        required_named_struct: Arc<RequiredNamedStructV0>,
    }

    #[test]
    fn create_clients_v0() {
        let argv: Vec<std::ffi::OsString> = vec![
            "argv0".into(),
            "--required-tuple-struct-v-0-uri=http://localhost/".into(),
            "--required-named-struct-v-0-uri=http://localhost/".into(),
            "--optional-named-struct-v-0-uri=http://localhost/".into(),
        ];
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        let a = comprehensive::Assembly::<TestClientsV0>::new_from_argv(argv).unwrap();

        let c1: Option<TestClient<Channel>> = a.top.optional_tuple_struct.client();
        let mut c2: TestClient<Channel> = a.top.required_tuple_struct.client();
        let c3: Option<TestClient<Channel>> = a.top.optional_named_struct.client();
        let mut c4: TestClient<Channel> = a.top.required_named_struct.client();

        assert!(c1.is_none());
        let _ = c2.greet(());
        let _ = c3.unwrap().greet(());
        let _ = c4.greet(());
    }

    #[derive(GrpcClient)]
    struct OptionalTupleStruct(Option<TestClient<Channel>>);

    #[derive(GrpcClient)]
    #[no_propagate_health]
    struct RequiredTupleStruct(TestClient<Channel>);

    #[derive(GrpcClient)]
    struct OptionalNamedStruct {
        client: Option<TestClient<Channel>>,
    }

    #[derive(GrpcClient)]
    struct RequiredNamedStruct {
        field_names: TestClient<Channel>,
    }

    #[derive(ResourceDependencies)]
    struct TestClients {
        optional_tuple_struct: Arc<OptionalTupleStruct>,
        required_tuple_struct: Arc<RequiredTupleStruct>,
        optional_named_struct: Arc<OptionalNamedStruct>,
        required_named_struct: Arc<RequiredNamedStruct>,
    }

    #[test]
    fn create_clients_v1() {
        let argv: Vec<std::ffi::OsString> = vec![
            "argv0".into(),
            "--required-tuple-struct-uri=http://localhost/".into(),
            "--required-named-struct-uri=http://localhost/".into(),
            "--optional-named-struct-uri=http://localhost/".into(),
        ];
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        let a = comprehensive::Assembly::<TestClients>::new_from_argv(argv).unwrap();

        let c1: Option<TestClient<Channel>> = a.top.optional_tuple_struct.client();
        let mut c2: TestClient<Channel> = a.top.required_tuple_struct.client();
        let c3: Option<TestClient<Channel>> = a.top.optional_named_struct.client();
        let mut c4: TestClient<Channel> = a.top.required_named_struct.client();

        assert!(c1.is_none());
        let _ = c2.greet(());
        let _ = c3.unwrap().greet(());
        let _ = c4.greet(());
    }
}
