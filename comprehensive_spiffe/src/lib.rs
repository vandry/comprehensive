//! Provide TLS configuration parameters to a [`comprehensive::Assembly`]
//! from SPIFFE by contacting the local agent using the workload API.
//!
//! # WARNING
//!
//! This provider is not yet usable because
//! [the SPIFFE certificates can't be verified](https://github.com/rustls/rustls/issues/1194).
//! This is a work in progress.

#![warn(missing_docs)]

use comprehensive::ResourceDependencies;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive_grpc::GrpcClient;
use comprehensive_grpc::client::GrpcClientResourceDefaults;
use comprehensive_traits::tls_config::{Exchange, Snapshot, TlsConfigProvider};
use futures::{SinkExt, StreamExt};
use rustls_pki_types::CertificateDer;
use std::sync::Arc;
use thiserror::Error;

mod pb {
    tonic::include_proto!("_");
}

type X509ParserError = x509_parser::nom::Err<x509_parser::error::X509Error>;

#[derive(Debug, Error)]
enum SpiffeError {
    #[error("X509SVIDResponse containing no SVIDs")]
    Empty,
    #[error("{0}")]
    KeyError(&'static str),
    #[error("{0}")]
    X509Error(#[from] X509ParserError),
}

struct Certificates<'a>(&'a [u8]);

impl<'a> Certificates<'a> {
    fn new(der: &'a [u8]) -> Self {
        Self(der)
    }
}

impl Iterator for Certificates<'_> {
    type Item = Result<CertificateDer<'static>, X509ParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        Some(match x509_parser::parse_x509_certificate(self.0) {
            Ok((rest, _)) => {
                let der_len = self.0.len() - rest.len();
                let cert = self.0[..der_len].to_vec().into();
                self.0 = rest;
                Ok(cert)
            }
            Err(e) => {
                self.0 = b"";
                Err(e)
            }
        })
    }
}

fn accept_svids(response: pb::X509svidResponse) -> Result<Box<Snapshot>, SpiffeError> {
    let mut it = response.svids.into_iter();
    let Some(svid) = it.next() else {
        return Err(SpiffeError::Empty);
    };
    if it.next().is_some() {
        log::warn!("X509SVIDResponse containing more than 1 SVID; using the first");
    }
    log::info!("Local SPIFFE ID is {}", svid.spiffe_id);
    Ok(Box::new(Snapshot {
        key: svid
            .x509_svid_key
            .try_into()
            .map_err(SpiffeError::KeyError)?,
        cert: Certificates::new(&svid.x509_svid).collect::<Result<Vec<_>, _>>()?,
        cacert: Some(Certificates::new(&svid.bundle).collect::<Result<Vec<_>, _>>()?),
    }))
}

fn grpc_client_defaults() -> GrpcClientResourceDefaults {
    let mut d = GrpcClientResourceDefaults::default();
    match std::env::var("SPIFFE_ENDPOINT_SOCKET") {
        Ok(endpoint) => {
            if let Some(path) = endpoint.strip_prefix("unix:///") {
                d.connect_uri = Some(format!("unix:/{}", path).into());
                d.uri = Some("http://localhost/".into());
            } else {
                log::warn!("Only unix:///path is supported for $SPIFFE_ENDPOINT_SOCKET");
            }
        }
        Err(_) => {
            d.connect_uri = Some("unix:/tmp/spire-agent/public/api.sock".into());
            d.uri = Some("http://localhost/".into());
        }
    }
    d.config.health_checking.service = Some("".into());
    d.config.pool.n_subchannels_want = 1;
    d.config.pool.n_subchannels_healthy_min = 1;
    d
}

#[derive(GrpcClient)]
#[defaults(grpc_client_defaults())]
#[no_tls]
struct SpiffeWorkloadApiClient(
    pb::spiffe_workload_api_client::SpiffeWorkloadApiClient<
        comprehensive_grpc::client::ChannelNoTls,
    >,
);

#[derive(ResourceDependencies)]
#[doc(hidden)]
pub struct Dependencies(Arc<SpiffeWorkloadApiClient>);

#[derive(clap::Args)]
#[doc(hidden)]
pub struct Args {
    #[arg(
        long,
        help = "Enable SPIFFE. Also enabled by the presence of $SPIFFE_ENDPOINT_SOCKET."
    )]
    spiffe: bool,
    #[arg(long, help = "Disable SPIFFE even if $SPIFFE_ENDPOINT_SOCKET exists.")]
    no_spiffe: bool,
}

/// Error type returned by [`SpiffeTlsProvider`] when it is not enabled.
/// Pass `--spiffe` or set `$SPIFFE_ENDPOINT_SOCKET` to enable it.
#[derive(Debug)]
pub struct NotEnabled;

impl std::fmt::Display for NotEnabled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "not enabled; set --spiffe or $SPIFFE_ENDPOINT_SOCKET to enable"
        )
    }
}

impl std::error::Error for NotEnabled {}

/// [`TlsConfigProvider`] using SPIFFE.
///
/// To use this, it is enough to mention this resource anywhere in the assembly
/// without depending on it, like this:
///
/// ```
/// #[derive(comprehensive::ResourceDependencies)]
/// struct SomeDependencies {
///     // ...dependencies...
///     _x: std::marker::PhantomData<comprehensive_spiffe::SpiffeTlsProvider>,
/// }
/// ```
///
/// It will then be picked up by [`comprehensive_tls::TlsConfig`].
///
/// [`comprehensive_tls::TlsConfig`]: https://docs.rs/comprehensive_tls/latest/comprehensive_tls/struct.TlsConfig.html
pub struct SpiffeTlsProvider(Exchange);

#[resource]
#[export(dyn TlsConfigProvider)]
impl Resource for SpiffeTlsProvider {
    fn new(
        d: Dependencies,
        a: Args,
        api: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, NotEnabled> {
        if a.no_spiffe || !(a.spiffe || std::env::var("SPIFFE_ENDPOINT_SOCKET").is_ok()) {
            return Err(NotEnabled);
        }
        let mut client = d.0.client();
        let shared = Arc::new(Self(Exchange::default()));
        let shared2 = Arc::clone(&shared);
        api.set_task(async move {
            let mut writer = shared.0.writer().unwrap();
            let mut req = tonic::Request::new(pb::X509svidRequest::default());
            let _ = req.metadata_mut().insert(
                "workload.spiffe.io",
                tonic::metadata::MetadataValue::from_static("true"),
            );
            let mut stream = client.fetch_x509svid(req).await?.into_inner();
            while let Some(frame) = stream.next().await {
                match frame {
                    Ok(response) => match accept_svids(response) {
                        Ok(d) => writer.send(d).await.unwrap(),
                        Err(e) => {
                            log::error!("X509SVIDResponse: {}", e);
                        }
                    },
                    Err(e) => {
                        log::error!("Error requesting SPIFFE X.509 SVID: {}", e);
                    }
                }
            }
            log::error!("lost stream");
            Ok(())
        });
        Ok(shared2)
    }
}

impl TlsConfigProvider for SpiffeTlsProvider {
    fn stream(&self) -> Option<comprehensive_traits::tls_config::Reader<'_>> {
        self.0.reader()
    }
}
