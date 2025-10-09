//! Provide TLS configuration parameters to a [`comprehensive::Assembly`]
//! from SPIFFE by contacting the local agent using the workload API.

#![warn(missing_docs)]
// Would impose a requirement for rustc 1.88
// https://github.com/rust-lang/rust/pull/132833
#![allow(clippy::collapsible_if)]

use backoff::ExponentialBackoffBuilder;
use backoff::backoff::Backoff;
use comprehensive::ResourceDependencies;
use comprehensive::v1::{AssemblyRuntime, Resource, resource};
#[cfg(not(test))]
use comprehensive_grpc::GrpcClient;
use comprehensive_grpc::client::GrpcClientResourceDefaults;
use comprehensive_tls::api::{
    IdentityHints, LatestValueStream, TlsConfigInstance, TlsConfigProvider,
    VerifyExpectedIdentityResult, rustls, rustls_pki_types, x509_parser,
};
use futures::{SinkExt, Stream, StreamExt};
use http::Uri;
use itertools::Itertools;
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls::{DistinguishedName, RootCertStore};
use rustls_pki_types::{CertificateDer, TrustAnchor};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use thiserror::Error;
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;

mod pb {
    tonic::include_proto!("_");
}

#[cfg(test)]
mod testdata;

type X509ParserError = x509_parser::nom::Err<x509_parser::error::X509Error>;

const SPIFFE_SCHEME: &str = "spiffe";

#[derive(Debug, Error)]
enum SpiffeError {
    #[error("X509SVIDResponse containing no SVIDs")]
    Empty,
    #[error("spiffe_id {0} is invalid URI: {1}")]
    InvalidUri(String, http::uri::InvalidUri),
    #[error("spiffe_id {0} has wrong scheme")]
    WrongScheme(String),
    #[error("{0}")]
    KeyError(&'static str),
    #[error("{0}")]
    X509Error(#[from] X509ParserError),
    #[error("{0}")]
    RustlsError(#[from] rustls::Error),
    #[error("{0}")]
    WebpkiError(#[from] webpki::Error),
}

struct ConcatenatedCertificates<'a>(&'a [u8]);

impl<'a> ConcatenatedCertificates<'a> {
    fn new(der: &'a [u8]) -> Self {
        Self(der)
    }
}

impl<'a> Iterator for ConcatenatedCertificates<'a> {
    type Item = Result<(CertificateDer<'static>, X509Certificate<'a>), X509ParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        Some(match x509_parser::parse_x509_certificate(self.0) {
            Ok((rest, parsed)) => {
                let der_len = self.0.len() - rest.len();
                let cert = self.0[..der_len].to_vec().into();
                self.0 = rest;
                Ok((cert, parsed))
            }
            Err(e) => {
                self.0 = b"";
                Err(e)
            }
        })
    }
}

#[derive(Debug)]
struct SvidBundle {
    id: Uri,
    trust_anchors: Arc<[TrustAnchor<'static>]>,
    root_subjects: Arc<[DistinguishedName]>,
}

impl<R: AsRef<[u8]>> TryFrom<(String, R)> for SvidBundle {
    type Error = SpiffeError;

    fn try_from((uri_s, roots_b): (String, R)) -> Result<Self, Self::Error> {
        let id: Uri = match uri_s.parse() {
            Ok(uri) => uri,
            Err(e) => {
                return Err(SpiffeError::InvalidUri(uri_s, e));
            }
        };
        if id.scheme_str() != Some(SPIFFE_SCHEME) {
            return Err(SpiffeError::WrongScheme(uri_s));
        }
        let roots = ConcatenatedCertificates::new(roots_b.as_ref())
            .map(|c| Ok(webpki::anchor_from_trusted_cert(&c?.0)?.to_owned()))
            .collect::<Result<RootCertStore, SpiffeError>>()?;
        Ok(SvidBundle {
            id,
            root_subjects: roots.subjects().into(),
            trust_anchors: roots.roots.into(),
        })
    }
}

#[derive(Debug)]
struct SingleSvid {
    bundle: SvidBundle,
    certified_key: Arc<CertifiedKey>,
    soonest_expiration: Option<OffsetDateTime>,
}

impl TryFrom<(pb::X509svid, &'_ CryptoProvider)> for SingleSvid {
    type Error = SpiffeError;

    fn try_from(
        (svid, crypto_provider): (pb::X509svid, &'_ CryptoProvider),
    ) -> Result<Self, Self::Error> {
        let bundle = (svid.spiffe_id, svid.bundle).try_into()?;
        let private_key = crypto_provider.key_provider.load_private_key(
            svid.x509_svid_key
                .try_into()
                .map_err(SpiffeError::KeyError)?,
        )?;
        let mut soonest_expiration = None;
        let cert = ConcatenatedCertificates::new(&svid.x509_svid)
            .map_ok(|(c, parsed)| {
                let this_expiration = parsed.validity().not_after.to_datetime();
                if soonest_expiration
                    .map(|e| this_expiration < e)
                    .unwrap_or(true)
                {
                    soonest_expiration = Some(this_expiration);
                }
                c
            })
            .collect::<Result<Vec<_>, _>>()?;
        let certified_key = CertifiedKey::new(cert, private_key);
        certified_key.keys_match()?;
        Ok(SingleSvid {
            certified_key: certified_key.into(),
            bundle,
            soonest_expiration,
        })
    }
}

#[derive(Copy, Clone, Debug)]
enum SvidReference {
    Native(usize),
    Federated(usize),
}

#[derive(Debug, Default)]
struct SpiffeConfig {
    svids: Vec<SingleSvid>,
    federated: Vec<SvidBundle>,
    domain_index: HashMap<String, SvidReference>,
    root_index: HashMap<Vec<u8>, SvidReference>,
    uri_index: HashMap<Uri, SvidReference>,
    soonest_expiration: Option<OffsetDateTime>,
}

impl SpiffeConfig {
    fn get_svid(&self, i: SvidReference) -> Option<&SingleSvid> {
        match i {
            SvidReference::Native(i) => self.svids.get(i),
            SvidReference::Federated(_) => None,
        }
    }

    fn get_bundle(&self, i: SvidReference) -> Option<&SvidBundle> {
        match i {
            SvidReference::Native(i) => self.svids.get(i).map(|s| &s.bundle),
            SvidReference::Federated(i) => self.federated.get(i),
        }
    }

    fn select_identity_impl(
        &self,
        try_harder: bool,
        requested: Option<&Uri>,
        root_hint_subjects: Option<&[DistinguishedName]>,
        sni: Option<&str>,
    ) -> Option<Arc<CertifiedKey>> {
        if try_harder {
            if self.svids.is_empty() {
                None
            } else {
                Some(&SvidReference::Native(0))
            }
        } else {
            requested
                .and_then(|uri| self.uri_index.get(uri))
                .or_else(|| match root_hint_subjects {
                    // Prefer root_hints if available.
                    Some(hints) => hints
                        .iter()
                        .filter_map(|dn| self.root_index.get(dn.as_ref()))
                        .next(),
                    // Fall back to SNI.
                    None => sni.and_then(|sni| self.domain_index.get(sni)),
                })
        }
        .and_then(|i| self.get_svid(*i).map(|s| Arc::clone(&s.certified_key)))
    }

    fn domain_to_bundle(&self, uri: Option<&Uri>) -> Option<&SvidBundle> {
        uri.filter(|uri| uri.scheme_str() == Some(SPIFFE_SCHEME))
            .and_then(|uri| uri.host())
            .and_then(|host| self.domain_index.get(host))
            .and_then(|i| self.get_bundle(*i))
    }
}

struct InstanceDiag<'a>(&'a SpiffeConfig);

impl std::fmt::Display for InstanceDiag<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<li><b>SpiffeTlsProvider</b> identity<ul>")?;
        for single in &self.0.svids {
            write!(
                f,
                "<li>{}<ul>",
                html_escape::encode_text(&format!("{}", single.bundle.id))
            )?;
            if let Some(exp) = &single.soonest_expiration {
                write!(f, "<li>expires at {}</li>", exp)?;
            }
            write!(
                f,
                "<li>with {} trust anchors</li></ul></li>",
                single.bundle.trust_anchors.len()
            )?;
        }
        for bundle in &self.0.federated {
            write!(
                f,
                "<li>federated with: {}<ul>",
                html_escape::encode_text(&format!("{}", bundle.id))
            )?;
            write!(
                f,
                "<li>with {} trust anchors</li></ul></li>",
                bundle.trust_anchors.len()
            )?;
        }
        writeln!(f, "</ul></li>")
    }
}

impl TlsConfigInstance for SpiffeConfig {
    fn has_any_identity(&self) -> bool {
        !self.svids.is_empty()
    }

    fn select_identity(
        &self,
        try_harder: bool,
        hints: &IdentityHints<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        self.select_identity_impl(
            try_harder,
            hints.requested,
            hints.root_hint_subjects,
            hints.sni,
        )
    }

    fn choose_root_hint_subjects(
        &self,
        _local_identity: Option<&Uri>,
        remote_identity: Option<&Uri>,
    ) -> Option<Arc<[DistinguishedName]>> {
        // Hint the trust roots for the SPIFFE domain we expect from the peer.
        self.domain_to_bundle(remote_identity)
            .map(|b| Arc::clone(&b.root_subjects))
    }

    fn trust_anchors_for_cert(
        &self,
        try_harder: bool,
        end_entity: &X509Certificate<'_>,
        _intermediates: &[X509Certificate<'_>],
    ) -> Option<Arc<[TrustAnchor<'static>]>> {
        if try_harder {
            // We already gave our best answer when try_harder was false.
            return None;
        }
        if let Ok(Some(ext)) = end_entity.subject_alternative_name() {
            for san in &ext.value.general_names {
                if let x509_parser::extensions::GeneralName::URI(u) = san {
                    if let Ok(uri) = u.parse::<Uri>() {
                        if let Some(bundle) = self.domain_to_bundle(Some(&uri)) {
                            return Some(Arc::clone(&bundle.trust_anchors));
                        }
                    }
                }
            }
        }
        None
    }

    fn verify_expected_identity(
        &self,
        end_entity: &X509Certificate<'_>,
        expected_identity: &Uri,
    ) -> VerifyExpectedIdentityResult {
        if expected_identity.scheme_str() != Some(SPIFFE_SCHEME) {
            return VerifyExpectedIdentityResult::No;
        };
        if let Ok(Some(ext)) = end_entity.subject_alternative_name() {
            for san in &ext.value.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = san {
                    if uri == expected_identity {
                        return VerifyExpectedIdentityResult::Yes;
                    }
                }
            }
        }
        VerifyExpectedIdentityResult::No
    }

    fn identity_valid_until(&self) -> Option<OffsetDateTime> {
        self.soonest_expiration
    }

    fn diag(&self) -> Option<String> {
        Some(format!("{}", InstanceDiag(self)))
    }
}

impl TryFrom<(pb::X509svidResponse, &'_ CryptoProvider)> for SpiffeConfig {
    type Error = SpiffeError;

    fn try_from(
        (response, crypto_provider): (pb::X509svidResponse, &'_ CryptoProvider),
    ) -> Result<Self, Self::Error> {
        let svids = response
            .svids
            .into_iter()
            .map(|s| (s, crypto_provider).try_into())
            .collect::<Result<Vec<SingleSvid>, _>>()?;
        let federated = response
            .federated_bundles
            .into_iter()
            .map(TryInto::<SvidBundle>::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        let mut conf = Self {
            domain_index: HashMap::new(),
            root_index: HashMap::new(),
            uri_index: HashMap::new(),
            soonest_expiration: svids
                .iter()
                .filter_map(|svid| svid.soonest_expiration)
                .min(),
            svids,
            federated,
        };
        if conf.svids.is_empty() {
            return Err(SpiffeError::Empty);
        };
        for (i, bundle) in conf
            .svids
            .iter()
            .map(|svid| &svid.bundle)
            .enumerate()
            .map(|(i, b)| (SvidReference::Native(i), b))
            .chain(
                conf.federated
                    .iter()
                    .enumerate()
                    .map(|(i, b)| (SvidReference::Federated(i), b)),
            )
        {
            if let Some(host) = bundle.id.host() {
                match conf.domain_index.entry(host.to_owned()) {
                    Entry::Occupied(other) => {
                        let other = *other.get();
                        log::warn!(
                            "SPIFFE ids {} and {} have the same domain. Will provide root_hint_subjects only for the first one when expecting servers in that domain.",
                            conf.get_bundle(other).map(|b| &b.id).unwrap(),
                            bundle.id
                        );
                    }
                    Entry::Vacant(vacant) => {
                        vacant.insert(i);
                    }
                }
            }
            for subject in bundle.root_subjects.as_ref() {
                match conf.root_index.entry(subject.as_ref().to_vec()) {
                    Entry::Occupied(other) => {
                        let other = *other.get();
                        log::warn!(
                            "SPIFFE ids {} and {} share a trust root. Will select only the first identity when that trust root is received through root_hint_subjects.",
                            conf.get_bundle(other).map(|b| &b.id).unwrap(),
                            bundle.id
                        );
                    }
                    Entry::Vacant(vacant) => {
                        vacant.insert(i);
                    }
                }
            }
            if matches!(i, SvidReference::Native(_)) {
                match conf.uri_index.entry(bundle.id.clone()) {
                    Entry::Occupied(_) => {
                        log::warn!(
                            "SPIFFE id {} is duplicated. Only one of them will be selectable as a requested local ID.",
                            bundle.id
                        );
                    }
                    Entry::Vacant(vacant) => {
                        vacant.insert(i);
                    }
                }
            }
        }
        log::info!(
            "{} local SPIFFE identities loaded: {}",
            conf.svids.len(),
            conf.svids
                .iter()
                .map(|id| id.bundle.id.to_string())
                .join(", ")
        );
        Ok(conf)
    }
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

#[cfg(test)]
struct SpiffeWorkloadApiClient;

#[cfg(not(test))]
#[derive(GrpcClient)]
#[defaults(grpc_client_defaults())]
#[no_propagate_health] // Okay to lose contact with the agent.
#[no_tls]
struct SpiffeWorkloadApiClient(
    pb::spiffe_workload_api_client::SpiffeWorkloadApiClient<
        comprehensive_grpc::client::ChannelNoTls,
    >,
);

#[derive(ResourceDependencies)]
#[doc(hidden)]
pub struct Dependencies {
    workload_api_client: Arc<SpiffeWorkloadApiClient>,
    crypto_provider: Arc<comprehensive_tls::crypto_provider::RustlsCryptoProvider>,
}

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
pub struct SpiffeTlsProvider(LatestValueStream);

async fn handle_stream<S, E, B>(
    mut stream: S,
    writer: &mut comprehensive_tls::api::Writer<'_>,
    crypto_provider: &CryptoProvider,
    backoff: &mut B,
) where
    S: Stream<Item = Result<pb::X509svidResponse, E>> + Unpin,
    E: std::error::Error,
    B: Backoff,
{
    while let Some(frame) = stream.next().await {
        match frame {
            Ok(response) => match (response, crypto_provider).try_into() {
                Ok(d) => {
                    writer.send(Box::<SpiffeConfig>::new(d)).await.unwrap();
                    backoff.reset();
                }
                Err(e) => {
                    log::error!("X509SVIDResponse: {}", e);
                }
            },
            Err(e) => {
                log::error!("Error requesting SPIFFE X.509 SVID: {}", e);
            }
        }
    }
}

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
        let mut client = d.workload_api_client.client();
        let crypto_provider = d.crypto_provider.crypto_provider();
        let shared = Arc::new(Self(LatestValueStream::default()));
        let shared2 = Arc::clone(&shared);
        let mut backoff = ExponentialBackoffBuilder::new()
            .with_max_elapsed_time(None) // Never completely give up.
            .build();
        api.set_task(async move {
            let mut writer = shared.0.writer();
            loop {
                let mut req = tonic::Request::new(pb::X509svidRequest::default());
                let _ = req.metadata_mut().insert(
                    "workload.spiffe.io",
                    tonic::metadata::MetadataValue::from_static("true"),
                );
                match client.fetch_x509svid(req).await {
                    Ok(r) => {
                        handle_stream(r.into_inner(), &mut writer, &crypto_provider, &mut backoff)
                            .await
                    }
                    Err(e) => {
                        log::error!("FetchX509SVID: {:?}", e);
                    }
                }
                match backoff.next_backoff() {
                    None => {
                        break;
                    }
                    Some(t) => tokio::time::sleep(t).await,
                }
            }
            Err("Gave up on SPIFFE (should not happen)".into())
        });
        Ok(shared2)
    }
}

impl TlsConfigProvider for SpiffeTlsProvider {
    fn stream(&self) -> comprehensive_tls::api::Reader<'_> {
        self.0.reader()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use comprehensive::Assembly;
    use futures::Stream;
    use futures::future::Either;
    use std::pin::pin;
    use tonic::Request;
    use x509_parser::prelude::FromDer;

    use crate::pb::{X509svidRequest, X509svidResponse};

    fn test_config() -> SpiffeConfig {
        let p = rustls::crypto::aws_lc_rs::default_provider();
        (testdata::SVID_RESPONSE.clone(), &p).try_into().unwrap()
    }

    #[resource]
    impl Resource for SpiffeWorkloadApiClient {
        fn new(
            _: comprehensive::NoDependencies,
            _: comprehensive::NoArgs,
            _: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            Ok(Arc::new(Self))
        }
    }

    pub struct MockResponse;

    impl MockResponse {
        pub fn into_inner(
            self,
        ) -> impl Stream<Item = Result<X509svidResponse, std::convert::Infallible>> {
            futures::stream::once(std::future::ready(Ok(testdata::SVID_RESPONSE.clone())))
                .chain(futures::stream::pending())
        }
    }

    pub struct MockSpiffeWorkloadApiClient;

    impl MockSpiffeWorkloadApiClient {
        pub async fn fetch_x509svid(
            &mut self,
            _: Request<X509svidRequest>,
        ) -> Result<MockResponse, std::convert::Infallible> {
            Ok(MockResponse)
        }
    }

    impl SpiffeWorkloadApiClient {
        pub fn client(&self) -> MockSpiffeWorkloadApiClient {
            let _ = grpc_client_defaults();
            MockSpiffeWorkloadApiClient
        }
    }

    #[derive(ResourceDependencies)]
    struct TopDependencies(Arc<SpiffeTlsProvider>);

    #[tokio::test]
    async fn end_to_end() {
        let argv: Vec<std::ffi::OsString> = vec!["cmd".into(), "--spiffe".into()];
        let a = Assembly::<TopDependencies>::new_from_argv(argv).unwrap();
        let spiffe_config = Arc::clone(&a.top.0);
        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        let mut stream = spiffe_config.stream();
        let mut reader = pin!(stream.next());
        let config = match futures::future::select(&mut r, &mut reader).await {
            Either::Left((e, _)) => {
                panic!("Assembly quit: {:?}", e);
            }
            Either::Right((o, _)) => o,
        };
        assert!(
            config
                .expect("Box<dyn TlsConfigInstance>")
                .has_any_identity()
        );
    }

    #[test]
    fn select_identity_no_hints() {
        let config = test_config();
        assert!(
            config
                .select_identity_impl(false, None, None, None)
                .is_none()
        );
    }

    #[test]
    fn select_identity_requested() {
        let config = test_config();
        let requested = Uri::from_static("spiffe://spiffe.example.org/node1/workload1");
        // Provide the other hints so they disagree. requested should win.
        let sni = "spiffe2.example.org";
        let root_hints = vec![DistinguishedName::from(testdata::SPIFFE2_ROOT_DN.to_vec())];
        assert_eq!(
            config
                .select_identity_impl(
                    false,
                    Some(&requested),
                    Some(root_hints.as_slice()),
                    Some(&sni)
                )
                .expect("workload1")
                .cert,
            config.svids[0].certified_key.cert
        );
    }

    #[test]
    fn select_identity_requested_not_available() {
        let config = test_config();
        let requested = Uri::from_static("spiffe://unknown.example.org/foo");
        // Since requested is not available, expect root_hints to be used.
        let sni = "spiffe2.example.org";
        let root_hints = vec![DistinguishedName::from(testdata::SPIFFE2_ROOT_DN.to_vec())];
        assert_eq!(
            config
                .select_identity_impl(
                    false,
                    Some(&requested),
                    Some(root_hints.as_slice()),
                    Some(&sni)
                )
                .expect("workload2")
                .cert,
            config.svids[1].certified_key.cert
        );
    }

    #[test]
    fn select_identity_root_hints_preferred() {
        let config = test_config();
        let sni = "spiffe.example.org";
        let root_hints = vec![DistinguishedName::from(testdata::SPIFFE2_ROOT_DN.to_vec())];
        assert_eq!(
            config
                .select_identity_impl(false, None, Some(root_hints.as_slice()), Some(&sni))
                .expect("workload2")
                .cert,
            config.svids[1].certified_key.cert
        );
    }

    #[test]
    fn select_identity_root_hints_not_available() {
        let config = test_config();
        let sni = "spiffe.example.org";
        let root_hints = vec![DistinguishedName::from(testdata::WRONG_DN.to_vec())];
        assert!(
            config
                .select_identity_impl(false, None, Some(root_hints.as_slice()), Some(&sni))
                .is_none()
        );
    }

    #[test]
    fn select_identity_sni() {
        let config = test_config();
        let sni = "spiffe2.example.org";
        assert_eq!(
            config
                .select_identity_impl(false, None, None, Some(&sni))
                .expect("workload2")
                .cert,
            config.svids[1].certified_key.cert
        );
    }

    #[test]
    fn choose_roots_no_remote_identity() {
        let config = test_config();
        assert!(config.choose_root_hint_subjects(None, None).is_none());
    }

    #[test]
    fn choose_roots_unrelated_remote_identity() {
        let config = test_config();

        let uri = Uri::from_static("https://user1/");
        assert!(config.choose_root_hint_subjects(None, Some(&uri)).is_none());

        let cert = X509Certificate::from_der(&testdata::UNRELATED_CERT)
            .unwrap()
            .1;
        assert!(config.trust_anchors_for_cert(false, &cert, &[]).is_none());
    }

    #[test]
    fn choose_roots_local_identity() {
        let config = test_config();
        let want = [testdata::SPIFFE2_ROOT_DN.as_ref()];

        let uri = Uri::from_static("spiffe://spiffe2.example.org/foo/bar");
        assert_eq!(
            config
                .choose_root_hint_subjects(None, Some(&uri))
                .expect("spiffe2")
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .as_slice(),
            want.as_slice()
        );

        let cert = X509Certificate::from_der(&config.svids[1].certified_key.cert[0].as_ref())
            .unwrap()
            .1;
        let ta = config
            .trust_anchors_for_cert(false, &cert, &[])
            .expect("spiffe2");
        assert_eq!(
            RootCertStore { roots: ta.to_vec() }
                .subjects()
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .as_slice(),
            want.as_slice(),
        );
    }

    #[test]
    fn choose_roots_federated_identity() {
        let config = test_config();
        let want = [testdata::SPIFFE3_ROOT_DN.as_ref()];

        let uri = Uri::from_static("spiffe://spiffe3.example.org/foo/bar");
        assert_eq!(
            config
                .choose_root_hint_subjects(None, Some(&uri))
                .expect("spiffe3")
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .as_slice(),
            want.as_slice()
        );

        let cert = X509Certificate::from_der(&testdata::SPIFFE3_CERT)
            .unwrap()
            .1;
        let ta = config
            .trust_anchors_for_cert(false, &cert, &[])
            .expect("spiffe3");
        assert_eq!(
            RootCertStore { roots: ta.to_vec() }
                .subjects()
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .as_slice(),
            want.as_slice(),
        );
    }

    #[test]
    fn verify_expected_identity_yes() {
        let cert = X509Certificate::from_der(&testdata::SPIFFE3_CERT)
            .unwrap()
            .1;
        let uri = Uri::from_static("spiffe://spiffe3.example.org/node3/workload3");
        let config = test_config();
        assert!(matches!(
            config.verify_expected_identity(&cert, &uri),
            VerifyExpectedIdentityResult::Yes
        ));
    }

    #[test]
    fn verify_expected_identity_no() {
        let cert = X509Certificate::from_der(&testdata::SPIFFE3_CERT)
            .unwrap()
            .1;
        let uri = Uri::from_static("spiffe://nifty3.example.org/node3/workload3");
        let config = test_config();
        assert!(matches!(
            config.verify_expected_identity(&cert, &uri),
            VerifyExpectedIdentityResult::No
        ));
    }

    #[test]
    fn expiration() {
        assert_eq!(
            test_config().identity_valid_until().expect("expiration"),
            OffsetDateTime::from_unix_timestamp(1753124458).unwrap(),
        );
    }
}
