//! [`comprehensive`] [`Resource`] generator for using S3 buckets
//!
//! This crate provides a macro for declaring an S3 bucket as a
//! [`comprehensive::Resource`]. It is a thin wrapper over the
//! [`s3::Bucket`] type. When included in a [`comprehensive::Assembly`]
//! it probes the bucket periodically as a health check signal.
//!
//! ```
//! // Defines a new type "SomeBucket" which is a Resource with
//! // display name "My storage". It installs command line flags
//! // beginning with "--app-data-" for specifying the bucket.
//! comprehensive_s3::bucket!(SomeBucket, "My storage", "app-data-");
//!
//! // It can later be used as a dependency for another Resource:
//! #[derive(comprehensive::ResourceDependencies)]
//! struct OtherDependencies {
//!     bucket: std::sync::Arc<SomeBucket>,
//! }
//! ```
//!
//! # Command line flags for buckets
//!
//! | Flag                     | Default  | Meaning                 |
//! |--------------------------|----------|-------------------------|
//! | `--PREFIXs3-endpoint`    | Auto     | Endpoint (usually https://...) If unset, [`s3::Region`] builtins will be used. |
//! | `--PREFIXs3-region-name` | Required | Region name as a string. |
//! | `--PREFIXbucket-name`    | Required | Bucket name as a string. |

#![warn(missing_docs)]

use comprehensive::health::{HealthReporter, HealthSignaller};
use comprehensive::{Resource, ResourceDependencies};
#[doc(hidden)]
pub use const_format;
use futures::future::Either;
use futures::pin_mut;
#[doc(hidden)]
pub use gensym::gensym;
use s3::Bucket;
use s3::Region;
use s3::creds::Credentials;
use s3::error::S3Error;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

const PROBE_TIMEOUT: Duration = Duration::from_millis(5000);
const PROBE_INTERVAL: Duration = Duration::from_millis(15000);
const REMIND_INTERVAL: Duration = Duration::from_millis(60000);

#[doc(hidden)]
pub trait BucketInstanceDescriptor: Sync + Send + 'static {
    const NAME: &str;
    const S3_ENDPOINT_FLAG_NAME: &str;
    const S3_REGION_NAME_FLAG_NAME: &str;
    const S3_BUCKET_NAME_FLAG_NAME: &str;
}

#[doc(hidden)]
#[derive(ResourceDependencies)]
pub struct Dependencies(Arc<HealthReporter>);

#[doc(hidden)]
#[derive(clap::Args, Debug)]
#[group(skip)]
pub struct Args<I: BucketInstanceDescriptor> {
    #[arg(long(I::S3_ENDPOINT_FLAG_NAME), id(I::S3_ENDPOINT_FLAG_NAME))]
    endpoint: Option<String>,

    #[arg(long(I::S3_REGION_NAME_FLAG_NAME), id(I::S3_REGION_NAME_FLAG_NAME))]
    region_name: String,

    #[arg(long(I::S3_BUCKET_NAME_FLAG_NAME), id(I::S3_BUCKET_NAME_FLAG_NAME))]
    bucket_name: String,

    #[clap(skip = PhantomData)]
    _i: PhantomData<I>,
}

#[derive(Debug)]
enum ProbeError {
    S3(S3Error),
    Timeout,
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::S3(ref e) => e.fmt(f),
            Self::Timeout => write!(f, "probe exceeded timeout of {:?}", PROBE_TIMEOUT),
        }
    }
}

impl std::error::Error for ProbeError {}

async fn probe(b: &Bucket) -> Result<(), ProbeError> {
    let deadline = sleep(PROBE_TIMEOUT);
    let task = b.head_object("health_probe");
    pin_mut!(deadline);
    pin_mut!(task);
    match futures::future::select(task, deadline).await {
        Either::Left((Ok(_), _)) => Ok(()),
        Either::Left((Err(S3Error::HttpFailWithBody(404, _)), _)) => Ok(()),
        Either::Left((Err(e), _)) => Err(ProbeError::S3(e)),
        Either::Right(_) => Err(ProbeError::Timeout),
    }
}

#[doc(hidden)]
pub struct BucketResource<I>
where
    I: BucketInstanceDescriptor + Sync + Send + 'static,
{
    bucket: Box<Bucket>,
    health_signaller: HealthSignaller,
    _i: PhantomData<I>,
}

impl<I> Resource for BucketResource<I>
where
    I: BucketInstanceDescriptor + Sync + Send + 'static,
{
    type Args = Args<I>;
    type Dependencies = Dependencies;
    const NAME: &str = I::NAME;

    fn new(d: Dependencies, args: Args<I>) -> Result<Self, Box<dyn std::error::Error>> {
        let cred = Credentials::default().unwrap();
        let region = match args.endpoint {
            Some(ep) => Region::Custom {
                region: args.region_name,
                endpoint: ep,
            },
            None => args.region_name.parse()?,
        };
        Ok(Self {
            bucket: Bucket::new(&args.bucket_name, region, cred)?,
            health_signaller: d.0.register(I::NAME)?,
            _i: PhantomData,
        })
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut healthy = false;
        let mut notified = None;
        loop {
            if let Err(e) = probe(self.bucket.as_ref()).await {
                let complain = match notified {
                    None => true,
                    Some(n) => Instant::now().duration_since(n) >= REMIND_INTERVAL,
                };
                if complain {
                    log::error!("S3 probe failed: {}", e);
                    notified = Some(Instant::now());
                }
                if healthy {
                    self.health_signaller.set_healthy(false);
                    healthy = false;
                }
            } else if !healthy {
                self.health_signaller.set_healthy(true);
                healthy = true;
            }
            sleep(PROBE_INTERVAL).await;
        }
    }
}

impl<I> AsRef<Bucket> for BucketResource<I>
where
    I: BucketInstanceDescriptor + Sync + Send + 'static,
{
    fn as_ref(&self) -> &Bucket {
        &self.bucket
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! _bucket {
    ($gensym:ident, $visibility:vis $type_name:ident, $name:literal, $flag_prefix:literal) => {
        $visibility type $type_name = ::comprehensive_s3::BucketResource<$gensym>;

        struct $gensym;

        impl ::comprehensive_s3::BucketInstanceDescriptor for $gensym {
            const NAME: &str = $name;
            const S3_ENDPOINT_FLAG_NAME: &str = ::comprehensive_s3::const_format::concatcp!($flag_prefix, "s3-endpoint");
            const S3_REGION_NAME_FLAG_NAME: &str = ::comprehensive_s3::const_format::concatcp!($flag_prefix, "s3-region-name");
            const S3_BUCKET_NAME_FLAG_NAME: &str = ::comprehensive_s3::const_format::concatcp!($flag_prefix, "bucket-name");
        }
    };
}

/// Defines a new type "SomeBucket" which is a Resource with
/// display name "My storage". It installs command line flags
/// beginning with "--app-data-" for specifying the bucket.
///
/// ```
/// comprehensive_s3::bucket!(SomeBucket, "My storage", "app-data-");
/// ```
///
/// The resulting struct implements:
/// * [`Resource`]
/// * [`AsRef<s3::Bucket>`]
#[macro_export]
macro_rules! bucket {
    ($visibility:vis $type_name:ident, $name:literal, $flag_prefix:literal) => {
        ::comprehensive_s3::gensym!{ ::comprehensive_s3::_bucket!{ $visibility $type_name, $name, $flag_prefix } }
    }
}
