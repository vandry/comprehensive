//! Shared trait definition for suppliers of TLS connection parameters.
//!
//! To install a mechanism for supplying TLS serving key and certificates
//! to a [`comprehensive`] [`Assembly`], implement and expose the
//! [`TlsConfigProvider`] trait. Thereafter, new updated TLS serving
//! parameters should be streamed to recipients whenever they are
//! available (such as when keys and certificates are replaced or renewed
//! from under the server).
//!
//! Currently, the first set of TLS parameters need to be delivered
//! immediately at startup, but this requirement will be relaxed in the
//! future.
//!
//! This trait is consumed by [`comprehensive_tls::TlsConfig`] which will
//! use the first working implementor resource and use it.
//!
//! [`comprehensive`]: https://docs.rs/comprehensive/latest/comprehensive/
//! [`comprehensive_tls::TlsConfig`]: https://docs.rs/comprehensive_tls/latest/comprehensive_tls/struct.TlsConfig.html
//! [`Assembly`]: https://docs.rs/comprehensive/latest/comprehensive/assembly/struct.Assembly.html

use atomicbox::AtomicOptionBox;
use futures::Stream;
use futures::sink::Sink;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use try_lock::TryLock;

/// TLS serving parameters as supplied by implementations of [`TlsConfigProvider`].
#[derive(Debug)] // OK to have: PrivateKeyDer's Debug elides the key.
pub struct Snapshot {
    /// X.509 private key belonging to this server.
    pub key: PrivateKeyDer<'static>,
    /// X.509 certificate(s) belonging to this server.
    pub cert: Vec<CertificateDer<'static>>,
    /// X.509 trust anchors this server should use to verify peers.
    pub cacert: Option<Vec<CertificateDer<'static>>>,
}

/// Object which implementors of the [`TlsConfigProvider`] trait need to contain.
///
/// An implementor of [`TlsConfigProvider`] should look like this:
///
/// ```
/// use comprehensive_traits::tls_config::{Exchange, Snapshot, TlsConfigProvider};
/// use futures::SinkExt;
///
/// pub struct WeGetKeysAndCertsFromSomewhere(Exchange);
///
/// impl TlsConfigProvider for WeGetKeysAndCertsFromSomewhere {
///     fn stream(&self) -> Option<comprehensive_traits::tls_config::Reader<'_>> {
///         self.0.reader()
///     }
/// }
///
/// # async fn demo() {
/// // somewhere in WeGetKeysAndCertsFromSomewhere::new
/// let x = WeGetKeysAndCertsFromSomewhere(Exchange::default());
///
/// // when we have some parameters to give:
/// x.0.writer().unwrap().send(Snapshot {
///     // ...
/// # key: rustls_pki_types::PrivateKeyDer::try_from(Vec::<u8>::new()).unwrap(),
/// # cert: Vec::new(),
/// # cacert: None,
/// }.into()).await;
/// # }
/// ```
#[derive(Default)]
pub struct Exchange {
    current: AtomicOptionBox<Snapshot>,
    flags: AtomicUsize,
    waker: TryLock<Option<Waker>>,
}

/// [`Stream`] of [`Snapshot`] supplied to consumers of [`TlsConfigProvider`].
pub struct Reader<'a>(&'a Exchange);

impl Stream for Reader<'_> {
    type Item = Box<Snapshot>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Box<Snapshot>>> {
        if let Some(v) = self.0.current.take(Ordering::SeqCst) {
            return Poll::Ready(Some(v));
        }
        if let Some(mut maybe_waker) = self
            .0
            .waker
            .try_lock_explicit(Ordering::SeqCst, Ordering::Release)
        {
            let park = maybe_waker
                .as_ref()
                .map(|w| !w.will_wake(cx.waker()))
                .unwrap_or(true);
            if park {
                let old = std::mem::replace(&mut *maybe_waker, Some(cx.waker().clone()));
                if let Some(w) = old {
                    w.wake();
                }
            }
        }
        if let Some(v) = self.0.current.take(Ordering::SeqCst) {
            Poll::Ready(Some(v))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for Reader<'_> {
    fn drop(&mut self) {
        self.0.flags.fetch_and(!1, Ordering::AcqRel);
    }
}

/// [`Sink`] for implementors of [`TlsConfigProvider`] to supply [`Snapshot`].
///
/// The sink is always ready to accept new values because the stream only
/// remembers the most recent value.
pub struct Writer<'a>(&'a Exchange);

impl Sink<Box<Snapshot>> for Writer<'_> {
    type Error = std::convert::Infallible;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(())) // always ready because new values squash old
    }

    fn start_send(self: Pin<&mut Self>, item: Box<Snapshot>) -> Result<(), Self::Error> {
        self.0.current.store(Some(item), Ordering::SeqCst);
        if let Some(mut maybe_waker) = self
            .0
            .waker
            .try_lock_explicit(Ordering::SeqCst, Ordering::Release)
        {
            if let Some(waker) = maybe_waker.take() {
                waker.wake()
            }
        }
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for Writer<'_> {
    fn drop(&mut self) {
        self.0.flags.fetch_and(!2, Ordering::AcqRel);
    }
}

impl Exchange {
    /// Get a stream of TLS serving parameters. Intended to be called in the
    /// implementation of [`TlsConfigProvider::stream`].
    pub fn reader(&self) -> Option<Reader<'_>> {
        if self.flags.fetch_or(1, Ordering::AcqRel) & 1 == 1 {
            None
        } else {
            Some(Reader(self))
        }
    }

    /// Get a sink for writing TLS serving parameters. Intended to be called
    /// by implementors of [`TlsConfigProvider`].
    pub fn writer(&self) -> Option<Writer<'_>> {
        if self.flags.fetch_or(2, Ordering::AcqRel) & 2 == 2 {
            None
        } else {
            Some(Writer(self))
        }
    }
}

/// A trait exposed by a resource that provides TLS serving parameters.
pub trait TlsConfigProvider: Send + Sync {
    /// Obtain a stream which will emit new updated TLS serving parameters
    /// whenever they are available.
    fn stream(&self) -> Option<Reader<'_>>;
}
