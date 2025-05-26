use fixedbitset::FixedBitSet;
use futures::Stream;
use slice_dst::SliceWithHeader;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use try_lock::TryLock;

pub struct Header {
    cursor: AtomicUsize,
    waker: TryLock<Option<Waker>>,
}

type Inner = SliceWithHeader<Header, AtomicUsize>;

pub struct Sentinel(Arc<Inner>, usize);

impl Sentinel {
    pub fn new(inner: &Arc<Inner>, index: usize) -> Self {
        Self(Arc::clone(inner), index)
    }

    fn notify(&self, mut new_cursor: usize) {
        loop {
            if let Some(mut maybe_waker) = self.0.header.waker.try_lock() {
                if let Some(waker) = maybe_waker.take() {
                    waker.wake()
                }
            } else {
                // Whoever does have the lock should notify for everyone.
                return;
            }
            let even_newer_cursor = self.0.header.cursor.load(Ordering::Acquire);
            if even_newer_cursor == new_cursor {
                // Nobody else incremented the cursor while we had the lock.
                return;
            }
            new_cursor = even_newer_cursor;
        }
    }
}

impl Drop for Sentinel {
    fn drop(&mut self) {
        let mut min_cursor = 0;
        loop {
            // Attempt to write at the indicated position or further if we
            // already know that's occupied.
            let cursor = self.0.header.cursor.load(Ordering::Acquire).max(min_cursor);
            // Write our own index at this position if someone else
            // has not already used it.
            match self.0.slice[cursor].compare_exchange_weak(
                usize::MAX,
                self.1,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // Update the cursor one past where we wrote unless someone
                    // else has updated it even higher.
                    let new_cursor = self
                        .0
                        .header
                        .cursor
                        .fetch_max(cursor + 1, Ordering::Release)
                        .max(cursor + 1);

                    self.notify(new_cursor);
                    return;
                }
                Err(current) => {
                    // If we refused to overwrite something that was not
                    // usize::MAX then we know to go past.
                    min_cursor = cursor + if current == usize::MAX { 0 } else { 1 };
                }
            }
        }
    }
}

pub struct Builder(Arc<Inner>, FixedBitSet);

/// A [`Stream`] that delivers a value every time an associated [`Sentinel`]
/// is dropped. The value is the serial number of the [`Sentinel`].
pub struct DropStream {
    inner: Arc<Inner>,
    cursor: usize,
    len: usize,
}

impl Builder {
    pub fn new(l: usize) -> Self {
        Self(
            SliceWithHeader::new(
                Header {
                    cursor: AtomicUsize::default(),
                    waker: TryLock::new(None),
                },
                std::iter::repeat_n((), l).map(|_| AtomicUsize::new(usize::MAX)),
            ),
            FixedBitSet::with_capacity(l),
        )
    }

    pub fn make_sentinel(&mut self, i: usize) -> Option<Sentinel> {
        if self.1.put(i) {
            None
        } else {
            Some(Sentinel::new(&self.0, i))
        }
    }

    pub fn into_stream(self) -> DropStream {
        DropStream { inner: self.0, cursor: 0, len: self.1.count_ones(..) }
    }
}

impl Stream for DropStream {
    type Item = usize;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<usize>> {
        if self.len == 0 || self.len == usize::MAX {
            self.len = usize::MAX;
            return Poll::Ready(None);
        }
        if self.inner.header.cursor.load(Ordering::Acquire) > self.cursor {
            let item = self.inner.slice[self.cursor].load(Ordering::Acquire);
            self.cursor += 1;
            self.len -= 1;
            return Poll::Ready(Some(item));
        }
        if let Some(mut maybe_waker) = self.inner.header.waker.try_lock() {
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
        if self.inner.header.cursor.load(Ordering::Acquire) > self.cursor {
            let item = self.inner.slice[self.cursor].load(Ordering::Acquire);
            self.cursor += 1;
            Poll::Ready(Some(item))
        } else {
            Poll::Pending
        }
    }
}

impl futures::stream::FusedStream for DropStream {
    fn is_terminated(&self) -> bool {
        self.len == usize::MAX
    }
}
