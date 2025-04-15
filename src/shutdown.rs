use fixedbitset::FixedBitSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use try_lock::TryLock;

// One participant we can hand to the user, one for us to keep to mop up.
pub(crate) const SHUTDOWN_SIGNAL_N_PARTICIPANTS: usize = 2;

struct ShutdownSignalEntry {
    refcount: AtomicUsize,
    wakers: [TryLock<Option<Waker>>; SHUTDOWN_SIGNAL_N_PARTICIPANTS],
    children: FixedBitSet,
}

impl ShutdownSignalEntry {
    fn new(s: usize) -> Self {
        ShutdownSignalEntry {
            refcount: AtomicUsize::new(1),
            wakers: [TryLock::new(None), TryLock::new(None)],
            children: FixedBitSet::with_capacity(s),
        }
    }
}

pub(crate) struct ShutdownSignal(Arc<[ShutdownSignalEntry]>);

#[doc(hidden)]
pub struct ShutdownSignalParticipant {
    matrix: Option<Arc<[ShutdownSignalEntry]>>,
    row: usize,
    waker_slot: usize,
}

pub struct ShutdownSignalForwarder {
    matrix: Arc<[ShutdownSignalEntry]>,
    row: usize,
}

#[doc(hidden)]
pub struct ShutdownSignalParticipantCreator(Option<ShutdownSignalParticipant>);

impl Iterator for ShutdownSignalParticipantCreator {
    type Item = ShutdownSignalParticipant;

    fn next(&mut self) -> Option<ShutdownSignalParticipant> {
        let (current, following) = match self.0.take() {
            None => (None, None),
            Some(p) => {
                let following = if p.waker_slot == SHUTDOWN_SIGNAL_N_PARTICIPANTS - 1 {
                    None
                } else {
                    Some(ShutdownSignalParticipant {
                        matrix: p.matrix.as_ref().map(Arc::clone),
                        row: p.row,
                        waker_slot: p.waker_slot + 1,
                    })
                };
                (Some(p), following)
            }
        };
        self.0 = following;
        current
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (
            SHUTDOWN_SIGNAL_N_PARTICIPANTS,
            Some(SHUTDOWN_SIGNAL_N_PARTICIPANTS),
        )
    }
}

impl ShutdownSignalParticipantCreator {
    // Like .take(1).next() but more efficient
    pub(crate) fn into_inner(self) -> Option<ShutdownSignalParticipant> {
        self.0
    }
}

impl ExactSizeIterator for ShutdownSignalParticipantCreator {}

pub(crate) struct ShutdownSignalMut<'a>(&'a mut [ShutdownSignalEntry]);

impl ShutdownSignal {
    pub(crate) fn new(s: usize) -> Self {
        Self(
            std::iter::repeat(())
                .map(|_| ShutdownSignalEntry::new(s))
                .take(s + 1) // An additional entry for the root
                .collect(),
        )
    }

    pub(crate) fn get_mut(&mut self) -> Option<ShutdownSignalMut<'_>> {
        Arc::get_mut(&mut self.0).map(ShutdownSignalMut)
    }
}

impl ShutdownSignalMut<'_> {
    pub(crate) fn add_parent(&mut self, child: usize, parent: Option<usize>) {
        self.0[parent.unwrap_or(self.0.len() - 1)]
            .children
            .insert(child);
        *self.0[child].refcount.get_mut() += 1
    }
}

pub(crate) struct ShutdownSignalIterator(Arc<[ShutdownSignalEntry]>, usize);

impl IntoIterator for ShutdownSignal {
    type Item = ShutdownSignalParticipantCreator;
    type IntoIter = ShutdownSignalIterator;

    fn into_iter(self) -> ShutdownSignalIterator {
        ShutdownSignalIterator(self.0, 0)
    }
}

impl Iterator for ShutdownSignalIterator {
    type Item = ShutdownSignalParticipantCreator;

    fn next(&mut self) -> Option<Self::Item> {
        let i = self.1;
        if i < self.0.len() {
            self.1 += 1;
            Some(ShutdownSignalParticipantCreator(Some(
                ShutdownSignalParticipant {
                    matrix: Some(Arc::clone(&self.0)),
                    row: i,
                    waker_slot: 0,
                },
            )))
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let l = self.0.len();
        (l, Some(l))
    }
}

impl ExactSizeIterator for ShutdownSignalIterator {}

impl ShutdownSignalForwarder {
    pub(crate) fn propagate(self) {
        // On entry, our own refcount is either 0 or 1 (we don't create this
        // object unless that's true) and 0 means we have already been called,
        // so we only proceed if it was 1. Either way it will become 0.
        if self.matrix[self.row]
            .refcount
            .fetch_min(0, Ordering::Release)
            == 1
        {
            for i in self.matrix[self.row].children.ones() {
                if self.matrix[i].refcount.fetch_sub(1, Ordering::Release) == 2 {
                    // The child's refcount has become 1 meaning it's time to
                    // wake it. Going below 1 will happen when it calls its own
                    // .propgate().
                    for slot in &self.matrix[i].wakers {
                        if let Some(mut maybe_waker) = slot.try_lock() {
                            if let Some(waker) = maybe_waker.take() {
                                waker.wake()
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Drop for ShutdownSignalParticipant {
    fn drop(&mut self) {
        if let Some(ref mut matrix) = self.matrix {
            if let Some(mut maybe_waker) = matrix[self.row].wakers[self.waker_slot].try_lock() {
                let _ = maybe_waker.take();
            }
        }
    }
}

impl ShutdownSignalParticipant {
    fn future_ready(&mut self) -> Poll<ShutdownSignalForwarder> {
        let matrix = self.matrix.take().unwrap();
        if let Some(mut maybe_waker) = matrix[self.row].wakers[self.waker_slot].try_lock() {
            let _ = maybe_waker.take();
        }
        Poll::Ready(ShutdownSignalForwarder {
            matrix,
            row: self.row,
        })
    }

    pub(crate) fn iter_children(&self) -> fixedbitset::Ones<'_> {
        self.matrix.as_ref().unwrap()[self.row].children.ones()
    }
}

impl Future for ShutdownSignalParticipant {
    type Output = ShutdownSignalForwarder;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<ShutdownSignalForwarder> {
        let this = Pin::into_inner(self);
        let matrix = this.matrix.as_mut().expect("poll called after Ready");
        let entry = &matrix[this.row];
        if entry.refcount.load(Ordering::Acquire) < 2 {
            return this.future_ready();
        }
        let took_lock = entry.wakers[this.waker_slot]
            .try_lock()
            .map(|mut maybe_waker| {
                let park = maybe_waker
                    .as_ref()
                    .map(|w| !w.will_wake(cx.waker()))
                    .unwrap_or(true);
                if park {
                    std::mem::replace(&mut *maybe_waker, Some(cx.waker().clone()))
                } else {
                    None
                }
            });
        if let Some(old) = took_lock {
            if let Some(waker) = old {
                waker.wake();
            }
            if entry.refcount.load(Ordering::Acquire) < 2 {
                return this.future_ready();
            }
        }
        Poll::Pending
    }
}

impl futures::future::FusedFuture for ShutdownSignalParticipant {
    fn is_terminated(&self) -> bool {
        self.matrix
            .as_ref()
            .map(|m| m[self.row].refcount.load(Ordering::Acquire) < 2)
            .unwrap_or(true)
    }
}
