use fixedbitset::FixedBitSet;
use futures::Stream;
use slice_dst::SliceWithHeader;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use try_lock::TryLock;

// One participant we can hand to the user, one for us to keep to mop up.
pub(crate) const SHUTDOWN_SIGNAL_N_PARTICIPANTS: usize = 2;

pub(crate) struct ShutdownSignalEntry {
    refcount: AtomicUsize,
    quit_order: AtomicUsize,
    wakers: [TryLock<Option<Waker>>; SHUTDOWN_SIGNAL_N_PARTICIPANTS],
    children: FixedBitSet,
}

impl ShutdownSignalEntry {
    fn new(s: usize) -> Self {
        ShutdownSignalEntry {
            refcount: AtomicUsize::new(1),
            quit_order: AtomicUsize::new(usize::MAX),
            wakers: [TryLock::new(None), TryLock::new(None)],
            children: FixedBitSet::with_capacity(s),
        }
    }
}

pub(crate) struct ShutdownSignalHeader {
    quit_cursor: AtomicUsize,
    task_quit_waker: TryLock<Option<Waker>>,
}

type ShutdownSignalInner = SliceWithHeader<ShutdownSignalHeader, ShutdownSignalEntry>;

pub(crate) struct ShutdownSignal(Arc<ShutdownSignalInner>);

#[doc(hidden)]
pub struct ShutdownSignalParticipant {
    matrix: Option<Arc<ShutdownSignalInner>>,
    row: usize,
    waker_slot: usize,
}

pub struct ShutdownSignalForwarder {
    matrix: Arc<ShutdownSignalInner>,
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

pub(crate) struct ShutdownSignalMut<'a>(&'a mut ShutdownSignalInner);

impl ShutdownSignal {
    pub(crate) fn new(s: usize) -> Self {
        Self(SliceWithHeader::new(
            // An additional entry for the root
            ShutdownSignalHeader {
                quit_cursor: AtomicUsize::default(),
                task_quit_waker: TryLock::new(None),
            },
            std::iter::repeat_n((), s + 1).map(|_| ShutdownSignalEntry::new(s)),
        ))
    }

    pub(crate) fn get_mut(&mut self) -> Option<ShutdownSignalMut<'_>> {
        Arc::get_mut(&mut self.0).map(ShutdownSignalMut)
    }

    pub(crate) fn into_monitors(self) -> (TaskQuits, ShutdownSignalIterator) {
        (
            TaskQuits(Arc::clone(&self.0), 0),
            ShutdownSignalIterator(self.0, 0),
        )
    }
}

impl ShutdownSignalMut<'_> {
    pub(crate) fn add_parent(&mut self, child: usize, parent: Option<usize>) {
        self.0.slice[parent.unwrap_or(self.0.slice.len() - 1)]
            .children
            .insert(child);
        *self.0.slice[child].refcount.get_mut() += 1
    }
}

pub(crate) struct ShutdownSignalIterator(Arc<ShutdownSignalInner>, usize);

impl Iterator for ShutdownSignalIterator {
    type Item = (TaskRunningSentinel, ShutdownSignalParticipantCreator);

    fn next(&mut self) -> Option<Self::Item> {
        let i = self.1;
        if i < self.0.slice.len() {
            self.1 += 1;
            Some((
                TaskRunningSentinel::new(&self.0, i),
                ShutdownSignalParticipantCreator(Some(ShutdownSignalParticipant {
                    matrix: Some(Arc::clone(&self.0)),
                    row: i,
                    waker_slot: 0,
                })),
            ))
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let l = self.0.slice.len();
        (l, Some(l))
    }
}

impl ExactSizeIterator for ShutdownSignalIterator {}

impl ShutdownSignalForwarder {
    pub(crate) fn propagate(self) {
        // On entry, our own refcount is either 0 or 1 (we don't create this
        // object unless that's true) and 0 means we have already been called,
        // so we only proceed if it was 1. Either way it will become 0.
        if self.matrix.slice[self.row]
            .refcount
            .fetch_min(0, Ordering::Release)
            == 1
        {
            for i in self.matrix.slice[self.row].children.ones() {
                if self.matrix.slice[i]
                    .refcount
                    .fetch_sub(1, Ordering::Release)
                    == 2
                {
                    // The child's refcount has become 1 meaning it's time to
                    // wake it. Going below 1 will happen when it calls its own
                    // .propgate().
                    for slot in &self.matrix.slice[i].wakers {
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
            if let Some(mut maybe_waker) = matrix.slice[self.row].wakers[self.waker_slot].try_lock()
            {
                let _ = maybe_waker.take();
            }
        }
    }
}

impl ShutdownSignalParticipant {
    fn future_ready(&mut self) -> Poll<ShutdownSignalForwarder> {
        let matrix = self.matrix.take().unwrap();
        if let Some(mut maybe_waker) = matrix.slice[self.row].wakers[self.waker_slot].try_lock() {
            let _ = maybe_waker.take();
        }
        Poll::Ready(ShutdownSignalForwarder {
            matrix,
            row: self.row,
        })
    }

    pub(crate) fn iter_children(&self) -> fixedbitset::Ones<'_> {
        self.matrix.as_ref().unwrap().slice[self.row]
            .children
            .ones()
    }
}

impl Future for ShutdownSignalParticipant {
    type Output = ShutdownSignalForwarder;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<ShutdownSignalForwarder> {
        let this = Pin::into_inner(self);
        let matrix = this.matrix.as_mut().expect("poll called after Ready");
        let entry = &matrix.slice[this.row];
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
            .map(|m| m.slice[self.row].refcount.load(Ordering::Acquire) < 2)
            .unwrap_or(true)
    }
}

pub struct TaskRunningSentinel(Arc<ShutdownSignalInner>, usize);

impl TaskRunningSentinel {
    pub(crate) fn new(inner: &Arc<ShutdownSignalInner>, index: usize) -> Self {
        Self(Arc::clone(inner), index)
    }

    fn notify(&self, mut new_cursor: usize) {
        loop {
            if let Some(mut maybe_waker) = self.0.header.task_quit_waker.try_lock() {
                if let Some(waker) = maybe_waker.take() {
                    waker.wake()
                }
            } else {
                // Whoever does have the lock should notify for everyone.
                return;
            }
            let even_newer_cursor = self.0.header.quit_cursor.load(Ordering::Acquire);
            if even_newer_cursor == new_cursor {
                // Nobody else incremented the cursor while we had the lock.
                return;
            }
            new_cursor = even_newer_cursor;
        }
    }
}

impl Drop for TaskRunningSentinel {
    fn drop(&mut self) {
        if self.1 == self.0.slice.len() - 1 {
            // Eat the last elemeny, it's not a real task.
            return;
        }
        let mut min_cursor = 0;
        loop {
            // Attempt to write at the indicated position or further if we
            // already know that's occupied.
            let cursor = self
                .0
                .header
                .quit_cursor
                .load(Ordering::Acquire)
                .max(min_cursor);
            // Write our own index at this position if someone else
            // has not already used it.
            match self.0.slice[cursor].quit_order.compare_exchange_weak(
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
                        .quit_cursor
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

pub(crate) struct TaskQuits(Arc<ShutdownSignalInner>, usize);

impl TaskQuits {
    pub(crate) fn len(&self) -> usize {
        let l = self.0.slice.len() - self.1;
        if l > 0 { l - 1 } else { 0 }
    }
}

impl Stream for TaskQuits {
    type Item = usize;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<usize>> {
        if self.1 >= self.0.slice.len() - 1 {
            self.1 = self.0.slice.len();
            return Poll::Ready(None);
        }
        if self.0.header.quit_cursor.load(Ordering::Acquire) > self.1 {
            let item = self.0.slice[self.1].quit_order.load(Ordering::Acquire);
            self.1 += 1;
            return Poll::Ready(Some(item));
        }
        if let Some(mut maybe_waker) = self.0.header.task_quit_waker.try_lock() {
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
        if self.0.header.quit_cursor.load(Ordering::Acquire) > self.1 {
            let item = self.0.slice[self.1].quit_order.load(Ordering::Acquire);
            self.1 += 1;
            Poll::Ready(Some(item))
        } else {
            Poll::Pending
        }
    }
}

impl futures::stream::FusedStream for TaskQuits {
    fn is_terminated(&self) -> bool {
        self.1 >= self.0.slice.len()
    }
}
