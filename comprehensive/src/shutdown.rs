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
    wakers: Option<[TryLock<Option<Waker>>; SHUTDOWN_SIGNAL_N_PARTICIPANTS]>,
    children: FixedBitSet,
}

impl ShutdownSignalEntry {
    fn new(s: usize, inert: bool) -> Self {
        ShutdownSignalEntry {
            refcount: AtomicUsize::new(1),
            quit_order: AtomicUsize::new(usize::MAX),
            wakers: if inert {
                None
            } else {
                Some([TryLock::new(None), TryLock::new(None)])
            },
            children: FixedBitSet::with_capacity(s),
        }
    }

    fn is_present(&self) -> bool {
        !self.children.is_empty()
    }
}

pub(crate) struct ShutdownSignalHeader {
    quit_cursor: AtomicUsize,
    task_quit_waker: TryLock<Option<Waker>>,
    n_nodes: usize,
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
pub struct ShutdownSignalParticipantCreator(Option<ShutdownSignalParticipant>, bool);

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
        if self.1 {
            (0, Some(0))
        } else {
            (
                SHUTDOWN_SIGNAL_N_PARTICIPANTS,
                Some(SHUTDOWN_SIGNAL_N_PARTICIPANTS),
            )
        }
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

enum AddOneState<I> {
    Inner(I),
    Done,
}

struct AddOne<I> {
    size_min: usize,
    size_max: Option<usize>,
    state: AddOneState<I>,
}

impl<I: Iterator> AddOne<I> {
    fn new(it: I) -> Self {
        let (size_min, size_max) = it.size_hint();
        Self {
            size_min: size_min.checked_add(1).expect("usize::MAX too many nodes"),
            size_max: size_max.map(|v| v.checked_add(1).expect("usize::MAX too many nodes")),
            state: AddOneState::Inner(it),
        }
    }
}

impl<I> Iterator for AddOne<I>
where
    I: Iterator,
    I::Item: Default,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            AddOneState::Inner(ref mut it) => match it.next() {
                Some(v) => Some(v),
                None => {
                    self.state = AddOneState::Done;
                    Some(Self::Item::default())
                }
            },
            AddOneState::Done => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.size_min, self.size_max)
    }
}

impl<I> ExactSizeIterator for AddOne<I>
where
    I: ExactSizeIterator,
    <I as Iterator>::Item: Default,
{
}

impl ShutdownSignal {
    pub(crate) fn new<I>(it: I) -> Self
    where
        I: std::iter::ExactSizeIterator<Item = bool>,
    {
        let l = it.len();
        Self(SliceWithHeader::new(
            // An additional entry for the root
            ShutdownSignalHeader {
                quit_cursor: AtomicUsize::default(),
                task_quit_waker: TryLock::new(None),
                n_nodes: l,
            },
            AddOne::new(it).map(|inert| ShutdownSignalEntry::new(l, inert)),
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

    pub(crate) fn edges(&self) -> impl Iterator<Item = (usize, usize)> {
        self.0
            .slice
            .iter()
            .enumerate()
            .flat_map(|(i_from, row)| row.children.ones().map(move |i_to| (i_from, i_to)))
    }

    pub(crate) fn nodes_len(&self) -> usize {
        self.0.header.n_nodes
    }
}

impl ShutdownSignalMut<'_> {
    pub(crate) fn add_parent(&mut self, child: usize, parent: Option<usize>) {
        self.0.slice[parent.unwrap_or(self.0.slice.len() - 1)]
            .children
            .insert(child);
        *self.0.slice[child].refcount.get_mut() += 1
    }

    pub(crate) fn remove_unreferenced(&mut self) {
        let l = self.0.slice.len() - 1;
        for i in 0..l {
            if *self.0.slice[i].refcount.get_mut() == 1 {
                self.unreference(i);
            }
        }
        self.0.header.n_nodes = self
            .0
            .slice
            .iter()
            .take(l)
            .filter(|e| e.is_present())
            .count();
    }

    fn unreference(&mut self, i: usize) {
        let e = &mut self.0.slice[i];
        let refcount = e.refcount.get_mut();
        *refcount -= 1;
        if *refcount == 0 {
            for j in std::mem::take(&mut e.children).into_ones() {
                self.unreference(j);
            }
        }
    }
}

pub(crate) struct ShutdownSignalIterator(Arc<ShutdownSignalInner>, usize);

impl Iterator for ShutdownSignalIterator {
    type Item = Option<(TaskRunningSentinel, ShutdownSignalParticipantCreator)>;

    fn next(&mut self) -> Option<Self::Item> {
        let i = self.1;
        if i < self.0.slice.len() {
            self.1 += 1;
            // .is_present() wrongly returns false in the case of an empty assembly,
            // so special-case that.
            if self.0.slice[i].is_present() || self.0.slice.len() == 1 {
                Some(Some((
                    TaskRunningSentinel::new(&self.0, i),
                    if self.0.slice[i].wakers.is_some() {
                        ShutdownSignalParticipantCreator(
                            Some(ShutdownSignalParticipant {
                                matrix: Some(Arc::clone(&self.0)),
                                row: i,
                                waker_slot: 0,
                            }),
                            false,
                        )
                    } else {
                        ShutdownSignalParticipantCreator(None, true)
                    },
                )))
            } else {
                Some(None)
            }
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

fn propagate(matrix: &ShutdownSignalInner, row: usize) {
    // On entry, our own refcount is either 0 or 1 (we don't create
    // ShutdownSignalForwarder unless that's true and don't call ourselves
    // recursively unless that's true) and 0 means we have already been called,
    // so we only proceed if it was 1. Either way it will become 0.
    if matrix.slice[row].refcount.fetch_min(0, Ordering::Release) == 1 {
        for i in matrix.slice[row].children.ones() {
            if matrix.slice[i].refcount.fetch_sub(1, Ordering::Release) == 2 {
                // The child's refcount has become 1 meaning it's time to
                // wake it. Going below 1 will happen when it calls its own
                // .propgate().
                if let Some(ref wakers) = matrix.slice[i].wakers {
                    for slot in wakers {
                        if let Some(mut maybe_waker) = slot.try_lock() {
                            if let Some(waker) = maybe_waker.take() {
                                waker.wake()
                            }
                        }
                    }
                } else {
                    // This row is inert, nobody is listening.
                    // Propagate on its behalf.
                    propagate(matrix, i);
                }
            }
        }
    }
}

impl ShutdownSignalForwarder {
    pub(crate) fn propagate(self) {
        propagate(&self.matrix, self.row)
    }
}

impl Drop for ShutdownSignalParticipant {
    fn drop(&mut self) {
        if let Some(ref mut matrix) = self.matrix {
            if let Some(mut maybe_waker) =
                matrix.slice[self.row].wakers.as_ref().unwrap()[self.waker_slot].try_lock()
            {
                let _ = maybe_waker.take();
            }
        }
    }
}

impl ShutdownSignalParticipant {
    fn future_ready(&mut self) -> Poll<ShutdownSignalForwarder> {
        let matrix = self.matrix.take().unwrap();
        if let Some(mut maybe_waker) =
            matrix.slice[self.row].wakers.as_ref().unwrap()[self.waker_slot].try_lock()
        {
            let _ = maybe_waker.take();
        }
        Poll::Ready(ShutdownSignalForwarder {
            matrix,
            row: self.row,
        })
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
        let took_lock = entry.wakers.as_ref().unwrap()[this.waker_slot]
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

    // Doesn't really belong here but it's the only convenient place.
    pub(crate) fn is_dependent_of(&self, candidate: usize) -> bool {
        self.0.slice[candidate].children.contains(self.1)
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
        self.0.header.n_nodes.saturating_sub(self.1)
    }
}

impl Stream for TaskQuits {
    type Item = usize;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<usize>> {
        if self.1 >= self.0.header.n_nodes {
            self.1 = usize::MAX;
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
        self.1 == usize::MAX
    }
}
